// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `ENGINE_load_private_key` implementation: resolve an `azihsm://` URI to an
//! HSM key and return an `EVP_PKEY`.
//!
//! The returned key carries the real public key (rebuilt from the SDK's DER via
//! the safe `openssl` crate) plus the live HSM private-key wrapper, stashed in
//! the underlying `EC_KEY` ex_data so it stays alive for later sign/derive
//! callbacks and is deleted from the HSM when the `EVP_PKEY` is freed. The
//! sign/derive methods themselves are not wired yet (a later change), so a
//! loaded key is currently usable for public-key operations (e.g. `-pubout`).
//!
//! Only EC keys are supported here; RSA loading (an HSM import + unmask path)
//! lands in a follow-up together with its test coverage.

use std::ffi::c_int;
use std::ffi::c_long;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::OnceLock;

use azihsm_api::HsmEccKeyUnmaskAlgo;
use azihsm_api::HsmEccPrivateKey;
use azihsm_api::HsmKeyCommonProps;
use azihsm_api::HsmKeyManager;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
use azihsm_ossl_engine_core::error::catch_panic;
use azihsm_ossl_engine_core::ffi;
use foreign_types::ForeignTypeRef;
use openssl::pkey::PKey;
use parking_lot::Mutex;

use crate::context::EngineData;
use crate::uri;
use crate::uri::KeyType;

/// Load the private key named by `key_id` (an `azihsm://…` URI) and return an
/// owning `*mut EVP_PKEY`.
pub fn load_key(data: &EngineData, key_id: &str) -> EngineResult<*mut ffi::EVP_PKEY> {
    let parsed = uri::parse(key_id)?;

    // First real caller of the lazy HSM open (idempotent).
    data.open_hsm_from_env()?;

    let masked = std::fs::read(&parsed.masked_key_path).map_err(|e| {
        EngineError::wrap(
            format!("read masked key {}", parsed.masked_key_path.display()),
            e,
        )
    })?;

    match parsed.key_type {
        KeyType::Ec => load_ec(data, &masked),
        // RSA loading lands in a follow-up (it needs an HSM import path plus
        // test coverage); recognize the type but reject it clearly for now.
        KeyType::Rsa | KeyType::RsaPss => Err(EngineError::Other(
            "RSA key loading is not yet supported".into(),
        )),
    }
}

fn load_ec(data: &EngineData, masked: &[u8]) -> EngineResult<*mut ffi::EVP_PKEY> {
    let priv_key = data.with_session(|session| {
        let mut algo = HsmEccKeyUnmaskAlgo {};
        HsmKeyManager::unmask_key_pair(session, &mut algo, masked)
            .map(|(private, _public)| private)
            .map_err(|e| EngineError::wrap("EC key unmask", e))
    })?;

    let der = priv_key
        .pub_key_der_vec()
        .map_err(|e| EngineError::wrap("read EC public key DER", e))?;

    build_ec_pkey(&der, priv_key)
}

/// Rebuild the public `EVP_PKEY` from `der` (safe `openssl` crate) and attach
/// the live HSM key to it before transferring ownership to OpenSSL.
fn build_ec_pkey(der: &[u8], key: HsmEccPrivateKey) -> EngineResult<*mut ffi::EVP_PKEY> {
    let pkey =
        PKey::public_key_from_der(der).map_err(|e| EngineError::wrap("parse public key DER", e))?;

    // The `openssl` crate's `EVP_PKEY` and the engine-ABI `EVP_PKEY` are the
    // same C struct (both link the one system libcrypto), so casting the raw
    // pointer at this single boundary is sound.
    let raw = pkey.as_ptr().cast::<ffi::EVP_PKEY>();

    // Attach while `pkey` still owns `raw`: if `attach_ec` fails, `pkey` drops
    // at end of scope and frees the EVP_PKEY.
    attach_ec(raw, key)?;

    // Success: hand ownership to OpenSSL.
    std::mem::forget(pkey);
    Ok(raw)
}

#[allow(unsafe_code)]
fn attach_ec(pkey: *mut ffi::EVP_PKEY, key: HsmEccPrivateKey) -> EngineResult<()> {
    let idx = ec_key_ex_index()?;

    // SAFETY: pkey is a valid EVP_PKEY holding an EC key (built above).
    let ec = unsafe { ffi::EVP_PKEY_get0_EC_KEY(pkey) };
    if ec.is_null() {
        return Err(EngineError::Other("EVP_PKEY has no EC_KEY".into()));
    }

    let boxed = Box::into_raw(Box::new(key)).cast::<c_void>();
    // SAFETY: ec is valid, idx is a registered EC_KEY ex_data slot, and boxed is
    // a fresh Box::into_raw whose ownership passes to the ex_data slot on success.
    let rc = unsafe { ffi::EC_KEY_set_ex_data(ec, idx, boxed) };
    if rc != 1 {
        // Reclaim the box we failed to store so it is not leaked.
        // SAFETY: boxed is the Box we just created and did not transfer.
        drop(unsafe { Box::from_raw(boxed.cast::<HsmEccPrivateKey>()) });
        return Err(EngineError::Other("EC_KEY_set_ex_data failed".into()));
    }
    Ok(())
}

/// Process-global EC_KEY ex_data slot index, registered once with
/// [`free_ec_key`] so freeing the EC_KEY deletes the HSM key.
#[allow(unsafe_code)]
fn ec_key_ex_index() -> EngineResult<c_int> {
    static IDX: OnceLock<c_int> = OnceLock::new();
    static INIT: Mutex<()> = Mutex::new(());

    if let Some(i) = IDX.get() {
        return Ok(*i);
    }
    let _guard = INIT.lock();
    if let Some(i) = IDX.get() {
        return Ok(*i);
    }
    // EC_KEY_get_ex_new_index is a macro in 1.1.x, so call the underlying
    // CRYPTO_get_ex_new_index with the EC_KEY class directly.
    // SAFETY: standard ex_data index registration; free_ec_key matches the
    // CRYPTO_EX_free signature.
    let idx = unsafe {
        ffi::CRYPTO_get_ex_new_index(
            ffi::CRYPTO_EX_INDEX_EC_KEY as c_int,
            0,
            null_mut(),
            None,
            None,
            Some(free_ec_key),
        )
    };
    if idx < 0 {
        return Err(EngineError::ExDataRegisterFailed);
    }
    let _ = IDX.set(idx);
    Ok(idx)
}

/// ex_data free callback: drops the `Box<HsmEccPrivateKey>` (whose `Drop`
/// deletes the HSM key). Runs when the owning EC_KEY is freed via
/// `EVP_PKEY_free`.
///
/// # Safety
/// Called by OpenSSL with the `ptr` previously stored via `EC_KEY_set_ex_data`.
#[allow(unsafe_code)]
unsafe extern "C" fn free_ec_key(
    _parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut ffi::CRYPTO_EX_DATA,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if ptr.is_null() {
        return;
    }
    catch_panic(
        || {
            // SAFETY: ptr is the Box<HsmEccPrivateKey> stored via EC_KEY_set_ex_data.
            drop(unsafe { Box::from_raw(ptr.cast::<HsmEccPrivateKey>()) });
        },
        (),
    );
}
