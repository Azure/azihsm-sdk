// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `ENGINE_load_private_key` implementation: resolve an `azihsm://` URI to an
//! HSM key and return an `EVP_PKEY`.
//!
//! The returned key carries the real public key (rebuilt from the SDK's DER via
//! the safe `openssl` crate). The live HSM private-key wrapper is owned by
//! [`EngineData`], which deletes it from the HSM when the engine is destroyed;
//! a non-owning pointer to it is stashed in the underlying `EC_KEY` ex_data for
//! later sign/derive callbacks. Deletion runs from the engine's destroy handler
//! (while this `.so` is loaded), never from a libcrypto ex_data free callback —
//! such a callback holds a function pointer into this `.so` and can be invoked
//! after the `.so` is unloaded (see [`azihsm_ossl_engine_core::exdata`]). The
//! sign/derive methods themselves are not wired yet (a later change), so a
//! loaded key is currently usable for public-key operations (e.g. `-pubout`).
//!
//! Only EC keys are supported here; RSA loading (an HSM import + unmask path)
//! lands in a follow-up together with its test coverage.

use std::ffi::c_int;
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::ptr::null_mut;
use std::sync::OnceLock;

use azihsm_api::HsmEccKeyUnmaskAlgo;
use azihsm_api::HsmEccPrivateKey;
use azihsm_api::HsmKeyCommonProps;
use azihsm_api::HsmKeyManager;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
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

    // Reject unsupported key types before any HSM open or file I/O, so they
    // fail with a clear error instead of a misleading environment/filesystem
    // one. RSA loading lands in a follow-up (it needs an HSM import path plus
    // test coverage).
    match parsed.key_type {
        KeyType::Ec => {}
        KeyType::Rsa | KeyType::RsaPss => {
            return Err(EngineError::Other(
                "RSA key loading is not yet supported".into(),
            ));
        }
    }

    // First real caller of the lazy HSM open (idempotent).
    data.open_hsm_from_env()?;
    let masked = read_masked_key(&parsed.masked_key_path)?;
    load_ec(data, &masked)
}

/// Upper bound on a masked-key blob. A masked EC/RSA key is far smaller; this
/// bounds allocation against a caller-supplied path pointing at a very large or
/// unbounded file. Mirrors `MAX_STORAGE_FILE_SIZE` in
/// azihsm_ossl_engine_resiliency.
const MAX_MASKED_KEY_SIZE: u64 = 64 * 1024;

/// Read a masked-key blob with the same hardening the rest of the engine
/// applies to key-material files: `O_NOFOLLOW` refuses a symlink at `path`,
/// `O_NONBLOCK` avoids blocking on a FIFO/device before the regular-file check,
/// `O_CLOEXEC` keeps the fd from leaking across exec, a non-regular file is
/// rejected outright, and the read is capped at [`MAX_MASKED_KEY_SIZE`].
/// Mirrors `read_regular_hardened` in azihsm_ossl_engine_resiliency.
fn read_masked_key(path: &Path) -> EngineResult<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| EngineError::wrap(format!("open masked key {}", path.display()), e))?;

    let meta = file
        .metadata()
        .map_err(|e| EngineError::wrap(format!("stat masked key {}", path.display()), e))?;
    if !meta.is_file() {
        return Err(EngineError::Other(format!(
            "masked key {} is not a regular file",
            path.display()
        )));
    }
    if meta.len() > MAX_MASKED_KEY_SIZE {
        return Err(EngineError::Other(format!(
            "masked key {} is too large ({} bytes, max {MAX_MASKED_KEY_SIZE})",
            path.display(),
            meta.len()
        )));
    }

    // Cap the read too: metadata can under-report (a growing or virtual file),
    // so bound the bytes actually read and reject anything over the limit.
    let mut buf = Vec::new();
    file.take(MAX_MASKED_KEY_SIZE + 1)
        .read_to_end(&mut buf)
        .map_err(|e| EngineError::wrap(format!("read masked key {}", path.display()), e))?;
    if buf.len() as u64 > MAX_MASKED_KEY_SIZE {
        return Err(EngineError::Other(format!(
            "masked key {} exceeds {MAX_MASKED_KEY_SIZE} bytes",
            path.display()
        )));
    }
    Ok(buf)
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

    build_ec_pkey(data, &der, priv_key)
}

/// Rebuild the public `EVP_PKEY` from `der` (safe `openssl` crate) and attach
/// the live HSM key to it before transferring ownership to OpenSSL.
fn build_ec_pkey(
    data: &EngineData,
    der: &[u8],
    key: HsmEccPrivateKey,
) -> EngineResult<*mut ffi::EVP_PKEY> {
    let pkey =
        PKey::public_key_from_der(der).map_err(|e| EngineError::wrap("parse public key DER", e))?;

    // The `openssl` crate's `EVP_PKEY` and the engine-ABI `EVP_PKEY` are the
    // same C struct (both link the one system libcrypto), so casting the raw
    // pointer at this single boundary is sound.
    let raw = pkey.as_ptr().cast::<ffi::EVP_PKEY>();

    // Attach while `pkey` still owns `raw`: if `attach_ec` fails, `pkey` drops
    // at end of scope and frees the EVP_PKEY.
    attach_ec(data, raw, key)?;

    // Success: hand ownership to OpenSSL.
    std::mem::forget(pkey);
    Ok(raw)
}

#[allow(unsafe_code)]
fn attach_ec(
    data: &EngineData,
    pkey: *mut ffi::EVP_PKEY,
    key: HsmEccPrivateKey,
) -> EngineResult<()> {
    let idx = ec_key_ex_index()?;

    // SAFETY: pkey is a valid EVP_PKEY holding an EC key (built above).
    let ec = unsafe { ffi::EVP_PKEY_get0_EC_KEY(pkey) };
    if ec.is_null() {
        return Err(EngineError::Other("EVP_PKEY has no EC_KEY".into()));
    }

    // Hand the key to EngineData, which owns it and deletes it from the HSM when
    // the engine is destroyed (while this `.so` is loaded). Stash the non-owning
    // pointer it returns for later sign/derive retrieval. The ex_data slot has
    // no free callback (see ec_key_ex_index), so libcrypto never calls back into
    // this `.so` for cleanup — even if the EVP_PKEY outlives the engine.
    let ptr = data.retain_loaded_key(key).cast_mut().cast::<c_void>();
    // SAFETY: ec is valid, idx is a registered EC_KEY ex_data slot, and ptr is a
    // non-owning pointer into a key EngineData keeps alive for the engine's
    // lifetime; the slot has no free callback, so no ownership is transferred.
    let rc = unsafe { ffi::EC_KEY_set_ex_data(ec, idx, ptr) };
    if rc != 1 {
        return Err(EngineError::Other("EC_KEY_set_ex_data failed".into()));
    }
    Ok(())
}

/// Process-global EC_KEY ex_data slot index, registered once **without** a free
/// callback: the stored pointer is non-owning (the key is owned by
/// [`EngineData`]), and a libcrypto-held free callback into this `.so` would be
/// unsafe across `.so` unload (see [`azihsm_ossl_engine_core::exdata`]).
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
    // SAFETY: standard ex_data index registration with no new/dup/free callbacks.
    let idx = unsafe {
        ffi::CRYPTO_get_ex_new_index(
            ffi::CRYPTO_EX_INDEX_EC_KEY as c_int,
            0,
            null_mut(),
            None,
            None,
            None,
        )
    };
    if idx < 0 {
        return Err(EngineError::ExDataRegisterFailed);
    }
    let _ = IDX.set(idx);
    Ok(idx)
}
