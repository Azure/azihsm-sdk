// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA masked-key loading: resolve an `azihsm://…;type=rsa` URI to an
//! engine-bound `RSA` carrying the public modulus/exponent plus the live HSM
//! private key.
//!
//! Mirrors [`crate::keyload`] for EC: the returned `RSA` is bound to the engine
//! (`RSA_new_method`), so the engine — hence [`EngineData`] and this `.so` —
//! outlives any `EVP_PKEY` built from it, and the stashed HSM-key pointer
//! (owned by `EngineData`, in `RSA` ex_data) never dangles. Private-key
//! operations (sign/decrypt) land on the RSA `EVP_PKEY_METHOD` in later work;
//! this module wires load + retention + the ex_data marker the serialization
//! method uses to recognize HSM-backed keys.

use std::ffi::c_int;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::OnceLock;

use azihsm_api::HsmKeyCommonProps;
use azihsm_api::HsmKeyManager;
use azihsm_api::HsmRsaKeyUnmaskAlgo;
use azihsm_api::HsmRsaPrivateKey;
use azihsm_ossl_engine_core::engine::Engine;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
use azihsm_ossl_engine_core::ffi;
use openssl::pkey::PKey;
use parking_lot::Mutex;

use crate::context::EngineData;

/// Unmask a masked RSA blob into the HSM and build the returned `EVP_PKEY`.
/// Shared by the loader (`azihsm://…;type=rsa`) and the import handler, which
/// masks then reloads.
pub(crate) fn load_rsa(
    engine: &Engine,
    data: &EngineData,
    masked: &[u8],
) -> EngineResult<*mut ffi::EVP_PKEY> {
    let priv_key = data.with_session(|session| {
        let mut algo = HsmRsaKeyUnmaskAlgo::default();
        // The public half is a software wrapper without a device-side handle
        // (its delete_key is a documented no-op).
        HsmKeyManager::unmask_key_pair(session, &mut algo, masked)
            .map(|(private, _public)| private)
            .map_err(|e| EngineError::wrap("RSA key unmask", e))
    })?;

    let der = match priv_key.pub_key_der_vec() {
        Ok(der) => der,
        Err(e) => {
            crate::context::delete_hsm_key(priv_key, "unmasked RSA private key");
            return Err(EngineError::wrap("read RSA public key DER", e));
        }
    };

    build_rsa_pkey(engine, data, &der, priv_key)
}

/// Build an engine-bound `RSA` carrying the modulus/exponent from the SPKI
/// `der`, with the live HSM key attached to its ex_data and retained by
/// `data`. Returns an owning `*mut RSA`.
#[allow(unsafe_code)]
pub(crate) fn build_bound_rsa_key(
    engine: &Engine,
    data: &EngineData,
    der: &[u8],
    key: HsmRsaPrivateKey,
) -> EngineResult<*mut ffi::RSA> {
    // Pre-attach failures must delete the HSM key (attach_rsa's rollback
    // covers post-attach ones).
    let rsa = match bound_public_rsa_key(engine, der) {
        Ok(rsa) => rsa,
        Err(e) => {
            crate::context::delete_hsm_key(key, "RSA private key");
            return Err(e);
        }
    };
    if let Err(e) = attach_rsa(data, rsa, key) {
        // SAFETY: rsa is ours and not yet handed out.
        unsafe { ffi::RSA_free(rsa) };
        return Err(e);
    }
    Ok(rsa)
}

/// Parse the SPKI `der` and build an engine-bound `RSA` carrying its modulus
/// and public exponent.
#[allow(unsafe_code)]
fn bound_public_rsa_key(engine: &Engine, der: &[u8]) -> EngineResult<*mut ffi::RSA> {
    let rsa = engine.new_rsa_key()?;
    if let Err(e) = set_rsa_public(rsa, der) {
        // SAFETY: rsa is ours and not yet handed out.
        unsafe { ffi::RSA_free(rsa) };
        return Err(e);
    }
    Ok(rsa)
}

/// Build a plain software `RSA` (not engine-bound) carrying the modulus and
/// public exponent from SPKI `der` — used for the exported unwrapping public
/// key, which needs no HSM operations.
#[allow(unsafe_code)]
fn software_public_rsa(der: &[u8]) -> EngineResult<*mut ffi::RSA> {
    // SAFETY: RSA_new allocates a fresh software RSA.
    let rsa = unsafe { ffi::RSA_new() };
    if rsa.is_null() {
        return Err(EngineError::Other("RSA_new failed".into()));
    }
    if let Err(e) = set_rsa_public(rsa, der) {
        // SAFETY: rsa is ours and not yet handed out.
        unsafe { ffi::RSA_free(rsa) };
        return Err(e);
    }
    Ok(rsa)
}

/// Set `rsa`'s modulus and public exponent from SPKI `der`. Recovers n and e
/// via the safe openssl crate as big-endian bytes, then rebuilds them as our
/// own ffi BIGNUMs (avoids mixing the openssl crate's foreign-types ownership
/// with our bindings).
///
/// # Safety
/// `rsa` must be a valid `RSA` with no key components set yet.
#[allow(unsafe_code)]
fn set_rsa_public(rsa: *mut ffi::RSA, der: &[u8]) -> EngineResult<()> {
    let parsed =
        PKey::public_key_from_der(der).map_err(|e| EngineError::wrap("parse RSA public DER", e))?;
    let rsa_pub = parsed
        .rsa()
        .map_err(|e| EngineError::wrap("public key is not RSA", e))?;
    let n_bytes = rsa_pub.n().to_vec();
    let e_bytes = rsa_pub.e().to_vec();

    // SAFETY: BN_bin2bn(ret = NULL) allocates a fresh BIGNUM from the big-endian
    // bytes; RSA_set0_key takes ownership of both on success (d = NULL: public
    // components only). On any failure we free whatever we still own.
    unsafe {
        let bn = |bytes: &[u8]| -> *mut ffi::BIGNUM {
            let len = c_int::try_from(bytes.len()).unwrap_or(-1);
            if len < 0 {
                return null_mut();
            }
            ffi::BN_bin2bn(bytes.as_ptr(), len, null_mut())
        };
        let n = bn(&n_bytes);
        let e = bn(&e_bytes);
        if n.is_null() || e.is_null() {
            ffi::BN_free(n);
            ffi::BN_free(e);
            return Err(EngineError::Other("BN_bin2bn failed".into()));
        }
        if ffi::RSA_set0_key(rsa, n, e, null_mut()) != 1 {
            ffi::BN_free(n);
            ffi::BN_free(e);
            return Err(EngineError::Other("RSA_set0_key failed".into()));
        }
    }
    Ok(())
}

/// Populate the caller's `pkey` with an engine-bound `RSA` carrying the public
/// key from `der` and the live HSM private `key` (import path).
///
/// # Safety
/// `pkey` must be a valid, empty `EVP_PKEY` from the keygen hook.
#[allow(unsafe_code)]
pub(crate) unsafe fn set_pkey_to_bound_rsa(
    pkey: *mut ffi::EVP_PKEY,
    engine: &Engine,
    data: &EngineData,
    der: &[u8],
    key: HsmRsaPrivateKey,
) -> EngineResult<()> {
    let rsa = build_bound_rsa_key(engine, data, der, key)?;
    // SAFETY: EVP_PKEY_set1_RSA up-refs rsa; drop our reference afterwards. On
    // failure free the bound key with its HSM-key retain rolled back.
    unsafe {
        if ffi::EVP_PKEY_set1_RSA(pkey, rsa) != 1 {
            free_bound_rsa_key(data, rsa);
            return Err(EngineError::Other("EVP_PKEY_set1_RSA failed".into()));
        }
        ffi::RSA_free(rsa);
    }
    Ok(())
}

/// Populate the caller's `pkey` with a software public `RSA` from `der` (the
/// exported unwrapping public key).
///
/// # Safety
/// `pkey` must be a valid, empty `EVP_PKEY` from the keygen hook.
#[allow(unsafe_code)]
pub(crate) unsafe fn set_pkey_to_public_rsa(
    pkey: *mut ffi::EVP_PKEY,
    der: &[u8],
) -> EngineResult<()> {
    let rsa = software_public_rsa(der)?;
    // SAFETY: EVP_PKEY_set1_RSA up-refs rsa; free our reference on both paths.
    unsafe {
        if ffi::EVP_PKEY_set1_RSA(pkey, rsa) != 1 {
            ffi::RSA_free(rsa);
            return Err(EngineError::Other("EVP_PKEY_set1_RSA failed".into()));
        }
        ffi::RSA_free(rsa);
    }
    Ok(())
}

/// Build the returned `EVP_PKEY` around an engine-bound `RSA`.
#[allow(unsafe_code)]
fn build_rsa_pkey(
    engine: &Engine,
    data: &EngineData,
    der: &[u8],
    key: HsmRsaPrivateKey,
) -> EngineResult<*mut ffi::EVP_PKEY> {
    let rsa = build_bound_rsa_key(engine, data, der, key)?;

    // EVP_PKEY_set1_RSA up-refs `rsa`; drop our own reference afterwards. The
    // OOM-only failure paths free the bound key with its HSM-key retain rolled
    // back.
    // SAFETY: standard EVP_PKEY construction; every return code is checked and
    // `rsa` is freed on each path.
    unsafe {
        let pkey = ffi::EVP_PKEY_new();
        if pkey.is_null() {
            free_bound_rsa_key(data, rsa);
            return Err(EngineError::Other("EVP_PKEY_new failed".into()));
        }
        if ffi::EVP_PKEY_set1_RSA(pkey, rsa) != 1 {
            ffi::EVP_PKEY_free(pkey);
            free_bound_rsa_key(data, rsa);
            return Err(EngineError::Other("EVP_PKEY_set1_RSA failed".into()));
        }
        ffi::RSA_free(rsa);
        Ok(pkey)
    }
}

/// Free a bound `RSA` from [`build_bound_rsa_key`] that could not be handed
/// out, rolling back the HSM-key retain.
///
/// # Safety
/// `rsa` must be the caller's own never-handed-out `RSA` from
/// [`build_bound_rsa_key`].
#[allow(unsafe_code)]
pub(crate) unsafe fn free_bound_rsa_key(data: &EngineData, rsa: *mut ffi::RSA) {
    let key_ptr = rsa_hsm_key(rsa);
    if !key_ptr.is_null() {
        data.release_loaded_rsa_key(key_ptr);
    }
    // SAFETY: rsa is valid and owned by the caller per this function's contract.
    unsafe { ffi::RSA_free(rsa) };
}

#[allow(unsafe_code)]
fn attach_rsa(data: &EngineData, rsa: *mut ffi::RSA, key: HsmRsaPrivateKey) -> EngineResult<()> {
    if rsa.is_null() {
        return Err(EngineError::Other("EVP_PKEY has no RSA".into()));
    }
    // Ownership of `key` has already been transferred into this call; if we
    // cannot get the ex_data slot we must delete it here, or the HSM handle
    // leaks (it is neither retained for teardown nor deleted on drop).
    let idx = match rsa_ex_index() {
        Ok(i) => i,
        Err(e) => {
            crate::context::delete_hsm_key(key, "imported RSA key (ex_index unavailable)");
            return Err(e);
        }
    };

    // Hand the key to EngineData (owns it, deletes it at engine teardown) and
    // stash the non-owning pointer for later sign/decrypt retrieval. The
    // ex_data slot has no free callback (see rsa_ex_index).
    let key_ptr = data.retain_loaded_rsa_key(key);
    // SAFETY: rsa is valid (checked), idx is a registered RSA ex_data slot, and
    // key_ptr is a non-owning pointer into a key EngineData keeps alive for the
    // engine's lifetime; the slot has no free callback, so no ownership moves.
    let rc = unsafe { ffi::RSA_set_ex_data(rsa, idx, key_ptr.cast_mut().cast::<c_void>()) };
    if rc != 1 {
        data.release_loaded_rsa_key(key_ptr);
        return Err(EngineError::Other("RSA_set_ex_data failed".into()));
    }
    Ok(())
}

/// Recover the `HsmRsaPrivateKey` [`attach_rsa`] stashed in `rsa`'s ex_data, or
/// null if none is set. The pointer is owned by `EngineData` and valid for the
/// engine's lifetime.
#[allow(unsafe_code)]
pub(crate) fn rsa_hsm_key(rsa: *mut ffi::RSA) -> *const HsmRsaPrivateKey {
    let Ok(idx) = rsa_ex_index() else {
        return std::ptr::null();
    };
    // SAFETY: rsa is a valid RSA; idx is our registered slot (returns NULL if
    // nothing was stored).
    unsafe { ffi::RSA_get_ex_data(rsa, idx) }.cast::<HsmRsaPrivateKey>()
}

/// Process-global RSA ex_data slot index, registered once **without** a free
/// callback (the stored pointer is non-owning; a libcrypto-held free callback
/// into this `.so` would be unsafe across `.so` unload — see
/// [`azihsm_ossl_engine_core::exdata`]).
#[allow(unsafe_code)]
fn rsa_ex_index() -> EngineResult<c_int> {
    static IDX: OnceLock<c_int> = OnceLock::new();
    static INIT: Mutex<()> = Mutex::new(());

    if let Some(i) = IDX.get() {
        return Ok(*i);
    }
    let _guard = INIT.lock();
    if let Some(i) = IDX.get() {
        return Ok(*i);
    }
    // SAFETY: standard ex_data index registration with no new/dup/free callbacks.
    let idx = unsafe {
        ffi::CRYPTO_get_ex_new_index(
            ffi::CRYPTO_EX_INDEX_RSA as c_int,
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
