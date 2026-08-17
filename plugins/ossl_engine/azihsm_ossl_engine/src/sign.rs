// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECDSA signing for engine-loaded EC keys.
//!
//! The engine registers a custom `EC_KEY_METHOD` (see [`ecdsa_method`]) at bind
//! time via `ENGINE_set_EC`, so every key the loader creates with
//! `EC_KEY_new_method` adopts it. Its `sign_sig` hook recovers the HSM key the
//! loader stashed in the `EC_KEY` ex_data and signs the caller's digest on the
//! HSM. OpenSSL's default `sign` DER-wraps the returned `ECDSA_SIG`, so both
//! the EVP/ABI path (`EVP_DigestSign`, `EVP_PKEY_sign`) and the CLI
//! (`openssl dgst -sign`, `openssl pkeyutl -sign`) route through here.
//! Verification stays in software, using the public key already on the
//! `EVP_PKEY`.
//!
//! The method is deliberately **not** attached per key with `EC_KEY_set_method`:
//! that call drops the key's engine reference (`ENGINE_finish` +
//! `key->engine = NULL`), which would let the engine — and the `EngineData`
//! owning the loaded HSM keys — be destroyed while the key is still alive.
//! Registering it engine-wide preserves the reference `EC_KEY_new_method`
//! takes. Software EC keys (created without the engine) are unaffected.

use std::ffi::c_int;
use std::ptr::null_mut;
use std::sync::OnceLock;

use azihsm_api::HsmEccSignAlgo;
use azihsm_api::HsmSigner;
use azihsm_ossl_engine_core::ec_method::EcdsaSignHandler;
use azihsm_ossl_engine_core::ec_method::new_ecdsa_method;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
use azihsm_ossl_engine_core::ffi;
use parking_lot::Mutex;

/// Marker type carrying the engine's ECDSA sign logic (see [`EcdsaSignHandler`]).
struct AzihsmEcdsaSign;

impl EcdsaSignHandler for AzihsmEcdsaSign {
    /// A key is ours iff the loader stashed an HSM key in its ex_data. Software
    /// EC keys that merely adopted the engine's method (e.g. via an application
    /// calling `ENGINE_set_default`) are signed by OpenSSL's software fallback.
    fn owns(ec_key: *mut ffi::EC_KEY) -> bool {
        !crate::keyload::ec_key_hsm_key(ec_key).is_null()
    }

    #[allow(unsafe_code)]
    fn sign(ec_key: *mut ffi::EC_KEY, digest: &[u8]) -> EngineResult<*mut ffi::ECDSA_SIG> {
        let key_ptr = crate::keyload::ec_key_hsm_key(ec_key);
        if key_ptr.is_null() {
            return Err(EngineError::Other(
                "no HSM key attached to EC_KEY for signing".into(),
            ));
        }
        // SAFETY: key_ptr points to an HsmEccPrivateKey owned by EngineData for
        // the engine's lifetime; this callback runs while the key is live.
        let key = unsafe { &*key_ptr };

        // The HSM signs the pre-computed digest with raw ECDSA and returns the
        // signature as raw r||s (each half the curve's field size).
        let mut algo = HsmEccSignAlgo::default();
        let raw = HsmSigner::sign_vec(&mut algo, key, digest)
            .map_err(|e| EngineError::wrap("ECDSA sign", e))?;
        raw_to_ecdsa_sig(&raw)
    }
}

/// Convert the HSM's raw `r||s` signature into an owning `*mut ECDSA_SIG`;
/// ownership transfers to OpenSSL (which DER-wraps it).
#[allow(unsafe_code)]
fn raw_to_ecdsa_sig(raw: &[u8]) -> EngineResult<*mut ffi::ECDSA_SIG> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(EngineError::Other(
            "HSM ECDSA signature has an invalid length".into(),
        ));
    }
    let half = raw.len() / 2;
    let half_len =
        c_int::try_from(half).map_err(|_| EngineError::Other("signature half too large".into()))?;

    // SAFETY: each half is `half_len` bytes of `raw`; a NULL `ret` allocates a
    // fresh BIGNUM.
    let r = unsafe { ffi::BN_bin2bn(raw.as_ptr(), half_len, null_mut()) };
    // SAFETY: as above, reading the second half.
    let s = unsafe { ffi::BN_bin2bn(raw[half..].as_ptr(), half_len, null_mut()) };
    if r.is_null() || s.is_null() {
        // SAFETY: free whichever allocated; BN_free(NULL) is a no-op.
        unsafe {
            ffi::BN_free(r);
            ffi::BN_free(s);
        }
        return Err(EngineError::Other("BN_bin2bn failed".into()));
    }

    // SAFETY: fresh ECDSA_SIG; NULL on allocation failure.
    let sig = unsafe { ffi::ECDSA_SIG_new() };
    if sig.is_null() {
        // SAFETY: r and s are still owned by us; free them.
        unsafe {
            ffi::BN_free(r);
            ffi::BN_free(s);
        }
        return Err(EngineError::Other("ECDSA_SIG_new failed".into()));
    }
    // SAFETY: sig is fresh; set0 takes ownership of r and s on success (returns 1).
    if unsafe { ffi::ECDSA_SIG_set0(sig, r, s) } != 1 {
        // SAFETY: set0 failed, so it did not take r/s; free everything.
        unsafe {
            ffi::BN_free(r);
            ffi::BN_free(s);
            ffi::ECDSA_SIG_free(sig);
        }
        return Err(EngineError::Other("ECDSA_SIG_set0 failed".into()));
    }
    Ok(sig)
}

/// Process-global ECDSA `EC_KEY_METHOD`, built once and kept for the process
/// lifetime (one method registered on the engine and shared by all loaded keys;
/// never freed, so no libcrypto-held pointer dangles at teardown). Stored as
/// `usize` because a raw pointer is not `Sync`.
pub(crate) fn ecdsa_method() -> EngineResult<*const ffi::EC_KEY_METHOD> {
    static METHOD: OnceLock<usize> = OnceLock::new();
    static INIT: Mutex<()> = Mutex::new(());

    if let Some(m) = METHOD.get() {
        return Ok(*m as *const ffi::EC_KEY_METHOD);
    }
    // Serialize construction so two concurrent first-loads can't each build a
    // method (only the first is kept; a second would leak).
    let _guard = INIT.lock();
    if let Some(m) = METHOD.get() {
        return Ok(*m as *const ffi::EC_KEY_METHOD);
    }
    let method = new_ecdsa_method::<AzihsmEcdsaSign>()?;
    let _ = METHOD.set(method as usize);
    Ok(method)
}
