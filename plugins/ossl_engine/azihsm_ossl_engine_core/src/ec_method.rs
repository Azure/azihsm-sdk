// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Custom `EC_KEY_METHOD` for routing ECDSA signing through a handler.
//!
//! [`new_ecdsa_method`] builds an `EC_KEY_METHOD` that keeps OpenSSL's software
//! EC operations but overrides `sign_sig` to dispatch to an [`EcdsaSignHandler`]
//! (e.g. one that signs on the HSM). This is a libcrypto `EC_KEY_METHOD`, not an
//! `ENGINE`, so it lives apart from the `Engine` wrapper in `engine.rs`.

use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ptr::null_mut;
use std::sync::OnceLock;

use azihsm_ossl_engine_sys as ffi;

use crate::error::EngineError;
use crate::error::EngineResult;
use crate::error::catch_panic;
use crate::error::result_to_ptr;

/// Caller-supplied ECDSA signing for an engine-backed EC key, invoked through
/// the `EC_KEY_METHOD` `sign_sig` hook. Implement on a marker type and pass it
/// to [`new_ecdsa_method`].
///
/// The method built by [`new_ecdsa_method`] is typically registered engine-wide
/// (`ENGINE_set_EC`). When an application makes the engine the process default
/// (the `openssl` apps do `ENGINE_set_default(e, ENGINE_METHOD_ALL)` for
/// `-engine`), *software* EC keys adopt it too — so the trampoline first asks
/// [`owns`](Self::owns) and falls back to OpenSSL's built-in `sign_sig` for
/// keys the handler does not own.
pub trait EcdsaSignHandler {
    /// Whether `ec_key` is one of the handler's keys (e.g. carries an attached
    /// HSM key handle in its ex_data). Keys not owned are signed by OpenSSL's
    /// built-in software `sign_sig` instead.
    fn owns(ec_key: *mut ffi::EC_KEY) -> bool;

    /// Sign the pre-computed `digest` for `ec_key` (e.g. recover an attached HSM
    /// key handle from the `EC_KEY`'s ex_data) and return an owning
    /// `*mut ECDSA_SIG` — ownership transfers to OpenSSL, which DER-wraps it.
    /// Return an error to surface a NULL result plus an ERR-queue entry.
    ///
    /// `ec_key` is the signing `EC_KEY` OpenSSL passed to the callback; it is a
    /// raw pointer (only meaningful to dereference in `unsafe`), valid for the
    /// duration of the call. Called only when [`owns`](Self::owns) is true.
    fn sign(ec_key: *mut ffi::EC_KEY, digest: &[u8]) -> EngineResult<*mut ffi::ECDSA_SIG>;
}

/// OpenSSL's built-in `sign_sig`, captured from `EC_KEY_OpenSSL()` by
/// [`new_ecdsa_method`] and used as the software fallback for keys the handler
/// does not own. Fn pointers are `Send + Sync`, and the built-in method is a
/// process-lifetime constant, so a process-global works.
type SignSigFn = unsafe extern "C" fn(
    *const c_uchar,
    c_int,
    *const ffi::BIGNUM,
    *const ffi::BIGNUM,
    *mut ffi::EC_KEY,
) -> *mut ffi::ECDSA_SIG;
static DEFAULT_SIGN_SIG: OnceLock<SignSigFn> = OnceLock::new();

/// C trampoline for `EC_KEY_METHOD_set_sign`'s `sign_sig` slot. Catches panics
/// and dispatches to `H::sign`, returning NULL on panic/error. A caller-supplied
/// precomputed nonce (`in_kinv`/`in_r`) is rejected rather than silently ignored
/// (the HSM generates its own nonce); the normal `EVP_DigestSign` path passes
/// both NULL.
///
/// # Safety
/// Called only by OpenSSL's ECDSA sign path. `dgst`/`dgst_len` describe the
/// digest and `eckey` is the signing key, per the `sign_sig` contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_ecdsa_sign_sig<H: EcdsaSignHandler>(
    dgst: *const c_uchar,
    dgst_len: c_int,
    in_kinv: *const ffi::BIGNUM,
    in_r: *const ffi::BIGNUM,
    eckey: *mut ffi::EC_KEY,
) -> *mut ffi::ECDSA_SIG {
    catch_panic(
        // SAFETY: dgst/dgst_len describe the digest OpenSSL computed and eckey is
        // the signing EC_KEY, per the sign_sig callback contract.
        || result_to_ptr(unsafe { ecdsa_sign_inner::<H>(dgst, dgst_len, in_kinv, in_r, eckey) }),
        null_mut(),
    )
}

/// Inner body of [`c_ecdsa_sign_sig`]: validate the params, and either delegate
/// a key the handler does not own to OpenSSL's built-in software `sign_sig`
/// (passing every argument through untouched, including a precomputed nonce),
/// or build a digest slice and dispatch to `H::sign`.
///
/// # Safety
/// `dgst` must be valid for `dgst_len` bytes (or NULL) and `eckey` the signing
/// `EC_KEY` (or NULL); `in_kinv`/`in_r` are the optional precomputed nonce.
#[allow(unsafe_code)]
unsafe fn ecdsa_sign_inner<H: EcdsaSignHandler>(
    dgst: *const c_uchar,
    dgst_len: c_int,
    in_kinv: *const ffi::BIGNUM,
    in_r: *const ffi::BIGNUM,
    eckey: *mut ffi::EC_KEY,
) -> EngineResult<*mut ffi::ECDSA_SIG> {
    if eckey.is_null() {
        return Err(EngineError::NullParam("eckey"));
    }

    // Software key that merely adopted the engine's method (e.g. because an
    // application made the engine the process-wide default): hand the whole
    // call to OpenSSL's built-in sign_sig, which fully supports it — including
    // a precomputed nonce.
    if !H::owns(eckey) {
        let dflt = DEFAULT_SIGN_SIG
            .get()
            .ok_or(EngineError::Other("default ECDSA sign_sig missing".into()))?;
        // SAFETY: forwarding the exact arguments OpenSSL passed to this
        // sign_sig callback to the built-in implementation.
        let sig = unsafe { dflt(dgst, dgst_len, in_kinv, in_r, eckey) };
        if sig.is_null() {
            return Err(EngineError::Other("software ECDSA sign failed".into()));
        }
        return Ok(sig);
    }

    if dgst.is_null() {
        return Err(EngineError::NullParam("dgst"));
    }
    // The HSM generates its own nonce, so a caller-supplied precomputed nonce
    // (kinv/r from ECDSA_sign_setup) can't be honored. Reject it rather than
    // silently signing with a different nonce; the normal EVP_DigestSign path
    // passes both NULL.
    if !in_kinv.is_null() || !in_r.is_null() {
        return Err(EngineError::Other(
            "precomputed ECDSA nonce (kinv/r) is not supported".into(),
        ));
    }
    let len = usize::try_from(dgst_len)
        .map_err(|_| EngineError::Other("negative digest length".into()))?;
    // SAFETY: dgst is non-null (checked) and valid for `len` bytes per contract.
    let digest = unsafe { std::slice::from_raw_parts(dgst, len) };
    H::sign(eckey, digest)
}

/// Build an `EC_KEY_METHOD` that signs via `H` (ECDSA), keeping OpenSSL's
/// default `sign`/`sign_setup` (they DER-wrap our `sign_sig`) and everything
/// else (verify, keygen, compute_key) from `EC_KEY_OpenSSL`. Attach the result
/// to a loaded key with `EC_KEY_set_method`.
///
/// The returned method is heap-allocated and intentionally not freed here: the
/// caller keeps it for the process lifetime (one method shared by all loaded
/// keys), so no libcrypto-held pointer dangles at teardown.
#[allow(unsafe_code)]
pub fn new_ecdsa_method<H: EcdsaSignHandler>() -> EngineResult<*mut ffi::EC_KEY_METHOD> {
    // SAFETY: EC_KEY_OpenSSL returns the built-in const method; EC_KEY_METHOD_new
    // copies it into a fresh owned method.
    let method = unsafe { ffi::EC_KEY_METHOD_new(ffi::EC_KEY_OpenSSL()) };
    if method.is_null() {
        return Err(EngineError::Other("EC_KEY_METHOD_new failed".into()));
    }

    // Keep the copied default sign/sign_setup (the default `sign` produces the
    // DER wrapper by calling `sign_sig`) and override only `sign_sig` — after
    // capturing the built-in `sign_sig` as the software fallback for keys the
    // handler does not own.
    let mut sign = None;
    let mut sign_setup = None;
    let mut sign_sig = None;
    // SAFETY: method is a fresh EC_KEY_METHOD copy of the built-in one;
    // get_sign writes the out-params it is given.
    unsafe { ffi::EC_KEY_METHOD_get_sign(method, &mut sign, &mut sign_setup, &mut sign_sig) };
    let Some(dflt) = sign_sig else {
        // SAFETY: method is ours and not yet published.
        unsafe { ffi::EC_KEY_METHOD_free(method) };
        return Err(EngineError::Other("built-in sign_sig missing".into()));
    };
    let _ = DEFAULT_SIGN_SIG.set(dflt);
    // SAFETY: method is ours; reinstall the defaults plus our sign_sig trampoline.
    unsafe { ffi::EC_KEY_METHOD_set_sign(method, sign, sign_setup, Some(c_ecdsa_sign_sig::<H>)) };
    Ok(method)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Stub `EcdsaSignHandler` that owns every key, ignores its inputs, and
    /// returns a fresh empty `ECDSA_SIG` (the caller frees it) — enough to
    /// exercise the dispatch path.
    struct StubSigner;
    impl EcdsaSignHandler for StubSigner {
        fn owns(_ec_key: *mut ffi::EC_KEY) -> bool {
            true
        }

        #[allow(unsafe_code)]
        fn sign(_ec_key: *mut ffi::EC_KEY, _digest: &[u8]) -> EngineResult<*mut ffi::ECDSA_SIG> {
            // SAFETY: ECDSA_SIG_new allocates a fresh signature owned by the caller.
            let sig = unsafe { ffi::ECDSA_SIG_new() };
            assert!(!sig.is_null());
            Ok(sig)
        }
    }

    /// Stub handler that owns nothing — every key delegates to the software
    /// fallback.
    struct DisownSigner;
    impl EcdsaSignHandler for DisownSigner {
        fn owns(_ec_key: *mut ffi::EC_KEY) -> bool {
            false
        }

        fn sign(_ec_key: *mut ffi::EC_KEY, _digest: &[u8]) -> EngineResult<*mut ffi::ECDSA_SIG> {
            unreachable!("sign must not be called for a key the handler does not own")
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn ecdsa_sign_inner_rejects_null_dgst() {
        // SAFETY: EC_KEY_new/free are standard entry points; a NULL dgst is
        // rejected before any dereference.
        unsafe {
            let ec = ffi::EC_KEY_new();
            assert!(!ec.is_null());
            let r = ecdsa_sign_inner::<StubSigner>(
                std::ptr::null(),
                32,
                std::ptr::null(),
                std::ptr::null(),
                ec,
            );
            assert!(matches!(r, Err(EngineError::NullParam("dgst"))));
            ffi::EC_KEY_free(ec);
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn ecdsa_sign_inner_rejects_null_eckey() {
        let dgst = [0u8; 32];
        // SAFETY: dgst is valid for 32 bytes; a NULL eckey is rejected before use.
        let r = unsafe {
            ecdsa_sign_inner::<StubSigner>(
                dgst.as_ptr(),
                32,
                std::ptr::null(),
                std::ptr::null(),
                null_mut(),
            )
        };
        assert!(matches!(r, Err(EngineError::NullParam("eckey"))));
    }

    #[test]
    #[allow(unsafe_code)]
    fn ecdsa_sign_inner_rejects_precomputed_nonce() {
        let dgst = [0u8; 32];
        // SAFETY: EC_KEY_new / BN_bin2bn / *_free are standard OpenSSL entry points;
        // a non-NULL kinv must be rejected rather than silently ignored.
        unsafe {
            let ec = ffi::EC_KEY_new();
            assert!(!ec.is_null());
            let one = [1u8];
            let kinv = ffi::BN_bin2bn(one.as_ptr(), 1, null_mut());
            assert!(!kinv.is_null());
            let r = ecdsa_sign_inner::<StubSigner>(dgst.as_ptr(), 32, kinv, std::ptr::null(), ec);
            assert!(matches!(r, Err(EngineError::Other(_))));
            ffi::BN_free(kinv);
            ffi::EC_KEY_free(ec);
        }
    }

    // A key the handler does not own must be signed by OpenSSL's software
    // sign_sig (the situation when an application makes the engine the process
    // default and plain software EC keys adopt the engine's method).
    #[test]
    #[allow(unsafe_code)]
    fn ecdsa_sign_inner_delegates_unowned_key_to_software() {
        // Build (and discard) a method so the software fallback is captured.
        let method = new_ecdsa_method::<DisownSigner>().unwrap();
        // SAFETY: method is ours and attached to nothing.
        unsafe { ffi::EC_KEY_METHOD_free(method) };

        let dgst = [7u8; 48];
        // SAFETY: standard EC_KEY/EC_GROUP construction of a software P-384
        // key; every return code is checked and everything is freed below.
        unsafe {
            let group = ffi::EC_GROUP_new_by_curve_name(ffi::NID_secp384r1 as c_int);
            assert!(!group.is_null());
            let ec = ffi::EC_KEY_new();
            assert!(!ec.is_null());
            assert_eq!(ffi::EC_KEY_set_group(ec, group), 1);
            assert_eq!(ffi::EC_KEY_generate_key(ec), 1);

            let sig = ecdsa_sign_inner::<DisownSigner>(
                dgst.as_ptr(),
                48,
                std::ptr::null(),
                std::ptr::null(),
                ec,
            )
            .expect("software fallback should sign");
            assert!(!sig.is_null());

            ffi::ECDSA_SIG_free(sig);
            ffi::EC_KEY_free(ec);
            ffi::EC_GROUP_free(group);
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn ecdsa_sign_inner_dispatches_to_handler() {
        let dgst = [7u8; 48];
        // SAFETY: EC_KEY_new returns a valid key; the stub returns a fresh
        // ECDSA_SIG that we free.
        unsafe {
            let ec = ffi::EC_KEY_new();
            assert!(!ec.is_null());
            let sig = ecdsa_sign_inner::<StubSigner>(
                dgst.as_ptr(),
                48,
                std::ptr::null(),
                std::ptr::null(),
                ec,
            )
            .expect("stub signer should succeed");
            assert!(!sig.is_null());
            ffi::ECDSA_SIG_free(sig);
            ffi::EC_KEY_free(ec);
        }
    }
}
