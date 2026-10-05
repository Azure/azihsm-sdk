// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Custom `RSA_METHOD` for routing RSA signing through a handler.
//!
//! [`new_rsa_sign_method`] builds an `RSA_METHOD` that keeps OpenSSL's software
//! RSA operations (verify, encrypt, decrypt) but overrides the `sign` slot to
//! dispatch to an [`RsaSignHandler`] (e.g. one that signs on the HSM). This is a
//! libcrypto `RSA_METHOD`, not an `ENGINE`, so it lives apart from the `Engine`
//! wrapper in `engine.rs`.
//!
//! In OpenSSL 1.1.1 `RSA_sign` dispatches to `meth->rsa_sign` whenever it is
//! non-NULL (there is no `RSA_FLAG_SIGN_VER` gate), and the RSA `EVP_PKEY`
//! signature path (`pkey_rsa_sign`) routes PKCS#1 v1.5 signing through `RSA_sign`
//! **only when a signature digest is set** — so `EVP_DigestSign` (and
//! `EVP_PKEY_sign` with a configured digest) reach the handler, which receives
//! the pre-computed digest and its digest NID and returns the finished PKCS#1
//! v1.5 signature (the HSM/host builds the DigestInfo and pads). A raw
//! `EVP_PKEY_sign` with no digest set takes `pkey_rsa_sign`'s other branch to
//! `rsa_priv_enc` instead and never reaches this slot; the caller must set a
//! digest.

use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_uint;

use azihsm_ossl_engine_sys as ffi;

use crate::error::EngineError;
use crate::error::EngineResult;
use crate::error::catch_panic;
use crate::error::result_to_int;

/// Caller-supplied RSA signing for an engine-backed RSA key, invoked through the
/// `RSA_METHOD` `sign` slot. Implement on a marker type and pass it to
/// [`new_rsa_sign_method`].
///
/// The method built by [`new_rsa_sign_method`] is registered engine-wide
/// (`ENGINE_set_RSA`). When an application makes the engine the process default
/// (the `openssl` apps do `ENGINE_set_default(e, ENGINE_METHOD_ALL)` for
/// `-engine`), *software* RSA keys adopt it too — so a key with no attached HSM
/// handle reaches [`sign`](Self::sign), which should return an error rather than
/// attempt an HSM operation (software RSA signing through the engine is out of
/// scope; verify/encrypt/decrypt still use the copied software slots).
pub trait RsaSignHandler {
    /// Sign the pre-computed digest `m` (digest algorithm `md_nid`) for `rsa`
    /// and return the PKCS#1 v1.5 signature — its length must be the RSA modulus
    /// size. `rsa` is the signing key OpenSSL passed to the callback; it is a raw
    /// pointer (only meaningful to dereference in `unsafe`), valid for the
    /// duration of the call. Return an error to surface a `0` result plus an
    /// ERR-queue entry.
    fn sign(rsa: *mut ffi::RSA, md_nid: c_int, m: &[u8]) -> EngineResult<Vec<u8>>;
}

/// C trampoline for `RSA_meth_set_sign`'s `sign` slot. Catches panics and
/// dispatches to `H::sign`, returning `0` on panic/error.
///
/// # Safety
/// Called only by OpenSSL's RSA sign path. `m`/`m_len` describe the digest,
/// `sigret`/`siglen` the output buffer, and `rsa` the signing key, per the
/// `rsa_sign` contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_rsa_sign<H: RsaSignHandler>(
    md_nid: c_int,
    m: *const c_uchar,
    m_len: c_uint,
    sigret: *mut c_uchar,
    siglen: *mut c_uint,
    rsa: *const ffi::RSA,
) -> c_int {
    catch_panic(
        // SAFETY: forwarding the arguments OpenSSL passed to this sign callback.
        || result_to_int(unsafe { rsa_sign_inner::<H>(md_nid, m, m_len, sigret, siglen, rsa) }),
        0,
    )
}

/// Inner body of [`c_rsa_sign`]: validate the params, dispatch to `H::sign`, and
/// copy the returned signature into the caller's buffer.
///
/// # Safety
/// `m` must be valid for `m_len` bytes (or NULL), `sigret` for `RSA_size(rsa)`
/// bytes, `siglen` writable, and `rsa` the signing key (or NULL).
#[allow(unsafe_code)]
unsafe fn rsa_sign_inner<H: RsaSignHandler>(
    md_nid: c_int,
    m: *const c_uchar,
    m_len: c_uint,
    sigret: *mut c_uchar,
    siglen: *mut c_uint,
    rsa: *const ffi::RSA,
) -> EngineResult<()> {
    if rsa.is_null() {
        return Err(EngineError::NullParam("rsa"));
    }
    if m.is_null() {
        return Err(EngineError::NullParam("m"));
    }
    if sigret.is_null() || siglen.is_null() {
        // OpenSSL always provides both for the sign slot.
        return Err(EngineError::NullParam("sigret/siglen"));
    }
    let len = usize::try_from(m_len).map_err(|_| EngineError::Other("digest too large".into()))?;
    // SAFETY: m is non-null (checked) and valid for m_len bytes per contract.
    let digest = unsafe { std::slice::from_raw_parts(m, len) };

    let rsa = rsa.cast_mut();
    let sig = H::sign(rsa, md_nid, digest)?;

    // A PKCS#1 v1.5 RSA signature is exactly `RSA_size(rsa)` bytes (the modulus
    // size), which is also the `sigret` buffer size. Require an exact match — a
    // shorter vector would be a malformed signature, not a valid short one.
    // SAFETY: rsa is a valid RSA (checked); RSA_size reads its modulus.
    let cap = unsafe { ffi::RSA_size(rsa) };
    let cap = usize::try_from(cap).map_err(|_| EngineError::Other("negative RSA_size".into()))?;
    if sig.len() != cap {
        return Err(EngineError::Other(format!(
            "RSA signature is {} bytes, expected RSA_size ({cap})",
            sig.len()
        )));
    }
    let out_len = c_uint::try_from(sig.len())
        .map_err(|_| EngineError::Other("signature too large".into()))?;
    // SAFETY: sigret is valid for cap >= sig.len() bytes per the sign contract;
    // siglen is writable (checked non-null).
    unsafe {
        std::ptr::copy_nonoverlapping(sig.as_ptr(), sigret, sig.len());
        *siglen = out_len;
    }
    Ok(())
}

/// Build an `RSA_METHOD` that signs via `H`, keeping OpenSSL's software RSA
/// operations (a dup of `RSA_PKCS1_OpenSSL`) for everything but `sign`. Register
/// the result on an engine with `ENGINE_set_RSA`.
///
/// The built-in `RSA_PKCS1_OpenSSL()` is dup'd rather than `RSA_get_default_method()`:
/// the latter is a mutable process-global that another `RSA_set_default_method`
/// caller can replace, which would make engine keys inherit a foreign method's
/// callbacks. This mirrors the EC path's use of `EC_KEY_OpenSSL()`.
///
/// The returned method is heap-allocated and intentionally not freed here: the
/// caller keeps it for the process lifetime (one method shared by all engine
/// keys), so no libcrypto-held pointer dangles at teardown.
#[allow(unsafe_code)]
pub fn new_rsa_sign_method<H: RsaSignHandler>() -> EngineResult<*mut ffi::RSA_METHOD> {
    // SAFETY: RSA_PKCS1_OpenSSL returns the built-in software const method;
    // RSA_meth_dup copies it into a fresh owned method.
    let method = unsafe { ffi::RSA_meth_dup(ffi::RSA_PKCS1_OpenSSL()) };
    if method.is_null() {
        return Err(EngineError::Other("RSA_meth_dup failed".into()));
    }
    // SAFETY: method is our fresh dup; install our sign slot. In 1.1.1 RSA_sign
    // dispatches to a non-NULL rsa_sign (no flag needed).
    if unsafe { ffi::RSA_meth_set_sign(method, Some(c_rsa_sign::<H>)) } != 1 {
        // SAFETY: method is ours and not yet published.
        unsafe { ffi::RSA_meth_free(method) };
        return Err(EngineError::Other("RSA_meth_set_sign failed".into()));
    }
    // RSA_meth_dup preserves RSA_FLAG_FIPS_METHOD from RSA_PKCS1_OpenSSL(); clear
    // it so this custom host-padding/HSM sign is not advertised as OpenSSL's
    // FIPS-validated method (which would let a FIPS build run it as approved).
    // SAFETY: method is our fresh dup; RSA_meth_get_flags reads its flags.
    let flags = unsafe { ffi::RSA_meth_get_flags(method) } & !ffi::RSA_FLAG_FIPS_METHOD_CONST;
    // SAFETY: method is our fresh dup; RSA_meth_set_flags writes its flags.
    if unsafe { ffi::RSA_meth_set_flags(method, flags) } != 1 {
        // SAFETY: method is ours and not yet published.
        unsafe { ffi::RSA_meth_free(method) };
        return Err(EngineError::Other("RSA_meth_set_flags failed".into()));
    }
    Ok(method)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::ptr::null_mut;

    use super::*;

    struct StubSigner;
    impl RsaSignHandler for StubSigner {
        fn sign(_rsa: *mut ffi::RSA, _md_nid: c_int, _m: &[u8]) -> EngineResult<Vec<u8>> {
            unreachable!("sign must not run when params are rejected")
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn new_rsa_sign_method_installs_sign_slot() {
        let method = new_rsa_sign_method::<StubSigner>().unwrap();
        assert!(!method.is_null());
        // SAFETY: our fresh method; the getter returns the installed slot.
        let sign = unsafe { ffi::RSA_meth_get_sign(method) };
        assert!(sign.is_some(), "sign slot must be installed");
        // SAFETY: method is ours and unregistered.
        unsafe { ffi::RSA_meth_free(method) };
    }

    #[test]
    #[allow(unsafe_code)]
    fn rsa_sign_inner_rejects_null_params() {
        let mut sig = [0u8; 8];
        let mut siglen: c_uint = 0;
        let m = [0u8; 4];
        // NULL rsa.
        // SAFETY: exercising the null-parameter guards; the stub never signs.
        let r = unsafe {
            rsa_sign_inner::<StubSigner>(
                0,
                m.as_ptr(),
                4,
                sig.as_mut_ptr(),
                &mut siglen,
                null_mut(),
            )
        };
        assert!(r.is_err(), "null rsa must be rejected");
    }
}
