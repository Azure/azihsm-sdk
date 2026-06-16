// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crate-private `OSSL_LIB_CTX` for this crate's OpenSSL backends.
//!
//! # Why this exists
//!
//! When this crate is built with the mock backend and loaded *inside* the
//! azihsm OpenSSL provider, its OpenSSL operations run in the process-global
//! default `OSSL_LIB_CTX` — the same one that has the `azihsm` provider loaded.
//! On OpenSSL 3.5 a bare (no-propquery) algorithm fetch in that libctx resolves
//! to the `azihsm` provider instead of the default one (3.0.x resolved it to
//! `default`). So a digest/MAC the mock SDK computes *while opening the HSM
//! session* re-enters azihsm's own digest/MAC, which calls back into the
//! session-open path — fatal re-entry that fails every operation on 3.5.
//!
//! The fix is to run the crate's OpenSSL crypto in a private libctx that holds
//! **only the default provider**, so a bare fetch can never resolve to
//! `azihsm`. This is correct on every OpenSSL version and independent of when
//! the session is opened (eager or lazy).
//!
//! # Scope
//!
//! All of this crate's OpenSSL backends fetch their algorithm from
//! [`crypto_libctx()`] instead of the crate's default-libctx APIs (`Hasher`,
//! `Signer`, …): hash, HMAC, HKDF, AES (CBC/GCM/ECB/XTS), ECDH, ECDSA, and RSA
//! (encrypt/decrypt, sign/verify, digest-sign). New backends adopt the same
//! accessor without touching this module.

use std::os::raw::c_char;
use std::os::raw::c_int;
use std::sync::OnceLock;

use foreign_types::ForeignTypeRef;
use openssl::lib_ctx::LibCtx;
use openssl::lib_ctx::LibCtxRef;
use openssl::provider::Provider;
use openssl_sys as ffi;

/// OpenSSL C-API success return code. Most libcrypto functions return `1` on
/// success (and `0` or a negative value on failure), so the FFI backends in
/// this crate compare against this constant instead of a bare `1` literal.
pub(crate) const OSSL_SUCCESS: c_int = 1;

/// Owns the private libctx and keeps its default provider loaded.
struct CryptoLibCtx {
    ctx: LibCtx,
    /// The default `OSSL_PROVIDER` must stay loaded for `ctx`'s whole lifetime;
    /// dropping this handle would unload it and break every later fetch.
    _default: Provider,
}

static CRYPTO_LIBCTX: OnceLock<CryptoLibCtx> = OnceLock::new();

fn init() -> CryptoLibCtx {
    // A fresh OSSL_LIB_CTX has no providers; load only `default` into it.
    // azihsm is loaded in the *process default* libctx, never in this one, so
    // bare fetches here can never resolve to azihsm.
    let ctx = LibCtx::new().expect("azihsm_crypto: failed to create private OSSL_LIB_CTX");
    let default = Provider::load(Some(&ctx), "default")
        .expect("azihsm_crypto: failed to load 'default' provider into private OSSL_LIB_CTX");
    CryptoLibCtx {
        ctx,
        _default: default,
    }
}

/// Returns the crate-private libctx (default-provider-only).
///
/// Algorithm fetches against it (`Md::fetch`, `EVP_MAC_fetch`, …) resolve to
/// the default provider and never to a third-party provider — notably `azihsm`
/// — that may be loaded in the process default libctx. Initialised lazily on
/// first use and shared for the process lifetime.
pub(crate) fn crypto_libctx() -> &'static LibCtxRef {
    &CRYPTO_LIBCTX.get_or_init(init).ctx
}

/// Raw `OSSL_LIB_CTX*` for the private libctx, for `openssl-sys` FFI calls that
/// take a libctx (e.g. `EVP_PKEY_CTX_new_from_pkey`). `as_ptr()` is safe; the
/// FFI that consumes the pointer is what's `unsafe`.
pub(crate) fn crypto_libctx_ptr() -> *mut ffi::OSSL_LIB_CTX {
    crypto_libctx().as_ptr()
}

// `EVP_PKEY_CTX_new_from_pkey` builds a pkey-operation context bound to a
// specific libctx, so the operation's algorithm fetch resolves there instead of
// in the process-default libctx (where azihsm may be loaded and would re-enter
// on OpenSSL 3.5). It exists in OpenSSL 3.0+ libcrypto but is not bound by
// openssl-sys 0.9.x, so it is declared once here and reused via [`PkeyCtx`]
// across the ECC / ECDH / RSA backends.
#[allow(unsafe_code)]
unsafe extern "C" {
    fn EVP_PKEY_CTX_new_from_pkey(
        libctx: *mut ffi::OSSL_LIB_CTX,
        pkey: *mut ffi::EVP_PKEY,
        propquery: *const c_char,
    ) -> *mut ffi::EVP_PKEY_CTX;
}

/// RAII guard owning an `EVP_PKEY_CTX*` built in the crate-private libctx.
///
/// The context is released with `EVP_PKEY_CTX_free` on drop, so call sites can
/// use `?` and early returns freely without leaking it on error paths.
pub(crate) struct PkeyCtx(*mut ffi::EVP_PKEY_CTX);

impl PkeyCtx {
    /// Builds a pkey-operation context for `pkey` in the crate-private libctx
    /// (default-provider only). Returns `None` if libcrypto could not create
    /// the context.
    ///
    /// # Safety
    ///
    /// `pkey` must be a valid, non-null `EVP_PKEY*` that stays alive for the
    /// lifetime of the returned guard.
    #[allow(unsafe_code)]
    pub(crate) unsafe fn from_pkey(pkey: *mut ffi::EVP_PKEY) -> Option<Self> {
        // SAFETY: `crypto_libctx_ptr()` returns a valid libctx pointer; `pkey`
        // is valid per this function's contract; a null propquery is allowed.
        let ctx =
            unsafe { EVP_PKEY_CTX_new_from_pkey(crypto_libctx_ptr(), pkey, std::ptr::null()) };
        (!ctx.is_null()).then_some(Self(ctx))
    }

    /// Raw `EVP_PKEY_CTX*` for passing to libcrypto FFI. The pointer remains
    /// owned by this guard and must not be freed by the caller.
    pub(crate) fn as_ptr(&self) -> *mut ffi::EVP_PKEY_CTX {
        self.0
    }
}

impl Drop for PkeyCtx {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by `EVP_PKEY_CTX_new_from_pkey` (and is
        // non-null by construction); it is freed exactly once, here.
        unsafe { ffi::EVP_PKEY_CTX_free(self.0) };
    }
}
