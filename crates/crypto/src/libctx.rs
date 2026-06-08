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
//! # Scope and extension
//!
//! Backends opt in by fetching their algorithm from [`crypto_libctx()`] instead
//! of using the crate's default-libctx APIs (`Hasher`, `Signer`, …). The hash
//! and HMAC backends — the ones that re-enter during the HSM session open — use
//! it today; the remaining backends (ec, rsa, hkdf, aes) can adopt the same
//! accessor incrementally without touching this module.

use std::sync::OnceLock;

use foreign_types::ForeignTypeRef;
use openssl::lib_ctx::{LibCtx, LibCtxRef};
use openssl::provider::Provider;
use openssl_sys as ffi;

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
