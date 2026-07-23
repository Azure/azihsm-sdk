// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Safe wrapper around `*mut ENGINE`.

use std::ffi::CStr;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_void;
use std::ptr::NonNull;
use std::ptr::null_mut;

use azihsm_ossl_engine_sys as ffi;

use crate::error::EngineError;
use crate::error::EngineResult;
use crate::error::RetCode;
use crate::error::catch_panic;
use crate::error::ossl_check;
use crate::error::result_to_int;
use crate::error::result_to_ptr;

pub struct Engine {
    ptr: *mut ffi::ENGINE,
}

// SAFETY: ENGINE access is serialized by OpenSSL's CRYPTO_LOCK_ENGINE.
#[allow(unsafe_code)]
unsafe impl Send for Engine {}
// SAFETY: Same as above.
#[allow(unsafe_code)]
unsafe impl Sync for Engine {}

impl Engine {
    /// # Safety
    /// `ptr` must point to a valid `ENGINE` for the lifetime of the returned value.
    #[allow(unsafe_code)]
    pub unsafe fn from_ptr(ptr: NonNull<ffi::ENGINE>) -> Self {
        Self { ptr: ptr.as_ptr() }
    }

    /// The raw `*mut ENGINE`, for FFI calls that need the pointer directly.
    pub(crate) fn as_ptr(&self) -> *mut ffi::ENGINE {
        self.ptr
    }

    /// Synchronize memory allocators with the host, then call `f`.
    ///
    /// # Safety
    /// `fns` must point to a valid `dynamic_fns` for the duration of this call.
    /// `id`, if non-null, must be a valid C string.
    #[allow(unsafe_code)]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub unsafe fn bind(
        &mut self,
        id: *const c_char,
        fns: NonNull<ffi::dynamic_fns>,
        f: fn(&mut Engine, &CStr) -> EngineResult<()>,
    ) -> EngineResult<()> {
        let fns_ptr = fns.as_ptr();

        // SAFETY: Caller guarantees fns points to a valid dynamic_fns.
        unsafe {
            if ffi::ENGINE_get_static_state() != (*fns_ptr).static_state {
                ossl_check(
                    ffi::CRYPTO_set_mem_functions(
                        (*fns_ptr).mem_fns.malloc_fn,
                        (*fns_ptr).mem_fns.realloc_fn,
                        (*fns_ptr).mem_fns.free_fn,
                    ),
                    EngineError::CryptoSetMemFunctionsFailed,
                )?;
                ossl_check(
                    ffi::OPENSSL_init_crypto(ffi::OPENSSL_INIT_NO_ATEXIT as u64, null_mut()),
                    EngineError::OpensslInitCryptoFailed,
                )?;
            }
        }

        let id = if id.is_null() {
            c""
        } else {
            // SAFETY: OpenSSL guarantees non-null id is a valid C string.
            unsafe { CStr::from_ptr(id) }
        };

        f(self, id)
    }

    /// Set the engine's id — the short identifier OpenSSL matches against
    /// (e.g. in `ENGINE_by_id`).
    #[allow(unsafe_code)]
    pub fn set_id(&self, id: &CStr) -> EngineResult<()> {
        // SAFETY: self.ptr is valid (from NonNull), id is a valid CStr.
        ossl_check(
            unsafe { ffi::ENGINE_set_id(self.ptr, id.as_ptr()) },
            EngineError::SetIdFailed,
        )
    }

    /// Set the engine's human-readable display name.
    #[allow(unsafe_code)]
    pub fn set_name(&self, name: &CStr) -> EngineResult<()> {
        // SAFETY: self.ptr is valid (from NonNull), name is a valid CStr.
        ossl_check(
            unsafe { ffi::ENGINE_set_name(self.ptr, name.as_ptr()) },
            EngineError::SetNameFailed,
        )
    }

    /// Register a destroy callback. `H::destroy` runs when OpenSSL tears
    /// the engine down (after the last `ENGINE_free`). Each `H` produces a
    /// distinct monomorphized C trampoline, so distinct engines may use
    /// distinct handlers without global state.
    #[allow(unsafe_code)]
    pub fn set_destroy<H: DestroyHandler>(&self) -> EngineResult<()> {
        // SAFETY: self.ptr is valid (from NonNull); c_destroy::<H> has the
        // correct C signature and stays valid for the lifetime of the
        // process (it's a 'static fn item).
        ossl_check(
            unsafe { ffi::ENGINE_set_destroy_function(self.ptr, Some(c_destroy::<H>)) },
            EngineError::SetDestroyFailed,
        )
    }

    /// Register the private-key loader OpenSSL invokes for
    /// `ENGINE_load_private_key` (e.g. `openssl … -keyform engine -inform engine
    /// -in <key_id>`). Like [`set_destroy`](Self::set_destroy), each `H`
    /// monomorphizes a distinct C trampoline.
    #[allow(unsafe_code)]
    pub fn set_load_privkey<H: LoadPrivKeyHandler>(&self) -> EngineResult<()> {
        // SAFETY: self.ptr is valid (from NonNull); c_load_privkey::<H> has the
        // correct ENGINE_LOAD_KEY_PTR signature and is a 'static fn item.
        ossl_check(
            unsafe { ffi::ENGINE_set_load_privkey_function(self.ptr, Some(c_load_privkey::<H>)) },
            EngineError::SetLoadPrivKeyFailed,
        )
    }

    /// Point the engine's `EC_KEY_METHOD` at OpenSSL's built-in default. This
    /// is required before [`new_ec_key`](Self::new_ec_key): `EC_KEY_new_method`
    /// fails unless the engine advertises an EC method. The default method keeps
    /// EC operations in software; a later change overrides `sign` to route
    /// signing through the HSM.
    #[allow(unsafe_code)]
    pub fn set_default_ec_method(&self) -> EngineResult<()> {
        // SAFETY: EC_KEY_OpenSSL returns the built-in const EC_KEY_METHOD;
        // ENGINE_set_EC just records that pointer on the engine.
        ossl_check(
            unsafe { ffi::ENGINE_set_EC(self.ptr, ffi::EC_KEY_OpenSSL()) },
            EngineError::Other("ENGINE_set_EC failed".into()),
        )
    }

    /// Create an `EC_KEY` bound to this engine via `EC_KEY_new_method`, which
    /// takes a functional reference on the engine (released on `EC_KEY_free`).
    /// OpenSSL therefore keeps the engine — and any state its destroy handler
    /// owns — alive for as long as the returned key (and any `EVP_PKEY` built
    /// from it) lives. Requires an EC method on the engine (see
    /// [`set_default_ec_method`](Self::set_default_ec_method)). The returned key
    /// has no group or public key set yet.
    #[allow(unsafe_code)]
    pub fn new_ec_key(&self) -> EngineResult<*mut ffi::EC_KEY> {
        // SAFETY: self.ptr is a valid ENGINE; EC_KEY_new_method up-refs it and
        // returns a fresh owned EC_KEY (NULL on allocation failure).
        let ec = unsafe { ffi::EC_KEY_new_method(self.ptr) };
        if ec.is_null() {
            return Err(EngineError::Other("EC_KEY_new_method failed".into()));
        }
        Ok(ec)
    }
}

/// Caller-supplied destroy logic, invoked by OpenSSL when an `ENGINE` is
/// torn down. Implement this on a zero-sized marker type and pass it as
/// the type parameter to [`Engine::set_destroy`].
///
/// Takes `&mut Engine` so a handler can `take()` ex_data (which requires
/// exclusive access) to drop attached state during teardown.
pub trait DestroyHandler {
    fn destroy(engine: &mut Engine) -> EngineResult<()>;
}

/// C trampoline for `ENGINE_set_destroy_function`. Catches panics and
/// dispatches to `H::destroy`. One instantiation per `H`.
///
/// # Safety
/// Called only by OpenSSL during `ENGINE_free`. `e` is the ENGINE being
/// destroyed (may be NULL on malformed input, handled by the trampoline).
#[allow(unsafe_code)]
unsafe extern "C" fn c_destroy<H: DestroyHandler>(e: *mut ffi::ENGINE) -> c_int {
    catch_panic(
        // SAFETY: `e` is the ENGINE OpenSSL is destroying, per the
        // ENGINE_set_destroy_function callback contract.
        || result_to_int(unsafe { destroy_inner::<H>(e) }),
        RetCode::Fail.into(),
    )
}

/// Inner body of [`c_destroy`]: rebuild a safe [`Engine`] from the raw pointer
/// and run the handler. Split out for readability (see [`c_destroy`]).
///
/// # Safety
/// `e` must be the `ENGINE` OpenSSL is destroying (may be NULL).
#[allow(unsafe_code)]
unsafe fn destroy_inner<H: DestroyHandler>(e: *mut ffi::ENGINE) -> EngineResult<()> {
    let nn = NonNull::new(e).ok_or(EngineError::NullParam("engine"))?;
    // SAFETY: `e` is the ENGINE OpenSSL is destroying; valid for this call.
    let mut engine = unsafe { Engine::from_ptr(nn) };
    H::destroy(&mut engine)
}

/// Caller-supplied private-key loader, invoked by OpenSSL for
/// `ENGINE_load_private_key`. Implement on a marker type and pass it as the
/// type parameter to [`Engine::set_load_privkey`].
pub trait LoadPrivKeyHandler {
    /// Load the key named `key_id` and return an owning `*mut EVP_PKEY`
    /// (ownership transfers to OpenSSL). Return an error to surface a NULL
    /// result plus an ERR-queue entry to the caller.
    fn load(engine: &Engine, key_id: &CStr) -> EngineResult<*mut ffi::EVP_PKEY>;
}

/// C trampoline for `ENGINE_set_load_privkey_function` (`ENGINE_LOAD_KEY_PTR`).
/// Catches panics and dispatches to `H::load`, returning NULL on panic/error.
/// The `UI_METHOD`/`cb_data` params are unused: keys are named by id, no prompt.
///
/// # Safety
/// Called only by OpenSSL. `e` is the loading ENGINE and `key_id` the key
/// identifier string, per the callback contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_load_privkey<H: LoadPrivKeyHandler>(
    e: *mut ffi::ENGINE,
    key_id: *const c_char,
    _ui: *mut ffi::UI_METHOD,
    _cb_data: *mut c_void,
) -> *mut ffi::EVP_PKEY {
    catch_panic(
        // SAFETY: `e` and `key_id` are the pointers OpenSSL passes to the
        // load_privkey callback per ENGINE_set_load_privkey_function.
        || result_to_ptr(unsafe { load_privkey_inner::<H>(e, key_id) }),
        null_mut(),
    )
}

/// Inner body of [`c_load_privkey`]: validate the raw pointers, rebuild a safe
/// [`Engine`], and dispatch to `H::load`.
///
/// # Safety
/// `e` must be the loading `ENGINE` and `key_id` a valid C string (or NULL).
#[allow(unsafe_code)]
unsafe fn load_privkey_inner<H: LoadPrivKeyHandler>(
    e: *mut ffi::ENGINE,
    key_id: *const c_char,
) -> EngineResult<*mut ffi::EVP_PKEY> {
    let nn = NonNull::new(e).ok_or(EngineError::NullParam("engine"))?;
    if key_id.is_null() {
        return Err(EngineError::NullParam("key_id"));
    }
    // SAFETY: `e` is non-null (checked) and the ENGINE OpenSSL is loading from.
    let engine = unsafe { Engine::from_ptr(nn) };
    // SAFETY: `key_id` is non-null (checked) and a valid C string per contract.
    let key_id = unsafe { CStr::from_ptr(key_id) };
    H::load(&engine, key_id)
}

/// Caller-supplied ECDSA signing for an engine-backed EC key, invoked through
/// the `EC_KEY_METHOD` `sign_sig` hook. Implement on a marker type and pass it
/// to [`new_ecdsa_method`].
pub trait EcdsaSignHandler {
    /// Sign the pre-computed `digest` for `ec_key` (e.g. recover an attached HSM
    /// key handle from the `EC_KEY`'s ex_data) and return an owning
    /// `*mut ECDSA_SIG` — ownership transfers to OpenSSL, which DER-wraps it.
    /// Return an error to surface a NULL result plus an ERR-queue entry.
    ///
    /// `ec_key` is the signing `EC_KEY` OpenSSL passed to the callback; it is a
    /// raw pointer (only meaningful to dereference in `unsafe`), valid for the
    /// duration of the call.
    fn sign(ec_key: *mut ffi::EC_KEY, digest: &[u8]) -> EngineResult<*mut ffi::ECDSA_SIG>;
}

/// C trampoline for `EC_KEY_METHOD_set_sign`'s `sign_sig` slot. Catches panics
/// and dispatches to `H::sign`, returning NULL on panic/error. `in_kinv`/`in_r`
/// (precomputed nonce) are unused: the HSM generates its own nonce.
///
/// # Safety
/// Called only by OpenSSL's ECDSA sign path. `dgst`/`dgst_len` describe the
/// digest and `eckey` is the signing key, per the `sign_sig` contract.
#[allow(unsafe_code)]
unsafe extern "C" fn c_ecdsa_sign_sig<H: EcdsaSignHandler>(
    dgst: *const c_uchar,
    dgst_len: c_int,
    _in_kinv: *const ffi::BIGNUM,
    _in_r: *const ffi::BIGNUM,
    eckey: *mut ffi::EC_KEY,
) -> *mut ffi::ECDSA_SIG {
    catch_panic(
        // SAFETY: dgst/dgst_len describe the digest OpenSSL computed and eckey is
        // the signing EC_KEY, per the sign_sig callback contract.
        || result_to_ptr(unsafe { ecdsa_sign_inner::<H>(dgst, dgst_len, eckey) }),
        null_mut(),
    )
}

/// Inner body of [`c_ecdsa_sign_sig`]: build a digest slice from the raw pointer
/// and dispatch to `H::sign`.
///
/// # Safety
/// `dgst` must be valid for `dgst_len` bytes (or NULL) and `eckey` the signing
/// `EC_KEY`, per the `sign_sig` contract.
#[allow(unsafe_code)]
unsafe fn ecdsa_sign_inner<H: EcdsaSignHandler>(
    dgst: *const c_uchar,
    dgst_len: c_int,
    eckey: *mut ffi::EC_KEY,
) -> EngineResult<*mut ffi::ECDSA_SIG> {
    if dgst.is_null() {
        return Err(EngineError::NullParam("dgst"));
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
    // DER wrapper by calling `sign_sig`) and override only `sign_sig`.
    let mut sign = None;
    let mut sign_setup = None;
    // SAFETY: method is a fresh EC_KEY_METHOD; get_sign writes the out-params it
    // is given (NULL for the sign_sig slot, which we don't need).
    unsafe { ffi::EC_KEY_METHOD_get_sign(method, &mut sign, &mut sign_setup, null_mut()) };
    // SAFETY: method is ours; reinstall the defaults plus our sign_sig trampoline.
    unsafe { ffi::EC_KEY_METHOD_set_sign(method, sign, sign_setup, Some(c_ecdsa_sign_sig::<H>)) };
    Ok(method)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use super::*;

    static DESTROY_COUNT: AtomicUsize = AtomicUsize::new(0);

    struct CountingDestroy;
    impl DestroyHandler for CountingDestroy {
        fn destroy(_: &mut Engine) -> EngineResult<()> {
            DESTROY_COUNT.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn set_destroy_runs_on_engine_free() {
        // SAFETY: ENGINE_new / ENGINE_free are standard OpenSSL entry points
        // taking no arguments / a valid ENGINE pointer respectively.
        let raw = unsafe { ffi::ENGINE_new() };
        let nn = NonNull::new(raw).expect("ENGINE_new returned NULL");
        // SAFETY: nn is non-null and owned until ENGINE_free below.
        let e = unsafe { Engine::from_ptr(nn) };

        let before = DESTROY_COUNT.load(Ordering::SeqCst);
        e.set_destroy::<CountingDestroy>().unwrap();
        assert_eq!(DESTROY_COUNT.load(Ordering::SeqCst), before);

        // SAFETY: same as above.
        unsafe { ffi::ENGINE_free(e.as_ptr()) };
        assert_eq!(
            DESTROY_COUNT.load(Ordering::SeqCst),
            before + 1,
            "destroy callback should run exactly once on ENGINE_free"
        );
    }

    struct NullLoader;
    impl LoadPrivKeyHandler for NullLoader {
        fn load(_: &Engine, _: &CStr) -> EngineResult<*mut ffi::EVP_PKEY> {
            Ok(null_mut())
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn set_load_privkey_registers_the_hook() {
        // SAFETY: ENGINE_new / ENGINE_free are standard OpenSSL entry points.
        let raw = unsafe { ffi::ENGINE_new() };
        let nn = NonNull::new(raw).expect("ENGINE_new returned NULL");
        // SAFETY: nn is non-null and owned until ENGINE_free below.
        let e = unsafe { Engine::from_ptr(nn) };

        e.set_load_privkey::<NullLoader>().unwrap();
        // SAFETY: e.as_ptr() is a valid ENGINE.
        let f = unsafe { ffi::ENGINE_get_load_privkey_function(e.as_ptr()) };
        assert!(f.is_some(), "load_privkey hook should be registered");

        // SAFETY: same as above.
        unsafe { ffi::ENGINE_free(e.as_ptr()) };
    }
}
