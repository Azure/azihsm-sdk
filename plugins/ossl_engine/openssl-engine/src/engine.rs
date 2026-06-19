// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Safe wrapper around `*mut ENGINE`.

use std::ffi::CStr;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ptr::NonNull;
use std::ptr::null_mut;

use openssl_sys_engine as ffi;

use crate::error::EngineError;
use crate::error::EngineResult;
use crate::error::RetCode;
use crate::error::catch_panic;
use crate::error::ossl_check;
use crate::error::result_to_int;

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
}
