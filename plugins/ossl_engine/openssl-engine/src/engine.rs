// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Safe wrapper around `*mut ENGINE`.

use std::ffi::CStr;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ptr::NonNull;
use std::ptr::null_mut;

use openssl_sys_engine as ffi;

pub struct Engine {
    ptr: *mut ffi::ENGINE,
}

/// Entry-point glue for a dynamic engine's `bind_engine` export.
///
/// Validates the raw pointers OpenSSL's dynamic loader passes to
/// `bind_engine` and dispatches to `f` with a safe [`Engine`].
///
/// # Safety
/// `engine`, `id`, and `fns` must be the pointers supplied by OpenSSL's
/// dynamic engine loader: `engine` and `fns`, if non-null, valid for this
/// call, and `id`, if non-null, a valid C string.
#[allow(unsafe_code)]
pub unsafe fn bind_entry(
    engine: *mut ffi::ENGINE,
    id: *const c_char,
    fns: *mut ffi::dynamic_fns,
    f: fn(&Engine, &CStr) -> c_int,
) -> c_int {
    let Some(engine) = NonNull::new(engine) else {
        return 0;
    };
    let Some(fns) = NonNull::new(fns) else {
        return 0;
    };
    // SAFETY: engine and fns are non-null (checked above) and valid for this
    // call (provided by OpenSSL's dynamic loader).
    unsafe { Engine::from_ptr(engine).bind(id, fns, f) }
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

    /// Synchronize memory allocators with the host, then call `f`.
    ///
    /// # Safety
    /// `fns` must point to a valid `dynamic_fns` for the duration of this call.
    /// `id`, if non-null, must be a valid C string.
    #[allow(unsafe_code)]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub unsafe fn bind(
        &self,
        id: *const c_char,
        fns: NonNull<ffi::dynamic_fns>,
        f: fn(&Engine, &CStr) -> c_int,
    ) -> c_int {
        let fns_ptr = fns.as_ptr();

        // SAFETY: Caller guarantees fns points to a valid dynamic_fns.
        unsafe {
            if ffi::ENGINE_get_static_state() != (*fns_ptr).static_state {
                if ffi::CRYPTO_set_mem_functions(
                    (*fns_ptr).mem_fns.malloc_fn,
                    (*fns_ptr).mem_fns.realloc_fn,
                    (*fns_ptr).mem_fns.free_fn,
                ) != 1
                {
                    return 0;
                }
                if ffi::OPENSSL_init_crypto(ffi::OPENSSL_INIT_NO_ATEXIT as u64, null_mut()) != 1 {
                    return 0;
                }
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

    #[allow(unsafe_code)]
    pub fn set_id(&self, id: &CStr) -> c_int {
        // SAFETY: self.ptr is valid (from NonNull), id is a valid CStr.
        unsafe { ffi::ENGINE_set_id(self.ptr, id.as_ptr()) }
    }

    #[allow(unsafe_code)]
    pub fn set_name(&self, name: &CStr) -> c_int {
        // SAFETY: self.ptr is valid (from NonNull), name is a valid CStr.
        unsafe { ffi::ENGINE_set_name(self.ptr, name.as_ptr()) }
    }
}
