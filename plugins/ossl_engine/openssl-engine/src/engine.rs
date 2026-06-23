// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Safe wrapper around `*mut ENGINE`.

use std::ffi::CStr;
use std::ffi::c_char;
use std::ptr::NonNull;
use std::ptr::null_mut;

use openssl_sys_engine as ffi;

use crate::error::EngineError;
use crate::error::EngineResult;
use crate::error::ossl_check;

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
        f: fn(&Engine, &CStr) -> EngineResult<()>,
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
}
