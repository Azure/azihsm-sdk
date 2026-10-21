// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL heap helpers.

use std::ffi::c_void;

use azihsm_ossl_engine_sys as ffi;

use crate::error::NO_FILE;
use crate::error::NO_LINE;

/// `OPENSSL_free`, which is a macro and so not in the bindings.
///
/// # Safety
/// `ptr` is NULL or an OpenSSL allocation that is not used afterwards.
#[allow(unsafe_code)]
pub unsafe fn openssl_free(ptr: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { ffi::CRYPTO_free(ptr, NO_FILE.as_ptr(), NO_LINE) };
}
