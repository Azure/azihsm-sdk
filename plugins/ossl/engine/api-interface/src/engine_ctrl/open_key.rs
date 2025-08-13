// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_char;
use std::ffi::c_void;
use std::ffi::CStr;

use openssl_rust::safeapi::error::OpenSSLError;
use openssl_rust::safeapi::error::OpenSSLResult;

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn name_from_ptr(name: *const c_char) -> OpenSSLResult<u16> {
    if name.is_null() {
        Err(OpenSSLError::InvalidKeyName("<null>".to_string()))?;
    }

    let name = unsafe { CStr::from_ptr(name) };
    let name = name
        .to_str()
        .map_err(|_| OpenSSLError::InvalidKeyName("<invalid>".to_string()))?;
    let name = name
        .parse::<u16>()
        .map_err(|e| OpenSSLError::InvalidKeyName(format!("{e}")))?;
    Ok(name)
}

pub fn is_key_ecdh(arg: *const c_void) -> bool {
    if arg.is_null() {
        return false;
    }

    unsafe { *(arg as *const bool) }
}
