// Copyright (C) Microsoft Corporation. All rights reserved.

//! C-facing API for wrapping key data

use std::slice::from_raw_parts;

use openssl_rust::safeapi::error::OpenSSLError;
use openssl_rust::safeapi::error::OpenSSLResult;
use openssl_rust::safeapi::util::slice_to_u8_ptr;

use crate::AziHsmUnwrappingKey;

pub struct UnwrappingKey(*mut AziHsmUnwrappingKey);

impl UnwrappingKey {
    pub fn new(key: *mut AziHsmUnwrappingKey) -> OpenSSLResult<Self> {
        if key.is_null() {
            Err(OpenSSLError::InvalidKey)?;
        }
        Ok(Self(key))
    }

    pub fn key_slice(&self) -> OpenSSLResult<&[u8]> {
        if unsafe { (*self.0).key.is_null() || (*self.0).key_len == 0 } {
            Err(OpenSSLError::InvalidKey)?;
        }
        Ok(unsafe { from_raw_parts((*self.0).key, (*self.0).key_len) })
    }

    pub fn set_key(&self, key: &[u8]) {
        unsafe {
            if !(*self.0).key.is_null() {
                slice_to_u8_ptr(key, (*self.0).key, (*self.0).key_len);
            }
            (*self.0).key_len = key.len();
        }
    }
}
