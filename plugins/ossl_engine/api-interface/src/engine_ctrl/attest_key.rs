// Copyright (C) Microsoft Corporation. All rights reserved.

//! C-facing API for attesting key data

use std::marker::PhantomData;

use openssl_rust::safeapi::error::*;
use openssl_rust::safeapi::util::slice_to_u8_ptr;

use crate::AziHsmAttestKey;
use crate::REPORT_DATA_SIZE;

pub struct AttestKey<T> {
    inner: *mut AziHsmAttestKey,
    _phantom: PhantomData<T>,
}

impl<T> AttestKey<T> {
    pub fn new(c_data: *mut AziHsmAttestKey) -> OpenSSLResult<Self> {
        if c_data.is_null() {
            Err(OpenSSLError::InvalidKeyData)?;
        }
        Ok(AttestKey {
            inner: c_data,
            _phantom: PhantomData,
        })
    }

    pub fn report_data(&self) -> OpenSSLResult<&[u8; REPORT_DATA_SIZE as usize]> {
        if unsafe {
            (*self.inner).report_data.is_null()
                || (*self.inner).report_data_len != REPORT_DATA_SIZE as usize
        } {
            Err(OpenSSLError::AttestKeyInvalidReport)?;
        }
        let report_data = unsafe {
            std::slice::from_raw_parts((*self.inner).report_data, REPORT_DATA_SIZE as usize)
        };

        report_data
            .try_into()
            .map_err(|_| OpenSSLError::AttestKeyInvalidReport)
    }

    pub fn key(&self) -> *mut T {
        unsafe { (*self.inner).key as *mut T }
    }

    pub fn set_claim(&mut self, claim: &[u8]) -> OpenSSLResult<()> {
        unsafe {
            if (*self.inner).claim.is_null() {
                (*self.inner).claim_len = claim.len() * 2;
            } else {
                if (*self.inner).claim_len < claim.len() {
                    Err(OpenSSLError::AttestKeyError)?;
                }
                (*self.inner).claim_len = claim.len();
                slice_to_u8_ptr(claim, (*self.inner).claim, claim.len());
            }
        }
        Ok(())
    }
}
