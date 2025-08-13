// Copyright (C) Microsoft Corporation. All rights reserved.

//! C-facing API for getting collateral data (device certificate chain)

use openssl_rust::safeapi::error::OpenSSLError;
use openssl_rust::safeapi::error::OpenSSLResult;
use openssl_rust::safeapi::util::slice_to_u8_ptr;

use crate::AziHsmCollateral;

pub struct Collateral(*mut AziHsmCollateral);

impl Collateral {
    pub fn new(collateral: *mut AziHsmCollateral) -> OpenSSLResult<Self> {
        if collateral.is_null() {
            tracing::error!("Collateral is null");
            Err(OpenSSLError::GetCollateralError)?;
        }
        Ok(Self(collateral))
    }

    pub fn set_collateral(&self, collateral_data: &[u8]) -> OpenSSLResult<()> {
        unsafe {
            let collateral_buf_len = (*self.0).collateral_len;
            let collateral_buf = (*self.0).collateral;

            let len: usize;
            if collateral_buf.is_null() {
                len = collateral_data.len() * 2;
            } else {
                if collateral_buf_len < collateral_data.len() {
                    tracing::error!("Collateral buffer is too small");
                    Err(OpenSSLError::GetCollateralError)?;
                }
                len = collateral_data.len();
                // Copy collateral_data into the buffer
                slice_to_u8_ptr(collateral_data, collateral_buf, len);
            }
            (*self.0).collateral_len = len;
        }
        Ok(())
    }
}
