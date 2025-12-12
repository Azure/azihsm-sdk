// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! Random number generation support
use windows::Win32::Foundation::STATUS_SUCCESS;
use windows::Win32::Security::Cryptography::*;

use super::*;
pub(crate) use crate::CryptoError;

/// RNG struct for random number generation
impl RngOp for Rng {
    #[allow(unsafe_code)]
    fn rand_bytes(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        //SAFETY: Calling Bcrypt unsafe functions
        let status = unsafe {
            BCryptGenRandom(
                None, // Use system RNG
                buf,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };

        if status != STATUS_SUCCESS {
            Err(CryptoError::RngError)?
        } else {
            Ok(())
        }
    }
}
