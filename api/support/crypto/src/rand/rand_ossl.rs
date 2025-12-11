// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! Random number generation support

use openssl::rand;

use super::*;
use crate::CryptoError;

/// RNG struct for random number generation
impl RngOp for Rng {
    fn rand_bytes(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        rand::rand_bytes(buf).map_err(|_| CryptoError::RngError)
    }
}
