// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Module for Rand.

use azihsm_crypto::Rng;

use crate::errors::ManticoreError;

///  RNG operation.
///
/// # Arguments
/// * `buf` - The buffer to be filled with cryptographically strong pseudo-random bytes.
///
/// # Returns
/// * Ok(()) - If the operation is successful.
///
/// # Errors
/// * `ManticoreError::RngError` - If the RNG operation fails.
pub fn rand_bytes(buf: &mut [u8]) -> Result<(), ManticoreError> {
    Rng::rand_bytes(buf).map_err(|e| {
        tracing::error!(?e, "Random number generation failed");
        ManticoreError::RngError
    })
}
