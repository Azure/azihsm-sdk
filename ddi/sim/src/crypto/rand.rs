// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for Rand.

#[cfg(target_os = "linux")]
use openssl::rand;
#[cfg(target_os = "windows")]
use symcrypt::symcrypt_random;

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
#[cfg(target_os = "linux")]
pub fn rand_bytes(buf: &mut [u8]) -> Result<(), ManticoreError> {
    rand::rand_bytes(buf).map_err(|_| ManticoreError::RngError)
}

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
#[cfg(target_os = "windows")]
pub fn rand_bytes(buf: &mut [u8]) -> Result<(), ManticoreError> {
    symcrypt_random(buf);
    Ok(())
}
