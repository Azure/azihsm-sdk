// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for Rand.

#[cfg(all(feature = "use-openssl", feature = "use-symcrypt"))]
compile_error!("OpenSSL and non-OpenSSL cannot be enabled at the same time.");

#[cfg(feature = "use-openssl")]
use openssl::rand;
#[cfg(feature = "use-symcrypt")]
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
#[cfg(feature = "use-openssl")]
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
#[cfg(feature = "use-symcrypt")]
pub fn rand_bytes(buf: &mut [u8]) -> Result<(), ManticoreError> {
    symcrypt_random(buf);
    Ok(())
}
