// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for Rand.

#[cfg(all(feature = "use-openssl", feature = "use-symcrypt"))]
compile_error!("OpenSSL and SymCrypt cannot be enabled at the same time.");

#[cfg(feature = "use-openssl")]
use openssl::rand;
#[cfg(feature = "use-symcrypt")]
use symcrypt::symcrypt_random;

use crate::CryptoError;

///  RNG operation.
///
/// # Arguments
/// * `buf` - The buffer to be filled with cryptographically strong pseudo-random bytes.
///
/// # Returns
/// * Ok(()) - If the operation is successful.
///
/// # Errors
/// * `CryptoError::RngError` - If the RNG operation fails.
#[cfg(feature = "use-openssl")]
pub fn rand_bytes(buf: &mut [u8]) -> Result<(), CryptoError> {
    rand::rand_bytes(buf).map_err(|_| CryptoError::RngError)
}

#[cfg(feature = "use-symcrypt")]
pub fn rand_bytes(buf: &mut [u8]) -> Result<(), CryptoError> {
    symcrypt_random(buf);
    Ok(())
}
