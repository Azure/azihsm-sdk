// Copyright (C) Microsoft Corporation. All rights reserved.

//! Windows CNG (Cryptography Next Generation) random number generator implementation.
//!
//! This module provides a Windows-specific implementation of cryptographically secure
//! random number generation using the Windows Cryptography Next Generation (CNG) API.
//! CNG provides access to the Windows system's preferred random number generator, which
//! is typically a hardware-based or cryptographically secure software implementation.
//!
//! # Features
//!
//! - **Cryptographically secure**: Uses Windows system's preferred RNG
//! - **Hardware acceleration**: Automatically leverages hardware RNG when available
//! - **FIPS compliance**: Uses FIPS 140-2 validated random number generators when configured
//! - **High performance**: Direct system calls minimize overhead
//!
//! # Security
//!
//! The implementation uses `BCryptGenRandom` with the `BCRYPT_USE_SYSTEM_PREFERRED_RNG`
//! flag, which ensures the system selects the most appropriate and secure random number
//! generator available. This typically includes:
//!
//! - Hardware RNG (RDRAND/RDSEED instructions on supported CPUs)
//! - Fortuna PRNG implementation
//! - Other cryptographically secure entropy sources
//!
//! # Thread Safety
//!
//! The Windows CNG RNG is thread-safe and can be called concurrently from multiple threads
//! without additional synchronization.

use windows::Win32::Security::Cryptography::*;

use super::*;

/// Windows CNG-based cryptographically secure random number generator.
///
/// This struct provides a zero-sized type that implements the [`RngOp`] trait
/// using Windows CNG's system-preferred random number generator. All methods
/// are static as no state needs to be maintained.
///
/// # Security Properties
///
/// - **Cryptographically secure**: Suitable for generating keys, nonces, and other security-critical values
/// - **Unpredictable**: Output cannot be predicted even with knowledge of previous values
/// - **Non-deterministic**: Uses true entropy sources when available
/// - **Forward secure**: Compromise of internal state doesn't reveal previous outputs
///
/// # Performance
///
/// Direct system calls to Windows CNG provide excellent performance with minimal
/// overhead. The implementation automatically selects the fastest secure RNG available.
#[derive(Debug, Clone)]
pub struct CngRng;

/// Implementation of random number generation using Windows CNG.
///
/// This implementation provides cryptographically secure random number generation
/// by leveraging the Windows CNG subsystem. It uses the system's preferred RNG
/// which automatically selects the best available entropy source.
impl RngOp for CngRng {
    /// Fills a buffer with cryptographically secure random bytes.
    ///
    /// This method uses Windows CNG's `BCryptGenRandom` function with the
    /// `BCRYPT_USE_SYSTEM_PREFERRED_RNG` flag to generate high-quality random data
    /// suitable for cryptographic operations.
    ///
    /// # Arguments
    ///
    /// * `buf` - Mutable byte slice to fill with random data
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Random data successfully generated
    /// * `Err(CryptoError::RngError)` - Random number generation failed
    ///
    /// # Errors
    ///
    /// Returns `RngError` if the Windows CNG random number generation fails.
    /// This is extremely rare and typically indicates a system-level issue.
    ///
    /// # Security Notes
    ///
    /// - Uses the system's preferred cryptographically secure RNG
    /// - Suitable for generating keys, initialization vectors, nonces, and salts
    /// - Output is unpredictable and cryptographically secure
    /// - Safe to use in security-critical applications
    ///
    /// # Performance
    ///
    /// This function is optimized for both security and performance. Large buffers
    /// are filled efficiently, and the overhead is minimal for small requests.
    ///
    /// # Safety
    ///
    /// Uses unsafe Windows API calls but ensures proper error handling and
    /// memory safety through careful parameter validation.
    #[allow(unsafe_code)]
    fn rand_bytes(buf: &mut [u8]) -> Result<(), CryptoError> {
        //SAFETY: Calling Bcrypt unsafe functions
        let status = unsafe {
            BCryptGenRandom(
                None, // Use system RNG
                buf,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        status.ok().map_err(|_| CryptoError::RngError)
    }
}
