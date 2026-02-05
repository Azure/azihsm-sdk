// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM encryption operations.
//!
//! This module provides the [`HsmEncrypter`] utility for performing encryption
//! operations using any algorithm that implements the [`HsmEncryptOp`] trait.

use super::*;

/// A utility struct for performing HSM encryption operations.
///
/// This struct provides a generic interface for encrypting data using various
/// encryption algorithms. It acts as a wrapper around types implementing the
/// [`HsmEncryptOp`] trait, providing a consistent API for encryption operations.
pub struct HsmEncrypter;

impl HsmEncrypter {
    /// Encrypts plaintext using the specified algorithm and key.
    ///
    /// This method provides a generic interface for encryption operations. It delegates
    /// to the provided algorithm's implementation of the [`HsmEncryptOp`] trait.
    ///
    /// The method operates in two modes:
    /// 1. **Size query mode**: When `ciphertext` is `None`, returns the required buffer size
    /// 2. **Encryption mode**: When `ciphertext` is `Some`, performs actual encryption
    ///
    /// # Type Parameters
    ///
    /// * `Algo` - The encryption algorithm type that implements [`HsmEncryptOp`]
    ///
    /// # Parameters
    ///
    /// * `session` - A mutable reference to the HSM session for the operation
    /// * `algo` - A mutable reference to the encryption algorithm implementation
    /// * `key` - A reference to the key to use for encryption
    /// * `plaintext` - The data to be encrypted
    /// * `ciphertext` - An optional mutable buffer for the encrypted output. If `None`,
    ///   the method returns the required buffer size. If `Some`, the buffer must be
    ///   large enough to hold the ciphertext.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The size of the ciphertext. In size query mode, this is the
    ///   required buffer size. In encryption mode, this is the number of bytes written.
    /// * `Err(Algo::Error)` - An error from the underlying encryption algorithm if the
    ///   operation fails
    ///
    /// # Errors
    ///
    /// This method returns an error if:
    /// - The session is invalid or expired
    /// - The key is not suitable for the encryption algorithm
    /// - The plaintext size is invalid
    /// - The output buffer is too small (when provided)
    /// - The underlying HSM operation fails
    pub fn encrypt<Algo: HsmEncryptOp>(
        algo: &mut Algo,
        key: &Algo::Key,
        plaintext: &[u8],
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, Algo::Error> {
        algo.encrypt(key, plaintext, ciphertext)
    }

    /// Encrypts plaintext and returns the ciphertext as a vector.
    ///
    /// This is a convenience method that handles buffer allocation automatically. It first
    /// queries the required buffer size, allocates the buffer, performs the encryption,
    /// and returns the ciphertext as a `Vec<u8>`.
    ///
    /// # Type Parameters
    ///
    /// * `Algo` - The encryption algorithm type that implements [`HsmEncryptOp`]
    ///
    /// # Parameters
    ///
    /// * `session` - A mutable reference to the HSM session for the operation
    /// * `algo` - A mutable reference to the encryption algorithm implementation
    /// * `key` - A reference to the key to use for encryption
    /// * `plaintext` - The data to be encrypted
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The encrypted ciphertext as a vector
    /// * `Err(Algo::Error)` - An error from the underlying encryption algorithm if the
    ///   operation fails
    ///
    /// # Errors
    ///
    /// This method returns an error if:
    /// - The session is invalid or expired
    /// - The key is not suitable for the encryption algorithm
    /// - The plaintext size is invalid
    /// - The underlying HSM operation fails
    pub fn encrypt_vec<Algo: HsmEncryptOp>(
        algo: &mut Algo,
        key: &Algo::Key,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Algo::Error> {
        let size = algo.encrypt(key, plaintext, None)?;
        let mut ciphertext = vec![0u8; size];
        let written = algo.encrypt(key, plaintext, Some(&mut ciphertext))?;
        ciphertext.truncate(written);
        Ok(ciphertext)
    }

    /// Initializes a streaming encryption operation.
    ///
    /// This method provides a generic interface for initializing multi-part encryption
    /// operations. It delegates to the provided algorithm's implementation of the
    /// [`HsmEncryptStreamingOp`] trait to create an encryption context.
    ///
    /// # Type Parameters
    ///
    /// * `Algo` - The streaming encryption algorithm type that implements [`HsmEncryptStreamingOp`]
    ///
    /// # Parameters
    ///
    /// * `session` - A mutable reference to the HSM session for the operation
    /// * `algo` - The encryption algorithm implementation (consumed to create the context)
    /// * `key` - The encryption key to use for the operation
    ///
    /// # Returns
    ///
    /// * `Ok(Algo::Context)` - An initialized encryption context ready to process data
    /// * `Err(Algo::Error)` - An error from the underlying encryption algorithm if
    ///   initialization fails
    ///
    /// # Errors
    ///
    /// This method returns an error if:
    /// - The session is invalid or expired
    /// - The key is not suitable for streaming encryption
    /// - The underlying HSM operation fails to initialize the context
    pub fn encrypt_init<Algo: HsmEncryptStreamingOp>(
        algo: Algo,
        key: Algo::Key,
    ) -> Result<Algo::Context, Algo::Error> {
        algo.encrypt_init(key)
    }
}
