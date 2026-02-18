// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM decryption operations.
//!
//! This module provides the [`HsmDecrypter`] utility for performing decryption
//! operations using any algorithm that implements the [`HsmDecryptOp`] trait.

use super::*;

/// A utility struct for performing HSM decryption operations.
///
/// This struct provides a generic interface for decrypting data using various
/// decryption algorithms. It acts as a wrapper around types implementing the
/// [`HsmDecryptOp`] trait, providing a consistent API for decryption operations.
pub struct HsmDecrypter;

impl HsmDecrypter {
    /// Decrypts ciphertext using the specified algorithm and key.
    ///
    /// This method provides a generic interface for decryption operations. It delegates
    /// to the provided algorithm's implementation of the [`HsmDecryptOp`] trait.
    ///
    /// The method operates in two modes:
    /// 1. **Size query mode**: When `plaintext` is `None`, returns the required buffer size
    /// 2. **Decryption mode**: When `plaintext` is `Some`, performs actual decryption
    ///
    /// # Type Parameters
    ///
    /// * `Algo` - The decryption algorithm type that implements [`HsmDecryptOp`]
    ///
    /// # Parameters
    ///
    /// * `session` - A mutable reference to the HSM session for the operation
    /// * `algo` - A mutable reference to the decryption algorithm implementation
    /// * `key` - A reference to the key to use for decryption
    /// * `ciphertext` - The data to be decrypted
    /// * `plaintext` - An optional mutable buffer for the decrypted output. If `None`,
    ///   the method returns the required buffer size. If `Some`, the buffer must be
    ///   large enough to hold the plaintext.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The size of the plaintext. In size query mode, this is the
    ///   required buffer size. In decryption mode, this is the number of bytes written.
    /// * `Err(Algo::Error)` - An error from the underlying decryption algorithm if the
    ///   operation fails
    ///
    /// # Errors
    ///
    /// This method returns an error if:
    /// - The session is invalid or expired
    /// - The key is not suitable for the decryption algorithm
    /// - The ciphertext size is invalid
    /// - The output buffer is too small (when provided)
    /// - The underlying HSM operation fails
    pub fn decrypt<Algo: HsmDecryptOp>(
        algo: &mut Algo,
        key: &Algo::Key,
        ciphertext: &[u8],
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, Algo::Error> {
        algo.decrypt(key, ciphertext, plaintext)
    }

    /// Decrypts ciphertext and returns the plaintext as a vector.
    ///
    /// This is a convenience method that handles buffer allocation automatically. It first
    /// queries the required buffer size, allocates the buffer, performs the decryption,
    /// and returns the plaintext as a `Vec<u8>`.
    ///
    /// # Type Parameters
    ///
    /// * `Algo` - The decryption algorithm type that implements [`HsmDecryptOp`]
    ///
    /// # Parameters
    ///
    /// * `session` - A mutable reference to the HSM session for the operation
    /// * `algo` - A mutable reference to the decryption algorithm implementation
    /// * `key` - A reference to the key to use for decryption
    /// * `ciphertext` - The data to be decrypted
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The decrypted plaintext as a vector
    /// * `Err(Algo::Error)` - An error from the underlying decryption algorithm if the
    ///   operation fails
    ///
    /// # Errors
    ///
    /// This method returns an error if:
    /// - The session is invalid or expired
    /// - The key is not suitable for the decryption algorithm
    /// - The ciphertext size is invalid
    /// - The underlying HSM operation fails
    pub fn decrypt_vec<Algo: HsmDecryptOp>(
        algo: &mut Algo,
        key: &Algo::Key,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Algo::Error> {
        let size = algo.decrypt(key, ciphertext, None)?;
        let mut plaintext = vec![0u8; size];
        let written = algo.decrypt(key, ciphertext, Some(&mut plaintext))?;
        plaintext.truncate(written);
        Ok(plaintext)
    }

    /// Initializes a streaming decryption operation.
    ///
    /// This method provides a generic interface for initializing multi-part decryption
    /// operations. It delegates to the provided algorithm's implementation of the
    /// [`HsmDecryptStreamingOp`] trait to create a decryption context.
    ///
    /// # Type Parameters
    ///
    /// * `Algo` - The streaming decryption algorithm type that implements [`HsmDecryptStreamingOp`]
    ///
    /// # Parameters
    ///
    /// * `session` - A mutable reference to the HSM session for the operation
    /// * `algo` - The decryption algorithm implementation (consumed to create the context)
    /// * `key` - The decryption key to use for the operation
    ///
    /// # Returns
    ///
    /// * `Ok(Algo::Context)` - An initialized decryption context ready to process data
    /// * `Err(Algo::Error)` - An error from the underlying decryption algorithm if
    ///   initialization fails
    ///
    /// # Errors
    ///
    /// This method returns an error if:
    /// - The session is invalid or expired
    /// - The key is not suitable for streaming decryption
    /// - The underlying HSM operation fails to initialize the context
    pub fn decrypt_init<Algo: HsmDecryptStreamingOp>(
        algo: Algo,
        key: Algo::Key,
    ) -> Result<Algo::Context, Algo::Error> {
        algo.decrypt_init(key)
    }
}
