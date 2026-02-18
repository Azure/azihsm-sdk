// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Encryption operation trait for HSM operations.
//!
//! This module defines the [`HsmEncryptOp`] trait, which provides an interface
//! for performing encryption operations using HSM keys within a session context.

use std::error::Error;

use super::*;

/// A trait for performing encryption operations on HSM keys.
///
/// This trait abstracts the encryption operation interface, allowing different
/// implementations to provide encryption functionality using various HSM backends.
/// The trait is generic over the key type, session type, and error type to provide
/// flexibility in implementation.
pub trait HsmEncryptOp {
    /// The type of key used by this encryption operation.
    type Key: HsmEncryptionKey;

    /// The error type returned by this encryption operation.
    type Error: Error;

    /// Encrypts plaintext using the provided key.
    ///
    /// This method performs encryption of the input plaintext using the specified key.
    /// It operates in two modes:
    ///
    /// 1. **Size query mode**: When `ciphertext` is `None`, returns the required
    ///    output buffer size without performing encryption.
    /// 2. **Encryption mode**: When `ciphertext` is `Some`, performs encryption
    ///    and writes the result to the provided buffer.
    ///
    /// # Parameters
    ///
    /// * `key` - The encryption key to use
    /// * `plaintext` - The data to be encrypted
    /// * `ciphertext` - Optional buffer to receive the encrypted output. If `None`,
    ///   returns the required buffer size. If `Some`, must be large enough to hold
    ///   the ciphertext.
    ///
    /// # Returns
    ///
    /// The size of the ciphertext. In size query mode, this is the required buffer
    /// size. In encryption mode, this is the actual number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is not suitable for encryption
    /// - The plaintext size is invalid for the encryption algorithm
    /// - The output buffer is too small (when provided)
    /// - An HSM-level error occurs
    fn encrypt(
        &mut self,
        key: &Self::Key,
        plaintext: &[u8],
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error>;
}

/// A trait for performing streaming encryption operations on HSM keys.
///
/// This trait provides an interface for multi-part encryption operations where
/// data can be encrypted incrementally. It abstracts the initialization of
/// streaming encryption contexts that can process data in multiple chunks.
pub trait HsmEncryptStreamingOp {
    /// The type of key used by this encryption operation.
    type Key: HsmEncryptionKey;

    /// The error type returned by this encryption operation.
    type Error: Error;

    /// The context type for maintaining state during streaming encryption.
    type Context: HsmEncryptContext<Algo = Self>;

    /// Initializes a new streaming encryption operation.
    ///
    /// Creates an encryption context that can be used to encrypt data incrementally
    /// using the `update` and `finish` methods. This method consumes the algorithm.
    ///
    /// # Parameters
    ///
    /// * `key` - The encryption key to use for the operation
    ///
    /// # Returns
    ///
    /// An initialized encryption context ready to process data.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is not suitable for streaming encryption
    /// - The HSM fails to initialize the encryption context
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, Self::Error>;
}

/// A trait representing the state of an ongoing streaming encryption operation.
///
/// This trait provides methods to process data incrementally during a multi-part
/// encryption operation. Data is encrypted through multiple calls to `update`,
/// followed by a final call to `finish` to complete the operation.
pub trait HsmEncryptContext {
    /// The streaming encryption algorithm associated with this context.
    type Algo: HsmEncryptStreamingOp;

    /// Encrypts a chunk of plaintext as part of a streaming operation.
    ///
    /// Processes a portion of the plaintext and produces a corresponding chunk of
    /// ciphertext. Can be called multiple times to encrypt data incrementally.
    /// Operates in two modes similar to single-shot encryption.
    ///
    /// # Parameters
    ///
    /// * `plaintext` - The chunk of data to encrypt
    /// * `ciphertext` - Optional buffer for the encrypted output. If `None`,
    ///   returns the required buffer size. If `Some`, must be large enough.
    ///
    /// # Returns
    ///
    /// The size of the output. In size query mode, this is the required buffer
    /// size. In encryption mode, this is the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The context is in an invalid state
    /// - The output buffer is too small (when provided)
    /// - An HSM-level error occurs
    fn update(
        &mut self,
        plaintext: &[u8],
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmEncryptStreamingOp>::Error>;

    /// Encrypts a chunk of plaintext and returns the ciphertext as a vector.
    ///
    /// Convenience method that handles buffer allocation automatically. Queries
    /// the required buffer size, allocates the buffer, encrypts the plaintext chunk,
    /// and returns the ciphertext as a `Vec<u8>`.
    ///
    /// # Parameters
    ///
    /// * `plaintext` - The chunk of data to encrypt
    ///
    /// # Returns
    ///
    /// The encrypted ciphertext chunk as a vector.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The context is in an invalid state
    /// - An HSM-level error occurs
    fn update_vec(
        &mut self,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, <Self::Algo as HsmEncryptStreamingOp>::Error> {
        let required_size = self.update(plaintext, None)?;
        let mut buffer = vec![0u8; required_size];
        let written_size = self.update(plaintext, Some(&mut buffer))?;
        buffer.truncate(written_size);
        Ok(buffer)
    }

    /// Finalizes the streaming encryption operation.
    ///
    /// Completes the encryption operation, producing any remaining ciphertext
    /// (such as final padding). After calling this method, the context should
    /// not be used for further operations.
    ///
    /// # Parameters
    ///
    /// * `ciphertext` - Optional buffer for the final encrypted output. If `None`,
    ///   returns the required buffer size. If `Some`, must be large enough to hold
    ///   any remaining ciphertext.
    ///
    /// # Returns
    ///
    /// The size of the final output. In size query mode, this is the required
    /// buffer size. In encryption mode, this is the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The context is in an invalid state
    /// - The output buffer is too small (when provided)
    /// - An HSM-level error occurs during finalization
    fn finish(
        &mut self,
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmEncryptStreamingOp>::Error>;

    /// Finalizes the streaming encryption operation and returns the ciphertext as a vector.
    ///
    /// Convenience method that handles buffer allocation automatically for the final
    /// encryption step. Queries the required buffer size, allocates the buffer,
    /// finalizes the encryption, and returns the final ciphertext as a `Vec<u8>`.
    ///
    /// # Returns
    ///
    /// The final ciphertext as a vector.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The context is in an invalid state
    /// - An HSM-level error occurs during finalization
    fn finish_vec(&mut self) -> Result<Vec<u8>, <Self::Algo as HsmEncryptStreamingOp>::Error> {
        let required_size = self.finish(None)?;
        let mut buffer = vec![0u8; required_size];
        let written_size = self.finish(Some(&mut buffer))?;
        buffer.truncate(written_size);
        Ok(buffer)
    }

    /// Returns a reference to the underlying hash algorithm.
    ///
    /// This method provides access to the algorithm instance associated with
    /// this hash context.
    ///
    /// # Returns
    ///
    /// A reference to the hash algorithm.
    fn algo(&self) -> &Self::Algo;

    /// Returns a mutable reference to the underlying hash algorithm.
    ///
    /// This method provides mutable access to the algorithm instance associated
    /// with this hash context.
    ///
    /// # Returns
    ///
    /// A mutable reference to the hash algorithm.
    fn algo_mut(&mut self) -> &mut Self::Algo;

    /// Consumes the context and returns the underlying hash algorithm.
    ///
    /// This method takes ownership of the context and returns the hash algorithm
    /// instance, allowing the algorithm to be reused or inspected after the
    /// context is no longer needed.
    ///
    /// # Returns
    ///
    /// The hash algorithm instance.
    fn into_algo(self) -> Self::Algo;
}
