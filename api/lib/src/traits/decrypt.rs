// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Decryption operation trait for HSM operations.
//!
//! This module defines the [`HsmDecryptOp`] trait, which provides an interface
//! for performing decryption operations using HSM keys within a session context.

use std::error::Error;

use super::*;

/// A trait for performing decryption operations on HSM keys.
///
/// This trait abstracts the decryption operation interface, allowing different
/// implementations to provide decryption functionality using various HSM backends.
/// The trait is generic over the key type, session type, and error type to provide
/// flexibility in implementation.
pub trait HsmDecryptOp {
    /// The type of key used by this decryption operation.
    ///
    /// This associated type represents the specific key type that will be used
    /// for decryption. It must implement the [`HsmDecryptionKey`] trait.
    type Key: HsmDecryptionKey;

    /// The error type returned by this decryption operation.
    ///
    /// This associated type represents errors that may occur during decryption.
    /// It must implement the standard [`Error`] trait.
    type Error: Error;

    /// Decrypts ciphertext using the provided key within the given session.
    ///
    /// This method performs decryption of the input ciphertext using the specified key.
    /// It can be called in two modes:
    ///
    /// 1. **Size query mode**: When `plaintext` is `None`, the method returns the
    ///    required size of the output buffer without performing decryption.
    /// 2. **Decryption mode**: When `plaintext` is `Some`, the method performs the
    ///    actual decryption and writes the result to the provided buffer.
    ///
    /// # Parameters
    ///
    /// * `session` - A mutable reference to the HSM session in which the operation
    ///   will be performed.
    /// * `key` - A reference to the decryption key to use.
    /// * `ciphertext` - The data to be decrypted.
    /// * `plaintext` - An optional mutable buffer to receive the decrypted output.
    ///   If `None`, the function returns the required buffer size. If `Some`, the
    ///   buffer must be large enough to hold the plaintext.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The size of the plaintext. In size query mode, this is the
    ///   required buffer size. In decryption mode, this is the actual number of bytes
    ///   written to the output buffer.
    /// * `Err(Self::Error)` - An error if the decryption operation fails. This could
    ///   occur due to invalid parameters, insufficient buffer size, session errors,
    ///   or HSM-specific failures.
    ///
    /// # Errors
    ///
    /// This method may return an error if:
    /// - The session is invalid or has expired
    /// - The key is not suitable for decryption
    /// - The ciphertext size is invalid for the decryption algorithm
    /// - The output buffer (if provided) is too small
    /// - An HSM-level error occurs
    fn decrypt(
        &mut self,
        key: &Self::Key,
        ciphertext: &[u8],
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error>;
}

/// A trait for performing streaming decryption operations on HSM keys.
///
/// This trait provides an interface for multi-part decryption operations where
/// data can be decrypted incrementally. It abstracts the initialization of
/// streaming decryption contexts that can process data in multiple chunks.
pub trait HsmDecryptStreamingOp {
    /// The type of key used by this decryption operation.
    ///
    /// This associated type represents the specific key type that will be used
    /// for decryption. It must implement the [`HsmDecryptionKey`] trait.
    type Key: HsmDecryptionKey;

    /// The error type returned by this decryption operation.
    ///
    /// This associated type represents errors that may occur during decryption.
    /// It must implement the standard [`Error`] trait.
    type Error: Error;

    /// The context type for maintaining state during streaming decryption.
    ///
    /// This associated type represents the decryption context that manages the
    /// state of a multi-part decryption operation. It must implement the
    /// [`HsmDecryptContext`] trait.
    type Context: HsmDecryptContext<Algo = Self>;

    /// Initializes a new streaming decryption operation.
    ///
    /// This method consumes the algorithm and creates a decryption context that
    /// can be used to decrypt data incrementally using the `update` and `finish`
    /// methods.
    ///
    /// # Parameters
    ///
    /// * `session` - A mutable reference to the HSM session for the operation
    /// * `key` - The decryption key to use for the operation
    ///
    /// # Returns
    ///
    /// * `Ok(Self::Context)` - An initialized decryption context ready to process data
    /// * `Err(Self::Error)` - An error if initialization fails
    ///
    /// # Errors
    ///
    /// This method may return an error if:
    /// - The session is invalid or has expired
    /// - The key is not suitable for streaming decryption
    /// - The HSM fails to initialize the decryption context
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, Self::Error>;
}

/// A trait representing the state of an ongoing streaming decryption operation.
///
/// This trait provides methods to process data incrementally during a multi-part
/// decryption operation. Data is decrypted through multiple calls to `update`,
/// followed by a final call to `finish` to complete the operation.
pub trait HsmDecryptContext {
    /// The streaming decryption algorithm associated with this context.
    ///
    /// This associated type represents the decryption algorithm that created
    /// this context and defines the key, session, and error types.
    type Algo: HsmDecryptStreamingOp;

    /// Decrypts a chunk of ciphertext as part of a streaming operation.
    ///
    /// This method processes a portion of the ciphertext and produces a corresponding
    /// chunk of plaintext. It can be called multiple times to decrypt data incrementally.
    /// The method operates in two modes similar to single-shot decryption.
    ///
    /// # Parameters
    ///
    /// * `session` - A mutable reference to the HSM session
    /// * `ciphertext` - The chunk of data to decrypt
    /// * `plaintext` - An optional mutable buffer for the decrypted output. If `None`,
    ///   returns the required buffer size. If `Some`, the buffer must be large enough.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The size of the output. In size query mode, this is the required
    ///   buffer size. In decryption mode, this is the number of bytes written.
    /// * `Err(...)` - An error if the operation fails
    ///
    /// # Errors
    ///
    /// This method may return an error if:
    /// - The session is invalid or has expired
    /// - The context is in an invalid state
    /// - The output buffer is too small (when provided)
    /// - An HSM-level error occurs
    fn update(
        &mut self,
        ciphertext: &[u8],
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmDecryptStreamingOp>::Error>;

    /// Decrypts a chunk of ciphertext and returns the plaintext as a vector.
    ///
    /// This is a convenience method that handles buffer allocation automatically for
    /// incremental decryption. It first queries the required buffer size, allocates
    /// the buffer, decrypts the ciphertext chunk, and returns the plaintext as a `Vec<u8>`.
    ///
    /// # Parameters
    ///
    /// * `session` - A mutable reference to the HSM session
    /// * `ciphertext` - The chunk of data to decrypt
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The decrypted plaintext chunk as a vector
    /// * `Err(...)` - An error if the operation fails
    ///
    /// # Errors
    ///
    /// This method may return an error if:
    /// - The session is invalid or has expired
    /// - The context is in an invalid state
    /// - An HSM-level error occurs
    fn update_vec(
        &mut self,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, <Self::Algo as HsmDecryptStreamingOp>::Error> {
        let required_size = self.update(ciphertext, None)?;
        let mut plaintext = vec![0u8; required_size];
        let written_size = self.update(ciphertext, Some(&mut plaintext))?;
        plaintext.truncate(written_size);
        Ok(plaintext)
    }

    /// Finalizes the streaming decryption operation.
    ///
    /// This method completes the decryption operation, producing any remaining
    /// plaintext (such as final padding removal) and finalizing the decryption context.
    /// After calling this method, the context should not be used for further operations.
    ///
    /// # Parameters
    ///
    /// * `session` - A mutable reference to the HSM session
    /// * `plaintext` - An optional mutable buffer for the final decrypted output.
    ///   If `None`, returns the required buffer size. If `Some`, the buffer must be
    ///   large enough to hold any remaining plaintext.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The size of the final output. In size query mode, this is the
    ///   required buffer size. In decryption mode, this is the number of bytes written.
    /// * `Err(...)` - An error if finalization fails
    ///
    /// # Errors
    ///
    /// This method may return an error if:
    /// - The session is invalid or has expired
    /// - The context is in an invalid state
    /// - The output buffer is too small (when provided)
    /// - An HSM-level error occurs during finalization
    fn finish(
        &mut self,
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmDecryptStreamingOp>::Error>;

    /// Finalizes the streaming decryption operation and returns the plaintext as a vector.
    ///
    /// This is a convenience method that handles buffer allocation automatically for the
    /// final decryption step. It first queries the required buffer size, allocates the
    /// buffer, finalizes the decryption, and returns the final plaintext as a `Vec<u8>`.
    ///
    /// # Parameters
    ///
    /// * `session` - A mutable reference to the HSM session
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The final plaintext as a vector
    /// * `Err(...)` - An error if finalization fails
    ///
    /// # Errors
    ///
    /// This method may return an error if:
    /// - The session is invalid or has expired
    /// - The context is in an invalid state
    /// - An HSM-level error occurs during finalization
    fn finish_vec(&mut self) -> Result<Vec<u8>, <Self::Algo as HsmDecryptStreamingOp>::Error> {
        let required_size = self.finish(None)?;
        let mut plaintext = vec![0u8; required_size];
        let written_size = self.finish(Some(&mut plaintext))?;
        plaintext.truncate(written_size);
        Ok(plaintext)
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
