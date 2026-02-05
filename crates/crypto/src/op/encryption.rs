// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Traits for encryption and decryption operations.
//!
//! This module provides trait definitions for both single-operation and streaming
//! encryption/decryption. These traits abstract over different encryption algorithms
//! and modes (e.g., AES-CBC, AES-GCM, AES-XTS) while providing a consistent interface.
//!
//! # Design
//!
//! The module provides two levels of encryption APIs:
//!
//! - **Single-operation**: [`EncryptionOp`] for encrypting/decrypting complete messages
//!   in a single call. Suitable for small messages or when all data is available at once.
//!
//! - **Streaming**: [`StreamingEncryptionOp`] and [`StreamingEncryptionOpContext`] for
//!   processing data in chunks. Useful for large messages, streaming data, or when
//!   memory constraints prevent loading entire messages.

use super::*;

/// Trait for single-operation encryption and decryption.
///
/// This trait provides a unified interface for encrypting or decrypting complete
/// messages in a single operation. It's suitable for algorithms where all data
/// must be processed at once, or when the entire message fits in memory.
///
/// # Type Parameters
///
/// * `Key` - The secret key type implementing [`SecretKey`]. Different encryption
///   algorithms may require different key types (e.g., AES-128, AES-256).
pub trait EncryptOp {
    /// The secret key type used for this encryption operation.
    type Key: EncryptionKey;

    /// Encrypts or decrypts data in a single operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key to use for the cryptographic operation
    /// * `mode` - Whether to encrypt or decrypt the data
    /// * `input` - Input data (plaintext for encryption, ciphertext for decryption)
    /// * `output` - Optional output buffer. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer, or the required
    /// buffer size if `ct` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The input data is invalid (e.g., wrong padding, authentication failure)
    /// - The key is invalid for this operation
    /// - The underlying cryptographic operation fails
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError>;
}

/// Trait for streaming encryption operations.
///
/// This trait provides an interface for multi-step encryption where data is
/// processed in chunks. This is useful for:
/// - Large files that don't fit in memory
/// - Streaming data sources (network, pipes)
/// - Progressive encryption with intermediate results
///
/// # Type Parameters
///
/// * `Key` - The secret key type implementing [`SymmetricKey`]
///
/// # Lifecycle
///
/// 1. Initialize: Call [`encrypt_init`](Self::encrypt_init) to create a context
/// 2. Update: Call [`update`](EncryptStreamingOpContext::update) repeatedly with data chunks
/// 3. Finalize: Call [`finish`](EncryptStreamingOpContext::finish) to complete the operation
pub trait EncryptStreamingOp<'a> {
    /// The secret key type used for this encryption operation.
    type Key: EncryptionKey;

    /// The context type for streaming encryption operations.
    type Context: EncryptOpContext<'a, Algo = Self>;

    /// Initializes a streaming encryption context.
    ///
    /// This method creates a new context for processing data in multiple chunks.
    /// The context maintains internal state across multiple [`update`](EncryptStreamingOpContext::update)
    /// calls until [`finish`](EncryptStreamingOpContext::finish) is called.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key to use for the cryptographic operation
    ///
    /// # Returns
    ///
    /// Returns a boxed context implementing [`EncryptStreamingOpContext`] that
    /// can be used to process data incrementally.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid for this operation
    /// - Initialization vector (IV) or other parameters are invalid
    /// - The underlying cryptographic provider fails to initialize
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError>;
}

/// Context for streaming encryption operations.
///
/// This trait represents an active encryption operation that processes data
/// incrementally. Contexts are created by [`EncryptStreamingOp::encrypt_init`]
/// and maintain internal state across multiple updates.
///
/// # Lifecycle
///
/// 1. Create context via [`EncryptStreamingOp::encrypt_init`]
/// 2. Process data chunks with [`update`](Self::update) (can be called multiple times)
/// 3. Complete operation with [`finish`](Self::finish) (consumes the context)
///
/// # Thread Safety
///
/// Contexts are not required to be thread-safe. Each context should be used from
/// a single thread.
pub trait EncryptOpContext<'a> {
    type Algo: EncryptStreamingOp<'a>;
    /// Processes a chunk of data.
    ///
    /// This method can be called multiple times to process data incrementally.
    /// Each call updates the internal state and may produce output.
    ///
    /// # Arguments
    ///
    /// * `input` - Data chunk to process
    /// * `output` - Optional output buffer. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer, or the required
    /// buffer size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The operation has already been finalized
    /// - The underlying cryptographic operation fails
    ///
    /// # Note
    ///
    /// For block ciphers, output size may be smaller than input size until enough
    /// data accumulates to form complete blocks. The remaining data is buffered
    /// internally and processed in subsequent calls or in [`finish`](Self::finish).
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError>;

    /// Finalizes the encryption/decryption operation.
    ///
    /// This method completes the operation, processes any remaining buffered data,
    /// and produces final output (e.g., final encrypted block, authentication tag).
    /// The context is consumed and cannot be used after this call.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer, or the required
    /// buffer size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - Padding is invalid (for decryption)
    /// - Authentication fails (for authenticated encryption modes)
    /// - The underlying cryptographic operation fails
    ///
    /// # Note
    ///
    /// After calling this method, the context is consumed and cannot be reused.
    /// A new context must be created for additional operations.
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError>;

    /// Finalizes the operation and returns the output as a vector.
    ///
    /// This is a convenience method that allocates the necessary output buffer,
    /// calls [`finish`](Self::finish), and returns the result as a `Vec<u8>`.
    ///
    /// # Returns
    ///
    /// Returns a vector containing the final encrypted/decrypted data.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`finish`](Self::finish).
    fn finish_vec(&mut self) -> Result<Vec<u8>, CryptoError> {
        let required_size = self.finish(None)?;
        let mut output = vec![0u8; required_size];
        let written_size = self.finish(Some(&mut output))?;
        output.truncate(written_size);
        Ok(output)
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
/// Trait for single-operation decryption.
///
/// This trait provides a unified interface for decrypting complete messages
/// in a single operation. It's suitable for algorithms where all data must be
/// processed at once, or when the entire message fits in memory.
///
/// # Type Parameters
///
/// * `Key` - The secret key type implementing [`SymmetricKey`]. Different decryption
///   algorithms may require different key types (e.g., AES-128, AES-256).
pub trait DecryptOp {
    /// The secret key type used for this decryption operation.
    type Key: DecryptionKey;

    /// Decrypts data in a single operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key to use for the cryptographic operation
    /// * `input` - Input data (ciphertext to decrypt)
    /// * `output` - Optional output buffer. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer, or the required
    /// buffer size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The input data is invalid (e.g., wrong padding, authentication failure)
    /// - The key is invalid for this operation
    /// - The underlying cryptographic operation fails
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError>;
}

/// Trait for streaming decryption operations.
///
/// This trait provides an interface for multi-step decryption where data is
/// processed in chunks. This is useful for:
/// - Large files that don't fit in memory
/// - Streaming data sources (network, pipes)
/// - Progressive decryption with intermediate results
///
/// # Type Parameters
///
/// * `Key` - The secret key type implementing [`SymmetricKey`]
///
/// # Lifecycle
///
/// 1. Initialize: Call [`decrypt_init`](Self::decrypt_init) to create a context
/// 2. Update: Call [`update`](DecryptStreamingOpContext::update) repeatedly with data chunks
/// 3. Finalize: Call [`finish`](DecryptStreamingOpContext::finish) to complete the operation
pub trait DecryptStreamingOp<'a> {
    /// The secret key type used for this decryption operation.
    type Key: DecryptionKey;

    /// The context type for streaming decryption operations.
    type Context: DecryptOpContext<'a, Algo = Self>;

    /// Initializes a streaming decryption context.
    ///
    /// This method creates a new context for processing data in multiple chunks.
    /// The context maintains internal state across multiple [`update`](DecryptStreamingOpContext::update)
    /// calls until [`finish`](DecryptStreamingOpContext::finish) is called.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key to use for the cryptographic operation
    ///
    /// # Returns
    ///
    /// Returns a boxed context implementing [`DecryptStreamingOpContext`] that
    /// can be used to process data incrementally.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid for this operation
    /// - Initialization vector (IV) or other parameters are invalid
    /// - The underlying cryptographic provider fails to initialize
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError>;
}

/// Context for streaming decryption operations.
///
/// This trait represents an active decryption operation that processes data
/// incrementally. Contexts are created by [`DecryptStreamingOp::decrypt_init`]
/// and maintain internal state across multiple updates.
///
/// # Lifecycle
///
/// 1. Create context via [`DecryptStreamingOp::decrypt_init`]
/// 2. Process data chunks with [`update`](Self::update) (can be called multiple times)
/// 3. Complete operation with [`finish`](Self::finish) (consumes the context)
///
/// # Thread Safety
///
/// Contexts are not required to be thread-safe. Each context should be used from
/// a single thread.
pub trait DecryptOpContext<'a> {
    /// The algorithm type for this decryption context.
    type Algo: DecryptStreamingOp<'a>;

    /// Processes a chunk of data.
    ///
    /// This method can be called multiple times to process data incrementally.
    /// Each call updates the internal state and may produce output.
    ///
    /// # Arguments
    ///
    /// * `input` - Data chunk to process (ciphertext)
    /// * `output` - Optional output buffer. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer, or the required
    /// buffer size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The operation has already been finalized
    /// - The underlying cryptographic operation fails
    ///
    /// # Note
    ///
    /// For block ciphers, output size may be smaller than input size until enough
    /// data accumulates to form complete blocks. The remaining data is buffered
    /// internally and processed in subsequent calls or in [`finish`](Self::finish).
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError>;

    /// Finalizes the decryption operation.
    ///
    /// This method completes the operation, processes any remaining buffered data,
    /// validates padding and authentication tags, and produces final output.
    /// The context is consumed and cannot be used after this call.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer, or the required
    /// buffer size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - Padding is invalid
    /// - Authentication fails (for authenticated encryption modes)
    /// - The underlying cryptographic operation fails
    ///
    /// # Note
    ///
    /// After calling this method, the context is consumed and cannot be reused.
    /// A new context must be created for additional operations.
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError>;

    /// Finalizes the operation and returns the output as a vector.
    ///
    /// This is a convenience method that allocates the necessary output buffer,
    /// calls [`finish`](Self::finish), and returns the result as a `Vec<u8>`.
    ///
    /// # Returns
    ///
    /// Returns a vector containing the final decrypted data.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`finish`](Self::finish).
    fn finish_vec(&mut self) -> Result<Vec<u8>, CryptoError> {
        let required_size = self.finish(None)?;
        let mut output = vec![0u8; required_size];
        let written_size = self.finish(Some(&mut output))?;
        output.truncate(written_size);
        Ok(output)
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
