// Copyright (C) Microsoft Corporation. All rights reserved.

use openssl::cipher::*;
use openssl::cipher_ctx::*;

use super::*;

/// AES GCM (Galois/Counter Mode) algorithm implementation for OpenSSL backend.
pub struct OsslAesGcmAlgo {
    aad: Option<Vec<u8>>,
    iv: Vec<u8>,
    tag: Vec<u8>,
}

impl OsslAesGcmAlgo {
    const IV_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;

    /// Creates a new AES-GCM algorithm instance for encryption.
    ///
    /// # Arguments
    ///
    /// * `iv` - Initialization vector (IV) for encryption.
    /// * `aad` - Optional additional authenticated data (AAD).
    ///
    /// # Returns
    ///
    /// Ok(Self) if the IV length is valid, otherwise an error.
    pub fn for_encrypt(iv: &[u8], aad: Option<&[u8]>) -> Result<Self, CryptoError> {
        if iv.len() != Self::IV_SIZE {
            return Err(CryptoError::GcmInvalidIvLength);
        }
        let iv = iv.to_vec();
        let tag = vec![0u8; Self::TAG_SIZE];
        let aad = aad.map(|a| a.to_vec());
        Ok(Self { iv, tag, aad })
    }

    /// Creates a new AES-GCM algorithm instance for decryption.
    ///
    /// # Arguments
    ///
    /// * `iv` - Initialization vector (IV) for decryption.
    /// * `aad` - Optional additional authenticated data (AAD).
    /// * `tag` - Authentication tag for decryption.
    ///
    /// # Returns
    ///
    /// Ok(Self) if the IV and tag lengths are valid, otherwise an error.
    pub fn for_decrypt(iv: &[u8], tag: &[u8], aad: Option<&[u8]>) -> Result<Self, CryptoError> {
        if iv.len() != Self::IV_SIZE {
            return Err(CryptoError::GcmInvalidIvLength);
        }
        if tag.len() != Self::TAG_SIZE {
            return Err(CryptoError::GcmInvalidTagLength);
        }
        let iv = iv.to_vec();
        let tag = tag.to_vec();
        let aad = aad.map(|a| a.to_vec());
        Ok(Self { iv, tag, aad })
    }

    /// Returns the IV used in the algorithm.
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    /// Returns the authentication tag used in the algorithm.
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    fn cipher(&self, key: &AesKey) -> Result<&'static CipherRef, CryptoError> {
        match key.size() {
            16 => Ok(Cipher::aes_128_gcm()),
            24 => Ok(Cipher::aes_192_gcm()),
            32 => Ok(Cipher::aes_256_gcm()),
            _ => Err(CryptoError::GcmInvalidKeySize),
        }
    }
}

impl EncryptOp for AesGcmAlgo {
    /// The key type for AES-GCM encryption.
    type Key = AesKey;

    /// Encrypts the input data using AES-GCM.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for encryption.
    /// * `input` - The plaintext data to encrypt.
    /// * `output` - Optional buffer to write the ciphertext to.
    ///
    /// # Returns
    ///
    /// Ok(usize) indicating the number of bytes written to output, or an error.
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let expected_len = input.len();

        let Some(output) = output else {
            return Ok(expected_len);
        };

        if output.len() < expected_len {
            return Err(CryptoError::GcmBufferTooSmall);
        }

        let cipher = self.cipher(key)?;

        let mut ctx = CipherCtx::new().map_err(|_| CryptoError::GcmEncryptionFailed)?;
        ctx.encrypt_init(Some(cipher), Some(key.bytes()), Some(&self.iv))
            .map_err(|_| CryptoError::GcmEncryptionFailed)?;
        if let Some(aad) = &self.aad {
            ctx.cipher_update(aad, None)
                .map_err(|_| CryptoError::GcmEncryptionFailed)?;
        }

        let count = ctx
            .cipher_update(input, Some(&mut output[..expected_len]))
            .map_err(|_| CryptoError::GcmEncryptionFailed)?;

        let mut final_block = vec![0u8; cipher.block_size()];
        ctx.cipher_final(&mut final_block)
            .map_err(|_| CryptoError::GcmEncryptionFailed)?;

        ctx.tag(&mut self.tag)
            .map_err(|_| CryptoError::GcmEncryptionFailed)?;

        Ok(count)
    }
}

/// Implements streaming encryption for AES-GCM.
impl<'a> EncryptStreamingOp<'a> for OsslAesGcmAlgo {
    type Key = AesKey;
    type Context = OsslAesGcmEncryptContext;

    /// Initializes a streaming AES-GCM encryption context.
    ///
    /// Creates a context for processing data in multiple chunks. This is useful for:
    /// - Large files that don't fit in memory
    /// - Streaming data from network or other sources
    /// - Progressive encryption with authentication
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key (128, 192, or 256 bits)
    ///
    /// # Returns
    ///
    /// A context implementing `EncryptOpContext` for streaming operations.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key size is invalid
    /// - The IV size is incorrect (must be 12 bytes)
    /// - OpenSSL context initialization fails
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let cipher = self.cipher(&key)?;
        let mut ctx = CipherCtx::new().map_err(|_| CryptoError::GcmEncryptionFailed)?;
        ctx.encrypt_init(Some(cipher), Some(key.bytes()), Some(&self.iv))
            .map_err(|_| CryptoError::GcmEncryptionFailed)?;

        // Process AAD if provided
        if let Some(aad) = &self.aad {
            ctx.cipher_update(aad, None)
                .map_err(|_| CryptoError::GcmEncryptionFailed)?;
        }

        Ok(OsslAesGcmEncryptContext { algo: self, ctx })
    }
}

/// Streaming context for AES-GCM encryption operations.
///
/// This structure maintains the state for a multi-step AES-GCM encryption operation.
/// It is created by `OsslAesGcmAlgo::encrypt_init` and processes data incrementally
/// through `update` calls, with finalization via `finish`.
///
/// # Lifecycle
///
/// 1. Create context via `encrypt_init`
/// 2. Process data chunks with `update` (can be called multiple times)
/// 3. Finalize with `finish` to produce the authentication tag
///
/// # Internal State
///
/// The context maintains:
/// - OpenSSL cipher context with key, IV, and AAD
/// - Authentication tag state
///
/// # Thread Safety
///
/// This context is not thread-safe and should be used from a single thread.
pub struct OsslAesGcmEncryptContext {
    algo: OsslAesGcmAlgo,
    ctx: CipherCtx,
}

/// Implements streaming encryption operations for the AES-GCM encrypt context.
impl<'a> EncryptOpContext<'a> for OsslAesGcmEncryptContext {
    type Algo = OsslAesGcmAlgo;

    /// Processes a chunk of input data.
    ///
    /// This method can be called multiple times to process data incrementally.
    /// Unlike block cipher modes, GCM is a stream cipher mode and processes
    /// data without requiring complete blocks.
    ///
    /// # Arguments
    ///
    /// * `input` - Input data chunk to encrypt
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer, or the required buffer
    /// size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The context has already been finalized
    /// - The underlying OpenSSL update operation fails
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let expected_len = input.len();

        let Some(output) = output else {
            return Ok(expected_len);
        };

        if output.len() < expected_len {
            return Err(CryptoError::GcmBufferTooSmall);
        }

        let count = self
            .ctx
            .cipher_update(input, Some(output))
            .map_err(|_| CryptoError::GcmEncryptionFailed)?;
        Ok(count)
    }

    /// Finalizes the encryption operation.
    ///
    /// This method completes the operation by:
    /// - Processing any remaining buffered data
    /// - Computing the authentication tag
    /// - Storing the tag in the algorithm instance for later retrieval
    ///
    /// The context is consumed and cannot be used after this call.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer (typically 0 for GCM),
    /// or the required buffer size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The underlying OpenSSL finalization fails
    /// - Tag extraction fails
    ///
    /// # Note
    ///
    /// After calling this method, the authentication tag can be retrieved via
    /// `algo().tag()`.
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        // Finalize the encryption
        let Some(output) = output else {
            return Ok(0);
        };

        let count = self
            .ctx
            .cipher_final(output)
            .map_err(|_| CryptoError::GcmEncryptionFailed)?;

        // Extract the authentication tag
        self.ctx
            .tag(&mut self.algo.tag)
            .map_err(|_| CryptoError::GcmEncryptionFailed)?;

        Ok(count)
    }

    /// Returns a reference to the underlying algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `OsslAesGcmAlgo` algorithm instance.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying algorithm.
    ///
    /// # Returns
    ///
    /// A mutable reference to the `OsslAesGcmAlgo` algorithm instance.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the underlying algorithm.
    ///
    /// # Returns
    ///
    /// The `OsslAesGcmAlgo` algorithm instance.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}

impl DecryptOp for AesGcmAlgo {
    /// The key type for AES-GCM decryption.
    type Key = AesKey;

    /// Decrypts the input data using AES-GCM.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for decryption.
    /// * `input` - The ciphertext data to decrypt.
    /// * `output` - Optional buffer to write the plaintext to.
    ///
    /// # Returns
    ///
    /// Ok(usize) indicating the number of bytes written to output, or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - Authentication tag verification fails
    /// - The underlying OpenSSL operation fails
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let expected_len = input.len();

        let Some(output) = output else {
            return Ok(expected_len);
        };

        if output.len() < expected_len {
            return Err(CryptoError::GcmBufferTooSmall);
        }

        let cipher = self.cipher(key)?;

        let mut ctx = CipherCtx::new().map_err(|_| CryptoError::GcmDecryptionFailed)?;
        ctx.decrypt_init(Some(cipher), Some(key.bytes()), Some(&self.iv))
            .map_err(|_| CryptoError::GcmDecryptionFailed)?;

        // Set the authentication tag for verification (must be done before AAD)
        ctx.set_tag(&self.tag)
            .map_err(|_| CryptoError::GcmDecryptionFailed)?;

        // Process AAD if provided
        if let Some(aad) = &self.aad {
            ctx.cipher_update(aad, None)
                .map_err(|_| CryptoError::GcmDecryptionFailed)?;
        }

        let count = ctx
            .cipher_update(input, Some(&mut output[..expected_len]))
            .map_err(|_| CryptoError::GcmDecryptionFailed)?;

        // Finalize will verify the tag
        let mut final_block = vec![0u8; cipher.block_size()];
        ctx.cipher_final(&mut final_block)
            .map_err(|_| CryptoError::GcmDecryptionFailed)?;

        Ok(count)
    }
}

/// Implements streaming decryption for AES-GCM.
impl<'a> DecryptStreamingOp<'a> for OsslAesGcmAlgo {
    type Key = AesKey;
    type Context = OsslAesGcmDecryptContext;

    /// Initializes a streaming AES-GCM decryption context.
    ///
    /// Creates a context for processing data in multiple chunks. This is useful for:
    /// - Large files that don't fit in memory
    /// - Streaming data from network or other sources
    /// - Progressive decryption with authentication
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key (128, 192, or 256 bits)
    ///
    /// # Returns
    ///
    /// A context implementing `DecryptOpContext` for streaming operations.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key size is invalid
    /// - The IV size is incorrect (must be 12 bytes)
    /// - The tag size is incorrect (must be 16 bytes)
    /// - OpenSSL context initialization fails
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        let cipher = self.cipher(&key)?;
        let mut ctx = CipherCtx::new().map_err(|_| CryptoError::GcmDecryptionFailed)?;
        ctx.decrypt_init(Some(cipher), Some(key.bytes()), Some(&self.iv))
            .map_err(|_| CryptoError::GcmDecryptionFailed)?;

        // Set the authentication tag for verification (must be done before AAD)
        ctx.set_tag(&self.tag)
            .map_err(|_| CryptoError::GcmDecryptionFailed)?;

        // Process AAD if provided
        if let Some(aad) = &self.aad {
            ctx.cipher_update(aad, None)
                .map_err(|_| CryptoError::GcmDecryptionFailed)?;
        }

        Ok(OsslAesGcmDecryptContext { algo: self, ctx })
    }
}

/// Streaming context for AES-GCM decryption operations.
///
/// This structure maintains the state for a multi-step AES-GCM decryption operation.
/// It is created by `OsslAesGcmAlgo::decrypt_init` and processes data incrementally
/// through `update` calls, with finalization via `finish`.
///
/// # Lifecycle
///
/// 1. Create context via `decrypt_init`
/// 2. Process data chunks with `update` (can be called multiple times)
/// 3. Finalize with `finish` to verify the authentication tag
///
/// # Internal State
///
/// The context maintains:
/// - OpenSSL cipher context with key, IV, AAD, and tag
/// - Authentication tag for verification during finalization
///
/// # Thread Safety
///
/// This context is not thread-safe and should be used from a single thread.
pub struct OsslAesGcmDecryptContext {
    algo: OsslAesGcmAlgo,
    ctx: CipherCtx,
}

/// Implements streaming decryption operations for the AES-GCM decrypt context.
impl<'a> DecryptOpContext<'a> for OsslAesGcmDecryptContext {
    type Algo = OsslAesGcmAlgo;

    /// Processes a chunk of input data.
    ///
    /// This method can be called multiple times to process data incrementally.
    /// Unlike block cipher modes, GCM is a stream cipher mode and processes
    /// data without requiring complete blocks.
    ///
    /// # Arguments
    ///
    /// * `input` - Input data chunk to decrypt
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer, or the required buffer
    /// size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The context has already been finalized
    /// - The underlying OpenSSL update operation fails
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let expected_len = input.len();

        let Some(output) = output else {
            return Ok(expected_len);
        };

        if output.len() < expected_len {
            return Err(CryptoError::GcmBufferTooSmall);
        }

        let count = self
            .ctx
            .cipher_update(input, Some(output))
            .map_err(|_| CryptoError::GcmDecryptionFailed)?;
        Ok(count)
    }

    /// Finalizes the decryption operation.
    ///
    /// This method completes the operation by:
    /// - Processing any remaining buffered data
    /// - Verifying the authentication tag
    /// - Producing final output
    ///
    /// The context is consumed and cannot be used after this call.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer (typically 0 for GCM),
    /// or the required buffer size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - Authentication tag verification fails
    /// - The underlying OpenSSL finalization fails
    ///
    /// # Security
    ///
    /// The authentication tag is verified during finalization. If verification
    /// fails, the entire decryption is considered invalid and an error is returned.
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        if output.is_none() {
            // GCM finalize typically produces no additional output
            return Ok(0);
        }

        // Finalize the decryption and verify the tag
        let output = output.unwrap();
        let count = self
            .ctx
            .cipher_final(output)
            .map_err(|_| CryptoError::GcmDecryptionFailed)?;

        Ok(count)
    }

    /// Returns a reference to the underlying algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `OsslAesGcmAlgo` algorithm instance.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying algorithm.
    ///
    /// # Returns
    ///
    /// A mutable reference to the `OsslAesGcmAlgo` algorithm instance.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the underlying algorithm.
    ///
    /// # Returns
    ///
    /// The `OsslAesGcmAlgo` algorithm instance.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}
