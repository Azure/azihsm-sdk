// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-CBC encryption and decryption operations.
//!
//! This module provides AES-CBC (Cipher Block Chaining) mode encryption and
//! decryption operations for HSM keys.

use super::*;

/// An algorithm implementation for AES-CBC encryption and decryption.
///
/// This struct provides both single-shot and streaming encryption and decryption
/// operations using the AES algorithm in CBC (Cipher Block Chaining) mode. It
/// implements the [`HsmEncryptOp`], [`HsmEncryptStreamingOp`], [`HsmDecryptOp`],
/// and [`HsmDecryptStreamingOp`] traits for HSM operations.
pub struct HsmAesCbcAlgo {
    /// Whether to apply PKCS#7 padding during encryption and remove it during decryption.
    ///
    /// When `true`, padding is applied to align data to block boundaries.
    /// When `false`, input data must already be block-aligned.
    pad: bool,

    /// The initialization vector for CBC mode.
    ///
    /// Must be exactly 16 bytes (one AES block). This IV is updated during
    /// encryption/decryption operations to support chaining.
    iv: Vec<u8>,
}

impl HsmAesCbcAlgo {
    /// AES block size in bytes.
    const BLOCK_SIZE: usize = 16;

    /// Size of the initialization vector (IV) in bytes.
    const IV_SIZE: usize = 16;

    /// Creates a new AES-CBC algorithm instance with the specified padding mode.
    ///
    /// # Arguments
    ///
    /// * `padding` - Whether to enable PKCS#7 padding (`true`) or require block-aligned input (`false`)
    /// * `iv` - The initialization vector (must be exactly 16 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - A configured AES-CBC algorithm instance
    /// * `Err(HsmError::InvalidArgument)` - If the IV is not exactly 16 bytes
    pub fn with_padding(iv: Vec<u8>) -> HsmResult<Self> {
        if iv.len() != Self::IV_SIZE {
            return Err(HsmError::InvalidArgument);
        }
        Ok(Self { pad: true, iv })
    }

    /// Creates a new AES-CBC algorithm instance without padding.
    ///
    /// This is a convenience method that calls `with_padding(false, iv)`.
    /// Input data must be block-aligned (multiples of 16 bytes).
    ///
    /// # Arguments
    ///
    /// * `iv` - The initialization vector (must be exactly 16 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - A configured AES-CBC algorithm instance without padding
    /// * `Err(HsmError::InvalidArgument)` - If the IV is not exactly 16 bytes
    pub fn with_no_padding(iv: Vec<u8>) -> HsmResult<Self> {
        if iv.len() != Self::IV_SIZE {
            return Err(HsmError::InvalidArgument);
        }
        Ok(Self { pad: false, iv })
    }

    /// Returns a reference to the initialization vector.
    ///
    /// # Returns
    ///
    /// A slice containing the current IV.
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }
}

impl HsmEncryptOp for HsmAesCbcAlgo {
    /// The AES key type used for encryption.
    type Key = HsmAesKey;

    /// The error type for encryption operations.
    type Error = HsmError;

    /// Encrypts plaintext using AES-CBC mode.
    ///
    /// This method performs single-shot encryption of data using AES-CBC mode.
    /// If padding is enabled, PKCS#7 padding will be applied automatically.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for encryption
    /// * `plaintext` - The data to encrypt
    /// * `ciphertext` - Optional buffer to write encrypted data to. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The number of bytes written to ciphertext, or required buffer size if `ciphertext` is `None`
    /// * `Err(HsmError::InvalidArgument)` - If padding is disabled and plaintext is not block-aligned
    /// * `Err(HsmError::BufferTooSmall)` - If the provided ciphertext buffer is too small
    ///
    /// # Block Alignment
    ///
    /// - With padding enabled: Output size is `ceil(plaintext.len() / 16) * 16`
    /// - With padding disabled: Plaintext length must be a multiple of 16 bytes
    fn encrypt(
        &mut self,
        key: &Self::Key,
        plaintext: &[u8],
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        // check if key can encrypt
        if !key.props().can_encrypt() {
            Err(HsmError::InvalidKey)?;
        }

        //Return error if padding is disabled and plaintext is not block aligned
        let expected_len = if self.pad {
            plaintext.len() + pkcs7_pad(plaintext, self.pad).len()
        } else {
            if plaintext.is_empty() || !plaintext.len().is_multiple_of(Self::BLOCK_SIZE) {
                return Err(HsmError::InvalidArgument);
            }
            plaintext.len()
        };
        let Some(ciphertext) = ciphertext else {
            return Ok(expected_len);
        };
        if ciphertext.len() != expected_len {
            return Err(HsmError::BufferTooSmall);
        }
        let padding = pkcs7_pad(plaintext, self.pad);
        ddi::aes_cbc_encrypt(key, &mut self.iv, &[plaintext, &padding], ciphertext)
    }
}

impl HsmEncryptStreamingOp for HsmAesCbcAlgo {
    /// The AES key type used for encryption.
    type Key = HsmAesKey;

    /// The error type for encryption operations.
    type Error = HsmError;

    /// The context type for streaming encryption.
    type Context = HsmAesCbcEncryptContext;

    /// Initializes a streaming AES-CBC encryption operation.
    ///
    /// Creates an encryption context that allows data to be encrypted incrementally
    /// through multiple calls to `update` and a final call to `finish`.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for encryption
    ///
    /// # Returns
    ///
    /// * `Ok(HsmAesCbcEncryptContext)` - An initialized encryption context
    /// * `Err(HsmError)` - If initialization fails
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        // check if key can encrypt
        if !key.props().can_encrypt() {
            Err(HsmError::InvalidKey)?;
        }

        Ok(HsmAesCbcEncryptContext {
            algo: self,
            key,
            block: AesCbcBlock::default(),
        })
    }
}

/// A context for streaming AES-CBC encryption operations.
///
/// This struct maintains the state of an ongoing AES-CBC encryption operation,
/// allowing data to be encrypted incrementally through multiple calls.
pub struct HsmAesCbcEncryptContext {
    /// The AES-CBC algorithm configuration including padding and IV.
    algo: HsmAesCbcAlgo,

    /// The AES key being used for encryption.
    key: HsmAesKey,

    /// Internal block buffer for managing partial blocks during streaming.
    block: AesCbcBlock,
}

impl HsmEncryptContext for HsmAesCbcEncryptContext {
    /// The AES-CBC algorithm for this encryption context.
    type Algo = HsmAesCbcAlgo;

    /// Encrypts a chunk of plaintext in the streaming operation.
    ///
    /// Processes input data incrementally, buffering incomplete blocks internally.
    /// Only complete blocks are encrypted and output during update calls.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext data to encrypt
    /// * `ciphertext` - Optional buffer for encrypted output. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written, or required buffer size if `ciphertext` is `None`
    /// * `Err(HsmError::BufferTooSmall)` - If the ciphertext buffer is too small
    ///
    /// # Note
    ///
    /// Partial blocks are buffered and will be processed in subsequent `update` calls
    /// or in the final `finish` call.
    fn update(
        &mut self,
        plaintext: &[u8],
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmEncryptStreamingOp>::Error> {
        let exepected_len = self.block.update_len(plaintext)?;
        let Some(ciphertext) = ciphertext else {
            return Ok(exepected_len);
        };
        if ciphertext.len() < exepected_len {
            return Err(HsmError::BufferTooSmall);
        }
        let mut offset = 0;
        self.block.update(plaintext, |input: &[u8]| {
            let written = ddi::aes_cbc_encrypt(
                &self.key,
                &mut self.algo.iv,
                &[input],
                &mut ciphertext[offset..offset + input.len()],
            )?;
            offset += written;
            Ok(written)
        })
    }

    /// Finalizes the streaming encryption operation and produces final ciphertext.
    ///
    /// Processes any remaining buffered data and applies PKCS#7 padding if enabled.
    /// After calling this method, the encryption operation is complete.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Optional buffer for final encrypted output. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written, or required buffer size if `ciphertext` is `None`
    /// * `Err(HsmError::BufferTooSmall)` - If the ciphertext buffer is too small
    ///
    /// # Padding
    ///
    /// If padding is enabled, PKCS#7 padding will be applied to the final block.
    /// The output size will always be a multiple of the block size (16 bytes).
    fn finish(
        &mut self,
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmEncryptStreamingOp>::Error> {
        let exepected_len = self.block.finish_len(self.algo.pad)?;
        let Some(ciphertext) = ciphertext else {
            return Ok(exepected_len);
        };
        if ciphertext.len() < exepected_len {
            return Err(HsmError::BufferTooSmall);
        }
        self.block.finish(|input: &[u8]| {
            let padding = pkcs7_pad(input, self.algo.pad);
            ddi::aes_cbc_encrypt(
                &self.key,
                &mut self.algo.iv,
                &[input, &padding],
                &mut ciphertext[..input.len() + padding.len()],
            )
        })
    }

    /// Returns a reference to the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `OsslHash` algorithm instance.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// A mutable reference to the `OsslHash` algorithm instance.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// The `OsslHash` algorithm instance.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}

impl HsmDecryptOp for HsmAesCbcAlgo {
    /// The AES key type used for decryption.
    type Key = HsmAesKey;

    /// The error type for decryption operations.
    type Error = HsmError;

    /// Decrypts ciphertext using AES-CBC mode.
    ///
    /// This method performs single-shot decryption of data using AES-CBC mode.
    /// If padding is enabled, PKCS#7 padding will be verified and removed automatically.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for decryption
    /// * `ciphertext` - The encrypted data to decrypt
    /// * `plaintext` - Optional buffer to write decrypted data to. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The number of bytes written to plaintext (after padding removal)
    /// * `Err(HsmError::InvalidArgument)` - If padding is invalid or ciphertext is malformed
    /// * `Err(HsmError::BufferTooSmall)` - If the provided plaintext buffer is too small
    ///
    /// # Security
    ///
    /// When padding is enabled, this method validates PKCS#7 padding and returns an error
    /// if the padding is incorrect. This helps detect tampering or corruption.
    fn decrypt(
        &mut self,
        key: &Self::Key,
        ciphertext: &[u8],
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        // check if key can decrypt
        if !key.props().can_decrypt() {
            Err(HsmError::InvalidKey)?;
        }

        //Return error if cipher text is not block aligned, AES Cipher Text should be always block aligned
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(Self::BLOCK_SIZE) {
            return Err(HsmError::InvalidArgument);
        }

        let expected_len = ciphertext.len();

        let Some(plaintext) = plaintext else {
            return Ok(expected_len);
        };
        if plaintext.len() != expected_len {
            return Err(HsmError::BufferTooSmall);
        }
        let len = ddi::aes_cbc_decrypt(key, &mut self.iv, ciphertext, plaintext)?;
        pkcs7_unpad(&plaintext[..len], self.pad)
    }
}

impl HsmDecryptStreamingOp for HsmAesCbcAlgo {
    /// The AES key type used for decryption.
    type Key = HsmAesKey;

    /// The error type for decryption operations.
    type Error = HsmError;

    /// The context type for streaming decryption.
    type Context = HsmAesCbcDecryptContext;

    /// Initializes a streaming AES-CBC decryption operation.
    ///
    /// Creates a decryption context that allows data to be decrypted incrementally
    /// through multiple calls to `update` and a final call to `finish`.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for decryption
    ///
    /// # Returns
    ///
    /// * `Ok(HsmAesCbcDecryptContext)` - An initialized decryption context
    /// * `Err(HsmError)` - If initialization fails
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        // check if key can decrypt
        if !key.props().can_decrypt() {
            Err(HsmError::InvalidKey)?;
        }

        Ok(HsmAesCbcDecryptContext {
            algo: self,
            key,
            block: AesCbcBlock::default(),
        })
    }
}

/// A context for streaming AES-CBC decryption operations.
///
/// This struct maintains the state of an ongoing AES-CBC decryption operation,
/// allowing data to be decrypted incrementally through multiple calls.
pub struct HsmAesCbcDecryptContext {
    /// The AES-CBC algorithm configuration including padding and IV.
    algo: HsmAesCbcAlgo,

    /// The AES key being used for decryption.
    key: HsmAesKey,

    /// Internal block buffer for managing partial blocks during streaming.
    block: AesCbcBlock,
}

impl HsmDecryptContext for HsmAesCbcDecryptContext {
    /// The AES-CBC algorithm for this decryption context.
    type Algo = HsmAesCbcAlgo;

    /// Decrypts a chunk of ciphertext in the streaming operation.
    ///
    /// Processes input data incrementally, buffering incomplete blocks internally.
    /// Only complete blocks are decrypted and output during update calls.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted data to decrypt
    /// * `plaintext` - Optional buffer for decrypted output. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written, or required buffer size if `plaintext` is `None`
    /// * `Err(HsmError::BufferTooSmall)` - If the plaintext buffer is too small
    ///
    /// # Note
    ///
    /// Partial blocks are buffered and will be processed in subsequent `update` calls
    /// or in the final `finish` call. Padding removal happens during finalization.
    fn update(
        &mut self,
        ciphertext: &[u8],
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmDecryptStreamingOp>::Error> {
        let expected_len = self.block.update_len(ciphertext)?;
        let Some(plaintext) = plaintext else {
            return Ok(expected_len);
        };
        if plaintext.len() < expected_len {
            return Err(HsmError::BufferTooSmall);
        }
        let mut offset = 0;
        self.block.update(ciphertext, |input: &[u8]| {
            let written = ddi::aes_cbc_decrypt(
                &self.key,
                &mut self.algo.iv,
                input,
                &mut plaintext[offset..offset + input.len()],
            )?;
            offset += written;
            Ok(written)
        })
    }

    /// Finalizes the streaming decryption operation and produces final plaintext.
    ///
    /// Processes any remaining buffered data and removes PKCS#7 padding if enabled.
    /// After calling this method, the decryption operation is complete.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Optional buffer for final decrypted output. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written (after padding removal)
    /// * `Err(HsmError::InvalidArgument)` - If padding validation fails
    /// * `Err(HsmError::BufferTooSmall)` - If the plaintext buffer is too small
    ///
    /// # Padding Validation
    ///
    /// If padding is enabled, this method validates and removes PKCS#7 padding.
    /// Invalid padding indicates corruption or tampering and will result in an error.
    fn finish(
        &mut self,
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmDecryptStreamingOp>::Error> {
        let expected_len = self.block.finish_len(self.algo.pad)?;
        let Some(plaintext) = plaintext else {
            return Ok(expected_len);
        };
        if plaintext.len() < expected_len {
            return Err(HsmError::BufferTooSmall);
        }
        let len = self.block.finish(|input: &[u8]| {
            // Todo remove padding here.
            ddi::aes_cbc_decrypt(
                &self.key,
                &mut self.algo.iv,
                input,
                &mut plaintext[..input.len()],
            )
        });
        pkcs7_unpad(&plaintext[..len?], self.algo.pad)
    }

    /// Returns a reference to the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `OsslHash` algorithm instance.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// A mutable reference to the `OsslHash` algorithm instance.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// The `OsslHash` algorithm instance.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}

/// Internal block buffer for managing AES-CBC streaming operations.
///
/// This structure provides buffering for partial AES blocks during streaming
/// encryption or decryption operations. AES requires input data to be aligned
/// to 16-byte boundaries, and this buffer manages incomplete blocks until
/// they can be processed.
///
/// # Buffer Management
///
/// - Maintains a 16-byte buffer for incomplete blocks
/// - Automatically processes complete blocks as they become available
/// - Handles boundary conditions between input chunks
///
/// # Memory Efficiency
///
/// The buffer is pre-allocated with the exact capacity needed (16 bytes)
/// to minimize memory allocations during streaming operations.
struct AesCbcBlock {
    /// Internal buffer for storing partial block data.
    ///
    /// This vector has a fixed capacity of 16 bytes (one AES block)
    /// and stores incomplete block data between update operations.
    block: Vec<u8>,
}

/// Default implementation for `AesCbcBlock`.
///
/// Creates a new block buffer with pre-allocated capacity for one AES block (16 bytes).
/// The buffer starts empty but with sufficient capacity to avoid reallocations.
impl Default for AesCbcBlock {
    fn default() -> Self {
        Self {
            block: Vec::with_capacity(Self::BLOCK_SIZE),
        }
    }
}

impl AesCbcBlock {
    /// AES block size in bytes.
    ///
    /// AES always operates on 128-bit (16-byte) blocks regardless of key size.
    const BLOCK_SIZE: usize = HsmAesCbcAlgo::BLOCK_SIZE;

    /// Processes input data with block-level buffering.
    ///
    /// This method handles streaming input data by:
    /// 1. Filling the internal buffer with input data
    /// 2. Processing complete blocks through the provided operation
    /// 3. Keeping partial blocks buffered for the next update
    ///
    /// # Algorithm
    ///
    /// - Fills the internal buffer first if it has space
    /// - Processes the buffered block if it becomes full and more input is available
    /// - Processes as many complete blocks as possible from remaining input
    /// - Keeps the last incomplete block (or one complete block if input ends on boundary)
    /// - Buffers any remaining partial data
    ///
    /// # Arguments
    ///
    /// * `input` - Input data to process
    /// * `op` - Closure that processes complete blocks and returns bytes written
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes processed by the operation
    /// * `Err(HsmError)` - If the block processing operation fails
    ///
    /// # Block Boundary Handling
    ///
    /// This method implements careful boundary handling:
    /// - If input ends exactly on a block boundary, one block is kept buffered
    /// - This ensures proper padding handling during finalization
    /// - Only processes blocks when more input is definitely available
    pub fn update<F>(&mut self, input: &[u8], mut op: F) -> Result<usize, HsmError>
    where
        F: FnMut(&[u8]) -> Result<usize, HsmError>,
    {
        let mut count = 0;
        let avail = self.block.capacity() - self.block.len();
        let fill = &input[..input.len().min(avail)];

        self.block.extend_from_slice(fill);

        let input = &input[fill.len()..];

        // process full block if buffer is full and there is input data
        if self.block.len() == self.block.capacity() && !input.is_empty() {
            count += op(&self.block)?;
            self.block.clear();
        }

        let mut blocks = input.len() / Self::BLOCK_SIZE;
        let tailing = input.len() % Self::BLOCK_SIZE;

        // keep last block in buffer if there is no tailing data
        if tailing == 0 && blocks > 0 {
            blocks -= 1;
        }

        let bytes = blocks * Self::BLOCK_SIZE;
        if bytes > 0 {
            count += op(&input[..bytes])?;
        }

        self.block.extend_from_slice(&input[bytes..]);

        Ok(count)
    }

    /// Calculates the output size for the given input without performing the operation.
    ///
    /// This method mirrors the logic of `update` but only calculates how many
    /// bytes would be processed, without actually performing any cryptographic
    /// operations. This is useful for determining buffer sizes.
    ///
    /// # Arguments
    ///
    /// * `input` - Input data to calculate processing size for
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes that would be processed
    /// * `Err(HsmError)` - Currently unused, maintained for consistency
    pub fn update_len(&self, input: &[u8]) -> Result<usize, HsmError> {
        let mut count = 0;
        let avail = self.block.capacity() - self.block.len();
        let fill = &input[..input.len().min(avail)];
        let input = &input[fill.len()..];

        if self.block.len() + fill.len() == self.block.capacity() && !input.is_empty() {
            count += Self::BLOCK_SIZE;
        }

        let mut blocks = input.len() / Self::BLOCK_SIZE;
        let tailing = input.len() % Self::BLOCK_SIZE;

        // keep last block in buffer if there is no tailing data
        if tailing == 0 && blocks > 0 {
            blocks -= 1;
        }
        count += blocks * Self::BLOCK_SIZE;
        Ok(count)
    }

    /// Returns the output size for finalization.
    ///
    /// This method always returns one block size (16 bytes) as finalization
    /// will process whatever data remains in the buffer, potentially with
    /// padding applied.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Always returns `BLOCK_SIZE` (16 bytes)
    /// * `Err(HsmError)` - Currently unused, maintained for consistency
    pub fn finish_len(&mut self, pad: bool) -> Result<usize, HsmError> {
        if pad {
            if self.block.len() == self.block.capacity() {
                Ok(Self::BLOCK_SIZE * 2)
            } else {
                Ok(Self::BLOCK_SIZE)
            }
        } else {
            if self.block.len() == self.block.capacity() {
                Ok(Self::BLOCK_SIZE)
            } else {
                Err(HsmError::InvalidArgument)
            }
        }
    }

    /// Processes the final buffered data.
    ///
    /// This method processes whatever data remains in the internal buffer
    /// through the provided operation. It's called during finalization to
    /// handle the last block, which may include padding.
    ///
    /// # Arguments
    ///
    /// * `op` - Closure that processes the final block data
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes processed by the operation
    /// * `Err(HsmError)` - If the final processing operation fails
    ///
    /// # Buffer State
    ///
    /// After calling this method, the buffer remains unchanged. The caller
    /// is responsible for any cleanup if needed.
    ///
    /// # Note
    ///
    /// The method name uses `r#final` syntax because `final` is a reserved
    /// keyword in Rust, but we want to maintain API consistency.
    pub fn finish<F>(&mut self, mut op: F) -> Result<usize, HsmError>
    where
        F: FnMut(&[u8]) -> Result<usize, HsmError>,
    {
        op(&self.block)
    }
}

/// Applies PKCS#7 padding to data.
///
/// PKCS#7 padding adds bytes to the end of data to align it to block boundaries.
/// Each padding byte contains the value of the padding length.
///
/// # Arguments
///
/// * `data` - The data to pad
/// * `pad` - Whether to apply padding. If `false`, returns an empty vector.
///
/// # Returns
///
/// A vector containing the padding bytes to append to the data.
///
/// # Padding Rules
///
/// - If data length is already block-aligned, adds a full block of padding (16 bytes of value 0x00)
/// - Otherwise, adds `n` bytes of value `n`, where `n` is the number of bytes needed
/// - Example: For 14 bytes of data, adds 2 bytes of value 0x02
///
/// # PKCS#7 Standard
///
/// This follows RFC 5652 Section 6.3 for content encryption padding.
/// The padding ensures unambiguous removal during decryption.
fn pkcs7_pad(data: &[u8], pad: bool) -> Vec<u8> {
    if !pad {
        return vec![];
    }

    let pad_len = HsmAesCbcAlgo::BLOCK_SIZE - (data.len() % HsmAesCbcAlgo::BLOCK_SIZE);
    if pad_len == 0 {
        vec![HsmAesCbcAlgo::BLOCK_SIZE as u8; HsmAesCbcAlgo::BLOCK_SIZE]
    } else {
        vec![pad_len as u8; pad_len]
    }
}

/// Validates and removes PKCS#7 padding from data.
///
/// Verifies that the padding is valid according to PKCS#7 rules and returns
/// the length of the actual data (excluding padding).
///
/// # Arguments
///
/// * `data` - The padded data to validate and unpad
/// * `pad` - Whether padding should be validated and removed. If `false`, returns data length unchanged.
///
/// # Returns
///
/// * `Ok(usize)` - The length of data without padding
/// * `Err(HsmError::InvalidArgument)` - If padding is invalid
///
/// # Validation
///
/// The function validates that:
/// - The last byte value is between 0 (representing 16) and 15
/// - All padding bytes have the same value
/// - The padding length matches the value of the padding bytes
///
/// # Errors
///
/// Returns an error if:
/// - Padding byte value is greater than 15 (invalid for AES)
/// - Not all padding bytes match the expected value
/// - This indicates data corruption or tampering
///
/// # Security
///
/// Proper padding validation is critical for security. Invalid padding
/// may indicate a padding oracle attack or data corruption.
fn pkcs7_unpad(data: &[u8], pad: bool) -> HsmResult<usize> {
    if !pad {
        return Ok(data.len());
    }

    let pad_byte = data[data.len() - 1];

    let pad_len = match pad_byte {
        1..=16 => pad_byte as usize,
        _ => Err(HsmError::InternalError)?,
    };

    let padding = &data[data.len() - pad_len..];
    for b in padding {
        if *b != pad_byte {
            return Err(HsmError::InternalError);
        }
    }

    Ok(data.len() - pad_len)
}
