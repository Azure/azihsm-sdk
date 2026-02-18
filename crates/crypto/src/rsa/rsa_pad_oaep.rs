// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA OAEP (Optimal Asymmetric Encryption Padding) implementation.
//!
//! This module implements the OAEP padding scheme as specified in RFC 8017 Section 7.1.
//! OAEP provides semantic security for RSA encryption and protection against various
//! attacks including chosen-ciphertext attacks.
//!
//! # OAEP Padding Format
//!
//! The padded message has the following structure:
//! ```text
//! EM = 0x00 || maskedSeed || maskedDB
//! ```
//!
//! Where:
//! - `0x00`: Leading zero byte
//! - `maskedSeed`: seed XOR MGF(DB, hLen)
//! - `maskedDB`: DB XOR MGF(seed, k - hLen - 1)
//! - `DB = lHash || PS || 0x01 || M`
//! - `lHash`: Hash of the optional label parameter L
//! - `PS`: Padding string of zeros
//! - `M`: The original message
//!
//! # Supported Key Sizes
//!
//! This implementation supports the following RSA modulus sizes:
//! - 2048 bits (256 bytes)
//! - 3072 bits (384 bytes)
//! - 4096 bits (512 bytes)
//!
//! # Security
//!
//! OAEP is the recommended padding scheme for RSA encryption in modern applications.
//! It provides semantic security and protects against padding oracle attacks, unlike
//! the legacy PKCS#1 v1.5 padding.
//!
//! Use SHA-256 or stronger hash algorithms for the hash function and MGF1.

use super::*;
use crate::HashAlgo;

/// RSA OAEP padding algorithm implementation.
///
/// This struct encapsulates the OAEP (Optimal Asymmetric Encryption Padding) scheme
/// for RSA encryption, which provides semantic security through randomized padding
/// and protection against various cryptographic attacks.
///
/// # Security
///
/// OAEP is the recommended padding scheme for RSA encryption in modern applications.
/// It provides:
/// - Semantic security (probabilistic encryption)
/// - Protection against chosen-ciphertext attacks
/// - Resistance to padding oracle attacks
///
/// # Components
///
/// - **Hash Algorithm**: Used for both the hash function and MGF1
/// - **Label**: Optional domain separation parameter (typically empty)
/// - **MGF1**: Mask Generation Function based on hash algorithm
pub struct RsaPadOaepAlgo {
    /// The size of the RSA modulus in bytes (256, 384, or 512).
    modulus_size: usize,
    /// The hash algorithm used for OAEP padding.
    hash_algo: HashAlgo,
    /// Optional label for domain separation (typically empty).
    label: Option<Vec<u8>>,
    /// The message to be padded or the extracted message after unpadding.
    message: Vec<u8>,
}

/// Parameters for OAEP padding decoding operations.
///
/// This struct holds the configuration parameters needed to decode an OAEP-padded
/// message. The same parameters used for encoding must be provided for decoding
/// to succeed.
///
/// # Fields
///
/// - `modulus_size`: The RSA key modulus size in bytes
/// - `hash_algo`: The hash algorithm instance (must match encoding)
/// - `label`: Optional label parameter (must match encoding, typically empty)
pub struct RsaPadOaepAlgoParams {
    modulus_size: usize,
    hash_algo: HashAlgo,
    label: Option<Vec<u8>>,
}

impl RsaPadOaepAlgo {
    /// Creates a new OAEP padding algorithm instance.
    ///
    /// # Arguments
    ///
    /// * `modulus_size` - The size of the RSA modulus in bytes (must be 256, 384, or 512)
    /// * `hash_algo` - The hash algorithm to use for OAEP padding
    /// * `message` - The message to be padded (for encoding) or the extracted message (for decoding)
    ///
    /// # Returns
    ///
    /// A new `RsaPadOaepAlgo` instance.
    pub fn with_mgf1(
        modulus_size: usize,
        hash_algo: HashAlgo,
        label: Option<&[u8]>,
        message: &[u8],
    ) -> Self {
        RsaPadOaepAlgo {
            modulus_size,
            hash_algo,
            label: label.map(|l| l.to_vec()),
            message: message.to_vec(),
        }
    }

    /// Returns the RSA modulus size in bytes.
    ///
    /// # Returns
    ///
    /// The modulus size (256, 384, or 512 bytes).
    pub fn modulus_size(&self) -> usize {
        self.modulus_size
    }

    /// Returns the message bytes.
    ///
    /// For encoding operations, this is the plaintext message to be padded.
    /// For decoding operations, this is the extracted message after unpadding.
    ///
    /// # Returns
    ///
    /// A slice containing the message bytes.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Returns a mutable reference to the message bytes.
    ///
    /// # Returns
    ///
    /// A mutable slice containing the message bytes.
    pub fn message_mut(&mut self) -> &mut [u8] {
        &mut self.message
    }

    /// Returns the optional label parameter.
    ///
    /// # Returns
    ///
    /// An optional slice containing the label bytes, or `None` if no label was specified.
    pub fn label(&self) -> Option<&[u8]> {
        self.label.as_deref()
    }

    /// Returns a reference to the hash algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `HashAlgo` instance used for OAEP padding.
    pub fn hash_algo(&self) -> &HashAlgo {
        &self.hash_algo
    }
}

impl RsaPadOaepAlgoParams {
    /// Creates a new OAEP padding parameters instance.
    ///
    /// # Arguments
    ///
    /// * `modulus_size` - The size of the RSA modulus in bytes (must be 256, 384, or 512)
    /// * `hash_algo` - The hash algorithm to use for OAEP padding
    /// * `label` - Optional label for OAEP padding
    ///
    /// # Returns
    ///
    /// A new `RsaPadOaepParams` instance.
    pub fn new(modulus_size: usize, hash_algo: HashAlgo, label: Option<&[u8]>) -> Self {
        RsaPadOaepAlgoParams {
            modulus_size,
            hash_algo,
            label: label.map(|l| l.to_vec()),
        }
    }

    /// Returns the RSA modulus size in bytes.
    ///
    /// # Returns
    ///
    /// The modulus size (256, 384, or 512 bytes).
    pub fn modulus_size(&self) -> usize {
        self.modulus_size
    }

    /// Returns the optional label parameter.
    ///
    /// # Returns
    ///
    /// An optional slice containing the label bytes, or `None` if no label was specified.
    pub fn label(&self) -> Option<&[u8]> {
        self.label.as_deref()
    }

    /// Returns a reference to the hash algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `HashAlgo` instance used for OAEP padding.
    pub fn hash_algo(&self) -> &HashAlgo {
        &self.hash_algo
    }
}

impl EncodeOp for RsaPadOaepAlgo {
    /// Applies OAEP padding to the message.
    ///
    /// This function implements the EME-OAEP-ENCODE operation from RFC 8017 Section 7.1.1.
    /// It uses an in-place algorithm with MGF1 to minimize memory allocations.
    ///
    /// # Algorithm
    ///
    /// 1. Compute lHash = Hash(label)
    /// 2. Build DB = lHash || PS || 0x01 || M (where PS is zero padding)
    /// 3. Generate random seed
    /// 4. Compute maskedDB = DB XOR MGF(seed, dbLen)
    /// 5. Compute maskedSeed = seed XOR MGF(maskedDB, hLen)
    /// 6. Return EM = 0x00 || maskedSeed || maskedDB
    ///
    /// # Arguments
    ///
    /// * `output` - Optional mutable buffer to write the padded message to.
    ///   If `None`, only the required output length is returned.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The length of the padded message (equal to `modulus_size`)
    /// * `Err(CryptoError::RsaUnsupportedModulusSize)` - If the modulus size is not 256, 384, or 512
    /// * `Err(CryptoError::RsaMessageTooLong)` - If the message is too long for the given key size
    ///   (message length must be at most `modulus_size - 2*hLen - 2`)
    /// * `Err(CryptoError::RsaBufferTooSmall)` - If the output buffer is too small
    /// * `Err(CryptoError::RngError)` - If random number generation fails
    /// * `Err(CryptoError::HashError)` - If hash computation fails
    ///
    /// # Security
    ///
    /// The random seed ensures that each encryption of the same message produces
    /// a different ciphertext, providing semantic security.
    fn to_bytes(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let k = self.modulus_size;

        // Validate modulus size
        if !matches!(k, 256 | 384 | 512) {
            return Err(CryptoError::RsaUnsupportedModulusSize);
        }

        let h_len = self.hash_algo.size();
        let m_len = self.message.len();

        // Check message length: mLen <= k - 2*hLen - 2
        if m_len > k - 2 * h_len - 2 {
            return Err(CryptoError::RsaMessageTooLong);
        }

        let em_len = k;

        if let Some(output) = output {
            if output.len() < em_len {
                return Err(CryptoError::RsaBufferTooSmall);
            }

            // Step 1: Initialize EM to all zeroes
            let em = &mut output[0..em_len];
            em.fill(0);

            let (seed, db) = em[1..].split_at_mut(h_len);

            // Step 2: Build DB = lHash || PS || 0x01 || M
            let db_len = k - h_len - 1;
            let ps_len = db_len - h_len - m_len - 1;
            let label = self.label.as_deref().unwrap_or(&[]);
            Hasher::hash(&mut self.hash_algo, label, Some(&mut db[0..h_len]))?;
            db[h_len + ps_len] = 0x01;
            db[(h_len + ps_len + 1)..].copy_from_slice(&self.message);

            // Step 3: Generate random seed
            // let seed = &mut em[1..(1 + h_len)];
            Rng::rand_bytes(seed)?;

            // Step 4: Compute maskedDB = DB XOR MGF(seed, db_len)
            mgf1_xor(&self.hash_algo, seed, db)?;

            // Step 5: Compute maskedSeed = seed XOR MGF(maskedDB, h_len)
            mgf1_xor(&self.hash_algo, db, seed)?;
        }

        Ok(em_len)
    }
}

impl DecodeOp for RsaPadOaepAlgo {
    type T = RsaPadOaepAlgo;
    type P = RsaPadOaepAlgoParams;

    /// Removes OAEP padding from a padded message.
    ///
    /// This function implements the EME-OAEP-DECODE operation from RFC 8017 Section 7.1.2.
    /// It validates the padding structure and extracts the original message using in-place
    /// operations with MGF1.
    ///
    /// # Algorithm
    ///
    /// 1. Parse EM = Y || maskedSeed || maskedDB
    /// 2. Recover seed = maskedSeed XOR MGF(maskedDB, hLen)
    /// 3. Recover DB = maskedDB XOR MGF(seed, k - hLen - 1)
    /// 4. Parse DB = lHash' || PS || 0x01 || M
    /// 5. Verify lHash' = Hash(label)
    /// 6. Verify padding structure and return M
    ///
    /// # Arguments
    ///
    /// * `input` - The padded message to decode (must be 256, 384, or 512 bytes)
    /// * `params` - The OAEP parameters (modulus size, hash algorithm, label)
    ///
    /// # Returns
    ///
    /// * `Ok(RsaPadOaepAlgo)` - The decoded message wrapped in a new instance
    /// * `Err(CryptoError::RsaUnsupportedModulusSize)` - If the input length is not 256, 384, or 512
    /// * `Err(CryptoError::RsaInvalidPadding)` - If the padding format is invalid, including:
    ///   - First byte is not 0x00
    ///   - lHash verification fails
    ///   - No 0x01 separator found
    ///   - Invalid padding structure
    ///
    /// # Security Note
    ///
    /// This implementation attempts to perform constant-time validation where possible
    /// to mitigate padding oracle attacks.
    fn from_bytes(input: &[u8], mut params: Self::P) -> Result<Self::T, CryptoError> {
        let k = params.modulus_size;

        // Validate modulus size
        if !matches!(k, 256 | 384 | 512) {
            return Err(CryptoError::RsaUnsupportedModulusSize);
        }

        if input.len() != k {
            return Err(CryptoError::RsaInvalidPadding);
        }

        let mut em = input.to_vec();
        let hash_algo = &mut params.hash_algo;
        let h_len = hash_algo.size();

        // Check that we have enough space for the minimum OAEP structure
        if k < 2 * h_len + 2 {
            return Err(CryptoError::RsaInvalidPadding);
        }

        // Step 1: Check first byte should be 0x00
        if em[0] != 0x00 {
            return Err(CryptoError::RsaInvalidPadding);
        }

        // Step 2: Recover seed = maskedSeed XOR MGF(maskedDB, hLen)
        // em[1..1+h_len] contains maskedSeed
        // em[1+h_len..] contains maskedDB
        let (seed, db) = em[1..].split_at_mut(h_len);

        // XOR maskedSeed with MGF(maskedDB) to get seed in-place
        mgf1_xor(hash_algo, db, seed)?;

        // Step 3: Recover DB = maskedDB XOR MGF(seed, db_len)
        // Now em[1..1+h_len] contains seed
        // XOR maskedDB with MGF(seed) to get DB in-place
        mgf1_xor(hash_algo, seed, db)?;

        // Step 4: Parse DB = lHash' || PS || 0x01 || M

        // Compute expected lHash
        let mut expected_lhash = vec![0u8; h_len];
        let label = params.label.as_deref().unwrap_or(&[]);
        Hasher::hash(hash_algo, label, Some(&mut expected_lhash))?;

        let (actual_lhash, ps) = db.split_at(h_len);

        // Verify lHash' matches expected lHash
        if expected_lhash != actual_lhash {
            return Err(CryptoError::RsaInvalidPadding);
        }

        // Find the fist non-zero byte in PS
        let pos = ps
            .iter()
            .position(|&b| b != 0x00)
            .ok_or(CryptoError::RsaInvalidPadding)?;

        if ps[pos] != 0x01 {
            return Err(CryptoError::RsaInvalidPadding);
        }

        Ok(RsaPadOaepAlgo::with_mgf1(
            params.modulus_size,
            params.hash_algo,
            params.label.as_deref(),
            &ps[pos + 1..],
        ))
    }
}

/// MGF1 (Mask Generation Function 1) with in-place XOR operation.
///
/// This function implements MGF1 as specified in RFC 8017 Appendix B.2.1,
/// with an optimization that XORs the generated mask directly into the target
/// buffer, avoiding temporary allocations.
///
/// # Algorithm
///
/// For each counter value i from 0 to ceil(maskLen / hLen) - 1:
/// 1. Compute Hash(seed || C) where C is i encoded as 4-byte big-endian
/// 2. XOR the hash output with the corresponding portion of the mask
///
/// # Arguments
///
/// * `hash_algo` - The hash algorithm to use for MGF1
/// * `seed` - The seed input for mask generation
/// * `mask` - The target buffer to XOR with the generated mask
///
/// # Returns
///
/// * `Ok(())` - If mask generation and XOR succeeds
/// * `Err(CryptoError)` - If hash operations fail
///
/// # Performance
///
/// This in-place variant minimizes memory allocations by reusing hash buffers
/// across iterations and XORing directly into the target buffer.
fn mgf1_xor(hash_algo: &HashAlgo, seed: &[u8], mut mask: &mut [u8]) -> Result<(), CryptoError> {
    let mut hash_algo = hash_algo.clone();
    let h_len = hash_algo.size();
    let mut hash = vec![0u8; h_len];
    let mut counter = 0u32;

    while !mask.is_empty() {
        let Some((first, rest)) = mask.split_at_mut_checked(std::cmp::min(h_len, mask.len()))
        else {
            break;
        };

        let mut hasher = hash_algo.hash_init()?;
        hasher.update(seed)?;
        hasher.update(&counter.to_be_bytes())?;
        hasher.finish(Some(&mut hash))?;
        for (x, y) in first.iter_mut().zip(hash.iter()) {
            *x ^= *y;
        }
        hash_algo = hasher.into_algo();
        counter = counter.wrapping_add(1);
        mask = rest;
    }

    Ok(())
}
