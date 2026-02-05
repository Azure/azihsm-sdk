// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA-PSS (Probabilistic Signature Scheme) padding implementation.
//!
//! This module implements the PSS padding scheme for RSA signatures as specified
//! in RFC 8017 (PKCS #1 v2.2). PSS is a provably secure padding scheme that provides
//! better security guarantees than the older PKCS#1 v1.5 signature padding.
//!
//! # PSS Overview
//!
//! PSS padding uses a hash function and a mask generation function (MGF1) to create
//! probabilistic padding that includes:
//! - A hash of the message
//! - A random salt value
//! - Padding bits
//! - A mask generated using MGF1
//!
//! The randomness provided by the salt makes signatures non-deterministic, providing
//! additional security properties.
//!
//! # Security
//!
//! PSS is considered more secure than PKCS#1 v1.5 signature padding because:
//! - It has a security proof in the random oracle model
//! - The randomness prevents certain signature attacks
//! - It's resistant to existential forgery under chosen message attacks
//!
//! # RFC 8017 References
//!
//! - Section 8.1: PSS signature scheme description
//! - Section 9.1: EMSA-PSS encoding operation
//! - Appendix B.2.1: MGF1 mask generation function

use super::*;

/// RSA-PSS padding algorithm with MGF1 mask generation.
///
/// This structure represents a PSS padding operation for RSA signatures.
/// It encapsulates the parameters needed for PSS encoding and decoding,
/// including the modulus size, hash algorithm, message digest, and salt length.
///
/// PSS (Probabilistic Signature Scheme) provides enhanced security over
/// deterministic padding schemes by incorporating randomness through a salt value.
///
/// # Fields
///
/// - `modulus_size`: RSA key modulus size in bytes (typically 256, 384, or 512)
/// - `hash_algo`: Hash algorithm for both message hashing and MGF1
/// - `digest`: The message digest to be padded
/// - `salt_length`: Length of the random salt in bytes
pub struct RsaPadPssAlgo {
    /// The size of the RSA modulus in bytes (256, 384, or 512).
    modulus_size: usize,
    /// The hash algorithm identifier for the DigestInfo structure.
    hash_algo: HashAlgo,
    /// The message digest (hash) to be padded.
    hash: Vec<u8>,
    /// The length of the salt to use in the PSS padding.
    salt_len: usize,
}

impl RsaPadPssAlgo {
    /// Creates a new PSS padding algorithm instance with MGF1.
    ///
    /// Initializes a PSS padding algorithm that uses MGF1 (Mask Generation Function 1)
    /// as the mask generation function. The same hash algorithm is used for both
    /// the message digest and MGF1.
    ///
    /// # Arguments
    ///
    /// * `modulus_size` - Size of the RSA modulus in bytes (256, 384, or 512)
    /// * `hash_algo` - Hash algorithm to use for PSS operations
    /// * `digest` - Message digest (hash) to be padded
    /// * `salt_length` - Length of the random salt in bytes
    ///
    /// # Returns
    ///
    /// A new `RsaPadPssAlgo` instance configured with the specified parameters.
    pub fn with_mgf1(
        modulus_size: usize,
        hash_algo: HashAlgo,
        digest: &[u8],
        salt_length: usize,
    ) -> Self {
        Self {
            modulus_size,
            hash_algo,
            hash: digest.to_vec(),
            salt_len: salt_length,
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

    /// Returns the message digest bytes.
    ///
    /// # Returns
    ///
    /// A slice containing the digest bytes.
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    /// Returns a reference to the hash algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `HashAlgo` instance.
    pub fn hash_algo(&self) -> &HashAlgo {
        &self.hash_algo
    }

    /// Returns the salt length in bytes.
    ///
    /// The salt length determines how many random bytes are incorporated
    /// into the PSS padding. Common choices are the hash length or zero
    /// for deterministic signatures.
    ///
    /// # Returns
    ///
    /// The salt length in bytes.
    pub fn salt_len(&self) -> usize {
        self.salt_len
    }
}

/// Parameters for RSA signature padding operations.
///
/// This structure holds the parameters needed for signature padding
/// operations, including both PSS and PKCS#1 v1.5 schemes. It specifies
/// the RSA key size and hash algorithm to use.
///
/// # Note
///
/// Despite the name suggesting PKCS#1 only, this type is used for both
/// PKCS#1 v1.5 and PSS padding parameter specification.
pub struct RsaPadPssAlgoParams {
    /// The size of the RSA modulus in bytes (256, 384, or 512).
    modulus_size: usize,
    /// The hash algorithm used to produce the digest.
    hash_algo: HashAlgo,
    /// The message digest (hash) to be padded.
    hash: Vec<u8>,
}

impl RsaPadPssAlgoParams {
    /// Creates new signature padding parameters.
    ///
    /// # Arguments
    ///
    /// * `modulus_size` - Size of the RSA modulus in bytes (256, 384, or 512)
    /// * `hash_algo` - Hash algorithm to use for the signature operation
    ///
    /// # Returns
    ///
    /// A new `RsaPkcs1SignPadParams` instance.
    pub fn new(modulus_size: usize, hash_algo: HashAlgo, hash: &[u8]) -> Self {
        Self {
            modulus_size,
            hash_algo,
            hash: hash.to_vec(),
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

    /// Returns a reference to the hash algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `HashAlgo` instance.
    pub fn hash_algo(&self) -> &HashAlgo {
        &self.hash_algo
    }

    /// Returns the message digest bytes.
    ///
    /// # Returns
    ///
    /// A slice containing the digest bytes.
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }
}

/// Implements PSS encoding operation.
///
/// This implementation encodes a message digest using the PSS padding scheme,
/// producing padded output suitable for RSA signature generation.
///
/// The implementation works in-place using the output buffer to minimize allocations.
impl EncodeOp for RsaPadPssAlgo {
    fn to_bytes(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        // RFC 8017 Section 9.1.1: EMSA-PSS-ENCODE (M, emBits)
        let h_len = self.hash_algo.size();
        let s_len = self.salt_len;

        // Validate digest length matches hash algorithm
        if self.hash.len() != h_len {
            return Err(CryptoError::RsaMessageTooLong);
        }

        // Calculate encoded message length
        // emLen = ceil((modBits - 1)/8) where modBits = modulus_size * 8
        let em_len = self.modulus_size;

        // Check if emLen < hLen + sLen + 2
        if em_len < h_len + s_len + 2 {
            return Err(CryptoError::RsaMessageTooLong);
        }

        // If output is None, just return the required size
        let Some(output) = output else {
            return Ok(em_len);
        };

        if output.len() < em_len {
            return Err(CryptoError::RsaBufferTooSmall);
        }

        let ps_len = em_len - s_len - h_len - 2;
        let db_len = em_len - h_len - 1;

        // Initialize output with DB = PS || 0x01 || salt
        // First, zero out the PS portion (padding string)
        output[..ps_len].fill(0);
        // Add the 0x01 separator byte
        output[ps_len] = 0x01;
        // Generate random salt directly in the output buffer
        if s_len > 0 {
            Rng::rand_bytes(&mut output[ps_len + 1..ps_len + 1 + s_len])?;
        }
        // Set the trailer byte 0xbc at the end
        output[em_len - 1] = 0xbc;

        // Now compute H = Hash(M') where M' = 00..00 || mHash || salt
        // We need to hash: 8 zero bytes || digest || salt
        // The salt is already in output[ps_len + 1..ps_len + 1 + s_len]
        let mut hasher = self.hash_algo.clone().hash_init()?;
        hasher.update(&[0u8; 8])?; // 8 zero bytes
        hasher.update(&self.hash)?; // mHash
        if s_len > 0 {
            hasher.update(&output[ps_len + 1..ps_len + 1 + s_len])?; // salt
        }

        // Write H directly to its final position in output: output[db_len..db_len + h_len]
        hasher.finish(Some(&mut output[db_len..db_len + h_len]))?;

        // Now apply MGF1 to mask DB using H as the seed
        // dbMask = MGF1(H, db_len), then maskedDB = DB XOR dbMask
        // mgf1_xor applies the mask in-place by XORing
        let (db, hash) = output.split_at_mut(db_len);
        mgf1_xor(&self.hash_algo, &hash[..h_len], db)?;

        // Set the leftmost 8*emLen - emBits bits to zero
        // Since emBits = modBits - 1 = modulus_size*8 - 1, we need to clear 1 bit
        output[0] &= 0x7F; // Clear the leftmost bit

        // Output now contains: maskedDB || H || 0xbc
        Ok(em_len)
    }
}

/// Implements PSS decoding operation.
///
/// This implementation decodes PSS-padded data during signature verification,
/// extracting and validating the message digest and salt.
impl DecodeOp for RsaPadPssAlgo {
    type T = RsaPadPssAlgo;
    type P = RsaPadPssAlgoParams;

    fn from_bytes(input: &[u8], params: Self::P) -> Result<Self::T, CryptoError> {
        // RFC 8017 Section 9.1.2: EMSA-PSS-VERIFY (M, EM, emBits)
        let modulus_size = params.modulus_size();
        let hash_algo = params.hash_algo();
        let m_hash = params.hash();
        let h_len = hash_algo.size();

        // Validate message hash length matches hash algorithm
        if m_hash.len() != h_len {
            return Err(CryptoError::RsaInvalidPadding);
        }

        // Calculate expected encoded message length
        let em_len = modulus_size;

        // Verify input length
        if input.len() != em_len {
            return Err(CryptoError::RsaInvalidPadding);
        }

        // Check if emLen < hLen + 2 (minimum size check)
        if em_len < h_len + 2 {
            return Err(CryptoError::RsaInvalidPadding);
        }

        // Check if rightmost octet is 0xbc
        if input[em_len - 1] != 0xbc {
            return Err(CryptoError::RsaInvalidPadding);
        }

        let db_len = em_len - h_len - 1;

        // Split input: maskedDB || H || 0xbc
        let masked_db = &input[..db_len];
        let h = &input[db_len..db_len + h_len];

        // Check if the leftmost bit of the leftmost octet is 0
        // (emBits = modBits - 1, so we need the MSB to be 0)
        if (masked_db[0] & 0x80) != 0 {
            return Err(CryptoError::RsaInvalidPadding);
        }

        // Unmask DB: DB = maskedDB XOR MGF(H, emLen - hLen - 1)
        let mut db = masked_db.to_vec();
        mgf1_xor(hash_algo, h, &mut db)?;

        // Set the leftmost bit to zero
        db[0] &= 0x7F;

        // Parse DB = PS || 0x01 || salt
        // Find the 0x01 separator byte
        let separator_pos = db.iter().position(|&b| b != 0x00);

        let Some(separator_pos) = separator_pos else {
            // No non-zero byte found
            return Err(CryptoError::RsaInvalidPadding);
        };

        // The separator must be 0x01
        if db[separator_pos] != 0x01 {
            return Err(CryptoError::RsaInvalidPadding);
        }

        // Extract salt (everything after 0x01)
        let salt = &db[separator_pos + 1..];
        let salt_len = salt.len();

        // Check if emLen < hLen + sLen + 2
        if em_len < h_len + salt_len + 2 {
            return Err(CryptoError::RsaInvalidPadding);
        }

        // Compute M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
        // Then compute H' = Hash(M') and compare it to H
        let mut hasher = hash_algo.clone().hash_init()?;
        hasher.update(&[0u8; 8])?; // 8 zero bytes
        hasher.update(m_hash)?; // mHash from params
        hasher.update(salt)?; // extracted salt

        let mut h_prime = vec![0u8; h_len];
        hasher.finish(Some(&mut h_prime))?;

        // Verify that H' == H (constant-time comparison would be better)
        if h_prime != h {
            return Err(CryptoError::RsaInvalidPadding);
        }

        // Verification successful - return the algorithm instance
        Ok(Self::T {
            modulus_size,
            hash_algo: params.hash_algo,
            hash: params.hash,
            salt_len,
        })
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
