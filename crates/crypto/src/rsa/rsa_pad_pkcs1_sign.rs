// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//! RSA PKCS#1 v1.5 signature padding implementation.
//!
//! This module implements the PKCS#1 v1.5 signature padding scheme as specified in
//! RFC 8017 Section 9.2. It provides encoding and decoding operations for RSA
//! signatures with proper padding.
//!
//! # PKCS#1 v1.5 Signature Padding Format
//!
//! The padded message has the following structure:
//! ```text
//! EM = 0x00 || 0x01 || PS || 0x00 || T
//! ```
//!
//! Where:
//! - `0x00`: Initial zero byte
//! - `0x01`: Block type for signing
//! - `PS`: Padding string of 0xFF bytes (at least 8 bytes)
//! - `0x00`: Separator byte
//! - `T`: DigestInfo structure containing the hash algorithm OID and hash value
//!
//! # DigestInfo Structure
//!
//! The DigestInfo is a DER-encoded structure:
//! ```text
//! DigestInfo ::= SEQUENCE {
//!     digestAlgorithm AlgorithmIdentifier,
//!     digest OCTET STRING
//! }
//! ```
//!
//! # Supported Key Sizes
//!
//! This implementation supports the following RSA modulus sizes:
//! - 2048 bits (256 bytes)
//! - 3072 bits (384 bytes)
//! - 4096 bits (512 bytes)
//!
//! # Security Note
//!
//! While PKCS#1 v1.5 signatures are still widely used and considered secure for
//! signature verification, RSA-PSS is recommended for new applications as it
//! provides provable security properties.

use super::*;

/// RSA PKCS#1 v1.5 signature padding algorithm.
///
/// This struct encapsulates the PKCS#1 v1.5 padding scheme for RSA signatures,
/// which adds deterministic padding to hashed messages before signing.
///
/// # Security Note
///
/// PKCS#1 v1.5 signature padding is still considered secure for signatures
/// (unlike encryption padding). However, RSA-PSS is recommended for new
/// applications as it provides stronger security guarantees.
pub struct RsaPadPkcs1SignAlgo {
    /// The size of the RSA modulus in bytes (256, 384, or 512).
    modulus_size: usize,
    /// The hash algorithm identifier for the DigestInfo structure.
    hash_algo: HashAlgo,
    /// The message digest (hash) to be padded.
    digest: Vec<u8>,
}

impl RsaPadPkcs1SignAlgo {
    /// Creates a new PKCS#1 v1.5 signature padding algorithm instance.
    ///
    /// # Arguments
    ///
    /// * `modulus_size` - The size of the RSA modulus in bytes (must be 256, 384, or 512)
    /// * `hash_algo` - The hash algorithm used to produce the digest
    /// * `digest` - The message digest (hash value) to be padded
    ///
    /// # Returns
    ///
    /// A new `RsaPkcs1SignPadAlgo` instance.
    pub fn new(modulus_size: usize, hash_algo: HashAlgo, digest: &[u8]) -> Self {
        Self {
            modulus_size,
            hash_algo,
            digest: digest.to_vec(),
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
        &self.digest
    }

    /// Returns a mutable reference to the digest bytes.
    ///
    /// # Returns
    ///
    /// A mutable slice containing the digest bytes.
    pub fn digest_mut(&mut self) -> &mut [u8] {
        &mut self.digest
    }

    /// Returns a reference to the hash algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `HashAlgo` instance.
    pub fn hash_algo(&self) -> &HashAlgo {
        &self.hash_algo
    }
}

/// Parameters for PKCS#1 v1.5 signature padding decoding.
///
/// This struct holds the configuration parameters needed to decode a PKCS#1 v1.5
/// signature-padded message. The same parameters used for encoding should be
/// provided for decoding to succeed.
pub struct RsaPadPkcs1SignAlgoParams {
    /// The size of the RSA modulus in bytes (256, 384, or 512).
    modulus_size: usize,
    /// The hash algorithm used to produce the digest.
    hash_algo: HashAlgo,
}

impl RsaPadPkcs1SignAlgoParams {
    /// Creates new PKCS#1 v1.5 signature padding parameters.
    ///
    /// # Arguments
    ///
    /// * `modulus_size` - The size of the RSA modulus in bytes (must be 256, 384, or 512)
    /// * `hash_algo` - The hash algorithm used to produce the digest
    ///
    /// # Returns
    ///
    /// A new `RsaPkcs1SignPadParams` instance.
    pub fn new(modulus_size: usize, hash_algo: HashAlgo) -> Self {
        Self {
            modulus_size,
            hash_algo,
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
}

impl EncodeOp for RsaPadPkcs1SignAlgo {
    /// Applies PKCS#1 v1.5 signature padding to the digest.
    ///
    /// This function implements the EMSA-PKCS1-v1_5-ENCODE operation from RFC 8017.
    /// It constructs a padded message with the format:
    /// `EM = 0x00 || 0x01 || PS || 0x00 || T`
    ///
    /// Where T is the DER-encoded DigestInfo structure.
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
    /// * `Err(CryptoError::RsaMessageTooLong)` - If the DigestInfo is too long for the given key size
    /// * `Err(CryptoError::RsaBufferTooSmall)` - If the output buffer is too small
    ///
    /// # Security
    ///
    /// The padding string (PS) consists of 0xFF bytes, making the padding deterministic.
    /// This is appropriate for signatures where determinism is desired.
    fn to_bytes(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let k = self.modulus_size;
        let Some(em) = output else { return Ok(k) };

        if em.len() != k {
            return Err(CryptoError::RsaBufferTooSmall);
        }

        let digest_info = DerDigestInfo::new(self.hash_algo.der_algo(), &self.digest)?;
        let der = digest_info.to_der_vec()?;

        // copy to end of the em buffer
        let t_len = der.len();
        if t_len > k - 3 - 8 {
            return Err(CryptoError::RsaMessageTooLong);
        }

        let start = k - t_len;

        em.fill(0xFF);
        em[0] = 0x00;
        em[1] = 0x01;
        em[start - 1] = 0x00;
        em[start..].copy_from_slice(&der);

        Ok(k)
    }
}

impl DecodeOp for RsaPadPkcs1SignAlgo {
    type T = RsaPadPkcs1SignAlgo;
    type P = RsaPadPkcs1SignAlgoParams;

    /// Removes PKCS#1 v1.5 signature padding from a padded message.
    ///
    /// This function implements the reverse of EMSA-PKCS1-v1_5-ENCODE from RFC 8017.
    /// It validates the padding structure and extracts the DigestInfo.
    ///
    /// # Arguments
    ///
    /// * `input` - The padded message to decode (must be 256, 384, or 512 bytes)
    /// * `params` - The padding parameters (modulus size)
    ///
    /// # Returns
    ///
    /// * `Ok(RsaPkcs1SignPadAlgo)` - The decoded digest wrapped in a new instance
    /// * `Err(CryptoError::RsaUnsupportedModulusSize)` - If the input length is not 256, 384, or 512
    /// * `Err(CryptoError::RsaInvalidPadding)` - If the padding format is invalid, including:
    ///   - First byte is not 0x00
    ///   - Second byte is not 0x01
    ///   - Padding string is less than 8 bytes
    ///   - Padding contains non-0xFF bytes
    ///   - No 0x00 separator byte found
    ///   - DigestInfo structure is invalid
    fn from_bytes(input: &[u8], params: Self::P) -> Result<Self::T, CryptoError> {
        let k = params.modulus_size;

        if input.len() != k {
            return Err(CryptoError::RsaUnsupportedModulusSize);
        }

        if input[0] != 0x00 || input[1] != 0x01 {
            return Err(CryptoError::RsaInvalidPadding);
        }

        // Find the 0x00 separator byte
        let pos = input[2..]
            .iter()
            .position(|&b| b != 0xFF)
            .ok_or(CryptoError::RsaInvalidPadding)?;

        if pos < 8 {
            return Err(CryptoError::RsaInvalidPadding);
        }

        if input[pos + 2] != 0x00 {
            return Err(CryptoError::RsaInvalidPadding);
        }

        let digest_info = DerDigestInfo::from_der(&input[pos + 3..])?;
        if digest_info.algo() != params.hash_algo.der_algo() {
            return Err(CryptoError::RsaInvalidPadding);
        }

        Ok(RsaPadPkcs1SignAlgo::new(
            k,
            params.hash_algo,
            digest_info.digest(),
        ))
    }
}
