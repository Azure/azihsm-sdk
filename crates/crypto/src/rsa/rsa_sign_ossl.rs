// Copyright (C) Microsoft Corporation. All rights reserved.

//! RSA signature generation and verification with pre-hashed data using OpenSSL.
//!
//! This module provides RSA signing and verification operations for pre-hashed digests
//! using the OpenSSL library. It supports both PKCS#1 v1.5 and PSS (Probabilistic
//! Signature Scheme) padding modes.
//!
//! **Note**: This module operates on message digests (hashes), not raw message data.
//! The caller must hash the message before passing it to the sign/verify operations.
//!
//! # Padding Schemes
//!
//! - **PKCS#1 v1.5**: Traditional deterministic padding scheme, widely supported
//! - **PSS**: Probabilistic padding with stronger security properties, recommended for new applications
//!
//! # Security Considerations
//!
//! - PSS padding is recommended over PKCS#1 v1.5 for new applications
//! - Use SHA-256 or stronger hash algorithms for message digests
//! - For PSS, salt length should typically match the hash output length
//! - PKCS#1 v1.5 is deterministic and may be vulnerable to certain attacks
//! - Always hash messages before signing (this module expects pre-computed digests)

use openssl::pkey_ctx::*;
use openssl::rsa::*;

use super::*;

/// RSA signing and verification context for pre-hashed data using OpenSSL.
///
/// This structure manages the configuration for RSA signature operations on message
/// digests (hashes), including padding scheme selection, hash algorithm identification,
/// and PSS-specific parameters.
///
/// **Important**: This context operates on pre-computed message digests, not raw messages.
/// The caller must hash the message using the appropriate hash algorithm before calling
/// sign or verify operations.
///
/// # Padding Configuration
///
/// The context can be configured for:
/// - **PKCS#1 v1.5**: Traditional deterministic padding for digests
/// - **PSS**: Probabilistic signature scheme with configurable salt length
///
/// # Trait Implementations
///
/// - `SignOp`: Signs a pre-computed message digest
/// - `VerifyOp`: Verifies a signature against a pre-computed message digest
pub struct OsslRsaSignAlgo {
    /// The padding scheme to use (PKCS#1 or PSS).
    padding: Padding,
    /// The hash instance to use.
    hash: Option<HashAlgo>,
    /// The salt length for PSS padding (ignored for PKCS#1).
    salt_len: usize,
}

impl SignOp for OsslRsaSignAlgo {
    type Key = RsaPrivateKey;

    /// Generates an RSA signature for a pre-hashed message digest.
    ///
    /// This operation signs a message digest (hash) that has already been computed
    /// by the caller. The digest size must match the output size of the hash algorithm
    /// configured for this signing context.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA private key to use for signing
    /// * `data` - The pre-computed message digest (hash output)
    /// * `signature` - Optional buffer for the signature. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the signature buffer, or the required buffer size
    /// if `signature` is `None`. The signature size equals the key size in bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RsaSignError` if:
    /// - The digest size doesn't match the expected hash output size
    /// - The OpenSSL signing operation fails
    /// - The signature buffer is too small
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let mut pkey_ctx = PkeyCtx::new(key.pkey()).map_err(|_| CryptoError::RsaError)?;
        pkey_ctx
            .sign_init()
            .map_err(|_| CryptoError::RsaSignError)?;
        self.configure_pkey_ctx(&mut pkey_ctx)?;
        let len = pkey_ctx
            .sign(data, signature)
            .map_err(|_| CryptoError::RsaSignError)?;
        Ok(len)
    }
}

impl VerifyOp for OsslRsaSignAlgo {
    type Key = RsaPublicKey;

    /// Verifies an RSA signature against a pre-computed message digest.
    ///
    /// This operation verifies that a signature is valid for a given message digest (hash)
    /// that has already been computed by the caller. The digest must be computed using
    /// the same hash algorithm configured for this verification context.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA public key to use for verification
    /// * `data` - The pre-computed message digest (hash output)
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid for the given digest, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if internal OpenSSL operations fail.
    /// Note: Invalid signatures return `Ok(false)`, not an error.
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let mut pkey_ctx = PkeyCtx::new(key.pkey()).map_err(|_| CryptoError::RsaError)?;
        pkey_ctx
            .verify_init()
            .map_err(|_| CryptoError::RsaVerifyError)?;
        self.configure_pkey_ctx(&mut pkey_ctx)?;
        pkey_ctx
            .verify(data, signature)
            .map_err(|_| CryptoError::RsaVerifyError)
    }
}

impl VerifyRecoverOp for OsslRsaSignAlgo {
    type Key = RsaPublicKey;

    /// Verifies an RSA signature and recovers the signed message digest.
    ///
    /// This operation verifies a signature and recovers the original message digest
    /// (hash) that was signed. The recovered digest must match the expected hash output
    /// size for the configured hash algorithm.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA public key to use for verification
    /// * `signature` - The signature to verify and recover from
    /// * `output` - Optional buffer to receive the recovered digest. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer, or the required buffer size
    /// if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The OpenSSL verification or recovery operation fails
    /// - The output buffer is too small
    fn verify_recover(
        &mut self,
        key: &Self::Key,
        signature: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let mut pkey_ctx = PkeyCtx::new(key.pkey()).map_err(|_| CryptoError::RsaError)?;
        pkey_ctx
            .verify_recover_init()
            .map_err(|_| CryptoError::RsaVerifyError)?;
        self.configure_pkey_ctx(&mut pkey_ctx)?;
        let len = pkey_ctx
            .verify_recover(signature, output)
            .map_err(|_| CryptoError::RsaVerifyError)?;
        Ok(len)
    }
}

impl OsslRsaSignAlgo {
    /// Creates a new RSA signing operation with no padding.
    ///
    /// This is a low-level operation that performs raw RSA signing without any padding
    /// or hashing. It should only be used when implementing custom padding schemes or
    /// for specific cryptographic protocols.
    ///
    /// # Security Warning
    ///
    /// Raw RSA operations without padding are vulnerable to various attacks and should
    /// not be used for general-purpose signing. Use PKCS#1 or PSS padding instead.
    ///
    /// # Returns
    ///
    /// A new signing context configured for raw RSA operations.
    pub fn with_no_padding() -> Self {
        Self {
            padding: Padding::NONE,
            hash: None,
            salt_len: 0,
        }
    }
    /// Creates a new RSA signing operation with PKCS#1 v1.5 padding.
    ///
    /// PKCS#1 v1.5 is the traditional RSA signature padding scheme. It is deterministic
    /// and widely supported but has weaker security properties than PSS.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash instance to use (SHA-256 or stronger recommended)
    ///
    /// # Returns
    ///
    /// A new `OsslRsaSigning` instance configured for PKCS#1 v1.5 padding.
    ///
    /// # Security Considerations
    ///
    /// - PKCS#1 v1.5 is deterministic, which can be a security concern in some contexts
    /// - Consider using PSS padding for new applications
    /// - Use SHA-256 or stronger hash algorithms
    pub fn with_pkcs1_padding(hash: HashAlgo) -> Self {
        Self {
            padding: Padding::PKCS1,
            hash: Some(hash),
            salt_len: 0,
        }
    }

    /// Creates a new RSA signing operation with PSS padding.
    ///
    /// PSS (Probabilistic Signature Scheme) is a randomized padding scheme with
    /// stronger security properties than PKCS#1 v1.5. It is recommended for new applications.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash instance to use (SHA-256 or stronger recommended)
    /// * `salt_len` - The salt length in bytes (typically matches hash output length)
    ///
    /// # Returns
    ///
    /// A new `OsslRsaSigning` instance configured for PSS padding.
    ///
    /// # Security Considerations
    ///
    /// - PSS provides stronger security guarantees than PKCS#1 v1.5
    /// - Salt length typically matches the hash output length for optimal security
    /// - PSS is randomized, providing better protection against certain attacks
    /// - Use SHA-256 or stronger hash algorithms
    pub fn with_pss_padding(hash: HashAlgo, salt_len: usize) -> Self {
        Self {
            padding: Padding::PKCS1_PSS,
            hash: Some(hash),
            salt_len,
        }
    }

    /// Configures the OpenSSL signer with the appropriate padding and parameters.
    ///
    /// Sets the padding mode and, for PSS, configures the salt length and MGF1 hash algorithm.
    ///
    /// # Arguments
    ///
    /// * `signer` - The OpenSSL signer to configure
    fn configure_pkey_ctx<T>(&self, pkey_ctx: &mut PkeyCtx<T>) -> Result<(), CryptoError> {
        pkey_ctx
            .set_rsa_padding(self.padding)
            .map_err(|_| CryptoError::RsaSetPropertyError)?;

        if let Some(hash) = &self.hash {
            pkey_ctx
                .set_signature_md(hash.md())
                .map_err(|_| CryptoError::RsaSetPropertyError)?;

            if self.padding == Padding::PKCS1_PSS {
                pkey_ctx
                    .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::custom(self.salt_len as i32))
                    .map_err(|_| CryptoError::RsaSetPropertyError)?;
                pkey_ctx
                    .set_rsa_mgf1_md(hash.md())
                    .map_err(|_| CryptoError::RsaSetPropertyError)?;
            }
        }

        Ok(())
    }
}
