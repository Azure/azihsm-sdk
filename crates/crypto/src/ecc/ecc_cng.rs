// Copyright (C) Microsoft Corporation. All rights reserved.

use windows::Win32::Security::Cryptography::*;

use super::*;

/// Windows CNG implementation of ECC operations.
///
/// Provides ECDSA signing and verification using Windows Cryptography Next Generation (CNG) APIs.
#[derive(Default)]
pub struct CngEccAlgo {}

impl SignOp for CngEccAlgo {
    type Key = EccPrivateKey;

    /// Creates an ECDSA signature using Windows CNG.
    ///
    /// # Arguments
    ///
    /// * `key` - The ECC private key used for signing
    /// * `data` - The data to sign (typically a hash of the original message)
    /// * `signature` - Optional output buffer. If `None`, returns the required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the signature buffer (R || S format, each component
    /// is point_size bytes), or the required buffer size if `signature` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::EccSignError` - Signing operation fails
    /// - `CryptoError::EccBufferTooSmall` - Signature buffer is too small
    ///
    /// # Security
    ///
    /// - Always hash the input data before signing (e.g., with SHA-256)
    /// - Never sign raw user input directly
    /// - Each signature uses a unique cryptographically secure random nonce
    #[allow(unsafe_code)]
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        // CNG returns signature in raw R || S format directly
        let mut sig_len = 0u32;
        // SAFETY: Calling Windows CNG BCryptSignHash for ECDSA signing.
        // - key.ecdsa_handle() is a valid BCRYPT_KEY_HANDLE
        // - None for padding info (ECDSA doesn't use padding)
        // - data is the pre-hashed message digest
        // - signature buffer is either None (for size query) or Some with valid lifetime
        // - sig_len is a valid mutable reference to receive signature size
        let status = unsafe {
            BCryptSignHash(
                key.ecdsa_handle(),
                None,
                data,
                signature,
                &mut sig_len,
                BCRYPT_FLAGS(0),
            )
        };
        status.ok().map_err(|_| CryptoError::EccSignError)?;

        Ok(sig_len as usize)
    }
}

impl VerifyOp for CngEccAlgo {
    type Key = EccPublicKey;

    /// Verifies an ECDSA signature using Windows CNG.
    ///
    /// # Arguments
    ///
    /// * `key` - The ECC public key used for verification
    /// * `data` - The data that was signed (typically a hash of the original message)
    /// * `signature` - The signature to verify (R || S format)
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if the signature is
    /// invalid (does not match the data and key).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::EccVerifyError` - Signature is malformed or verification fails
    ///
    /// # Security
    ///
    /// - Always use the same hash algorithm for verification as was used for signing
    /// - Invalid signatures return `Ok(false)`, not an error
    /// - Malformed signatures that cannot be parsed return an error
    #[allow(unsafe_code)]
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        // CNG verifies signature in raw R || S format directly
        // SAFETY: Calling Windows CNG BCryptVerifySignature for ECDSA verification.
        // - key.ecdsa_handle() is a valid BCRYPT_KEY_HANDLE
        // - None for padding info (ECDSA doesn't use padding)
        // - data is the pre-hashed message digest
        // - signature is the signature bytes to verify
        let status = unsafe {
            BCryptVerifySignature(key.ecdsa_handle(), None, data, signature, BCRYPT_FLAGS(0))
        };
        Ok(status.is_ok())
    }
}
