// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA signature generation and verification with pre-hashed data using Windows CNG.
//!
//! This module provides RSA signing and verification operations for pre-hashed digests
//! using the Windows Cryptography Next Generation (CNG) API. It supports both PKCS#1 v1.5
//! and PSS (Probabilistic Signature Scheme) padding modes.
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

use windows::Win32::Security::Cryptography::*;

use super::*;

/// RSA signature padding schemes.
///
/// Defines the supported padding modes for RSA signature operations.
/// The padding scheme determines how the message hash is formatted before
/// the RSA operation is applied.
enum Padding {
    /// No padding (not recommended).
    ///
    /// This mode applies no padding to the message hash. It is insecure and should
    /// not be used in practice. Included here for completeness.
    None,
    /// PKCS#1 v1.5 padding (deterministic).
    ///
    /// Traditional padding scheme defined in RFC 8017. It is deterministic,
    /// meaning the same message always produces the same signature with the
    /// same key. While widely supported, it has weaker security properties
    /// than PSS.
    Pkcs1,
    /// PSS padding (probabilistic, recommended).
    ///
    /// Probabilistic Signature Scheme defined in RFC 8017. It uses randomization
    /// to provide stronger security guarantees than PKCS#1 v1.5. Different
    /// signatures are produced for the same message, making certain attacks
    /// more difficult. Recommended for new applications.
    Pss,
}

/// Internal representation of padding information for Windows CNG.
///
/// This enum holds the platform-specific padding information structures
/// required by Windows CNG BCrypt APIs. Each variant contains the appropriate
/// structure for its padding scheme.
#[derive(PartialEq)]
enum PaddingInfo {
    None,
    /// PKCS#1 v1.5 padding information.
    ///
    /// Contains the hash algorithm identifier required by Windows CNG
    /// for PKCS#1 v1.5 signature operations.
    Pkcs1(BCRYPT_PKCS1_PADDING_INFO),
    /// PSS padding information.
    ///
    /// Contains the hash algorithm identifier and salt length required
    /// by Windows CNG for PSS signature operations.
    Pss(BCRYPT_PSS_PADDING_INFO),
}

/// RSA signing and verification context for pre-hashed data using Windows CNG.
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
pub struct CngRsaSignAlgo {
    /// The padding scheme to use (PKCS#1 or PSS).
    padding: Padding,
    /// The hash algorithm to use.
    hash: HashAlgo,
    /// The salt length for PSS padding (ignored for PKCS#1).
    salt_len: usize,
}

impl SignOp for CngRsaSignAlgo {
    type Key = RsaPrivateKey;

    /// Generates an RSA signature for a pre-computed message digest.
    ///
    /// This operation signs a message digest (hash) that has already been computed
    /// by the caller. The digest size must match the output size of the hash algorithm
    /// configured for this signing context.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA private key to use for signing
    /// * `data` - The pre-computed message digest (hash output), must match key size
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
    /// - The digest size doesn't match the key size
    /// - The Windows CNG signing operation fails
    /// - The signature buffer is too small
    #[allow(unsafe_code)]
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let (pad, flags) = self.padding_info();
        let pad_ptr = pad_ptr(&pad);
        let mut len = 0u32;
        // SAFETY: Calling Windows CNG BCryptSignHash/BCryptDecrypt APIs.
        // - key.handle() is a valid BCRYPT_KEY_HANDLE obtained from a CNG private key object
        //   that remains valid for the lifetime of the key reference
        // - pad_ptr is either None or points to valid BCRYPT_PKCS1_PADDING_INFO or
        //   BCRYPT_PSS_PADDING_INFO structure that remains valid on the stack for the call
        // - data slice is valid for reads for the entire duration of the FFI call
        // - signature is either None (for size query) or Some with a valid mutable slice;
        //   BCrypt will not write beyond the slice bounds and will return an error if too small
        // - len is a valid mutable reference to a u32 on the stack
        // - flags are valid BCRYPT_FLAGS values determined by padding_info()
        // For Padding::None, BCryptDecrypt is used to perform raw RSA private key operation
        let status = unsafe {
            match self.padding {
                Padding::None => BCryptDecrypt(
                    key.handle(),
                    Some(data),
                    None,
                    None,
                    signature,
                    &mut len,
                    flags,
                ),
                _ => BCryptSignHash(key.handle(), pad_ptr, data, signature, &mut len, flags),
            }
        };
        status.ok().map_err(|_| CryptoError::RsaSignError)?;
        Ok(len as usize)
    }
}

impl VerifyOp for CngRsaSignAlgo {
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
    /// * `data` - The pre-computed message digest (hash output), must match key size
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid for the given digest, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RsaVerifyError` if:
    /// - The digest size doesn't match the key size
    /// - Internal Windows CNG operations fail
    ///
    /// Note: Invalid signatures return `Ok(false)`, not an error.
    #[allow(unsafe_code)]
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let (pad, flags) = self.padding_info();
        let pad_ptr = pad_ptr(&pad);
        // SAFETY: Calling Windows CNG BCryptVerifySignature API.
        // - key.handle() is a valid BCRYPT_KEY_HANDLE obtained from a CNG public key object
        //   that remains valid for the lifetime of the key reference
        // - pad_ptr is either None or points to valid BCRYPT_PKCS1_PADDING_INFO or
        //   BCRYPT_PSS_PADDING_INFO structure on the stack that remains valid for the call
        // - data slice (message digest) is valid for reads for the entire duration of the FFI call
        // - signature slice is valid for reads for the entire duration of the FFI call
        // - flags are valid BCRYPT_FLAGS values determined by padding_info()
        // The function performs read-only operations and returns a status code
        let status =
            unsafe { BCryptVerifySignature(key.handle(), pad_ptr, data, signature, flags) };
        Ok(status.is_ok())
    }
}

impl VerifyRecoverOp for CngRsaSignAlgo {
    type Key = RsaPublicKey;

    /// Recovers the signed message digest from an RSA signature.
    ///
    /// This operation recovers the original message digest (hash) that was signed,
    /// given the RSA signature and public key. The recovered digest can then be
    /// compared against a locally computed digest for verification.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA public key to use for recovery
    /// * `signature` - The RSA signature to recover the digest from
    ///
    /// # Returns
    ///
    /// A vector containing the recovered message digest (hash).
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RsaVerifyError` if:
    /// - Internal Windows CNG operations fail
    #[allow(unsafe_code)]
    fn verify_recover(
        &mut self,
        key: &Self::Key,
        signature: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let (pad, flags) = self.padding_info();
        let pad_ptr = pad_ptr(&pad);

        let mut len = 0u32;
        // SAFETY: Calling Windows CNG BCryptEncrypt to perform RSA public key operation for signature recovery.
        // - key.handle() is a valid BCRYPT_KEY_HANDLE obtained from a CNG public key object
        //   that remains valid for the lifetime of the key reference
        // - signature slice is treated as "plaintext" input and is valid for reads for the FFI call
        // - pad_ptr is either None or points to valid padding info structure on the stack
        // - None is passed for IV (RSA operations don't use initialization vectors)
        // - output is either None (for size query) or Some with a valid mutable slice;
        //   BCrypt will not write beyond the slice bounds and will return an error if too small
        // - len is a valid mutable reference to a u32 on the stack that receives output size
        // - flags are valid BCRYPT_FLAGS values determined by padding_info()
        // BCryptEncrypt with an RSA public key performs the public key operation needed for recovery
        let status = unsafe {
            BCryptEncrypt(
                key.handle(),
                Some(signature),
                pad_ptr,
                None,
                output,
                &mut len,
                flags,
            )
        };
        status.ok().map_err(|_| CryptoError::RsaVerifyError)?;
        Ok(len as usize)
    }
}

impl CngRsaSignAlgo {
    pub fn with_no_padding() -> Self {
        Self {
            padding: Padding::None,
            hash: HashAlgo::sha1(), // Placeholder, not used
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
    /// * `hash_algo` - The hash algorithm to use (SHA-256 or stronger recommended)
    ///
    /// # Returns
    ///
    /// A new `CngRsaSigning` instance configured for PKCS#1 v1.5 padding.
    ///
    /// # Security Considerations
    ///
    /// - PKCS#1 v1.5 is deterministic, which can be a security concern in some contexts
    /// - Consider using PSS padding for new applications
    /// - Use SHA-256 or stronger hash algorithms
    pub fn with_pkcs1_padding(hash: HashAlgo) -> Self {
        Self {
            padding: Padding::Pkcs1,
            hash,
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
    /// * `hash_algo` - The hash algorithm to use (SHA-256 or stronger recommended)
    /// * `salt_len` - The salt length in bytes (typically matches hash output length)
    ///
    /// # Returns
    ///
    /// A new `CngRsaSigning` instance configured for PSS padding.
    ///
    /// # Security Considerations
    ///
    /// - PSS provides stronger security guarantees than PKCS#1 v1.5
    /// - Salt length typically matches the hash output length for optimal security
    /// - PSS is randomized, providing better protection against certain attacks
    /// - Use SHA-256 or stronger hash algorithms
    pub fn with_pss_padding(hash: HashAlgo, salt_len: usize) -> Self {
        Self {
            padding: Padding::Pss,
            hash,
            salt_len,
        }
    }

    /// Constructs padding information and flags for Windows CNG API calls.
    ///
    /// This method creates the appropriate padding information structure and
    /// flags based on the configured padding scheme. The structures are used
    /// by BCryptSignHash and BCryptVerifySignature.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The padding information structure (PKCS#1 or PSS)
    /// - The corresponding flags for Windows CNG APIs
    fn padding_info(&self) -> (PaddingInfo, BCRYPT_FLAGS) {
        match self.padding {
            Padding::None => (PaddingInfo::None, BCRYPT_PAD_NONE),
            Padding::Pkcs1 => (
                PaddingInfo::Pkcs1(BCRYPT_PKCS1_PADDING_INFO {
                    pszAlgId: self.hash.algo_id(),
                }),
                BCRYPT_PAD_PKCS1,
            ),
            Padding::Pss => (
                PaddingInfo::Pss(BCRYPT_PSS_PADDING_INFO {
                    pszAlgId: self.hash.algo_id(),
                    cbSalt: self.salt_len as u32,
                }),
                BCRYPT_PAD_PSS,
            ),
        }
    }
}

/// Converts padding information to a pointer for Windows CNG APIs.
///
/// This helper function takes a reference to padding information and returns
/// a void pointer that can be passed to Windows CNG BCrypt signature functions.
/// The pointer references the appropriate padding structure based on the scheme.
///
/// # Arguments
///
/// * `pad` - The padding information to convert
///
/// # Returns
///
/// An optional pointer to the padding information structure, cast to `c_void`.
/// The returned pointer is valid as long as the `PaddingInfo` reference is valid.
///
/// # Safety
///
/// The returned pointer must only be used while the `PaddingInfo` reference
/// remains valid. Dereferencing after the reference is dropped is undefined behavior.
fn pad_ptr(pad: &PaddingInfo) -> Option<*const std::ffi::c_void> {
    match &pad {
        PaddingInfo::None => None,
        PaddingInfo::Pkcs1(info) => Some(info as *const _ as *const std::ffi::c_void),
        PaddingInfo::Pss(info) => Some(info as *const _ as *const std::ffi::c_void),
    }
}
