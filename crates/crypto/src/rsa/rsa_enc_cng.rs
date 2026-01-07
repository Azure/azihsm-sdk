// Copyright (C) Microsoft Corporation. All rights reserved.

//! RSA encryption and decryption using Windows CNG.
//!
//! This module provides RSA encryption and decryption operations using the Windows
//! Cryptography Next Generation (CNG) API. It supports both raw (no padding) and
//! OAEP (Optimal Asymmetric Encryption Padding) padding schemes.
//!
//! # Padding Schemes
//!
//! - **No Padding**: Direct RSA encryption without padding (not recommended for security)
//! - **OAEP**: Recommended padding scheme providing semantic security and protection
//!   against chosen-ciphertext attacks
//!
//! # Security Considerations
//!
//! - Always use OAEP padding for new applications
//! - Use SHA-256 or stronger hash algorithms with OAEP
//! - No padding mode should only be used for legacy compatibility
//! - The plaintext size must be smaller than the key size minus padding overhead

use windows::Win32::Security::Cryptography::*;

use super::*;

/// RSA padding scheme selection for CNG operations.
///
/// This enum specifies which padding scheme to use for RSA encryption/decryption
/// operations with Windows CNG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Padding {
    /// No padding (raw RSA). Insecure and should only be used for legacy compatibility.
    None,
    /// PKCS#1 v1.5 padding. Legacy scheme vulnerable to padding oracle attacks.
    Pkcs1,
    /// OAEP padding. Recommended secure padding scheme for new applications.
    Oaep,
}

/// RSA encryption and decryption context using Windows CNG.
///
/// This structure manages the configuration for RSA encryption and decryption
/// operations, including padding scheme selection and OAEP parameters.
///
/// # Padding Configuration
///
/// The context can be configured for:
/// - **No padding**: Raw RSA without any padding scheme
/// - **OAEP padding**: Secure padding with configurable hash algorithm and label
///
/// # Trait Implementations
///
/// - `EncryptOp`: Encrypts data using an RSA public key
/// - `DecryptOp`: Decrypts data using an RSA private key
///
/// # Lifetimes
///
/// The `'a` lifetime parameter allows the struct to optionally hold a reference
/// to the OAEP label data without requiring allocation in all cases.
pub struct CngRsaEncryptAlgo {
    /// Whether OAEP padding is enabled.
    pad: Padding,
    /// The label for OAEP padding (optional, typically empty).
    label: Vec<u8>,
    /// The hashing algorithm used for OAEP padding.
    hash: Option<HashAlgo>,
}

impl DecryptOp for CngRsaEncryptAlgo {
    type Key = RsaPrivateKey;

    /// Decrypts data using an RSA private key.
    ///
    /// The decryption operation uses the padding configuration set in this context.
    /// For OAEP padding, the hash algorithm and label must match those used during encryption.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA private key to use for decryption
    /// * `input` - The ciphertext to decrypt
    /// * `output` - Optional buffer for the plaintext. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer, or the required buffer size
    /// if `output` is `None`.
    ///
    /// # Security
    ///
    /// - The input size must match the key size
    /// - OAEP parameters (hash algorithm and label) must match encryption parameters
    /// - Timing side-channels may leak information about padding validity
    #[allow(unsafe_code)]
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let (flags, pad) = self.pad_info()?;
        let pad_ptr = pad
            .as_ref()
            .map(|info| info as *const _ as *const std::ffi::c_void);
        let mut len = 0u32;
        // SAFETY: Calling Windows CNG BCryptDecrypt API.
        // - key.handle() is a valid BCRYPT_KEY_HANDLE from a CNG key object
        // - input buffer is valid for the duration of the call
        // - pad_ptr is either null or points to valid OAEP padding info
        // - output buffer validity is ensured by BCrypt checking len
        let status = unsafe {
            BCryptDecrypt(
                key.handle(),
                Some(input),
                pad_ptr,
                None,
                output,
                &mut len,
                flags,
            )
        };
        status.ok().map_err(|_| CryptoError::RsaDecryptError)?;
        Ok(len as usize)
    }
}

impl EncryptOp for CngRsaEncryptAlgo {
    type Key = RsaPublicKey;

    /// Encrypts data using an RSA public key.
    ///
    /// The encryption operation uses the padding configuration set in this context.
    /// The plaintext size must be appropriate for the key size and padding scheme.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA public key to use for encryption
    /// * `input` - The plaintext to encrypt
    /// * `output` - Optional buffer for the ciphertext. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer, or the required buffer size
    /// if `output` is `None`.
    ///
    /// # Size Constraints
    ///
    /// For OAEP with SHA-256 on a 2048-bit (256-byte) key:
    /// - Maximum plaintext size: 256 - 2*32 - 2 = 190 bytes
    ///
    /// For no padding:
    /// - Plaintext size must equal the key size
    #[allow(unsafe_code)]
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        if self.pad == Padding::None && input.len() != key.size() {
            return Err(CryptoError::RsaEncryptError);
        }

        let (flags, pad) = self.pad_info()?;
        let pad_ptr = pad
            .as_ref()
            .map(|info| info as *const _ as *const std::ffi::c_void);
        let mut len = 0u32;
        // SAFETY: Calling Windows CNG BCryptEncrypt for RSA encryption.
        // - key.handle() is a valid BCRYPT_KEY_HANDLE
        // - input contains the plaintext data
        // - pad_ptr is either null or points to valid padding info with appropriate lifetime
        // - None for IV (RSA doesn't use IV)
        // - output buffer is either None (for size query) or Some with valid lifetime
        // - len is a valid mutable reference to receive ciphertext size
        let status = unsafe {
            BCryptEncrypt(
                key.handle(),
                Some(input),
                pad_ptr,
                None,
                output,
                &mut len,
                flags,
            )
        };
        status.ok().map_err(|_| CryptoError::RsaEncryptError)?;
        Ok(len as usize)
    }
}

impl CngRsaEncryptAlgo {
    /// Creates a new RSA encryption/decryption context with default settings.
    ///
    /// The default configuration uses no padding. For secure encryption,
    /// use `with_oaep_padding()` to configure OAEP padding with a hash algorithm.
    ///
    /// # Returns
    ///
    /// A new `CngRsaEncryption` instance with:
    /// - No padding (must be configured before use)
    /// - No hash algorithm (placeholder value)
    /// - Empty label
    ///
    /// # Security Warning
    ///
    /// No padding mode is insecure and should only be used for legacy compatibility.
    /// Use `with_oaep_padding()` for new applications.
    pub fn with_no_padding() -> Self {
        Self {
            pad: Padding::None,
            label: Vec::new(),
            hash: None,
        }
    }

    /// Configures PKCS#1 v1.5 padding with the specified hash algorithm.
    ///
    /// PKCS#1 v1.5 is a legacy padding scheme that should only be used
    /// for compatibility with older systems. For new applications, prefer
    /// OAEP padding via `with_oaep_padding()`.
    ///
    /// # Returns
    ///
    /// A new `CngRsaEncryptAlgo` instance configured with PKCS#1 v1.5 padding.
    ///
    /// # Security Warning
    ///
    /// PKCS#1 v1.5 padding is vulnerable to padding oracle attacks. Use OAEP
    /// padding instead unless required for legacy compatibility.
    pub fn with_pkcs1_padding() -> Self {
        Self {
            pad: Padding::Pkcs1,
            label: Vec::new(),
            hash: None,
        }
    }

    /// Configures OAEP padding with the specified hash algorithm and label.
    ///
    /// OAEP (Optimal Asymmetric Encryption Padding) provides semantic security
    /// and protection against various attacks. It is the recommended padding
    /// scheme for new applications.
    ///
    /// # Arguments
    ///
    /// * `hash_algo` - The hash algorithm to use for OAEP (SHA-256 or stronger recommended)
    /// * `label` - Optional label for OAEP (typically empty, but can be used for domain separation)
    ///
    /// # Returns
    ///
    /// A new `CngRsaEncryption` instance configured with OAEP padding.
    ///
    /// # Security
    ///
    /// - Use SHA-256 or stronger hash algorithms for new applications
    /// - The label parameter can be used for domain separation but is typically empty
    /// - OAEP provides protection against chosen-ciphertext attacks
    /// - The same hash algorithm and label must be used for both encryption and decryption
    pub fn with_oaep_padding(hash: HashAlgo, label: Option<&[u8]>) -> Self {
        Self {
            pad: Padding::Oaep,
            label: label.map_or(Vec::new(), |l| l.to_vec()),
            hash: Some(hash),
        }
    }

    /// Constructs the padding information for Windows CNG API calls.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The padding flags (`BCRYPT_PAD_OAEP` or `BCRYPT_PAD_NONE`)
    /// - Optional OAEP padding info structure with hash algorithm and label
    fn pad_info(
        &mut self,
    ) -> Result<(BCRYPT_FLAGS, Option<BCRYPT_OAEP_PADDING_INFO>), CryptoError> {
        match self.pad {
            Padding::Oaep => {
                let mut pad_info = BCRYPT_OAEP_PADDING_INFO {
                    pszAlgId: self.bcrypt_hash_algo_id()?,
                    ..Default::default()
                };

                if !self.label.is_empty() {
                    pad_info.pbLabel = self.label.as_mut_ptr();
                    pad_info.cbLabel = self.label.len() as u32;
                }

                Ok((BCRYPT_PAD_OAEP, Some(pad_info)))
            }
            Padding::Pkcs1 => Ok((BCRYPT_PAD_PKCS1, None)),
            Padding::None => Ok((BCRYPT_FLAGS(0), None)),
        }
    }

    /// Converts the hash algorithm enum to the Windows CNG algorithm identifier.
    ///
    /// # Returns
    ///
    /// The corresponding Windows CNG hash algorithm constant.
    fn bcrypt_hash_algo_id(&self) -> Result<windows::core::PCWSTR, CryptoError> {
        match &self.hash {
            Some(hash) => Ok(hash.algo_id()),
            None => Err(CryptoError::RsaInvalidHashAlgorithm),
        }
    }
}
