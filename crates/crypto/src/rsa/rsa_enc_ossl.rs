// Copyright (C) Microsoft Corporation. All rights reserved.

//! OpenSSL-based RSA encryption and decryption operations.
//!
//! This module provides RSA encryption and decryption functionality using OpenSSL
//! as the underlying cryptographic backend. It supports various padding schemes
//! including OAEP (Optimal Asymmetric Encryption Padding) for enhanced security.
//!
//! # Supported Padding Schemes
//!
//! - **OAEP**: Optimal Asymmetric Encryption Padding with configurable hash algorithms
//! - **PKCS#1 v1.5**: Legacy padding (use OAEP for new applications)
//!
//! # Security Considerations
//!
//! - Always use OAEP padding for new applications
//! - OAEP provides semantic security and protection against various attacks
//! - Choose appropriate hash algorithms (SHA-256 or stronger recommended)
//! - RSA encryption is typically used for small data (e.g., symmetric key wrapping)

use openssl::rsa::*;

use super::*;

/// OpenSSL-backed RSA encryption and decryption implementation.
///
/// This structure provides RSA encryption and decryption operations with support
/// for various padding schemes. It maintains configuration for padding mode,
/// hash algorithm selection, and optional OAEP labels.
///
/// # Lifetime Parameter
///
/// The lifetime parameter `'a` is used for the OAEP label, which must remain
/// valid for the duration of the encryption/decryption operation.
///
/// # Padding Modes
///
/// - **NONE**: No padding (use with caution)
/// - **PKCS1_OAEP**: Optimal Asymmetric Encryption Padding with hash function
///
/// # Thread Safety
///
/// This structure is `Send` and `Sync` as OpenSSL's RSA operations are thread-safe.
pub struct OsslRsaEncryptAlgo<'a> {
    /// The padding scheme to use for encryption/decryption
    padding: Padding,
    /// The hash instance for OAEP padding (if applicable)
    hash: Option<HashAlgo>,
    /// The label for OAEP padding (optional, typically empty)
    label: Option<&'a [u8]>,
}

/// Implements RSA encryption operations using OpenSSL.
///
/// This implementation performs RSA encryption with the configured padding scheme.
/// Encryption uses the RSA public key and produces ciphertext that can only be
/// decrypted with the corresponding private key.
impl EncryptOp for OsslRsaEncryptAlgo<'_> {
    type Key = RsaPublicKey;

    /// Encrypts data using RSA with the configured padding scheme.
    ///
    /// This method encrypts the input data using the provided RSA public key.
    /// The output buffer pattern allows querying the required buffer size before
    /// performing the actual encryption.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA public key to use for encryption
    /// * `input` - The plaintext data to encrypt
    /// * `output` - Optional output buffer. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the buffer, or the required buffer size
    /// if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::RsaError` - Encrypter creation or length calculation fails
    /// - `CryptoError::RsaBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::RsaEncryptError` - Encryption operation fails
    ///
    /// # Security
    ///
    /// - RSA encryption should only be used for small data (typically symmetric keys)
    /// - Use OAEP padding for new applications
    /// - Ensure the public key is authenticated to prevent substitution attacks
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        use openssl::encrypt::Encrypter;
        let mut encrypter = Encrypter::new(key.pkey()).map_err(|_| CryptoError::RsaError)?;
        self.configure_encrypter(&mut encrypter)?;
        let len = encrypter
            .encrypt_len(input)
            .map_err(|_| CryptoError::RsaError)?;
        if let Some(output) = output {
            if output.len() < len {
                return Err(CryptoError::RsaBufferTooSmall);
            }
            encrypter
                .encrypt(input, output)
                .map_err(|_| CryptoError::RsaEncryptError)?;
        }
        Ok(len)
    }
}

/// Implements RSA decryption operations using OpenSSL.
///
/// This implementation performs RSA decryption with the configured padding scheme.
/// Decryption uses the RSA private key to recover the original plaintext from
/// ciphertext that was encrypted with the corresponding public key.
impl DecryptOp for OsslRsaEncryptAlgo<'_> {
    type Key = RsaPrivateKey;

    /// Decrypts data using RSA with the configured padding scheme.
    ///
    /// This method decrypts the input ciphertext using the provided RSA private key.
    /// The output buffer pattern allows querying the required buffer size before
    /// performing the actual decryption.
    ///
    /// # Arguments
    ///
    /// * `key` - The RSA private key to use for decryption
    /// * `input` - The ciphertext data to decrypt
    /// * `output` - Optional output buffer. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the buffer, or the required buffer size
    /// if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::RsaError` - Decrypter creation or length calculation fails
    /// - `CryptoError::RsaBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::RsaDecryptError` - Decryption operation fails
    ///
    /// # Security
    ///
    /// - Protect private keys from unauthorized access
    /// - Use constant-time operations when possible to prevent timing attacks
    /// - Validate decrypted data before use
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        use openssl::encrypt::Decrypter;
        let mut decrypter = Decrypter::new(key.pkey()).map_err(|_| CryptoError::RsaError)?;
        self.configure_decrypter(&mut decrypter)?;
        let len = decrypter
            .decrypt_len(input)
            .map_err(|_| CryptoError::RsaError)?;
        let len = if let Some(output) = output {
            if output.len() < len {
                return Err(CryptoError::RsaBufferTooSmall);
            }
            decrypter
                .decrypt(input, output)
                .map_err(|_| CryptoError::RsaDecryptError)?
        } else {
            len
        };
        Ok(len)
    }
}

impl<'a> OsslRsaEncryptAlgo<'a> {
    /// Creates a new RSA encryption/decryption context with default settings.
    ///
    /// The default configuration uses no padding. For secure encryption,
    /// use `with_oaep_padding()` to configure OAEP padding with a hash algorithm.
    ///
    /// # Returns
    ///
    /// A new `OsslRsaEncryption` instance with:
    /// - No padding (must be configured before use)
    /// - No hash algorithm
    /// - Empty label
    pub fn with_no_padding() -> Self {
        Self {
            padding: Padding::NONE,
            hash: None,
            label: None,
        }
    }

    /// Creates a new RSA encryption/decryption context with PKCS#1 v1.5 padding.
    ///
    /// PKCS#1 v1.5 padding is a legacy padding scheme that should only be used
    /// for compatibility with existing systems. For new applications, use OAEP
    /// padding via `with_oaep_padding()` instead.
    ///
    /// # Returns
    ///
    /// A new `OsslRsaEncryption` instance configured with PKCS#1 v1.5 padding.
    ///
    /// # Security Warning
    ///
    /// PKCS#1 v1.5 padding is vulnerable to padding oracle attacks (Bleichenbacher's attack).
    /// It is considered legacy and should not be used in new applications unless required
    /// for compatibility with existing systems that cannot be upgraded.
    pub fn with_pkcs1_padding() -> Self {
        Self {
            padding: Padding::PKCS1,
            hash: None,
            label: None,
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
    /// * `hash` - The hash instance to use for OAEP (SHA-256 or stronger recommended)
    /// * `label` - Optional label for OAEP (typically empty, but can be used for domain separation)
    ///
    /// # Returns
    ///
    /// The modified `OsslRsaEncryption` instance configured with OAEP padding.
    ///
    /// # Security
    ///
    /// - Use SHA-256 or stronger hash algorithms for new applications
    /// - The label parameter can be used for domain separation but is typically empty
    /// - OAEP provides protection against chosen-ciphertext attacks
    pub fn with_oaep_padding(hash: HashAlgo, label: Option<&'a [u8]>) -> Self {
        Self {
            padding: Padding::PKCS1_OAEP,
            hash: Some(hash),
            label,
        }
    }

    /// Configures the OpenSSL encrypter with the specified padding parameters.
    ///
    /// This internal method applies the padding configuration to the OpenSSL
    /// encrypter, including OAEP padding mode, hash algorithms, and label.
    ///
    /// # Arguments
    ///
    /// * `encrypter` - The OpenSSL encrypter to configure
    ///
    /// # Returns
    ///
    /// `Ok(())` if padding configuration succeeds.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RsaSetPropertyError` if:
    /// - Setting the padding mode fails
    /// - Setting the OAEP hash algorithm fails
    /// - Setting the MGF1 hash algorithm fails
    /// - Setting the OAEP label fails
    fn configure_encrypter<'b>(
        &mut self,
        encrypter: &mut openssl::encrypt::Encrypter<'b>,
    ) -> Result<(), CryptoError> {
        // Set the padding mode first, OAEP or NONE
        encrypter
            .set_rsa_padding(self.padding)
            .map_err(|_| CryptoError::RsaSetPropertyError)?;

        if self.padding == Padding::PKCS1_OAEP {
            if let Some(hash) = &self.hash {
                encrypter
                    .set_rsa_oaep_md(hash.message_digest())
                    .map_err(|_| CryptoError::RsaSetPropertyError)?;
                encrypter
                    .set_rsa_mgf1_md(hash.message_digest())
                    .map_err(|_| CryptoError::RsaSetPropertyError)?;
            }
            if let Some(label) = self.label {
                encrypter
                    .set_rsa_oaep_label(label)
                    .map_err(|_| CryptoError::RsaSetPropertyError)?;
            }
        }
        Ok(())
    }

    /// Configures the OpenSSL decrypter with the specified padding parameters.
    ///
    /// This internal method applies the padding configuration to the OpenSSL
    /// decrypter, including OAEP padding mode, hash algorithms, and label.
    ///
    /// # Arguments
    ///
    /// * `decrypter` - The OpenSSL decrypter to configure
    ///
    /// # Returns
    ///
    /// `Ok(())` if padding configuration succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::RsaSetPropertyError` - Setting padding, OAEP hash algorithm, or label fails
    /// - `CryptoError::RsaError` - Setting MGF1 hash algorithm fails
    fn configure_decrypter<'b>(
        &mut self,
        decrypter: &mut openssl::encrypt::Decrypter<'b>,
    ) -> Result<(), CryptoError> {
        // Set the padding mode first, OAEP or NONE
        decrypter
            .set_rsa_padding(self.padding)
            .map_err(|_| CryptoError::RsaSetPropertyError)?;

        if self.padding == Padding::PKCS1_OAEP {
            if let Some(hash) = &self.hash {
                decrypter
                    .set_rsa_oaep_md(hash.message_digest())
                    .map_err(|_| CryptoError::RsaSetPropertyError)?;
                decrypter
                    .set_rsa_mgf1_md(hash.message_digest())
                    .map_err(|_| CryptoError::RsaError)?;
            }
            if let Some(label) = self.label {
                decrypter
                    .set_rsa_oaep_label(label)
                    .map_err(|_| CryptoError::RsaSetPropertyError)?;
            }
        }
        Ok(())
    }
}
