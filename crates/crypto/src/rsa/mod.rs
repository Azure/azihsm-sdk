// Copyright (C) Microsoft Corporation. All rights reserved.

//! RSA (Rivest-Shamir-Adleman) cryptographic operations.
//!
//! This module provides a comprehensive interface for RSA cryptographic operations
//! including key generation, encryption, decryption, signing, and verification.
//! The implementation abstracts over platform-specific backends to provide
//! consistent APIs across different operating systems.
//!
//! # Supported Operations
//!
//! - **Key Generation**: Generate RSA key pairs with configurable key sizes
//! - **Encryption/Decryption**: RSA-OAEP padding for secure encryption
//! - **Digital Signatures**: RSA-PSS and PKCS#1 v1.5 signature schemes
//! - **Hash-based Signing**: Combined hash and sign operations
//! - **Key Import/Export**: Serialize and deserialize keys in DER format
//!
//! # Key Sizes
//!
//! Supported RSA key sizes:
//! - **2048 bits**: Minimum recommended for current use
//! - **3072 bits**: Enhanced security for long-term protection
//! - **4096 bits**: Maximum security for critical applications
//!
//! # Platform Support
//!
//! - **Linux**: Uses OpenSSL implementations via `key_ossl`, `rsa_enc_ossl`, `rsa_sign_ossl` modules
//! - **Windows**: Uses Windows CNG via `key_cng`, `rsa_enc_cng`, `rsa_sign_cng` modules
//!
//! # Architecture
//!
//! The module is structured around several key components:
//!
//! - [`RsaPrivateKey`]: Platform-specific private key type
//! - [`RsaPublicKey`]: Platform-specific public key type
//! - [`RsaEncryption`]: Encryption and decryption operations with RSA-OAEP
//! - [`RsaSigning`]: Raw signature operations (typically used with external hashing)
//! - [`RsaHashSigning`]: Combined hash and signature operations
//!
//! # Security Considerations
//!
//! - Use minimum 2048-bit keys for new applications (3072+ bits recommended)
//! - Always use proper padding schemes (OAEP for encryption, PSS for signatures)
//! - Never use the same key for both encryption and signing
//! - Private keys must be kept secure and never exposed
//! - Use appropriate hash algorithms (SHA-256 minimum, SHA-384/512 preferred)
//! - Be aware of timing attack vulnerabilities in older implementations
cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod key_ossl;
        mod rsa_enc_ossl;
        mod rsa_sign_ossl;
        mod rsa_hash_sign_ossl;
    } else if #[cfg(target_os = "windows")] {
        mod key_cng;
        mod rsa_enc_cng;
        mod rsa_sign_cng;
        mod rsa_hash_sign_cng;
    } else {
        compile_error!("Unsupported target OS for AES-CBC implementation");
    }
}

mod rsa_aes_kw;
mod rsa_pad_oaep;
mod rsa_pad_pkcs1_enc;
mod rsa_pad_pkcs1_sign;
mod rsa_pad_pss;

use super::*;

/// Trait for RSA key-specific operations.
///
/// This trait provides methods for retrieving RSA-specific parameters
/// from key objects, including the modulus (n) and public exponent (e).
/// It's implemented by both private and public RSA keys.
///
/// # RSA Key Parameters
///
/// RSA keys consist of:
/// - **n (modulus)**: The product of two large prime numbers, size varies by key strength
/// - **e (public exponent)**: Typically 65537 (0x10001), used for encryption and verification
pub trait RsaKeyOp {
    /// Retrieves the RSA modulus (n).
    ///
    /// This method can either return the required buffer size (when `n` is `None`)
    /// or copy the modulus to the provided buffer (when `n` is `Some`).
    ///
    /// # Arguments
    ///
    /// * `n` - Optional output buffer for the modulus. Must be at least the key size in bytes.
    ///
    /// # Returns
    ///
    /// The size of the modulus in bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccBufferTooSmall` if the provided buffer is too small.
    fn n(&self, n: Option<&mut [u8]>) -> Result<usize, CryptoError>;

    /// Retrieves the RSA modulus (n) as a vector.
    ///
    /// This is a convenience method that allocates a vector for the modulus
    /// and calls `n()` to fill it.
    ///
    /// # Returns
    ///
    /// A vector containing the RSA modulus in big-endian byte order.
    ///
    /// # Errors
    ///
    /// Returns errors if modulus extraction fails.
    fn n_vec(&self) -> Result<Vec<u8>, CryptoError> {
        let key_len = self.n(None)?;
        let mut n_bytes = vec![0u8; key_len];
        self.n(Some(&mut n_bytes))?;
        Ok(n_bytes)
    }

    /// Retrieves the RSA public exponent (e).
    ///
    /// This method can either return the required buffer size (when `e` is `None`)
    /// or copy the exponent to the provided buffer (when `e` is `Some`).
    ///
    /// # Arguments
    ///
    /// * `e` - Optional output buffer for the exponent.
    ///
    /// # Returns
    ///
    /// The size of the exponent in bytes (typically 3 bytes for value 65537).
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccBufferTooSmall` if the provided buffer is too small.
    fn e(&self, e: Option<&mut [u8]>) -> Result<usize, CryptoError>;

    /// Retrieves the RSA public exponent (e) as a vector.
    ///
    /// This is a convenience method that allocates a vector for the exponent
    /// and calls `e()` to fill it.
    ///
    /// # Returns
    ///
    /// A vector containing the RSA public exponent in big-endian byte order.
    ///
    /// # Errors
    ///
    /// Returns errors if exponent extraction fails.
    fn e_vec(&self) -> Result<Vec<u8>, CryptoError> {
        let key_len = self.e(None)?;
        let mut e_bytes = vec![0u8; key_len];
        self.e(Some(&mut e_bytes))?;
        Ok(e_bytes)
    }
}

define_type!(pub RsaPrivateKey, key_ossl::OsslRsaPrivateKey, key_cng::CngRsaPrivateKey);
define_type!(pub RsaPublicKey, key_ossl::OsslRsaPublicKey, key_cng::CngRsaPublicKey);
define_type!(pub RsaEncryptAlgo<'a>, rsa_enc_ossl::OsslRsaEncryptAlgo<'a>, rsa_enc_cng::CngRsaEncryptAlgo);
define_type!(pub RsaSignAlgo, rsa_sign_ossl::OsslRsaSignAlgo, rsa_sign_cng::CngRsaSignAlgo);
define_type!(pub RsaHashSignAlgo, rsa_hash_sign_ossl::OsslRsaHashSignAlgo, rsa_hash_sign_cng::CngRsaHashSignAlgo);
define_type!(pub RsaHashSignAlgoSignContext, rsa_hash_sign_ossl::OsslRsaHashSignAlgoSignContext, rsa_hash_sign_cng::CngRsaHashSignAlgoSignContext);
define_type!(pub RsaHashSignAlgoVerifyContext, rsa_hash_sign_ossl::OsslRsaHashSignAlgoVerifyContext, rsa_hash_sign_cng::CngRsaHashSignAlgoVerifyContext);

pub use rsa_aes_kw::RsaAesKeyWrap;
pub use rsa_pad_oaep::*;
pub use rsa_pad_pkcs1_enc::*;
pub use rsa_pad_pkcs1_sign::*;
pub use rsa_pad_pss::*;

#[cfg(test)]
mod tests;
