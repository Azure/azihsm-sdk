// Copyright (C) Microsoft Corporation. All rights reserved.

//! New cryptographic library for HSM operations.
//!
//! This crate provides a collection of cryptographic primitives and utilities
//! for working with Hardware Security Modules (HSMs). It includes support for:
//!
//! - **AES**: Symmetric encryption with various modes (CBC, GCM, XTS)
//! - **ECC**: Elliptic Curve Cryptography with NIST curves (P-256, P-384, P-521)
//! - **Hash**: Cryptographic hash functions (SHA-256, SHA-384, SHA-512)
//! - **HMAC**: Hash-based Message Authentication Codes
//! - **DER**: DER encoding/decoding for cryptographic keys
//! - **RNG**: Cryptographically secure random number generation
//! - **X509**: PEM/DER encoding and decoding for X.509 certificates
//!
//! # Platform Support
//!
//! This library provides platform-specific implementations:
//! - Linux: OpenSSL-based implementations
//! - Windows: Native Windows cryptography APIs

mod aes;
mod der;
mod ecc;
mod hash;
mod hmac;
mod kdf;
mod rand;
mod rsa;
mod secret;
mod x509;

mod op;
mod traits;

pub use aes::*;
pub use der::*;
pub use ecc::*;
pub use hash::*;
pub use hmac::*;
pub use kdf::*;
pub use op::*;
pub use rand::*;
pub use rsa::*;
pub use secret::*;
use thiserror::Error;
pub use traits::*;
pub use x509::*;

/// Comprehensive error type for all cryptographic operations.
///
/// This enum covers errors from various cryptographic operations including
/// AES encryption/decryption, hashing, HMAC, DER encoding/decoding, and
/// random number generation.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum CryptoError {
    // AES-related errors
    /// AES key size is invalid for the specified algorithm.
    #[error("AES invalid key size")]
    AesInvalidKeySize,
    /// AES data size is invalid for the operation.
    #[error("AES invalid data size")]
    AesDataSizeError,
    /// AES input size is invalid.
    #[error("AES invalid input size")]
    AesInvalidInputSize,
    /// AES initialization vector size is invalid.
    #[error("AES invalid IV size")]
    AesInvalidIVSize,
    /// AES initialization vector is invalid.
    #[error("AES invalid IV")]
    AesInvalidIVError,
    /// AES Alternative Initial Value (AIV) verification failed.
    #[error("AES AIV mismatch")]
    AesAIVMismatch,
    /// AES Message Length Indicator (MLI) is invalid.
    #[error("AES invalid MLI (Message Length Indicator)")]
    AesInvlidMLI,
    /// AES padding is invalid or verification failed.
    #[error("AES invalid padding")]
    AesInvalidPadding,
    /// AES key generation failed.
    #[error("AES key generation failed")]
    AesKeyGenError,
    /// AES encryption operation failed.
    #[error("AES encryption failed")]
    AesEncryptError,
    /// AES decryption operation failed.
    #[error("AES decryption failed")]
    AesDecryptError,
    /// Output buffer is too small for AES operation.
    #[error("AES buffer too small")]
    AesBufferTooSmall,
    /// General AES operation failure.
    #[error("AES operation failed")]
    AesError,

    /// AES XTS related errors
    /// AES XTS Key size is invalid.
    #[error("AES XTS invalid key size")]
    AesXtsInvalidKeySize,
    /// AES XTS invalid key
    #[error("AES XTS invalid key - both halves are identical")]
    AesXtsInvalidKey,
    /// AES XTS data size is invalid for the operation.
    #[error("AES XTS invalid data size")]
    AesXtsInvalidDataSize,
    /// AES XTS buffer size is too small.
    #[error("AES XTS buffer too small")]
    AesXtsBufferTooSmall,
    /// AES XTS input size is invalid.
    #[error("AES XTS invalid input size")]
    AesXtsInvalidInputSize,
    /// AES XTS encryption operation failed.
    #[error("AES XTS encryption failed")]
    AesXtsEncryptError,
    /// AES XTS decryption operation failed.
    #[error("AES XTS decryption failed")]
    AesXtsDecryptError,
    /// AES XTS invalid tweak size.
    #[error("AES XTS invalid tweak size")]
    AesXtsInvalidTweakSize,
    /// AES XTS invalid data unit length
    #[error("AES XTS invalid data unit length")]
    AesXtsInvalidDataUnitLen,
    /// AES XTS config error
    #[error("AES XTS config error")]
    AesXtsConfigError,
    /// AES XTS tweak overflow.
    #[error("AES XTS tweak overflow")]
    AesXtsTweakOverflow,

    // Random number generation errors
    /// Random number generation operation failed.
    #[error("Random number generation failed")]
    RngError,

    // Hash-related errors
    /// Output buffer is too small to hold the hash result.
    #[error("Hash buffer too small")]
    HashBufferTooSmall,
    /// General hashing operation failure.
    #[error("Hashing operation failed")]
    HashError,
    /// Hash context initialization failed.
    #[error("Hash initialization failed")]
    HashInitError,
    /// Hash update operation failed.
    #[error("Hash update failed")]
    HashUpdateError,
    /// Hash finalization failed.
    #[error("Hash finalization failed")]
    HashFinishError,
    /// Failed to retrieve hash property.
    #[error("Hash get property failed")]
    HashGetPropertyError,

    // HMAC-related errors
    /// HMAC context initialization failed.
    #[error("HMAC initialization failed")]
    HmacInitError,
    /// HMAC key size is invalid for the specified algorithm.
    #[error("HMAC invalid key size")]
    HmacInvalidKeySize,
    /// HMAC key generation failed.
    #[error("HMAC key generation failed")]
    HmacKeyError,
    /// HMAC key import failed.
    #[error("HMAC key import failed")]
    HmacKeyImportError,
    /// HMAC key export failed.
    #[error("HMAC key export failed")]
    HmacKeyExportError,
    /// Output buffer is too small for HMAC operation.
    #[error("HMAC buffer too small")]
    HmacBufferTooSmall,
    /// Failed to retrieve HMAC property.
    #[error("HMAC get property failed")]
    HmacGetPropertyError,
    /// Output buffer is too small to hold HMAC signature.
    #[error("HMAC signature buffer too small")]
    HmacSignatureBufferTooSmall,
    /// HMAC signing operation failed.
    #[error("HMAC sign failed")]
    HmacSignError,
    /// HMAC signing context initialization failed.
    #[error("HMAC sign initialization failed")]
    HmacSignInitError,
    /// HMAC signing update operation failed.
    #[error("HMAC sign update failed")]
    HmacSignUpdateError,
    /// HMAC signing finalization failed.
    #[error("HMAC sign finalization failed")]
    HmacSignFinishError,
    /// HMAC verification operation failed.
    #[error("HMAC verify failed")]
    HmacVerifyError,
    /// HMAC verification context initialization failed.
    #[error("HMAC verify initialization failed")]
    HmacVerifyInitError,
    /// HMAC verification update operation failed.
    #[error("HMAC verify update failed")]
    HmacVerifyUpdateError,
    /// HMAC verification finalization failed.
    #[error("HMAC verify finalization failed")]
    HmacVerifyFinishError,
    /// HMAC invalid derived key length.
    #[error("HMAC invalid derived key length")]
    HmacInvalidDerivedKeyLength,

    // DER encoding/decoding errors
    /// Invalid ASN.1 Object Identifier in DER structure.
    #[error("DER invalid Object Identifier")]
    DerInvalidOid,
    /// Invalid key parameter or length in DER structure.
    #[error("DER invalid parameter")]
    DerInvalidParameter,
    /// Failed to decode ASN.1 DER structure.
    #[error("DER ASN.1 decode error")]
    DerAsn1DecodeError,
    /// Failed to encode ASN.1 DER structure.
    #[error("DER ASN.1 encode error")]
    DerAsn1EncodeError,
    /// Output buffer is too small for DER-encoded data.
    #[error("DER buffer too small")]
    DerBufferTooSmall,
    /// Invalid public key format in DER structure.
    #[error("DER invalid public key")]
    DerInvalidPubKey,
    /// Invalid digest size for the specified hash algorithm.
    #[error("DER invalid digest size")]
    DerInvalidDigestSize,

    // ECC-related errors
    /// ECC key generation failed.
    #[error("ECC key generation failed")]
    EccKeyGenError,
    /// ECC key import failed.
    #[error("ECC key import failed")]
    EccKeyImportError,
    /// ECC key export failed.
    #[error("ECC key export failed")]
    EccKeyExportError,
    /// Output buffer is too small for ECC operation.
    #[error("ECC buffer too small")]
    EccBufferTooSmall,
    /// ECC key size is invalid.
    #[error("ECC invalid key size")]
    EccInvalidKeySize,
    /// General ECC operation failure.
    #[error("ECC operation failed")]
    EccError,
    /// ECC signing operation failed.
    #[error("ECC sign failed")]
    EccSignError,
    /// ECC verification operation failed.
    #[error("ECC verify failed")]
    EccVerifyError,

    // ECDH-related errors
    /// ECDH key derivation operation failed.
    #[error("ECDH operation failed")]
    EcdhError,
    /// ECDH set peer key property failed.
    #[error("ECDH set property failed")]
    EcdhSetPropertyError,
    /// ECDH derive operation failed.
    #[error("ECDH derive failed")]
    EcdhDeriveError,

    /// ECDH invalid derived key length.
    #[error("ECDH invalid derived key length")]
    EcdhInvalidDerivedKeyLength,

    // RSA-related errors
    /// General RSA operation failure.
    #[error("RSA operation failed")]
    RsaError,
    /// Invalid RSA key size.
    #[error("RSA invalid key size")]
    RsaInvalidKeySize,
    /// RSA key generation failed.
    #[error("RSA key generation failed")]
    RsaKeyGenError,
    /// RSA key import failed.
    #[error("RSA key import failed")]
    RsaKeyImportError,
    /// RSA key export failed.
    #[error("RSA key export failed")]
    RsaKeyExportError,
    /// RSA encryption operation failed.
    #[error("RSA encryption failed")]
    RsaEncryptError,
    /// RSA decryption operation failed.
    #[error("RSA decryption failed")]
    RsaDecryptError,
    /// Invalid hash algorithm for RSA operation.
    #[error("RSA invalid hash algorithm")]
    RsaInvalidHashAlgorithm,
    /// Output buffer is too small for RSA operation.
    #[error("RSA buffer too small")]
    RsaBufferTooSmall,
    /// Failed to set RSA property.
    #[error("RSA set property failed")]
    RsaSetPropertyError,
    /// RSA signing operation failed.
    #[error("RSA sign failed")]
    RsaSignError,
    /// RSA signing update operation failed.
    #[error("RSA sign update failed")]
    RsaSignUpdateError,
    /// RSA signing finalization failed.
    #[error("RSA sign finalization failed")]
    RsaSignFinishError,
    /// RSA verification operation failed.
    #[error("RSA verify failed")]
    RsaVerifyError,
    /// RSA verification update operation failed.
    #[error("RSA verify update failed")]
    RsaVerifyUpdateError,
    /// RSA verification finalization failed.
    #[error("RSA verify finalization failed")]
    RsaVerifyFinishError,
    /// Invalid RSA private key blob format.
    #[error("RSA invalid private key blob")]
    RsaInvalidPrivateKeyBlob,
    /// Invalid RSA public key blob format.
    #[error("RSA invalid public key blob")]
    RsaInvalidPublicKeyBlob,
    /// RSA modulus size is not supported.
    #[error("RSA unsupported modulus size")]
    RsaUnsupportedModulusSize,
    /// RSA message is too long for the given key size and padding scheme.
    #[error("RSA message too long")]
    RsaMessageTooLong,
    /// RSA padding is invalid or verification failed.
    #[error("RSA invalid padding")]
    RsaInvalidPadding,

    /// HKDF operation failed.
    #[error("HKDF operation failed")]
    HkdfError,
    /// HKDF initialization or property setting failed.
    #[error("HKDF initialization failed")]
    HkdfSetPropertyError,
    /// HKDF key derivation operation failed.
    #[error("HKDF derive operation failed")]
    HkdfDeriveError,
    /// HKDF invalid PRK length.
    #[error("HKDF invalid PRK length")]
    HkdfInvalidPrkLength,

    /// KBKDF operation failed.
    #[error("KBKDF operation failed")]
    KbkdfError,
    /// KBKDF initialization or property setting failed.
    #[error("KBKDF initialization failed")]
    KbkdfSetPropertyError,
    /// KBKDF key derivation operation failed.
    #[error("KBKDF derive operation failed")]
    KbkdfDeriveError,
    /// KBKDF invalid derived key length.
    #[error("KBKDF invalid derived key length")]
    KbkdfInvalidDerivedKeyLength,
    /// KBKDF invalid prk
    #[error("KBKDF invalid prk length")]
    KbkdfInvalidKdkLength,

    /// AES-GCM related errors

    /// AES-GCM invalid IV length.
    #[error("AES-GCM invalid IV length")]
    GcmInvalidIvLength,
    /// AES-GCM invalid tag length.
    #[error("AES-GCM invalid tag length")]
    GcmInvalidTagLength,
    /// AES-GCM output buffer is too small.
    #[error("AES-GCM output buffer too small")]
    GcmBufferTooSmall,
    /// AES-GCM invalid key size.
    #[error("AES-GCM invalid key size")]
    GcmInvalidKeySize,
    /// AES-GCM encryption operation failed.
    #[error("AES-GCM encryption failed")]
    GcmEncryptionFailed,
    /// AES-GCM decryption operation failed.
    #[error("AES-GCM decryption failed")]
    GcmDecryptionFailed,
}

/// Macro for defining platform-specific algorithm type aliases.
///
/// This macro creates platform-specific type aliases for cryptographic algorithms,
/// allowing different implementations on Linux and Windows.
macro_rules! define_type {
    ($vis:vis $name: ident, $linux_type: ty, $windows_type: ty) => {
        /// Default key type for the current platform
        #[cfg(target_os = "linux")]
        $vis type $name = $linux_type;

        /// Default key type for the current platform
        #[cfg(target_os = "windows")]
        $vis type $name = $windows_type;
    };
    ($vis:vis $name: ident<$lt:lifetime>, $linux_type: ty, $windows_type: ty) => {
        /// Default key type for the current platform
        #[cfg(target_os = "linux")]
        $vis type $name<$lt> = $linux_type;

        /// Default key type for the current platform
        #[cfg(target_os = "windows")]
        $vis type $name<$lt> = $windows_type;
    };

    ($vis:vis $name: ident<$lt:lifetime, $t1:ident>, $linux_type: ty, $windows_type: ty) => {
        /// Default key type for the current platform
        #[cfg(target_os = "linux")]
        $vis type $name<$lt, $t1> = $linux_type;

        /// Default key type for the current platform
        #[cfg(target_os = "windows")]
        $vis type $name<$lt, $t1> = $windows_type;
    };
}

pub(crate) use define_type;
