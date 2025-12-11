// Copyright (C) Microsoft Corporation. All rights reserved.

#[cfg(all(feature = "use-openssl", feature = "use-symcrypt"))]
compile_error!("OpenSSL and SymCrypt cannot be enabled at the same time.");

pub mod aes;
pub mod cert;
pub mod ecc;
pub mod rand;
pub mod rsa;
pub mod sha;

use thiserror::Error;

/// RSA Encryption/ Decryption Padding
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CryptoRsaCryptoPadding {
    // No Padding
    None,

    /// OAEP Padding
    Oaep,
}

/// RSA Signature Padding
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CryptoRsaSignaturePadding {
    /// PSS Padding
    Pss,

    /// PKCS1.5 Padding
    Pkcs1_5,
}

/// Digest Kind / Hash Algorithm
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CryptoHashAlgorithm {
    /// SHA1
    Sha1,

    /// SHA256
    Sha256,

    /// SHA384
    Sha384,

    /// SHA512
    Sha512,
}

/// Kind of Cryptographic Key.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CryptoKeyKind {
    /// RSA 2048-bit Public Key.
    Rsa2kPublic,

    /// RSA 3072-bit Public Key.
    Rsa3kPublic,

    /// RSA 4096-bit Public Key.
    Rsa4kPublic,

    /// RSA 2048-bit Private Key.
    Rsa2kPrivate,

    /// RSA 3072-bit Private Key.
    Rsa3kPrivate,

    /// RSA 4096-bit Private Key.
    Rsa4kPrivate,

    /// RSA 2048-bit Private CRT Key.
    Rsa2kPrivateCrt,

    /// RSA 3072-bit Private CRT Key.
    Rsa3kPrivateCrt,

    /// RSA 4096-bit Private CRT Key.
    Rsa4kPrivateCrt,

    /// ECC 256 Public Key
    Ecc256Public,

    /// ECC 384 Public Key
    Ecc384Public,

    /// ECC 521 Public Key
    Ecc521Public,

    /// ECC 256 Private Key
    Ecc256Private,

    /// ECC 384 Private Key
    Ecc384Private,

    /// ECC 521 Private Key
    Ecc521Private,

    /// AES 128-bit Key.
    Aes128,

    /// AES 192-bit Key.
    Aes192,

    /// AES 256-bit Key.
    Aes256,

    /// AES XTS Bulk 256-bit Key.
    AesXtsBulk256,

    /// AES GCM Bulk 256-bit Key.
    AesGcmBulk256,

    /// AES GCM Bulk 256-bit Unapproved Key.
    AesGcmBulk256Unapproved,

    /// 256-bit Secret from key exchange
    Secret256,

    /// 384-bit Secret from key exchange
    Secret384,

    /// 521-bit Secret from key exchange
    Secret521,

    /// 256-bit HMAC key for SHA256
    HmacSha256,

    /// 384-bit HMAC key for SHA384
    HmacSha384,

    /// 512-bit HMAC key for SHA512
    HmacSha512,
}

/// HSM Error
#[derive(Error, Debug, PartialEq, Eq, Clone, Copy)]
pub enum CryptoError {
    /// Invalid parameter
    #[error("invalid parameter")]
    InvalidParameter,

    /// Invalid certificate
    #[error("invalid certificate")]
    InvalidCertificate,

    /// RSA Encrypt Failed
    #[error("rsa encrypt failed")]
    RsaEncryptFailed,

    /// RSA Decrypt Failed
    #[error("rsa decrypt failed")]
    RsaDecryptFailed,

    /// RSA Sign Failed
    #[error("rsa sign failed")]
    RsaSignFailed,

    /// RSA Verify Failed
    #[error("rsa verify failed")]
    RsaVerifyFailed,

    /// DER-encoded content does not decode to provided key type.
    #[error("der does not match key type")]
    DerAndKeyTypeMismatch,

    /// ECC Sign Failed
    #[error("ecc sign failed")]
    EccSignFailed,

    /// ECC Verify Failed
    #[error("ecc verify failed")]
    EccVerifyFailed,

    /// AES Encrypt Failed
    #[error("aes encrypt failed")]
    AesEncryptFailed,

    /// AES Decrypt Failed
    #[error("aes decrypt failed")]
    AesDecryptFailed,

    /// RSA to DER error
    #[error("rsa to der error")]
    RsaToDerError,

    /// RSA from DER error
    #[error("rsa from der error")]
    RsaFromDerError,

    /// RSA from raw error
    #[error("rsa from raw error")]
    RsaFromRawError,

    /// RSA generate error
    #[error("rsa generate error")]
    RsaGenerateError,

    /// RSA get modulus error
    #[error("rsa get modulus error")]
    RsaGetModulusError,

    /// RSA get public exponent error
    #[error("rsa get public exponent error")]
    RsaGetPublicExponentError,

    /// RSA invalid key length
    #[error("rsa invalid key length")]
    RsaInvalidKeyLength,

    /// ECC to DER error
    #[error("ecc to der error")]
    EccToDerError,

    /// ECC from DER error
    #[error("ecc from der error")]
    EccFromDerError,

    /// ECC generate error
    #[error("ecc generate error")]
    EccGenerateError,

    /// ECC derive error
    #[error("ecc derive error")]
    EccDeriveError,

    /// ECC get curve error
    #[error("ecc get curve error")]
    EccGetCurveError,

    /// ECC get coordinates error
    #[error("ecc get coordinates error")]
    EccGetCoordinatesError,

    /// SHA error
    #[error("sha error")]
    ShaError,

    /// AES generate error
    #[error("aes generate error")]
    AesGenerateError,

    /// RNG error
    #[error("rng error")]
    RngError,

    /// AES invalid key length
    #[error("aes invalid key length")]
    AesInvalidKeyLength,

    /// HMAC error
    #[error("hmac error")]
    HmacError,

    /// HKDF error
    #[error("HKDF error")]
    HkdfError,

    /// ECC from RAW error
    #[error("ecc from raw error")]
    EccFromRawError,

    /// Failure to create `MborByteArray`
    #[error("failure to create MborByteArray")]
    ByteArrayCreationError,

    /// Output buffer too small
    #[error("output buffer too small")]
    OutputBufferTooSmall,

    /// Invalid algorithm
    #[error("invalid algorithm")]
    InvalidAlgorithm,

    /// Invalid key length
    #[error("invalid key length")]
    InvalidKeyLength,

    /// Metadata encoding failed
    #[error("metadata encoding failed")]
    MetadataEncodeFailed,

    /// Metadata decoding failed
    #[error("metadata decoding failed")]
    MetadataDecodeFailed,

    /// Masked Key Pre-Encoding Failed
    #[error("masked key pre-encoding failed")]
    MaskedKeyPreEncodeFailed,

    /// Masked Key Encoding Failed
    #[error("masked key encoding failed")]
    MaskedKeyEncodeFailed,

    /// Masked Key Decoding Failed
    #[error("masked key decoding failed")]
    MaskedKeyDecodeFailed,

    /// MBOR Encoding Failed
    #[error("mbor encoding failed")]
    MborEncodeFailed,

    /// KBKDF error
    #[error("kbkdf error")]
    KbkdfError,
}
