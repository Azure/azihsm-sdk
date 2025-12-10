// Copyright (C) Microsoft Corporation. All rights reserved.

mod aes;
mod ecc;
mod ecdh;
mod ecdsa;
mod eckey;
mod hkdf;
mod hmac;
mod kbkdf;
mod rand;
mod rsa;
mod secretkey;
mod sha;

pub use aes::*;
pub use ecc::*;
pub use ecdh::*;
pub use ecdsa::*;
pub use eckey::*;
pub use hkdf::*;
pub use hmac::*;
pub use kbkdf::*;
pub use rand::*;
pub use rsa::*;
pub use secretkey::*;
pub use sha::*;
use thiserror::Error;

/// HSM Error
#[derive(Error, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// SHA error
    #[error("sha error")]
    ShaError,
    #[error("sha invalid digest size")]
    ShaDigestSizeError,

    //AES related erros
    #[error("AES invalid key size")]
    AesKeySizeError,
    #[error("AES invalid data size")]
    AesDataSizeError,
    #[error("AES invalid IV ")]
    AesInvalidIVError,
    #[error("AES Key Generation Error")]
    AesKeyGenError,
    #[error("AES Encryption Error")]
    AesEncryptError,
    #[error("AES Decryption Error")]
    AesDecryptError,
    #[error("AES Error")]
    AesError,

    //ECC Error
    #[error("ecc error")]
    EccError,
    #[error("ecc Unsupported curve in Key generation")]
    EccUnsupportedCurveInKeyGen,
    #[error("ecc sign error")]
    EccSignError,
    #[error("ecc verify error")]
    EccVerifyError,
    #[error("ECC Unsupported Hash Algorithm")]
    EccUnsupportedHashAlgorithm,
    #[error("ECC Unsupported Digest size")]
    EccUnsupportedDigestSize,
    #[error("ECC Unsupported EC feature")]
    EccUnsupportedFeaure,
    #[error("ECC Key Import failed")]
    EcImportFailed,
    #[error("ECC Key Export failed")]
    EcExportFailed,
    #[error("ECC Invalid key")]
    EcInvalidKey,
    #[error("ECC Error caused by backend crypto")]
    EcBackendError,
    #[error("ECC invalid signature size")]
    EcdsaInvalidRawSignatureSize,
    #[error("Buffer is too small")]
    EcBufferTooSmall,
    /// ASN.1 parse error
    #[error("ASN.1 parse error")]
    EcAsn1ParseError,
    /// Curve mismatch or unsupported curve
    #[error("Curve mismatch or unsupported curve")]
    EcCurveMismatch,
    /// Key size mismatch (expected vs actual)
    #[error("Key size mismatch")]
    EcKeySizeMismatch,

    // HMAC
    #[error("Invalid signature size")]
    HmacSignatureBufferTooSmall,
    #[error("HMAC Backend error")]
    HmacBackendFail,
    #[error("HMAC Failed to sign the data")]
    HmacSignFail,
    #[error("HMAC signature length mismatch")]
    HmacSignatureLengthMismatch,
    #[error("HMAC verify failed")]
    HmacVerifyFail,
    #[error("HMAC signature mismatch")]
    HmacSignatureMismatch,
    /// Returned when the HMAC key is empty, which is not allowed by the backend.
    #[error("HMAC key is empty")]
    HmacKeyEmpty,
    /// Returned when the HMAC key size is not within the valid range for the algorithm.
    #[error("HMAC key size is invalid for the selected algorithm")]
    HmacInvalidKeySize,
    /// Returned when the HMAC key is shorter than the minimum allowed for the hash algorithm.
    #[error("HMAC key is too short")]
    HmacKeyTooShort,
    /// Returned when the HMAC key is longer than the maximum allowed for the hash algorithm.
    #[error("HMAC key is too long")]
    HmacKeyTooLong,
    /// Output length must be greater than zero
    #[error("Output length must be greater than zero")]
    InvalidOutputLength,

    /// Unsupported hash algorithm
    #[error("Unsupported hash algorithm")]
    UnsupportedHashAlgorithm,

    /// Failed to create CNG secret
    #[error("Failed to create CNG secret")]
    SecretCreationFailed,

    /// KBKDF key derivation failed
    #[error("KBKDF key derivation failed")]
    KeyDerivationFailed,

    /// KBKDF PKey error
    #[error("KBKDF: PKey::hmac failed")]
    KbkdfPKeyError,

    /// KBKDF Signer error
    #[error("KBKDF: Signer::new failed")]
    KbkdfSignerError,

    /// KBKDF Signer update error
    #[error("KBKDF: signer.update failed")]
    KbkdfSignerUpdateError,

    /// KBKDF Signer sign_to_vec error
    #[error("KBKDF: signer.sign_to_vec failed")]
    KbkdfSignToVecError,

    /// KBKDF output buffer too small
    #[error("KBKDF: output buffer too small")]
    OutputBufferTooSmall,
    ///RSA Error
    #[error("RSA Error")]
    RsaError,
    /// RSA key size is less than the minimum allowed
    #[error("RSA key size too small")]
    RsaKeySizeTooSmall,
    /// RSA key size is greater than the maximum allowed
    #[error("RSA key size too large")]
    RsaKeySizeTooLarge,
    /// RSA key size is not a valid step
    #[error("RSA key size invalid step")]
    RsaKeySizeInvalidStep,
    /// RSA invalid key size
    #[error("RSA invalid key size")]
    RsaInvalidKeySize,
    /// Failed to open RSA algorithm provider
    #[error("RSA algorithm provider open failed")]
    RsaAlgoOpenFailed,
    /// Failed to generate RSA key pair
    #[error("RSA key pair generation failed")]
    RsaKeyPairGenFailed,
    /// Failed to extract RSA public key using OpenSSL
    #[error("RSA public key extraction failed (OpenSSL)")]
    RsaPublicKeyExtractFailed,
    /// Failed to finalize RSA key pair
    #[error("RSA key pair finalize failed")]
    RsaKeyPairFinalizeFailed,
    /// Failed to cleanup after RSA key pair finalize
    #[error("RSA key pair cleanup failed")]
    RsaKeyPairCleanupFailed,
    /// RSA DER buffer is empty
    #[error("RSA DER buffer is empty")]
    RsaDerBufferEmpty,
    /// Failed to get private key blob size for export
    #[error("RSA export blob size failed")]
    RsaExportBlobSizeFailed,
    /// Failed to export private key blob
    #[error("RSA export blob failed")]
    RsaExportBlobFailed,
    /// Failed to encode DER
    #[error("RSA DER encode failed")]
    RsaDerEncodeFailed,
    /// DER buffer provided is too small
    #[error("RSA DER buffer too small")]
    RsaDerBufferTooSmall,
    /// Failed to decode DER for RSA key
    #[error("RSA DER decode failed")]
    RsaDerDecodeFailed,
    /// Failed to import private key into CNG
    #[error("RSA import key failed")]
    RsaImportKeyFailed,
    /// Input data to encrypt is empty
    #[error("RSA encrypt input is empty")]
    RsaEncryptInputEmpty,
    /// Output buffer for cipher data is empty
    #[error("RSA encrypt output buffer is empty")]
    RsaEncryptOutputBufferEmpty,
    /// Failed to get expected cipher length
    #[error("RSA encrypt get cipher length failed")]
    RsaEncryptGetCipherLenFailed,
    /// Cipher buffer size is too small
    #[error("RSA encrypt output buffer too small")]
    RsaEncryptOutputBufferTooSmall,
    /// Failed to encrypt data
    #[error("RSA encrypt failed")]
    RsaEncryptFailed,
    /// Expected cipher text length does not match actual length
    #[error("RSA encrypt length mismatch")]
    RsaEncryptLengthMismatch,
    /// Input cipher data to decrypt is empty
    #[error("RSA decrypt input is empty")]
    RsaDecryptInputEmpty,
    /// Output buffer for decrypted data is empty
    #[error("RSA decrypt output buffer is empty")]
    RsaDecryptOutputBufferEmpty,
    /// Failed to get expected plain text length
    #[error("RSA decrypt get plain text length failed")]
    RsaDecryptGetPlainLenFailed,
    /// Decrypted buffer size is too small
    #[error("RSA decrypt output buffer too small")]
    RsaDecryptOutputBufferTooSmall,
    /// Failed to decrypt data
    #[error("RSA decrypt failed")]
    RsaDecryptFailed,
    /// Expected plain text length does not match actual length
    #[error("RSA decrypt length mismatch")]
    RsaDecryptLengthMismatch,
    /// Failed to decode PKCS#1 DER for RSA key
    #[error("RSA PKCS#1 DER decode failed")]
    RsaDecodeFailed,
    /// Failed to compute CRT inverse for RSA key
    #[error("RSA CRT inverse failed")]
    RsaCrtInverseFailed,
    /// Invalid block size for padding none
    #[error("RSA Input data is wrong size for padding none ")]
    RsaEncryptInputWrongSize,
    /// Feature not yet implemented
    #[error("Rsa sub feature not implemented yet")]
    RsaFeatureNotImplemented,
    /// Invalid salt length for RSA-PSS
    #[error("RSA PSS salt length is invalid for the given hash algorithm")]
    RsaPssSaltlenInvalid,
    /// Signature is invalid
    #[error("RSA signature is invalid")]
    RsaSignatureInvalid,
    /// Signature verification failed
    #[error("RSA signature verification failed ")]
    RsaSignatureFailed,
    /// Failed to create signature verifier
    #[error("RSA signature verifier creation failed")]
    RsaSignatureVerifierCreateFailed,
    /// Failed to set signature padding
    #[error("RSA signature set padding failed")]
    RsaSignatureSetPaddingFailed,
    /// Failed to set PSS salt length
    #[error("RSA signature set PSS salt length failed")]
    RsaSignatureSetPssSaltlenFailed,
    /// Failed to update verifier with data
    #[error("RSA signature verifier update failed")]
    RsaSignatureVerifierUpdateFailed,
    /// Output buffer for signature is too small
    #[error("RSA sign output buffer too small")]
    RsaSignOutputBufferTooSmall,
    /// Input data to verify is empty
    #[error("RSA verify input is empty")]
    RsaVerifyInputEmpty,
    /// Signature to verify is empty
    #[error("RSA verify signature is empty")]
    RsaVerifySignatureEmpty,
    /// Signature verification failed
    #[error("RSA verify failed")]
    RsaVerifyFailed,
    /// Feature not yet implemented for RSA decrypt
    #[error("RSA decrypt feature not implemented yet")]
    RsaDecryptFeatureNotImplemented,
    /// Feature not yet implemented for RSA encrypt
    #[error("RSA encrypt feature not implemented yet")]
    RsaEncryptFeatureNotImplemented,
    /// Feature not yet implemented for RSA sign
    #[error("RSA sign feature not implemented yet")]
    RsaSignFeatureNotImplemented,
    /// Feature not yet implemented for RSA verify
    #[error("RSA verify feature not implemented yet")]
    RsaVerifyFeatureNotImplemented,
    /// Failed to sign data
    #[error("RSA sign failed")]
    RsaSignFailed,
    /// Expected signature length does not match actual length
    #[error("RSA sign length mismatch")]
    RsaSignLengthMismatch,
    /// Input data to sign is empty
    #[error("RSA sign input is empty")]
    RsaSignInputEmpty,
    /// Output buffer for signature is empty
    #[error("RSA sign output buffer is empty")]
    RsaSignOutputBufferEmpty,
    /// Not supported by platform or FIPS policy
    #[error("RSA operation not supported by platform or FIPS policy")]
    RsaNotSupported,
    /// Input data to encrypt is too large for the key/padding
    #[error("RSA encrypt input is too large for the key/padding")]
    RsaEncryptInputTooLarge,
    /// AES key to wrap is empty
    #[error("RSA wrap input is empty")]
    RsaWrapInputEmpty,
    /// Output buffer for wrapped key is empty
    #[error("RSA wrap output buffer is empty")]
    RsaWrapOutputBufferEmpty,
    /// AES key length does not match expected size
    #[error("RSA wrap input wrong size")]
    RsaWrapInputWrongSize,
    /// Wrapped key to unwrap is empty
    #[error("RSA unwrap input is empty")]
    RsaUnwrapInputEmpty,
    /// Output buffer for unwrapped key is empty
    #[error("RSA unwrap output buffer is empty")]
    RsaUnwrapOutputBufferEmpty,
    // Unwrap buffer is too small
    #[error("RSA unwrap output buffer too small")]
    RsaUnwrapOutputBufferTooSmall,
    /// Unwrapped AES key length does not match expected size
    #[error("RSA unwrap output wrong size")]
    RsaUnwrapOutputWrongSize,
    /// Output buffer for wrapped blob is too small
    #[error("RSA wrap output buffer too small")]
    RsaWrapOutputBufferTooSmall,
    /// Failed to generate random AES session key
    #[error("RSA wrap AES key generation failed")]
    RsaWrapAesKeyGenFailed,
    /// Failed to encrypt user data with AES
    #[error("RSA wrap AES encryption failed")]
    RsaWrapAesEncryptFailed,
    /// Wrapped blob is too small to contain valid data
    #[error("RSA unwrap input too small")]
    RsaUnwrapInputTooSmall,
    /// Failed to decrypt user data with AES
    #[error("RSA unwrap AES decryption failed")]
    RsaUnwrapAesDecryptFailed,
    /// Invalid wrapped blob format
    #[error("RSA unwrap invalid blob format")]
    RsaUnwrapInvalidBlobFormat,
    // ECDH specific errors
    #[error("ECDH internal error")]
    EcdhInternalError,
    #[error("ECDH key agreement failed")]
    EcdhKeyAgreementFailed,
    #[error("ECDH key derivation failed")]
    EcdhKeyDerivationFailed,
    #[error("ECDH output buffer too small")]
    EcdhBufferTooSmall,
    #[error("ECDH get key size failed")]
    EcdhGetKeySizeFailed,

    //HKDF
    #[error("HKDF key is empty")]
    HkdfSecretCreationFailed,
    #[error("HKDF backend fail")]
    HkdfBackendFail,
    #[error("Unsupported hash algorithm")]
    HkdfUnsupportedHashAlgorithm,
    /// HKDF Extract phase failed during HMAC operations
    #[error("HKDF Extract phase failed")]
    HkdfExtractFailed,
    /// HKDF Expand phase failed during HMAC operations
    #[error("HKDF Expand phase failed")]
    HkdfExpandFailed,
    /// HKDF output length exceeds maximum allowed (255 * hash_len)
    #[error("HKDF output length too large")]
    HkdfOutputTooLarge,
    /// HKDF output length is zero
    #[error("HKDF output length cannot be zero")]
    HkdfOutputLengthZero,
    /// HKDF output buffer is too small for requested length
    #[error("HKDF output buffer too small")]
    HkdfOutputBufferTooSmall,
    /// HKDF PRK (Pseudorandom Key) has invalid length
    #[error("HKDF PRK has invalid length")]
    HkdfInvalidPrkLength,
    /// HKDF HMAC signer creation failed
    #[error("HKDF HMAC signer creation failed")]
    HkdfHmacSignerFailed,
    /// HKDF HMAC key creation failed
    #[error("HKDF HMAC key creation failed")]
    HkdfHmacKeyFailed,

    /// Random number generation failed
    #[error("Random number generation failed")]
    RngError,
}
