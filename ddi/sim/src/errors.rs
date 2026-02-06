// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Errors reported by Manticore operations.

use azihsm_ddi_types::DdiStatus;
// Imports for use in doc links.
#[allow(unused)]
use {crate::session::UserSession, uuid::Uuid};

/// Errors reported by Manticore operations.
///
/// # Links
/// * [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
/// * [CBOR](https://en.wikipedia.org/wiki/CBOR)
/// * [PKCS8](https://en.wikipedia.org/wiki/PKCS_8)
///
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ManticoreError {
    /// The argument is invalid.
    InvalidArgument,

    /// Unexpected failure
    InternalError,

    /// A session is not expected in this context.
    SessionNotExpected,

    /// A session is not expected in this context.
    SessionExpected,

    /// Not enough space exists to store keys.
    NotEnoughSpace,

    /// The maximum number of keys that can be stored has been reached.
    ReachedMaxKeys,

    /// The supplied key index is invalid.
    InvalidKeyIndex,

    /// The key could not be deleted because it is in use. Please try to delete it again later.
    /// However, it has been disabled for new requests.
    CannotDeleteKeyInUse,

    /// More than one keys could not be deleted because they are in use. Please try to delete them again later.
    /// However, they have been disabled for new requests.
    CannotDeleteSomeKeysInUse,

    /// The session could not be closed because it is in use. Please try to close it again later.
    /// However, it has been disabled for new requests.
    CannotCloseSessionInUse,

    /// More than one session could not be closed because it is in use. Please try to close it again later.
    /// However, it has been disabled for new requests.
    CannotCloseSomeSessionsInUse,

    /// Both at least one session and one key, each, could not be closed or deleted. Please try to close it again later.
    /// However, both session(s) and key(s) have been disabled for new requests.
    CannotDeleteKeyAndCloseSessionInUse,

    /// The app with given [Uuid] does not exist.
    AppNotFound,

    /// An app with given key already exists.
    AppAlreadyExists,

    /// The supplied key number is invalid.
    InvalidKeyNumber,

    /// The key was not found.
    KeyNotFound,

    /// Another key with given tag already exists.
    KeyTagAlreadyExists,

    /// This key can only be set once
    KeyAlreadyExists,

    /// The vault with given [Uuid] does not exist.
    VaultNotFound,

    /// The maximum number of sessions that can be active on the vault has been reached.
    VaultSessionLimitReached,

    /// The maximum number of apps that can be created have been created.
    VaultAppLimitReached,

    /// The supplied credentials are invalid.
    InvalidVaultManagerCredentials,

    /// The supplied credentials are invalid.
    InvalidAppCredentials,

    /// The credentials are default values, and should be changed before some operations.
    CannotUseDefaultCredentials,

    /// The supplied [Uuid] is reserved for internal use.
    /// Note: mapped to DdiStatus::EInvalidarg
    CannotUseReservedId,

    /// [AppSession] with given id does not exit.
    SessionNotFound,

    /// Session exists but needs renegotiation.
    SessionNeedsRenegotiation,

    /// The function is not found.
    FunctionNotFound,

    /// Unsupported API revision.
    UnsupportedRevision,

    /// Generic invalid key type error.
    InvalidKeyType,

    /// DER-encoded content does not decode to provided key type.
    DerAndKeyTypeMismatch,

    /// The key could not be read from DER-encoded format.
    RsaFromDerError,

    /// The key could not be converted to DER-encoded format.
    RsaToDerError,

    /// RSA key generation failed.
    RsaGenerateError,

    /// RSA encryption failed.
    RsaEncryptError,

    /// RSA decryption failed.
    RsaDecryptError,

    /// RSA signing failed.
    RsaSignError,

    /// RSA verification failed.
    RsaVerifyError,

    /// Get RSA modulus failed.
    RsaGetModulusError,

    /// Get RSA public exponent failed.
    RsaGetPublicExponentError,

    /// The key used for a cryptographic operation does not have expected type.
    RsaInvalidKeyType,

    /// The length of requested key is invalid. It can only be one of `[2048, 3072, 4096]`.
    RsaInvalidKeyLength,

    /// Not enough permissions to execute the requested operation.
    InvalidPermissions,

    /// Decoding from CBOR representation failed.
    CborDecodeError,

    /// Encoding to CBOR representation failed.
    CborEncodeError,

    /// The key could not be read from DER-encoded format.
    EccFromDerError,

    /// The key could not be converted to DER-encoded format.
    EccToDerError,

    /// ECC key generation failed.
    EccGenerateError,

    /// ECC signing failed.
    EccSignError,

    /// ECC verification failed.
    EccVerifyError,

    /// ECC Key derivation failed.
    EccDeriveError,

    /// Get ECC curve failed.
    EccGetCurveError,

    /// Get ECC coordinates failed.
    EccGetCoordinatesError,

    /// Sha computation failed.
    ShaError,

    /// The key used for a cryptographic operation does not have expected type.
    EccInvalidKeyType,

    /// AES Generate failed.
    AesGenerateError,

    /// AES Encryption failed.
    AesEncryptError,

    /// AES Decryption failed.
    AesDecryptError,

    /// The key used for a cryptographic operation does not have expected type.
    AesInvalidKeyType,

    /// The CoseSign1 signature is unexpected.
    CoseSign1UnexpectedSignature,

    /// HKDF failed.
    HkdfError,

    /// KBKDF failed.
    KbkdfError,

    /// HMAC operation failed.
    HmacError,

    /// PIN decryption failed because of tag/Hmac mismatch
    PinDecryptionFailed,

    /// RSA unwrap invalid request.
    RsaUnwrapInvalidReq,

    /// RSA unwrap invalid unwrapping key.
    RsaUnwrapInvalidUnwrappingKeyLength,

    /// RSA-Oaep decryption failed during RSA unwrap command.
    RsaUnwrapRsaOaepDecryptFailed,

    /// AES unwrap failed during RSA unwrap command.
    RsaUnwrapAesUnwrapFailed,

    /// Attest Key internal errors
    AttestKeyInternalErr,

    /// FP AES error codes
    /// AesGcmInvalidBufSize
    ///  buffer size is not valid
    ///
    AesGcmInvalidBufSize,

    /// AesInvalidShortAppId
    /// Short app id provided is not
    /// valid
    AesInvalidShortAppId,

    /// AesInvalidTag
    AesInvalidTag,

    /// FP AES XTS error code
    AesXtsInvalidBufSize,

    /// Data unit length provided
    /// is not valid
    AesXtsInvalidDul,

    /// The length of ECC key is invalid. It can only be one of `[256, 384, 521]`.
    EccInvalidKeyLength,

    /// The length of ECC key is invalid. It can only be one of `[16, 24, 32]`.
    AesInvalidKeyLength,

    /// Error in generating a public key certificate.
    EccPubKeyCertGenerateError,

    /// Cannot delete internal keys, such as RSA unwrap key
    CannotDeleteInternalKeys,

    /// RNG Error
    RngError,

    /// Nonce mismatch
    NonceMismatch,

    /// Masked key length is not valid
    MaskedKeyInvalidLength,

    /// Masked key pre-encode failed
    MaskedKeyPreEncodeFailed,

    /// Masked key encode failed
    MaskedKeyEncodeFailed,

    /// Masked key decode failed
    MaskedKeyDecodeFailed,

    /// Partition already provisioned
    PartitionAlreadyProvisioned,

    /// Sealed BK3 data is too large
    SealedBk3TooLarge,

    /// Sealed BK3 not present on device
    SealedBk3NotPresent,

    /// Credentials haven't been established. Cannot open a session
    CredentialsNotEstablished,

    /// Partition has not been provisioned.
    PartitionNotProvisioned,

    /// Invalid algorithm specified
    InvalidAlgorithm,

    /// Output buffer provided is too small
    OutputBufferTooSmall,

    /// Invalid parameter provided
    InvalidKeyLength,

    /// Mbor encoding failed
    MborEncodeFailed,

    /// Mbor decoding failed
    MetadataEncodeFailed,

    /// Mbor decoding failed
    MetadataDecodeFailed,

    /// AES encryption failed
    AesEncryptFailed,

    /// AES decryption failed
    AesDecryptFailed,

    /// Report signature does not match
    ReportSignatureMismatch,
    /// Bk3 Already Initialized
    Bk3AlreadyInitialized,

    /// Sealed BK3 already set
    SealedBk3AlreadySet,

    /// Partition ID Key Generation PCT failed
    PartitionIdKeyGenerationPctFailed,
}

impl From<ManticoreError> for DdiStatus {
    fn from(value: ManticoreError) -> Self {
        match value {
            ManticoreError::InvalidArgument => DdiStatus::InvalidArg,
            ManticoreError::InternalError => DdiStatus::InternalError,
            ManticoreError::AppNotFound => DdiStatus::AppNotFound,
            ManticoreError::AppAlreadyExists => DdiStatus::AppAlreadyExists,
            ManticoreError::VaultNotFound => DdiStatus::VaultNotFound,
            ManticoreError::VaultSessionLimitReached => DdiStatus::VaultSessionLimitReached,
            ManticoreError::InvalidVaultManagerCredentials => DdiStatus::InvalidManagerCredentials,
            ManticoreError::InvalidAppCredentials => DdiStatus::InvalidAppCredentials,
            ManticoreError::CannotUseDefaultCredentials => DdiStatus::CannotUseDefaultCredentials,
            ManticoreError::CannotUseReservedId => DdiStatus::InvalidArg,
            ManticoreError::SessionNotExpected => DdiStatus::SessionNotExpected,
            ManticoreError::SessionExpected => DdiStatus::SessionExpected,
            ManticoreError::CborDecodeError => DdiStatus::DdiDecodeFailed,
            ManticoreError::CborEncodeError => DdiStatus::DdiEncodeFailed,
            ManticoreError::SessionNotFound => DdiStatus::SessionNotFound,
            ManticoreError::SessionNeedsRenegotiation => DdiStatus::SessionNeedsRenegotiation,
            ManticoreError::InvalidKeyIndex => DdiStatus::KeyNotFound,
            ManticoreError::KeyNotFound => DdiStatus::KeyNotFound,
            ManticoreError::KeyTagAlreadyExists => DdiStatus::KeyTagAlreadyExists,
            ManticoreError::KeyAlreadyExists => DdiStatus::KeyTagAlreadyExists,
            ManticoreError::RsaInvalidKeyType => DdiStatus::InvalidKeyType,
            ManticoreError::InvalidKeyType => DdiStatus::InvalidKeyType,
            ManticoreError::DerAndKeyTypeMismatch => DdiStatus::DerAndKeyTypeMismatch,
            ManticoreError::RsaFromDerError => DdiStatus::KeyDecodeFailed,
            ManticoreError::NotEnoughSpace => DdiStatus::NotEnoughSpace,
            ManticoreError::ReachedMaxKeys => DdiStatus::ReachedMaxKeys,
            ManticoreError::CannotDeleteKeyInUse => DdiStatus::CannotDeleteKeyInUse,
            ManticoreError::CannotDeleteSomeKeysInUse => DdiStatus::CannotDeleteSomeKeysInUse,
            ManticoreError::CannotCloseSessionInUse => DdiStatus::CannotCloseSessionInUse,
            ManticoreError::CannotCloseSomeSessionsInUse => DdiStatus::CannotCloseSomeSessionsInUse,
            ManticoreError::CannotDeleteKeyAndCloseSessionInUse => {
                DdiStatus::CannotDeleteKeyAndCloseSessionInUse
            }
            ManticoreError::InvalidKeyNumber => DdiStatus::InvalidKeyNumber,
            ManticoreError::FunctionNotFound => DdiStatus::FunctionNotFound,
            ManticoreError::UnsupportedRevision => DdiStatus::UnsupportedRevision,
            ManticoreError::RsaToDerError => DdiStatus::RsaToDerError,
            ManticoreError::RsaGenerateError => DdiStatus::RsaGenerateError,
            ManticoreError::RsaEncryptError => DdiStatus::InternalError, // only internal-facing API will throw ManticoreError::RsaEncryptError
            ManticoreError::RsaDecryptError => DdiStatus::RsaDecryptFailed,
            ManticoreError::RsaSignError => DdiStatus::RsaSignFailed,
            ManticoreError::RsaVerifyError => DdiStatus::InternalError, // only internal-facing API will throw ManticoreError::RsaVerifyError
            ManticoreError::RsaGetModulusError => DdiStatus::RsaGetModulusError,
            ManticoreError::RsaGetPublicExponentError => DdiStatus::RsaGetPublicExponentError,
            ManticoreError::RsaInvalidKeyLength => DdiStatus::RsaInvalidKeyLength,
            ManticoreError::InvalidPermissions => DdiStatus::InvalidPermissions,
            ManticoreError::EccFromDerError => DdiStatus::KeyDecodeFailed,
            ManticoreError::EccToDerError => DdiStatus::EccToDerError,
            ManticoreError::EccGenerateError => DdiStatus::EccGenerateError,
            ManticoreError::EccSignError => DdiStatus::EccSignFailed,
            ManticoreError::EccVerifyError => DdiStatus::InternalError, // only internal-facing API will throw ManticoreError::EccVerifyError
            ManticoreError::EccDeriveError => DdiStatus::EccDeriveError,
            ManticoreError::EccGetCurveError => DdiStatus::EccGetCurveError,
            ManticoreError::EccGetCoordinatesError => DdiStatus::EccGetCoordinatesError,
            ManticoreError::ShaError => DdiStatus::ShaError,
            ManticoreError::HmacError => DdiStatus::HmacError,
            ManticoreError::PinDecryptionFailed => DdiStatus::PinDecryptionFailed,
            ManticoreError::EccInvalidKeyType => DdiStatus::InvalidKeyType,
            ManticoreError::AesGenerateError => DdiStatus::AesGenerateError,
            ManticoreError::AesEncryptError => DdiStatus::AesEncryptFailed,
            ManticoreError::AesDecryptError => DdiStatus::AesDecryptFailed,
            ManticoreError::AesInvalidKeyType => DdiStatus::InvalidKeyType,
            ManticoreError::CoseSign1UnexpectedSignature => DdiStatus::CoseSign1UnexpectedSignature,
            ManticoreError::HkdfError => DdiStatus::HkdfError,
            ManticoreError::VaultAppLimitReached => DdiStatus::VaultAppLimitReached,
            ManticoreError::KbkdfError => DdiStatus::KbkdfError,
            ManticoreError::RsaUnwrapInvalidReq => DdiStatus::RsaUnwrapInvalidRequest,
            ManticoreError::RsaUnwrapInvalidUnwrappingKeyLength => DdiStatus::RsaUnwrapInvalidKek,
            ManticoreError::RsaUnwrapRsaOaepDecryptFailed => DdiStatus::RsaUnwrapOaepDecodeFailed,
            ManticoreError::RsaUnwrapAesUnwrapFailed => DdiStatus::RsaUnwrapAesUnwrapFailed,
            ManticoreError::AesGcmInvalidBufSize => DdiStatus::AesGcmInvalidBufferSize,
            ManticoreError::AesInvalidShortAppId => DdiStatus::InvalidShortAppId,
            ManticoreError::AesInvalidTag => DdiStatus::AesGcmDecryptTagDoesNotMatch,
            ManticoreError::AttestKeyInternalErr => DdiStatus::AttestKeyInternalError,
            ManticoreError::AesXtsInvalidBufSize => DdiStatus::AesXtsInvalidBufferSize,
            ManticoreError::AesXtsInvalidDul => DdiStatus::AesXtsInvalidDul,
            ManticoreError::EccInvalidKeyLength => DdiStatus::EccInvalidKeyLength,
            ManticoreError::AesInvalidKeyLength => DdiStatus::AesInvalidKeyLength,
            ManticoreError::EccPubKeyCertGenerateError => DdiStatus::InvalidCertificate,
            ManticoreError::CannotDeleteInternalKeys => DdiStatus::CannotDeleteInternalKeys,
            ManticoreError::RngError => DdiStatus::RngError,
            ManticoreError::NonceMismatch => DdiStatus::NonceMismatch,
            ManticoreError::MaskedKeyInvalidLength => DdiStatus::MaskedKeyInvalidLength,
            ManticoreError::MaskedKeyPreEncodeFailed => DdiStatus::MaskedKeyPreEncodeFailed,
            ManticoreError::MaskedKeyEncodeFailed => DdiStatus::MaskedKeyEncodeFailed,
            ManticoreError::MaskedKeyDecodeFailed => DdiStatus::MaskedKeyDecodeFailed,
            ManticoreError::PartitionAlreadyProvisioned => DdiStatus::PartitionAlreadyProvisioned,
            ManticoreError::SealedBk3NotPresent => DdiStatus::SealedBk3NotPresent,
            ManticoreError::SealedBk3TooLarge => DdiStatus::SealedBk3TooLarge,
            ManticoreError::CredentialsNotEstablished => DdiStatus::CredentialsNotEstablished,
            ManticoreError::PartitionNotProvisioned => DdiStatus::PartitionNotProvisioned,
            ManticoreError::InvalidAlgorithm => DdiStatus::InvalidArg,
            ManticoreError::OutputBufferTooSmall => DdiStatus::InvalidArg,
            ManticoreError::InvalidKeyLength => DdiStatus::InvalidArg,
            ManticoreError::MborEncodeFailed => DdiStatus::InvalidArg,
            ManticoreError::MetadataEncodeFailed => DdiStatus::InvalidArg,
            ManticoreError::MetadataDecodeFailed => DdiStatus::InvalidArg,
            ManticoreError::AesEncryptFailed => DdiStatus::InvalidArg,
            ManticoreError::AesDecryptFailed => DdiStatus::InvalidArg,
            ManticoreError::ReportSignatureMismatch => DdiStatus::InvalidArg,
            ManticoreError::Bk3AlreadyInitialized => DdiStatus::Bk3AlreadyInitialized,
            ManticoreError::SealedBk3AlreadySet => DdiStatus::SealedBk3AlreadySet,
            ManticoreError::PartitionIdKeyGenerationPctFailed => {
                DdiStatus::PartitionIdKeyGenerationPctFailed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // This test helps achieve 100% test coverage
    // as debug trait is mainly used for test purposes
    #[test]
    fn test_debug_trait_print() {
        println!("ManticoreError {:?}", ManticoreError::InvalidKeyNumber);
    }
}
