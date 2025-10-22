// Copyright (C) Microsoft Corporation. All rights reserved.

use mcr_ddi::DdiError;
use mcr_ddi::DriverError;
use mcr_ddi_types::DdiStatus;
use thiserror::Error;

/// HSM Error
#[derive(Clone, Error, Debug, PartialEq, Eq)]
pub enum HsmError {
    /// Invalid parameter
    #[error("invalid parameter")]
    InvalidParameter,

    /// Index out of bounds
    #[error("index out of bounds")]
    IndexOutOfBounds,

    /// Invalid C string
    #[error("invalid C string")]
    InvalidStr,

    /// Invalid C pointer
    #[error("invalid C pointer")]
    InvalidPtr,

    /// HSM device not found
    #[error("device not found")]
    DeviceNotFound,

    /// CBOR encoding failed
    #[error("CBOR encoding failed")]
    CborEncodeFailed,

    /// CBOR decoding failed
    #[error("CBOR decoding failed")]
    CborDecodeFailed,

    /// Session id is not present in the
    ///  device handle.
    #[error("No existing session present in device handle")]
    NoExistingSessionPresentInDeviceHandle,

    /// Only one session allowed per device handle
    #[error("only one session allowed per device handle")]
    OnlyOneSessionAllowedPerDeviceHandle,

    /// Session id provided in request does not match the
    /// open session id
    #[error("session id in request does not match opened session id")]
    SessionIdDoesNotMatch,

    /// Invalid API Version
    #[error("invalid api version")]
    InvalidApiRevision,

    /// Session closed
    #[error("session closed")]
    SessionClosed,

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

    /// Another key with same tag already exists
    #[error("another key with same tag already exists")]
    KeyTagAlreadyExists,

    /// Invalid Session Kind
    #[error("invalid session kind")]
    InvalidSessionKind,

    /// Invalid Key Type
    #[error("invalid key type")]
    InvalidKeyType,

    /// DER-encoded content does not decode to provided key type.
    #[error("der does not match key type")]
    DerAndKeyTypeMismatch,

    /// Invalid Permissions
    #[error("invalid permissions")]
    InvalidPermissions,

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

    /// Function not enabled
    #[error("function not enabled")]
    FunctionNotEnabled,

    /// Another key in use by the given engine
    #[error("another key is being used by the given engine")]
    AnotherKeyInUse,

    /// Key is not in use by the given engine
    #[error("key is not in use by the given engine")]
    KeyNotInUse,

    /// Internal error
    #[error("internal error")]
    InternalError,

    /// Vault session limit reached
    #[error("vault session limit reached")]
    VaultSessionLimitReached,

    /// Session not expected
    #[error("session not expected")]
    SessionNotExpected,

    /// Session expected
    #[error("session expected")]
    SessionExpected,

    /// Session not found
    #[error("session not found")]
    SessionNotFound,

    /// Session needs renegotiation
    #[error("session needs renegotiation")]
    SessionNeedsRenegotiation,

    /// Attestation report signature doesn't match leaf cert
    /// This can happen if LM has occurred between attest_key and get_cert_chain
    #[error("attestation report signature doesn't match leaf cert")]
    AttestReportSignatureMismatch,

    /// Invalid vault manager credentials
    #[error("invalid vault manager credentials")]
    InvalidVaultManagerCredentials,

    /// Invalid app credentials
    #[error("invalid app credentials")]
    InvalidAppCredentials,

    /// Vault not found
    #[error("vault not found")]
    VaultNotFound,

    /// App already exists
    #[error("app already exists")]
    AppAlreadyExists,

    /// App not found
    #[error("app not found")]
    AppNotFound,

    /// Key not found
    #[error("key not found")]
    KeyNotFound,

    /// Key DER decode failed
    #[error("key DER decode failed")]
    KeyDecodeFailed,

    /// Vault app limit reached
    #[error("vault app limit reached")]
    VaultAppLimitReached,

    /// Not enough space
    #[error("not enough space")]
    NotEnoughSpace,

    /// Reached max keys
    #[error("reached max keys")]
    ReachedMaxKeys,

    /// Cannot delete key in use
    #[error("cannot delete key in use")]
    CannotDeleteKeyInUse,

    /// Cannot delete some keys in use
    #[error("cannot delete some keys in use")]
    CannotDeleteSomeKeysInUse,

    /// Cannot close session in use
    #[error("cannot close session in use")]
    CannotCloseSessionInUse,

    /// Cannot close some sessions in use
    #[error("cannot close some sessions in use")]
    CannotCloseSomeSessionsInUse,

    /// Cannot delete key and close session in use
    #[error("cannot delete key and close session in use")]
    CannotDeleteKeyAndCloseSessionInUse,

    /// Invalid key number
    #[error("invalid key number")]
    InvalidKeyNumber,

    /// Function not found
    #[error("function not found")]
    FunctionNotFound,

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

    /// HKDF error
    #[error("hkdf error")]
    HkdfError,

    /// KBKDF error
    #[error("kbkdf error")]
    KbkdfError,

    /// COSE sign1 unexpected signature
    #[error("cose sign1 unexpected signature")]
    CoseSign1UnexpectedSignature,

    /// Invalid API Version
    #[error("invalid api version")]
    InvalidApiVersion,

    /// Device driver interface error
    #[error("device driver interface error")]
    DdiError(u32),

    /// Linux error
    #[cfg(target_os = "linux")]
    #[error("nix error")]
    NixError(#[from] nix::errno::Errno),

    /// Windows error
    #[cfg(target_os = "windows")]
    #[error("win error")]
    WinError(u32),

    /// IO error
    #[error("io error")]
    IoError,

    /// Cannot use the default credentials for some operations
    #[error("Cannot use the default credentials for some operations")]
    CannotUseDefaultCredentials,

    /// RsaUnwrap error
    #[error("RsaUnwrap error")]
    RsaUnwrapError,

    /// Fast path decryption. No tag provided
    #[error("Fast path AES GCM Decryption. No tag provided")]
    AesGcmDecryptionNoTagProvided,

    /// AttestKey error
    #[error("AttestKey error")]
    AttestKeyError,

    /// short app id is invalid
    #[error("Invalid short app id error")]
    InvalidShortAppId,

    /// short app id has not been created
    #[error("Short app id not created error")]
    NoShortAppIdCreated,

    /// For AES GCM decryption, no tag is provided
    #[error("AES GCM. No tag provided error")]
    NoTagProvided,

    /// Invalid buffer size in AES GCM
    #[error("AES GCM. Invalid buffer size error")]
    AesGcmInvalidBufferSize,

    /// Tag does not match in AES GCM decryption
    #[error("AES GCM. Tag does not match error")]
    AesGcmDecryptTagDoesNotMatch,

    /// Invalid buffer size in AES XTS
    #[error("AES XTS. Invalid buffer size error")]
    AesXtsInvalidBufferSize,

    /// Invalid data unit length value
    #[error("AES XTS. Invalid data unit length error")]
    AesXtsInvalidDul,

    /// ECC invalid key length
    #[error("ecc invalid key length")]
    EccInvalidKeyLength,

    /// ECC invalid key length
    #[error("aes invalid key length")]
    AesInvalidKeyLength,

    /// Unsupported command
    #[error("unsupported command")]
    UnsupportedCmd,

    /// Invalid certificate
    #[error("invalid certificate")]
    InvalidCertificate,

    /// Errors indicated by device on fast path
    #[error("Lion FP Error")]
    AesFpErrorGeneric,

    /// HMAC error
    #[error("HMAC Error")]
    HmacError,

    /// Pin Decryption failed
    #[error("PIN decryption failed")]
    PinDecryptionFailed,

    /// Device info ioctl invalid data
    #[error("Device info ioctl error")]
    DeviceInfoIoctlInvalidData,

    /// Key availability is pending key generation
    #[error("Key availability is pending key generation")]
    PendingKeyGeneration,

    /// Cannot delete internal keys, such as RSA unwrap key
    #[error("Cannot delete internal keys")]
    CannotDeleteInternalKeys,

    /// Failed to Get Certificate
    #[error("fail to get certificate")]
    GetCertificateError,

    /// Certificate hash mismatch
    #[error("certificate hash mismatch")]
    CertificateHashMismatch,

    /// Device not ready
    #[error("Device not ready")]
    DeviceNotReady,

    /// Failed to send SoftAes request to co-processor
    #[error("Failed to send SoftAes request to co-processor")]
    SoftAesReqSendFailed,

    /// AES Bulk Key Vault Exhausted
    #[error("AES Bulk Key Vault Exhausted")]
    ReachedMaxAesBulkKeys,

    /// HMAC Invalid Data Length
    #[error("HMAC Invalid Data length")]
    HmacInvalidInputSize,

    /// Nonce Mismatch
    #[error("Nonce Mismatch")]
    NonceMismatch,

    /// Establish Cred Encryption Key Generate Failed
    #[error("Establish Cred Encryption Key Generate Failed")]
    EstablishCredEncryptionKeyGenerateFailed,

    /// ECC from RAW error
    #[error("ecc from raw error")]
    EccFromRawError,

    /// HKDF Invalid Input Parameters
    #[error("HKDF Invalid Input Parameters")]
    HkdfInvalidInputParam,

    /// KBKDF Invalid Input Parameters
    #[error("KBKDF Invalid Input Parameters")]
    KbkdfInvalidInputParam,

    /// CBOR byte array creation failed
    #[error("CBOR byte array creation failure")]
    CborByteArrayCreationError,

    /// Pin Policy login attempt while locked out
    #[error("Pin Policy login attempt while locked out")]
    LoginFailed,

    /// SoftAes response is invalid
    #[error("SoftAes response is invalid")]
    SoftAesInvalidResp,

    /// key structural validation failed
    #[error("key structural validation failed")]
    KeyStructuralValidationFailed,

    /// Pending IO
    #[error("Pending IO")]
    PendingIo,

    /// Received empty IO event
    #[error("Received empty IO event")]
    ReceivedEmptyIoEvent,

    /// Firmware IO channel Receive Error
    #[error("Firmware IO channel receive error")]
    IoChannelReceiveError,

    /// Firmware IO channel decode error
    #[error("Firmware IO channel decode error")]
    IoChannelDecodeError,

    /// Firmware IO channel unknown operation
    #[error("Firmware IO channel unknown operation")]
    IoChannelUnknownOp,

    /// Firmware IO channel invalid source length
    #[error("Firmware IO channel invalid source length")]
    IoChannelInvalidSrcLen,

    /// Firmware IO channel invalid destination length
    #[error("Firmware IO channel invalid destination length")]
    IoChannelInvalidDstLen,

    /// Partition Not Enabled
    #[error("Partition not enabled")]
    PartitionNotEnabled,

    /// FW IO channel pipe not enabled
    #[error("FW IO channel pipe not enabled")]
    IoChannePipelNotEnabled,

    /// FW IO channel pipe not valid
    #[error("FW IO channel pipe not valid")]
    IoChannePipeNotValid,

    /// FW DMA buffer allocation failure
    #[error("FW DMA buffer allocation failure")]
    DmaBufferAllocFailure,

    /// Firmware IO channel invalid buffer descriptor
    #[error("Firmware IO channel invalid buffer descriptor")]
    IoChannelInvalidBufferDescriptor,

    /// Firmware DMA hardware empty completion found
    #[error("Firmware DMA hardware empty completion found")]
    DmaHardwareEmptyCompletionFound,

    /// Firmware DMA completed with error
    #[error("Firmware DMA completed with error")]
    DmaCompletedWithError,

    /// Firmware DMA IO identifier mismatch
    #[error("Firmware DMA IO identifier mismatch")]
    DmaIoIdentifierMismatch,

    /// Firmware IO channel pipe not found
    #[error("Firmware IO channel pipe not found")]
    IoChannelPipeNotFound,

    /// Firmware failed to associate IO with a partition
    #[error("Firmware failed to associate IO with a partition")]
    FailedToAssociateIoWithPartition,

    /// Firmware failed to start the DMA transaction
    #[error("Firmware failed to start the DMA transaction")]
    FailedToStartDmaTransaction,

    /// Firmware IO channel failed to send a response
    #[error("Firmware IO channel failed to send a response")]
    IoChannelFailedToSendResponse,

    /// Firmware failed to identify DMA buffer
    #[error("Firmware failed to identify DMA buffer")]
    FailedToIdentifyDmaBuffer,

    /// Firmware IO channel request decode error
    #[error("Firmware IO channel request decode error")]
    IoChannelRequestDecodeError,

    /// Firmware IO command not found
    #[error("Firmware IO command not found")]
    IoCommandNotFound,

    /// Firmware IO channel invalid source alignment
    #[error("Firmware IO channel invalid source alignment")]
    IoChannelInvalidSrcAlignment,

    /// Firmware IO channel invalid destination alignment
    #[error("Firmware IO channel invalid destination alignment")]
    IoChannelInvalidDstAlignment,

    /// Firmware IO command error
    #[error("Firmware IO command error")]
    IoCommandError,

    /// Firmware spurious IPC message received
    #[error("Firmware spurious IPC message received")]
    SpuriousIpcMessageReceived,

    /// Firmware invalid IPC message received
    #[error("Firmware invalid IPC message received")]
    InvalidIpcMessageReceived,

    /// Firmware failed to decode IPC message
    #[error("Firmware failed to decode IPC message")]
    FailedToDecodeIpcMessage,

    /// Firmware invalid IPC message op code found
    #[error("Firmware invalid IPC message op code found")]
    InvalidIpcMessageOpCodeFound,

    /// Firmware IO channel Tx empty completion found
    #[error("Firmware IO channel Tx empty completion found")]
    IoChannelTxEmptyCompletionFound,

    /// Firmware failed to associate IO with a completion
    #[error("Firmware failed to associate IO with a completion")]
    FailedToAssociateIoWithCompletion,

    /// Firmware IO channel failed to send a completion
    #[error("Firmware IO channel failed to send a completion")]
    IoChannelFailedToSendCompletion,

    /// Defragmentation needed for Key vault
    #[error("Defragmentation needed for Key vault")]
    DefragmentationNeeded,

    /// Invalid session control opcode
    #[error("Invalid session control opcode")]
    InvalidSessionControlOpcode,

    /// DER decode failed
    #[error("DER decode failed")]
    DerDecodeFailed,

    /// Firmware Invalid Memory Map Entry
    #[error("Firmware Invalid Memory Map Entry")]
    InvalidMemoryMapEntry,

    /// Firmware processed invalid IO event
    #[error("Firmware processed invalid IO event")]
    ProcessedInvalidIoEvent,

    /// Firmware processed IO event in invalid state
    #[error("Firmware processed IO event in invalid state")]
    ProcessedIoEventInInvalidState,

    /// Firmware cannot associate IO with a PKA completion
    #[error("Firmware cannot associate IO with a PKA completion")]
    CannotAssociateIoWithPkaCompletion,

    /// Firmware identified PKA engine not busy
    #[error("Firmware identified PKA engine not busy")]
    IdentifiedPkaEngineNotBusy,

    /// Firmware identified ECC calculation failure
    #[error("Firmware identified ECC calculation failure")]
    IdentifiedEccCalculationFailure,

    /// Firmware failed to generate ECC public key
    #[error("Firmware failed to generate ECC public key")]
    FailedToGenerateEccPublicKey,

    /// Firmware identified RSA calculation failure
    #[error("Firmware identified RSA calculation failure")]
    IdentifiedRsaCalculationFailure,

    /// Firmware failed to begin RSA calculation
    #[error("Firmware failed to begin RSA calculation")]
    FailedToBeginRsaCalculation,

    /// Frirmware failed to perform RSA multiplication
    #[error("Firmware failed to perform RSA multiplication")]
    FailedToPerformRsaMultiplication,

    /// Firmware failed to end RSA calculation
    #[error("Firmware failed to end RSA calculation")]
    FailedToEndRsaCalculation,

    /// Firmware failed to perform RSA modular inverse
    #[error("Firmware failed to perform RSA modular inverse")]
    FailedToPerformRsaModularInverse,

    /// Firmware failed to compute ECDH shared secret
    #[error("Firmware failed to compute ECDH shared secret")]
    FailedToComputeEcdhSharedSecret,

    /// Firmware failed to identify IO channel pipe
    #[error("Firmware failed to identify IO channel pipe")]
    FailedToIdentifyIoChannelPipe,

    /// Firmware identified invalid IO channel pipe
    #[error("Firmware identified invalid IO channel pipe")]
    IdentifiedInvalidIoChannelPipe,

    /// Firmware failed to send IP message
    #[error("Firmware failed to send IP message")]
    FailedToSendIpMessage,

    /// Firmware IPC response failure
    #[error("Firmware IPC response failure")]
    IpcResponseFailure,

    /// Firmware key derivation failure
    #[error("Firmware key derivation failure")]
    KeyDerivationFailure,

    /// DER decoding failure for AES bulk key
    #[error("DER decoding failure for AES bulk key")]
    DerDecodeFailedForAesBulkKey,

    /// Firmware Invalid IPC shutdown message
    #[error("Firmware Invalid IPC shutdown message")]
    InvalidIpcShutdownMessage,

    /// Session encryption key generation failed
    #[error("Session encryption key generation failed")]
    SessionEncryptionKeyGenerateFailed,

    /// Firmware IO timed out
    #[error("Firmware IO timed out")]
    IoTimedOut,

    /// Firmware IO drain is in progress
    #[error("Firmware IO drain is in progress")]
    IoDrainInProgress,

    /// Firmware IO channel pipe delete error
    #[error("Firmware IO channel pipe delete error")]
    IoChannelPipeDeleteError,

    /// Firmware IPC response decode error
    #[error("Firmware IPC response decode error")]
    IpcResponseDecodeError,

    /// Firmware Unknown self-test request received
    #[error("Firmware Unknown self-test request received")]
    UnknownSelfTestRequestReceived,

    /// Firmware self-test missing instance
    #[error("Firmware self-test missing instance")]
    SelfTestMissingInstance,

    /// Firmware failed to wipe PKA memory
    #[error("Firmware failed to wipe PKA memory")]
    FailedToWipePkaMemory,

    /// Firmware IO drain ready
    #[error("Firmware IO drain ready")]
    IoDrainReady,

    /// Invalid FW package information in memory map
    #[error("Invalid FW package information in memory map")]
    InvalidPackageInfo,

    /// ECC Gen Key PCT validation failed
    #[error("ECC Gen Key PCT validation failed")]
    PctValidationEccGenKeyFailed,

    /// Get Establish Credential Encryption Key PCT validation failed
    #[error("Get Establish Credential Encryption Key PCT validation failed")]
    PctValidationEstablishCredEncKeyFailed,

    /// Get Session Encryption Key PCT validation failed
    #[error("Get Session Encryption Key PCT validation failed")]
    PctValidationSessionEncKeyFailed,

    /// Get Unwrapping Key PCT validation failed
    #[error("Get Unwrapping Key PCT validation failed")]
    PctValidationUnwrappingKeyFailed,

    /// RSA Unwrap ECC Key PCT validation failed
    #[error("RSA Unwrap ECC Key PCT validation failed")]
    PctValidationRsaUnwrapEccKeyFailed,

    /// RSA Unwrap RSA Key PCT validation failed
    #[error("RSA Unwrap RSA Key PCT validation failed")]
    PctValidationRsaUnwrapRsaKeyFailed,

    /// Non FIPS approved digest passed to a FIPS approved module.
    #[error("Non FIPS approved digest passed to a FIPS approved module")]
    NonFipsApprovedDigest,

    /// Digest hash algorithm mismatches the ECC curve used.
    #[error("Digest hash algorithm mismatches the ECC curve used")]
    DigestHashMismatchWithEccCurve,

    /// Unsupported Digest hash algorithm used.
    #[error("Unsupported Digest hash algorithm used")]
    UnsupportedDigestHashAlgorithm,

    /// Failed to begin ECC public key validation
    #[error("Begin ECC public key validation failed")]
    FailedToStartPublicKeyValidation,

    /// Failed to end ECC public key validation
    #[error("End ECC public key validation failed")]
    FailedToEndEccPublicKeyValidation,

    /// ECC public key provided is not in the ECC curve point
    #[error("ECC Public key point validation failed")]
    EccPointValidationFailed,

    /// ECC Public key validation failed
    #[error("Ecc Public key validation failed")]
    EccPublicKeyValidationFailed,

    /// Ecc DER key is shorter than the curve
    #[error("Ecc DER key is shorter than the curve")]
    EccDerKeyShorterThanCurve,

    /// RSA unwrap invalid request
    #[error("RSA unwrap invalid request")]
    RsaUnwrapInvalidRequest,

    /// RSA unwrap invalid KEK
    #[error("RSA unwrap invalid KEK")]
    RsaUnwrapInvalidKek,

    /// RSA unwrap OAEP decode failed
    #[error("RSA unwrap OAEP decode failed")]
    RsaUnwrapOaepDecodeFailed,

    /// RSA unwrap invalid AES unwrap state
    #[error("RSA unwrap invalid AES unwrap state")]
    RsaUnwrapInvalidAesUnwrapState,

    /// RSA unwrap AES unwrap failed
    #[error("RSA unwrap AES unwrap failed")]
    RsaUnwrapAesUnwrapFailed,

    /// Attestation report encoding failed
    #[error("Attestation report encoding failed")]
    AttestationReportEncodeFailed,

    /// COSE Key encoding failed
    #[error("COSE Key encoding failed")]
    CoseKeyEncodeFailed,

    /// Attestation key internal error
    #[error("Attestation key internal error")]
    AttestKeyInternalError,

    /// Masked key length is not valid
    #[error("Masked key has an invalid length")]
    MaskedKeyInvalidLength,

    /// Masked key pre-encode failed
    #[error("Masked key pre-encode failed")]
    MaskedKeyPreEncodeFailed,

    /// Masked key encode failed
    #[error("Masked key encode failed")]
    MaskedKeyEncodeFailed,

    /// Masked key decode failed
    #[error("Masked key decode failed")]
    MaskedKeyDecodeFailed,

    /// Reset Device error
    #[error("Reset device error")]
    ResetDeviceError(u32),

    /// Partition failed to restore after live migration
    #[error("Partition failed to restore after live migration")]
    RestorePartitionFailed,

    /// Output buffer too small
    #[error("Output buffer too small")]
    OutputBufferTooSmall,

    /// Invalid key length
    #[error("Invalid key length")]
    InvalidKeyLength,

    /// Invalid algorithm
    #[error("Invalid algorithm")]
    InvalidAlgorithm,

    /// Metadata encoding failed
    #[error("Metadata encoding failed")]
    MetadataEncodeFailed,

    /// Metadata decoding failed
    #[error("Metadata decoding failed")]
    MetadataDecodeFailed,

    /// MBOR encoding failed
    #[error("MBOR encoding failed")]
    MborEncodeFailed,

    /// Disk access failed
    #[error("Access for app data on disk failed")]
    DiskAccessFailed,

    /// Sealed BK3 not present
    #[error("Sealed BK3 not present")]
    SealedBk3NotPresent,

    /// Partition is already provisioned
    #[error("Partition is already provisioned")]
    PartitionAlreadyProvisioned,

    /// Partition is not provisioned
    #[error("Partition is not provisioned")]
    PartitionNotProvisioned,

    /// Credentials need to be established before opening a session
    #[error("Credentials are not established")]
    CredentialsNotEstablished,

    /// Alias key was invalid
    #[error("Invalid Alias Key")]
    InvalidAliasKey,

    /// Invalid Partition Id Private Key
    #[error("Invalid Partition Id Private Key")]
    InvalidPartIdPrivKeyInternalError,

    /// Named Keys Not Supported
    #[error("Named keys are not supported")]
    NamedKeysNotSupported,

    /// Unknown error
    #[error("unknown error")]
    UnknownError,
}

impl HsmError {
    /// Maps HsmError to an isize error code.
    pub fn to_error_code(&self) -> isize {
        match self {
            HsmError::InvalidParameter => -100,
            HsmError::IndexOutOfBounds => -101,
            HsmError::InvalidStr => -102,
            HsmError::InvalidPtr => -103,
            HsmError::DeviceNotFound => -104,
            HsmError::CborEncodeFailed => -105,
            HsmError::CborDecodeFailed => -106,
            HsmError::NoExistingSessionPresentInDeviceHandle => -107,
            HsmError::OnlyOneSessionAllowedPerDeviceHandle => -108,
            HsmError::SessionIdDoesNotMatch => -109,
            HsmError::InvalidApiRevision => -110,
            HsmError::SessionClosed => -111,
            HsmError::RsaEncryptFailed => -112,
            HsmError::RsaDecryptFailed => -113,
            HsmError::RsaSignFailed => -114,
            HsmError::RsaVerifyFailed => -115,
            HsmError::KeyTagAlreadyExists => -116,
            HsmError::InvalidSessionKind => -117,
            HsmError::InvalidKeyType => -118,
            HsmError::DerAndKeyTypeMismatch => -119,
            HsmError::InvalidPermissions => -120,
            HsmError::EccSignFailed => -121,
            HsmError::EccVerifyFailed => -122,
            HsmError::AesEncryptFailed => -123,
            HsmError::AesDecryptFailed => -124,
            HsmError::FunctionNotEnabled => -125,
            HsmError::AnotherKeyInUse => -126,
            HsmError::KeyNotInUse => -127,
            HsmError::InternalError => -128,
            HsmError::VaultSessionLimitReached => -129,
            HsmError::SessionNotExpected => -130,
            HsmError::SessionExpected => -131,
            HsmError::SessionNotFound => -132,
            HsmError::InvalidVaultManagerCredentials => -133,
            HsmError::InvalidAppCredentials => -134,
            HsmError::VaultNotFound => -135,
            HsmError::AppAlreadyExists => -136,
            HsmError::AppNotFound => -137,
            HsmError::KeyNotFound => -140,
            HsmError::KeyDecodeFailed => -141,
            HsmError::VaultAppLimitReached => -142,
            HsmError::NotEnoughSpace => -143,
            HsmError::ReachedMaxKeys => -144,
            HsmError::CannotDeleteKeyInUse => -145,
            HsmError::CannotDeleteSomeKeysInUse => -146,
            HsmError::CannotCloseSessionInUse => -147,
            HsmError::CannotCloseSomeSessionsInUse => -148,
            HsmError::CannotDeleteKeyAndCloseSessionInUse => -149,
            HsmError::InvalidKeyNumber => -150,
            HsmError::FunctionNotFound => -151,
            HsmError::RsaToDerError => -152,
            HsmError::RsaFromDerError => -153,
            HsmError::RsaGenerateError => -154,
            HsmError::RsaGetModulusError => -155,
            HsmError::RsaGetPublicExponentError => -156,
            HsmError::RsaInvalidKeyLength => -157,
            HsmError::EccToDerError => -158,
            HsmError::EccFromDerError => -159,
            HsmError::EccGenerateError => -160,
            HsmError::EccDeriveError => -161,
            HsmError::EccGetCurveError => -162,
            HsmError::EccGetCoordinatesError => -163,
            HsmError::ShaError => -164,
            HsmError::AesGenerateError => -165,
            HsmError::HkdfError => -166,
            HsmError::KbkdfError => -167,
            HsmError::CoseSign1UnexpectedSignature => -168,
            HsmError::InvalidApiVersion => -169,
            HsmError::DdiError(code) => *code as isize,
            #[cfg(target_os = "linux")]
            HsmError::NixError(_) => -170,
            #[cfg(target_os = "windows")]
            HsmError::WinError(code) => *code as isize,
            HsmError::IoError => -171,
            HsmError::CannotUseDefaultCredentials => -172,
            HsmError::RngError => -173,
            HsmError::RsaUnwrapError => -174,
            HsmError::AttestKeyError => -175,
            HsmError::AesGcmDecryptionNoTagProvided => -176,
            HsmError::InvalidShortAppId => -177,
            HsmError::NoShortAppIdCreated => -178,
            HsmError::NoTagProvided => -179,
            HsmError::AesGcmInvalidBufferSize => -180,
            HsmError::AesGcmDecryptTagDoesNotMatch => -181,
            HsmError::AesXtsInvalidBufferSize => -182,
            HsmError::AesXtsInvalidDul => -183,
            HsmError::EccInvalidKeyLength => -184,
            HsmError::AesInvalidKeyLength => -185,
            HsmError::UnsupportedCmd => -186,
            HsmError::InvalidCertificate => -187,
            HsmError::AesFpErrorGeneric => -188,
            HsmError::DeviceInfoIoctlInvalidData => -189,
            HsmError::PendingKeyGeneration => -190,
            HsmError::CannotDeleteInternalKeys => -191,
            HsmError::GetCertificateError => -192,
            HsmError::DeviceNotReady => -193,
            HsmError::SoftAesReqSendFailed => -194,
            HsmError::HmacError => -195,
            HsmError::PinDecryptionFailed => -196,
            HsmError::ReachedMaxAesBulkKeys => -197,
            HsmError::HmacInvalidInputSize => -198,
            HsmError::NonceMismatch => -199,
            HsmError::EstablishCredEncryptionKeyGenerateFailed => -200,
            HsmError::EccFromRawError => -201,
            HsmError::HkdfInvalidInputParam => -202,
            HsmError::KbkdfInvalidInputParam => -203,
            HsmError::CborByteArrayCreationError => -204,
            HsmError::LoginFailed => -205,
            HsmError::SoftAesInvalidResp => -206,
            HsmError::KeyStructuralValidationFailed => -207,
            HsmError::PendingIo => -208,
            HsmError::ReceivedEmptyIoEvent => -209,
            HsmError::IoChannelReceiveError => -210,
            HsmError::IoChannelDecodeError => -211,
            HsmError::IoChannelUnknownOp => -212,
            HsmError::IoChannelInvalidSrcLen => -213,
            HsmError::IoChannelInvalidDstLen => -214,
            HsmError::PartitionNotEnabled => -215,
            HsmError::IoChannePipelNotEnabled => -216,
            HsmError::IoChannePipeNotValid => -217,
            HsmError::DmaBufferAllocFailure => -218,
            HsmError::IoChannelInvalidBufferDescriptor => -219,
            HsmError::DmaHardwareEmptyCompletionFound => -220,
            HsmError::DmaCompletedWithError => -221,
            HsmError::DmaIoIdentifierMismatch => -222,
            HsmError::IoChannelPipeNotFound => -223,
            HsmError::FailedToAssociateIoWithPartition => -224,
            HsmError::FailedToStartDmaTransaction => -225,
            HsmError::IoChannelFailedToSendResponse => -226,
            HsmError::FailedToIdentifyDmaBuffer => -227,
            HsmError::IoChannelRequestDecodeError => -228,
            HsmError::IoCommandNotFound => -229,
            HsmError::IoChannelInvalidSrcAlignment => -230,
            HsmError::IoChannelInvalidDstAlignment => -231,
            HsmError::IoCommandError => -232,
            HsmError::SpuriousIpcMessageReceived => -233,
            HsmError::InvalidIpcMessageReceived => -234,
            HsmError::FailedToDecodeIpcMessage => -235,
            HsmError::InvalidIpcMessageOpCodeFound => -236,
            HsmError::IoChannelTxEmptyCompletionFound => -237,
            HsmError::FailedToAssociateIoWithCompletion => -238,
            HsmError::IoChannelFailedToSendCompletion => -239,
            HsmError::DefragmentationNeeded => -240,
            HsmError::InvalidSessionControlOpcode => -241,
            HsmError::DerDecodeFailed => -242,
            HsmError::InvalidMemoryMapEntry => -243,
            HsmError::ProcessedInvalidIoEvent => -244,
            HsmError::ProcessedIoEventInInvalidState => -245,
            HsmError::CannotAssociateIoWithPkaCompletion => -246,
            HsmError::IdentifiedPkaEngineNotBusy => -247,
            HsmError::IdentifiedEccCalculationFailure => -248,
            HsmError::FailedToGenerateEccPublicKey => -249,
            HsmError::IdentifiedRsaCalculationFailure => -250,
            HsmError::FailedToBeginRsaCalculation => -251,
            HsmError::FailedToPerformRsaMultiplication => -252,
            HsmError::FailedToEndRsaCalculation => -253,
            HsmError::FailedToPerformRsaModularInverse => -254,
            HsmError::FailedToComputeEcdhSharedSecret => -255,
            HsmError::FailedToIdentifyIoChannelPipe => -256,
            HsmError::IdentifiedInvalidIoChannelPipe => -257,
            HsmError::FailedToSendIpMessage => -258,
            HsmError::IpcResponseFailure => -259,
            HsmError::KeyDerivationFailure => -260,
            HsmError::DerDecodeFailedForAesBulkKey => -261,
            HsmError::InvalidIpcShutdownMessage => -262,
            HsmError::SessionEncryptionKeyGenerateFailed => -263,
            HsmError::IoTimedOut => -264,
            HsmError::IoDrainInProgress => -265,
            HsmError::IoChannelPipeDeleteError => -266,
            HsmError::IpcResponseDecodeError => -267,
            HsmError::UnknownSelfTestRequestReceived => -268,
            HsmError::SelfTestMissingInstance => -269,
            HsmError::FailedToWipePkaMemory => -270,
            HsmError::IoDrainReady => -271,
            HsmError::InvalidPackageInfo => -272,
            HsmError::PctValidationEccGenKeyFailed => -273,
            HsmError::PctValidationEstablishCredEncKeyFailed => -274,
            HsmError::PctValidationSessionEncKeyFailed => -275,
            HsmError::PctValidationUnwrappingKeyFailed => -276,
            HsmError::PctValidationRsaUnwrapEccKeyFailed => -277,
            HsmError::PctValidationRsaUnwrapRsaKeyFailed => -278,
            HsmError::NonFipsApprovedDigest => -279,
            HsmError::DigestHashMismatchWithEccCurve => -280,
            HsmError::UnsupportedDigestHashAlgorithm => -281,
            HsmError::FailedToStartPublicKeyValidation => -282,
            HsmError::FailedToEndEccPublicKeyValidation => -283,
            HsmError::EccPointValidationFailed => -284,
            HsmError::EccPublicKeyValidationFailed => -285,
            HsmError::EccDerKeyShorterThanCurve => -286,
            HsmError::RsaUnwrapInvalidRequest => -287,
            HsmError::RsaUnwrapInvalidKek => -288,
            HsmError::RsaUnwrapOaepDecodeFailed => -289,
            HsmError::RsaUnwrapInvalidAesUnwrapState => -290,
            HsmError::RsaUnwrapAesUnwrapFailed => -291,
            HsmError::AttestationReportEncodeFailed => -292,
            HsmError::CoseKeyEncodeFailed => -293,
            HsmError::AttestKeyInternalError => -294,
            HsmError::MaskedKeyInvalidLength => -295,
            HsmError::MaskedKeyPreEncodeFailed => -296,
            HsmError::MaskedKeyEncodeFailed => -297,
            HsmError::MaskedKeyDecodeFailed => -298,
            HsmError::SessionNeedsRenegotiation => -299,
            HsmError::RestorePartitionFailed => -300,
            HsmError::OutputBufferTooSmall => -301,
            HsmError::InvalidKeyLength => -302,
            HsmError::InvalidAlgorithm => -303,
            HsmError::MetadataEncodeFailed => -304,
            HsmError::MetadataDecodeFailed => -305,
            HsmError::MborEncodeFailed => -306,
            HsmError::ResetDeviceError(_) => -307,
            HsmError::DiskAccessFailed => -308,
            HsmError::SealedBk3NotPresent => -309,
            HsmError::PartitionAlreadyProvisioned => -310,
            HsmError::CredentialsNotEstablished => -311,
            HsmError::InvalidAliasKey => -312,
            HsmError::InvalidPartIdPrivKeyInternalError => -313,
            HsmError::CertificateHashMismatch => -314,
            HsmError::PartitionNotProvisioned => -315,
            HsmError::RsaFromRawError => -316,
            HsmError::NamedKeysNotSupported => -317,
            HsmError::AttestReportSignatureMismatch => -318,
            HsmError::UnknownError => -999,
        }
    }
}

impl From<DdiError> for HsmError {
    fn from(value: DdiError) -> Self {
        match value {
            DdiError::InvalidParameter => HsmError::InvalidParameter,
            DdiError::IndexOutOfBounds => HsmError::IndexOutOfBounds,
            DdiError::InvalidStr => HsmError::InvalidStr,
            DdiError::InvalidPtr => HsmError::InvalidPtr,
            DdiError::DeviceNotFound => HsmError::DeviceNotFound,
            DdiError::DeviceNotReady => HsmError::DeviceNotReady,
            DdiError::DdiEncodingFault(_) => HsmError::CborEncodeFailed,
            DdiError::DdiDecodingFault(_) => HsmError::CborDecodeFailed,
            DdiError::DdiError(err_code) => HsmError::DdiError(err_code),
            DdiError::MborError(err_code) => match err_code {
                mcr_ddi_types::MborError::DecodeError => HsmError::CborDecodeFailed,
                mcr_ddi_types::MborError::EncodeError => HsmError::CborEncodeFailed,
            },
            DdiError::DdiStatus(ddi_status) => match ddi_status {
                DdiStatus::Success => HsmError::InternalError, // This conversion should never happen unless there is a bug.
                DdiStatus::InvalidArg => HsmError::InvalidParameter,
                DdiStatus::InternalError => HsmError::InternalError,
                DdiStatus::DdiEncodeFailed => HsmError::CborEncodeFailed,
                DdiStatus::DdiDecodeFailed => HsmError::CborDecodeFailed,
                DdiStatus::VaultSessionLimitReached => HsmError::VaultSessionLimitReached,
                DdiStatus::SessionNotExpected => HsmError::SessionNotExpected,
                DdiStatus::SessionExpected => HsmError::SessionExpected,
                DdiStatus::SessionNotFound => HsmError::SessionNotFound,
                DdiStatus::SessionNeedsRenegotiation => HsmError::SessionNeedsRenegotiation,
                DdiStatus::SealedBk3NotPresent => HsmError::SealedBk3NotPresent,
                DdiStatus::PartitionAlreadyProvisioned => HsmError::PartitionAlreadyProvisioned,
                DdiStatus::PartitionNotProvisioned => HsmError::PartitionNotProvisioned,
                DdiStatus::InvalidPartitionIdContent => HsmError::InvalidPartIdPrivKeyInternalError,
                DdiStatus::CannotUseDefaultCredentials => HsmError::CannotUseDefaultCredentials,
                DdiStatus::InvalidManagerCredentials => HsmError::InvalidVaultManagerCredentials,
                DdiStatus::InvalidAppCredentials => HsmError::InvalidAppCredentials,
                DdiStatus::VaultNotFound => HsmError::VaultNotFound,
                DdiStatus::AppAlreadyExists => HsmError::AppAlreadyExists,
                DdiStatus::AppNotFound => HsmError::AppNotFound,
                DdiStatus::KeyNotFound => HsmError::KeyNotFound,
                DdiStatus::InvalidKeyType => HsmError::InvalidKeyType,
                DdiStatus::DerAndKeyTypeMismatch => HsmError::DerAndKeyTypeMismatch,
                DdiStatus::KeyDecodeFailed => HsmError::KeyDecodeFailed,
                DdiStatus::RsaDecryptFailed => HsmError::RsaDecryptFailed,
                DdiStatus::RsaSignFailed => HsmError::RsaSignFailed,
                DdiStatus::FileHandleNoExistingSession => {
                    HsmError::NoExistingSessionPresentInDeviceHandle
                }
                DdiStatus::FileHandleSessionLimitReached => {
                    HsmError::OnlyOneSessionAllowedPerDeviceHandle
                }
                DdiStatus::FileHandleSessionIdDoesNotMatch => HsmError::SessionIdDoesNotMatch,
                DdiStatus::KeyTagAlreadyExists => HsmError::KeyTagAlreadyExists,
                DdiStatus::InvalidPermissions => HsmError::InvalidPermissions,
                DdiStatus::EccSignFailed => HsmError::EccSignFailed,
                DdiStatus::AesEncryptFailed => HsmError::AesEncryptFailed,
                DdiStatus::AesDecryptFailed => HsmError::AesDecryptFailed,
                DdiStatus::FunctionNotEnabled => HsmError::FunctionNotEnabled,
                DdiStatus::AnotherKeyInUse => HsmError::AnotherKeyInUse,
                DdiStatus::KeyNotInUse => HsmError::KeyNotInUse,
                DdiStatus::UnsupportedRevision => HsmError::InvalidApiRevision,
                DdiStatus::VaultAppLimitReached => HsmError::VaultAppLimitReached,
                DdiStatus::NotEnoughSpace => HsmError::NotEnoughSpace,
                DdiStatus::ReachedMaxKeys => HsmError::ReachedMaxKeys,
                DdiStatus::CannotDeleteKeyInUse => HsmError::CannotDeleteKeyInUse,
                DdiStatus::CannotDeleteSomeKeysInUse => HsmError::CannotDeleteSomeKeysInUse,
                DdiStatus::CannotCloseSessionInUse => HsmError::CannotCloseSessionInUse,
                DdiStatus::CannotCloseSomeSessionsInUse => HsmError::CannotCloseSomeSessionsInUse,
                DdiStatus::CannotDeleteKeyAndCloseSessionInUse => {
                    HsmError::CannotDeleteKeyAndCloseSessionInUse
                }
                DdiStatus::InvalidKeyNumber => HsmError::InvalidKeyNumber,
                DdiStatus::FunctionNotFound => HsmError::FunctionNotFound,
                DdiStatus::RsaToDerError => HsmError::RsaToDerError,
                DdiStatus::RsaGenerateError => HsmError::RsaGenerateError,
                DdiStatus::RsaGetModulusError => HsmError::RsaGetModulusError,
                DdiStatus::RsaGetPublicExponentError => HsmError::RsaGetPublicExponentError,
                DdiStatus::RsaInvalidKeyLength => HsmError::RsaInvalidKeyLength,
                DdiStatus::EccToDerError => HsmError::EccToDerError,
                DdiStatus::EccGenerateError => HsmError::EccGenerateError,
                DdiStatus::EccDeriveError => HsmError::EccDeriveError,
                DdiStatus::EccGetCurveError => HsmError::EccGetCurveError,
                DdiStatus::EccGetCoordinatesError => HsmError::EccGetCoordinatesError,
                DdiStatus::ShaError => HsmError::ShaError,
                DdiStatus::AesGenerateError => HsmError::AesGenerateError,
                DdiStatus::CoseSign1UnexpectedSignature => HsmError::CoseSign1UnexpectedSignature,
                DdiStatus::HkdfError => HsmError::HkdfError,
                DdiStatus::KbkdfError => HsmError::KbkdfError,
                DdiStatus::InvalidShortAppId => HsmError::InvalidShortAppId,
                DdiStatus::NoShortAppIdCreated => HsmError::NoShortAppIdCreated,
                DdiStatus::NoTagProvided => HsmError::NoTagProvided,
                DdiStatus::AesGcmInvalidBufferSize => HsmError::AesGcmInvalidBufferSize,
                DdiStatus::AesGcmDecryptTagDoesNotMatch => HsmError::AesGcmDecryptTagDoesNotMatch,
                DdiStatus::AesXtsInvalidBufferSize => HsmError::AesXtsInvalidBufferSize,
                DdiStatus::AesXtsInvalidDul => HsmError::AesXtsInvalidDul,
                DdiStatus::RsaUnwrapError => HsmError::RsaUnwrapError,
                DdiStatus::AttestKeyError => HsmError::AttestKeyError,
                DdiStatus::EccInvalidKeyLength => HsmError::EccInvalidKeyLength,
                DdiStatus::AesInvalidKeyLength => HsmError::AesInvalidKeyLength,
                DdiStatus::RsaEncryptFailed => HsmError::RsaEncryptFailed,
                DdiStatus::EccVerifyFailed => HsmError::EccVerifyFailed,
                DdiStatus::UnsupportedCmd => HsmError::UnsupportedCmd,
                DdiStatus::InvalidCertificate => HsmError::InvalidCertificate,
                DdiStatus::HmacError => HsmError::HmacError,
                DdiStatus::PinDecryptionFailed => HsmError::PinDecryptionFailed,
                DdiStatus::PendingKeyGeneration => HsmError::PendingKeyGeneration,
                DdiStatus::CannotDeleteInternalKeys => HsmError::CannotDeleteInternalKeys,
                DdiStatus::FailedToSendSoftAesRequest => HsmError::SoftAesReqSendFailed,
                DdiStatus::ReachedMaxAesBulkKeys => HsmError::ReachedMaxAesBulkKeys,
                DdiStatus::HmacInvalidInputSize => HsmError::HmacInvalidInputSize,
                DdiStatus::RngError => HsmError::RngError,
                DdiStatus::NonceMismatch => HsmError::NonceMismatch,
                DdiStatus::EstablishCredEncryptionKeyGenerateFailed => {
                    HsmError::EstablishCredEncryptionKeyGenerateFailed
                }
                DdiStatus::HkdfInvalidInputParam => HsmError::HkdfInvalidInputParam,
                DdiStatus::KbkdfInvalidInputParam => HsmError::KbkdfInvalidInputParam,
                DdiStatus::LoginFailed => HsmError::LoginFailed,
                DdiStatus::FailedSoftAesResponse => HsmError::SoftAesInvalidResp,
                DdiStatus::KeyStructuralValidationFailed => HsmError::KeyStructuralValidationFailed,
                DdiStatus::PendingIo => HsmError::PendingIo,
                DdiStatus::ReceivedEmptyIoEvent => HsmError::ReceivedEmptyIoEvent,
                DdiStatus::IoChannelReceiveError => HsmError::IoChannelReceiveError,
                DdiStatus::IoChannelDecodeError => HsmError::IoChannelDecodeError,
                DdiStatus::IoChannelUnknownOp => HsmError::IoChannelUnknownOp,
                DdiStatus::IoChannelInvalidSrcLen => HsmError::IoChannelInvalidSrcLen,
                DdiStatus::IoChannelInvalidDstLen => HsmError::IoChannelInvalidDstLen,
                DdiStatus::PartitionNotEnabled => HsmError::PartitionNotEnabled,
                DdiStatus::IoChannePipelNotEnabled => HsmError::IoChannePipelNotEnabled,
                DdiStatus::IoChannePipeNotValid => HsmError::IoChannePipeNotValid,
                DdiStatus::DmaBufferAllocFailure => HsmError::DmaBufferAllocFailure,
                DdiStatus::IoChannelInvalidBufferDescriptor => {
                    HsmError::IoChannelInvalidBufferDescriptor
                }
                DdiStatus::DmaHardwareEmptyCompletionFound => {
                    HsmError::DmaHardwareEmptyCompletionFound
                }
                DdiStatus::DmaCompletedWithError => HsmError::DmaCompletedWithError,
                DdiStatus::DmaIoIdentifierMismatch => HsmError::DmaIoIdentifierMismatch,
                DdiStatus::IoChannelPipeNotFound => HsmError::IoChannelPipeNotFound,
                DdiStatus::FailedToAssociateIoWithPartition => {
                    HsmError::FailedToAssociateIoWithPartition
                }
                DdiStatus::FailedToStartDmaTransaction => HsmError::FailedToStartDmaTransaction,
                DdiStatus::IoChannelFailedToSendResponse => HsmError::IoChannelFailedToSendResponse,
                DdiStatus::FailedToIdentifyDmaBuffer => HsmError::FailedToIdentifyDmaBuffer,
                DdiStatus::IoChannelRequestDecodeError => HsmError::IoChannelRequestDecodeError,
                DdiStatus::IoCommandNotFound => HsmError::IoCommandNotFound,
                DdiStatus::IoChannelInvalidSrcAlignment => HsmError::IoChannelInvalidSrcAlignment,
                DdiStatus::IoChannelInvalidDstAlignment => HsmError::IoChannelInvalidDstAlignment,
                DdiStatus::IoCommandError => HsmError::IoCommandError,
                DdiStatus::SpuriousIpcMessageReceived => HsmError::SpuriousIpcMessageReceived,
                DdiStatus::InvalidIpcMessageReceived => HsmError::InvalidIpcMessageReceived,
                DdiStatus::FailedToDecodeIpcMessage => HsmError::FailedToDecodeIpcMessage,
                DdiStatus::InvalidIpcMessageOpCodeFound => HsmError::InvalidIpcMessageOpCodeFound,
                DdiStatus::IoChannelTxEmptyCompletionFound => {
                    HsmError::IoChannelTxEmptyCompletionFound
                }
                DdiStatus::FailedToAssociateIoWithCompletion => {
                    HsmError::FailedToAssociateIoWithCompletion
                }
                DdiStatus::IoChannelFailedToSendCompletion => {
                    HsmError::IoChannelFailedToSendCompletion
                }
                DdiStatus::DefragmentationNeeded => HsmError::DefragmentationNeeded,
                DdiStatus::InvalidSessionControlOpcode => HsmError::InvalidSessionControlOpcode,
                DdiStatus::DerDecodeFailed => HsmError::DerDecodeFailed,
                DdiStatus::InvalidMemoryMapEntry => HsmError::InvalidMemoryMapEntry,
                DdiStatus::ProcessedInvalidIoEvent => HsmError::ProcessedInvalidIoEvent,
                DdiStatus::ProcessedIoEventInInvalidState => {
                    HsmError::ProcessedIoEventInInvalidState
                }
                DdiStatus::CannotAssociateIoWithPkaCompletion => {
                    HsmError::CannotAssociateIoWithPkaCompletion
                }
                DdiStatus::IdentifiedPkaEngineNotBusy => HsmError::IdentifiedPkaEngineNotBusy,
                DdiStatus::IdentifiedEccCalculationFailure => {
                    HsmError::IdentifiedEccCalculationFailure
                }
                DdiStatus::FailedToGenerateEccPublicKey => HsmError::FailedToGenerateEccPublicKey,
                DdiStatus::IdentifiedRsaCalculationFailure => {
                    HsmError::IdentifiedRsaCalculationFailure
                }
                DdiStatus::FailedToBeginRsaCalculation => HsmError::FailedToBeginRsaCalculation,
                DdiStatus::FailedToPerformRsaMultiplication => {
                    HsmError::FailedToPerformRsaMultiplication
                }
                DdiStatus::FailedToEndRsaCalculation => HsmError::FailedToEndRsaCalculation,
                DdiStatus::FailedToPerformRsaModularInverse => {
                    HsmError::FailedToPerformRsaModularInverse
                }
                DdiStatus::FailedToComputeEcdhSharedSecret => {
                    HsmError::FailedToComputeEcdhSharedSecret
                }
                DdiStatus::FailedToIdentifyIoChannelPipe => HsmError::FailedToIdentifyIoChannelPipe,
                DdiStatus::IdentifiedInvalidIoChannelPipe => {
                    HsmError::IdentifiedInvalidIoChannelPipe
                }
                DdiStatus::FailedToSendIpMessage => HsmError::FailedToSendIpMessage,
                DdiStatus::IpcResponseFailure => HsmError::IpcResponseFailure,
                DdiStatus::KeyDerivationFailure => HsmError::KeyDerivationFailure,
                DdiStatus::DerDecodeFailedForAesBulkKey => HsmError::DerDecodeFailedForAesBulkKey,
                DdiStatus::InvalidIpcShutdownMessage => HsmError::InvalidIpcShutdownMessage,
                DdiStatus::SessionEncryptionKeyGenerateFailed => {
                    HsmError::SessionEncryptionKeyGenerateFailed
                }
                DdiStatus::IoTimedOut => HsmError::IoTimedOut,
                DdiStatus::IoDrainInProgress => HsmError::IoDrainInProgress,
                DdiStatus::IoChannelPipeDeleteError => HsmError::IoChannelPipeDeleteError,
                DdiStatus::IpcResponseDecodeError => HsmError::IpcResponseDecodeError,
                DdiStatus::UnknownSelfTestRequestReceived => {
                    HsmError::UnknownSelfTestRequestReceived
                }
                DdiStatus::SelfTestMissingInstance => HsmError::SelfTestMissingInstance,
                DdiStatus::FailedToWipePkaMemory => HsmError::FailedToWipePkaMemory,
                DdiStatus::IoDrainReady => HsmError::IoDrainReady,
                DdiStatus::InvalidPackageInfo => HsmError::InvalidPackageInfo,
                DdiStatus::PctValidationEccGenKeyFailed => HsmError::PctValidationEccGenKeyFailed,
                DdiStatus::PctValidationEstablishCredEncKeyFailed => {
                    HsmError::PctValidationEstablishCredEncKeyFailed
                }
                DdiStatus::PctValidationSessionEncKeyFailed => {
                    HsmError::PctValidationSessionEncKeyFailed
                }
                DdiStatus::PctValidationUnwrappingKeyFailed => {
                    HsmError::PctValidationUnwrappingKeyFailed
                }
                DdiStatus::PctValidationRsaUnwrapEccKeyFailed => {
                    HsmError::PctValidationRsaUnwrapEccKeyFailed
                }
                DdiStatus::PctValidationRsaUnwrapRsaKeyFailed => {
                    HsmError::PctValidationRsaUnwrapRsaKeyFailed
                }
                DdiStatus::NonFipsApprovedDigest => HsmError::NonFipsApprovedDigest,
                DdiStatus::DigestHashMismatchWithEccCurve => {
                    HsmError::DigestHashMismatchWithEccCurve
                }
                DdiStatus::UnsupportedDigestHashAlgorithm => {
                    HsmError::UnsupportedDigestHashAlgorithm
                }
                DdiStatus::FailedToStartPublicKeyValidation => {
                    HsmError::FailedToStartPublicKeyValidation
                }
                DdiStatus::FailedToEndEccPublicKeyValidation => {
                    HsmError::FailedToEndEccPublicKeyValidation
                }
                DdiStatus::EccPointValidationFailed => HsmError::EccPointValidationFailed,
                DdiStatus::EccPublicKeyValidationFailed => HsmError::EccPublicKeyValidationFailed,
                DdiStatus::EccDerKeyShorterThanCurve => HsmError::EccDerKeyShorterThanCurve,
                DdiStatus::RsaUnwrapInvalidRequest => HsmError::RsaUnwrapInvalidRequest,
                DdiStatus::RsaUnwrapInvalidKek => HsmError::RsaUnwrapInvalidKek,
                DdiStatus::RsaUnwrapOaepDecodeFailed => HsmError::RsaUnwrapOaepDecodeFailed,
                DdiStatus::RsaUnwrapInvalidAesUnwrapState => {
                    HsmError::RsaUnwrapInvalidAesUnwrapState
                }
                DdiStatus::RsaUnwrapAesUnwrapFailed => HsmError::RsaUnwrapAesUnwrapFailed,
                DdiStatus::AttestationReportEncodeFailed => HsmError::AttestationReportEncodeFailed,
                DdiStatus::CoseKeyEncodeFailed => HsmError::CoseKeyEncodeFailed,
                DdiStatus::AttestKeyInternalError => HsmError::AttestKeyInternalError,
                DdiStatus::MaskedKeyDecodeFailed => HsmError::MaskedKeyDecodeFailed,
                DdiStatus::MaskedKeyEncodeFailed => HsmError::MaskedKeyEncodeFailed,
                DdiStatus::MaskedKeyInvalidLength => HsmError::MaskedKeyInvalidLength,
                DdiStatus::MaskedKeyPreEncodeFailed => HsmError::MaskedKeyPreEncodeFailed,
                DdiStatus::CredentialsNotEstablished => HsmError::CredentialsNotEstablished,
                _ => {
                    tracing::warn!("Unknown DdiStatus encountered: {:?}", ddi_status);
                    HsmError::UnknownError
                }
            },
            #[cfg(target_os = "linux")]
            DdiError::NixError(err_code) => HsmError::NixError(err_code),
            #[cfg(target_os = "windows")]
            DdiError::WinError(err_code) => HsmError::WinError(err_code),
            DdiError::IoError(_) => HsmError::IoError, // std::io::Error does not implement PartialEq so we must convert to a single error
            DdiError::InvalidApiVersion => HsmError::InvalidApiVersion,
            DdiError::FpError(_) => HsmError::AesFpErrorGeneric,
            DdiError::FpCmdSpecificError(_) => HsmError::AesFpErrorGeneric,
            DdiError::DeviceInfoIoctlInvalidData => HsmError::DeviceInfoIoctlInvalidData,
            DdiError::DriverError(driver_error) => match driver_error {
                DriverError::IoAbortInProgress => HsmError::IoError,
                DriverError::IoAborted => HsmError::IoError,
            },
            DdiError::ResetDeviceError(err_code) => HsmError::ResetDeviceError(err_code),
        }
    }
}
