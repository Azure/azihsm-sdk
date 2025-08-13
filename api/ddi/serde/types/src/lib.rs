// Copyright (c) Microsoft Corporation. All rights reserved.

#![cfg_attr(not(feature = "fuzzing"), no_std)]

mod aes;
mod attest_key;
mod change_pin;
mod close_session;
mod decoder;
mod delete_key;
mod der;
mod derive;
mod ecc;
mod encoder;
mod error;
mod establish_credential;
mod get_api_rev;
mod get_cert;
mod get_collateral;
mod get_device_info;
mod get_establish_cred_encryption_key;
mod get_session_encryption_key;
mod get_unwrapping_key;
mod hmac;
mod mask;
mod open_key;
mod open_session;
mod reopen_session;
mod rsa;
mod sessctrl;
mod test_ops;

pub use aes::*;
pub use attest_key::*;
pub use change_pin::*;
pub use close_session::*;
pub use decoder::DdiDecoder;
pub use delete_key::*;
pub use der::*;
pub use derive::*;
pub use ecc::*;
pub use encoder::DdiEncoder;
pub use error::*;
pub use establish_credential::*;
pub use get_api_rev::*;
pub use get_cert::*;
pub use get_collateral::*;
pub use get_device_info::*;
pub use get_establish_cred_encryption_key::*;
pub use get_session_encryption_key::*;
pub use get_unwrapping_key::*;
pub use hmac::*;
pub use mask::*;
use mcr_ddi_derive::Ddi;
use mcr_ddi_mbor::*;
use open_enum::open_enum;
pub use open_key::*;
pub use open_session::*;
pub use reopen_session::*;
pub use rsa::*;
pub use sessctrl::*;
pub use test_ops::*;

/// Maximum key label length
pub const DDI_MAX_KEY_LABEL_LENGTH: usize = 128;

// Constant used for pre_encode/post_decode for ECC public key data
#[cfg(feature = "post_decode")]
const MAX_ECC_DER_COMPONENT_SIZE: usize = 66;

/// DDI command enumeration
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiOp {
    /// Invalid operation
    Invalid = 1001,

    /// Get API revision
    GetApiRev = 1002,

    /// Get Device Info
    GetDeviceInfo = 1003,

    /// Delete key
    DeleteKey = 1014,

    /// Open key
    OpenKey = 1015,

    /// Generate attestation report for key
    AttestKey = 1016,

    /// Get collateral
    GetCollateral = 1017,

    /// RSA Modular Exponentiation
    RsaModExp = 1031,

    /// RSA unwrap
    RsaUnwrap = 1035,

    /// Get unwrapping RSA key
    GetUnwrappingKey = 1051,

    /// ECC generate key pair
    EccGenerateKeyPair = 1061,

    /// ECC sign
    EccSign = 1062,

    /// AES Generate Key
    AesGenerateKey = 1071,

    /// AES Encrypt/ Decrypt
    AesEncryptDecrypt = 1072,

    /// ECDH key exchange
    EcdhKeyExchange = 1074,

    /// HKDF Derive
    HkdfDerive = 1075,

    /// KBKDF (SP800-108) Counter HMAC Derive
    KbkdfCounterHmacDerive = 1076,

    /// HMAC with Sha
    Hmac = 1077,

    /// Get establish cred encryption ECC key
    GetEstablishCredEncryptionKey = 1101,

    /// Establish credential
    EstablishCredential = 1102,

    /// Get session encryption ECC key
    GetSessionEncryptionKey = 1103,

    /// Open Session
    OpenSession = 1104,

    /// Close Session
    CloseSession = 1105,

    /// Change PIN
    ChangePin = 1106,

    /// Unmask Key
    UnmaskKey = 1107,

    /// Get Cert Chain Info
    GetCertChainInfo = 1108,

    /// Get Certificate
    GetCertificate = 1109,

    /// Re-open Session
    ReopenSession = 1110,

    // Test only opcodes below
    /// Reset function to default state for testing
    ResetFunction = 2001,

    /// Import key in DER format for testing including private keys
    DerKeyImport = 2002,

    /// Get Perf Log Chunk
    GetPerfLogChunk = 2003,

    /// Test action request
    TestAction = 2004,

    /// Get Private Key request
    GetPrivKey = 2005,

    /// SHA Digest
    ShaDigest = 2006,

    /// Get Random Number using RNG
    GetRandomNumber = 2007,

    /// Import a key in RAW format
    RawKeyImport = 2008,

    /// Aes KWP ECB
    SoftAes = 2009,

    /// RSA Unwrap KEK
    RsaUnwrapKek = 2010,
}

/// DDI status code enumeration
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiStatus {
    /// Operation was successful
    Success = 0,

    /// Invalid argument
    InvalidArg = 134217731,

    /// General failure
    InternalError = 134217736,

    /// Unsupported Command
    UnsupportedCmd = 134217737,

    /// CBOR encoding failed
    DdiEncodeFailed = 141033473,

    /// CBOR decoding failed
    DdiDecodeFailed = 141033474,

    /// Max number of sessions for the vault has been reached
    VaultSessionLimitReached = 141557761,

    /// Session was not expected as part of the request but is present
    SessionNotExpected = 141557762,

    /// Session was expected as part of the request but is missing
    SessionExpected = 141557763,

    /// Session was not found
    SessionNotFound = 141557764,

    /// Invalid credentials for manager
    InvalidManagerCredentials = 141557766,

    /// Invalid credentials for app
    InvalidAppCredentials = 141557767,

    /// Vault was not found
    VaultNotFound = 141557768,

    /// App already exists
    AppAlreadyExists = 141557769,

    /// App was not found
    AppNotFound = 141557770,

    /// Key was not found
    KeyNotFound = 141557774,

    /// Invalid key type
    InvalidKeyType = 141557775,

    /// Key DER decode failed
    KeyDecodeFailed = 141557776,

    /// RSA encrypt failed
    RsaEncryptFailed = 141557777,

    /// RSA decrypt failed
    RsaDecryptFailed = 141557778,

    /// RSA sign failed
    RsaSignFailed = 141557779,

    /// Part of session handling.
    /// SessionLimitReached indicates
    /// that no more session ids can
    /// be stored on the file handle.
    ///
    FileHandleSessionLimitReached = 141557790,

    /// Error code to indicate the file
    /// handle has no existing session
    ///
    FileHandleNoExistingSession = 141557791,

    /// Error code to indicate that the session
    /// id provided in the request does not match
    /// the current value in the context
    FileHandleSessionIdDoesNotMatch = 141557792,

    /// Another key with the same tag already exists
    KeyTagAlreadyExists = 141557793,

    /// Invalid Permissions
    InvalidPermissions = 141557794,

    /// ECC sign failed
    EccSignFailed = 141557795,

    /// ECC verify failed
    EccVerifyFailed = 141557796,

    /// AES encrypt failed
    AesEncryptFailed = 141557797,

    /// AES decrypt failed
    AesDecryptFailed = 141557798,

    /// Function not enabled
    FunctionNotEnabled = 141557799,

    /// Another key in use by the given engine.
    AnotherKeyInUse = 141557800,

    /// Key is not being used by the given engine.
    KeyNotInUse = 141557801,

    /// Unsupported revision
    UnsupportedRevision = 141557802,

    /// DER-encoded content does not decode to provided key type.
    DerAndKeyTypeMismatch = 141557803,

    /// Max number of apps for the vault has been reached
    VaultAppLimitReached = 141557804,

    /// There is not enough space to store the key
    NotEnoughSpace = 141557805,

    /// Maxium number of keys for the vault has been reached
    ReachedMaxKeys = 141557806,

    /// The key could not be deleted because it is in use. Please try to delete it again later.
    /// However, it has been disabled for new requests.
    CannotDeleteKeyInUse = 141557807,

    /// More than one keys could not be deleted because they are in use. Please try to delete them again later.
    /// However, they have been disabled for new requests.
    CannotDeleteSomeKeysInUse = 141557808,

    /// The session could not be closed because it is in use. Please try to close it again later.
    /// However, it has been disabled for new requests.
    CannotCloseSessionInUse = 141557809,

    /// More than one session could not be closed because it is in use. Please try to close it again later.
    /// However, it has been disabled for new requests.
    CannotCloseSomeSessionsInUse = 141557810,

    /// Both at least one session and one key, each, could not be closed or deleted. Please try to close it again later.
    /// However, both session(s) and key(s) have been disabled for new requests.
    CannotDeleteKeyAndCloseSessionInUse = 141557811,

    /// The supplied key number is invalid.
    InvalidKeyNumber = 141557812,

    /// The function is not found.
    FunctionNotFound = 141557814,

    /// The key could not be converted to DER-encoded format.
    RsaToDerError = 141557815,

    /// RSA key generation failed.
    RsaGenerateError = 141557816,

    /// Get RSA modulus failed.
    RsaGetModulusError = 141557817,

    /// Get RSA public exponent failed.
    RsaGetPublicExponentError = 141557818,

    /// The length of requested key is invalid. It can only be one of `[2048, 3072, 4096]`.
    RsaInvalidKeyLength = 141557819,

    /// The key could not be converted to DER-encoded format.
    EccToDerError = 141557820,

    /// ECC key generation failed.
    EccGenerateError = 141557821,

    /// ECC Key derivation failed.
    EccDeriveError = 141557822,

    /// Get ECC curve failed.
    EccGetCurveError = 141557823,

    /// Get ECC coordinates failed.
    EccGetCoordinatesError = 141557824,

    /// Sha computation failed.
    ShaError = 141557825,

    /// AES Generate failed.
    AesGenerateError = 141557826,

    /// The CoseSign1 signature is unexpected.
    CoseSign1UnexpectedSignature = 141557827,

    /// Cannot use the default credentials for some operations
    CannotUseDefaultCredentials = 141557828,

    /// HMAC Key Derivation Function failed.
    HkdfError = 141557829,

    /// Key-Based Key Derivation Function failed.
    KbkdfError = 141557830,

    /// RSA unwrap failed.
    RsaUnwrapError = 141557831,

    /// Attest key failed.
    AttestKeyError = 141557832,

    /// Invalid short app id
    /// Introduced for fast path ioctl operations
    InvalidShortAppId = 141557833,

    /// No short app id has been created yet on
    /// the file handle
    NoShortAppIdCreated = 141557834,

    /// No tag provided
    /// A tag must be provided as input to a AES
    /// GCM decryption operation
    ///
    NoTagProvided = 141557835,

    /// FPAESGCMErrors
    /// FP AES GCM encryption
    /// Input buffer size is not valid
    AesGcmInvalidBufferSize = 141557836,

    /// Tag provided for AES GCM decryption
    /// is not valid (Does not match the value
    /// returned in GCM encryption)
    AesGcmDecryptTagDoesNotMatch = 141557837,

    /// Aes Xts buffer invalid size
    AesXtsInvalidBufferSize = 141557838,

    /// Aes Xts data unit length is not valid
    AesXtsInvalidDul = 141557839,

    /// The length of ECC key is invalid. It can only be one of `[256, 384, 521]`.
    EccInvalidKeyLength = 141557840,

    /// The length of ECC key is invalid. It can only be one of `[256, 384, 521]`.
    AesInvalidKeyLength = 141557841,

    /// Certificate is not valid
    InvalidCertificate = 141557842,

    /// Key availibility is pending key generation.
    PendingKeyGeneration = 141557843,

    /// Cannot delete internal keys, like RSA unwrapping key.
    CannotDeleteInternalKeys = 141557844,

    /// Failure to send Soft AES request to Admin core.
    FailedToSendSoftAesRequest = 141557845,

    /// The HMAC operation failed
    HmacError = 141557846,

    /// Decryption using param encryption key failed
    PinDecryptionFailed = 141557847,

    /// Reached maximum number of AES bulk keys
    ReachedMaxAesBulkKeys = 141557848,

    /// HMAC Input Data Size Error
    HmacInvalidInputSize = 141557849,

    /// RNG Error
    RngError = 141557850,

    /// Nonce Mismatch
    NonceMismatch = 141557851,

    /// Establish Cred Encryption Key Generate Failed
    EstablishCredEncryptionKeyGenerateFailed = 141557852,

    /// Hkdf Invalid Input Parameter Error
    HkdfInvalidInputParam = 141557853,

    /// Kbkdf Invalid Input Parameter Error
    KbkdfInvalidInputParam = 141557854,

    /// Failed to open session due to pin policy lockout
    LoginFailed = 141557855,

    /// Failed Soft AES Response
    FailedSoftAesResponse = 141557856,

    /// key structural validation failed
    KeyStructuralValidationFailed = 141557857,

    /// Pending IO
    PendingIo = 141557858,

    /// Received empty IO event
    ReceivedEmptyIoEvent = 141557859,

    /// Firmware IO channel Receive Error
    IoChannelReceiveError = 141557860,

    /// Firmware IO channel decode error
    IoChannelDecodeError = 141557861,

    /// Firmware IO channel unknown operation
    IoChannelUnknownOp = 141557862,

    /// Firmware IO channel invalid source length
    IoChannelInvalidSrcLen = 141557863,

    /// Firmware IO channel invalid destination length
    IoChannelInvalidDstLen = 141557864,

    /// Partition Not Enabled
    PartitionNotEnabled = 141557865,

    /// FW IO channel pipe not enabled
    IoChannePipelNotEnabled = 141557866,

    /// FW IO channel pipe not valid
    IoChannePipeNotValid = 141557867,

    /// FW DMA buffer allocation failure
    DmaBufferAllocFailure = 141557868,

    /// Firmware IO channel invalid buffer descriptor
    IoChannelInvalidBufferDescriptor = 141557869,

    /// Firmware DMA hardware empty completion found
    DmaHardwareEmptyCompletionFound = 141557870,

    /// Firmware DMA completed with error
    DmaCompletedWithError = 141557871,

    /// Firmware DMA IO identifier mismatch
    DmaIoIdentifierMismatch = 141557872,

    /// Firmware IO channel pipe not found
    IoChannelPipeNotFound = 141557873,

    /// Firmware failed to associate IO with a partition
    FailedToAssociateIoWithPartition = 141557874,

    /// Firmware failed to start the DMA transaction
    FailedToStartDmaTransaction = 141557875,

    /// Firmware IO channel failed to send a response
    IoChannelFailedToSendResponse = 141557876,

    /// Firmware failed to identify DMA buffer
    FailedToIdentifyDmaBuffer = 141557877,

    /// Firmware IO channel request decode error
    IoChannelRequestDecodeError = 141557878,

    /// Firmware IO command not found
    IoCommandNotFound = 141557879,

    /// Firmware IO channel invalid source alignment
    IoChannelInvalidSrcAlignment = 141557880,

    /// Firmware IO channel invalid destination alignment
    IoChannelInvalidDstAlignment = 141557881,

    /// Firmware IO command error
    IoCommandError = 141557882,

    /// Firmware spurious IPC message received
    SpuriousIpcMessageReceived = 141557883,

    /// Firmware invalid IPC message received
    InvalidIpcMessageReceived = 141557884,

    /// Firmware failed to decode IPC message
    FailedToDecodeIpcMessage = 141557885,

    /// Firmware invalid IPC message op code found
    InvalidIpcMessageOpCodeFound = 141557886,

    /// Firmware IO channel Tx empty completion found
    IoChannelTxEmptyCompletionFound = 141557887,

    /// Firmware failed to associate IO with a completion
    FailedToAssociateIoWithCompletion = 141557888,

    /// Firmware IO channel failed to send a completion
    IoChannelFailedToSendCompletion = 141557889,

    /// Defragmentation needed for Key vault
    DefragmentationNeeded = 141557890,

    /// Invalid session control opcode
    InvalidSessionControlOpcode = 141557891,

    /// DER decode failed
    DerDecodeFailed = 141557892,

    /// Firmware Invalid Memory Map Entry
    InvalidMemoryMapEntry = 141557893,

    /// Firmware processed invalid IO event
    ProcessedInvalidIoEvent = 141557894,

    /// Firmware processed IO event in invalid state
    ProcessedIoEventInInvalidState = 141557895,

    /// Firmware cannot associate IO with a PKA completion
    CannotAssociateIoWithPkaCompletion = 141557896,

    /// Firmware identified PKA engine not busy
    IdentifiedPkaEngineNotBusy = 141557897,

    /// Firmware identified ECC calculation failure
    IdentifiedEccCalculationFailure = 141557898,

    /// Firmware failed to generate ECC public key
    FailedToGenerateEccPublicKey = 141557899,

    /// Firmware identified RSA calculation failure
    IdentifiedRsaCalculationFailure = 141557900,

    /// Firmware failed to begin RSA calculation
    FailedToBeginRsaCalculation = 141557901,

    /// Frirmware failed to perform RSA multiplication
    FailedToPerformRsaMultiplication = 141557902,

    /// Firmware failed to end RSA calculation
    FailedToEndRsaCalculation = 141557903,

    /// Firmware failed to perform RSA modular inverse
    FailedToPerformRsaModularInverse = 141557904,

    /// Firmware failed to compute ECDH shared secret
    FailedToComputeEcdhSharedSecret = 141557905,

    /// Firmware failed to identify IO channel pipe
    FailedToIdentifyIoChannelPipe = 141557906,

    /// Firmware identified invalid IO channel pipe
    IdentifiedInvalidIoChannelPipe = 141557907,

    /// Firmware failed to send IP message
    FailedToSendIpMessage = 141557908,

    /// Firmware IPC response failure
    IpcResponseFailure = 141557909,

    /// Firmware key derivation failure
    KeyDerivationFailure = 141557910,

    /// DER decoding failure for AES bulk key
    DerDecodeFailedForAesBulkKey = 141557911,

    /// Firmware Invalid IPC shutdown message
    InvalidIpcShutdownMessage = 141557912,

    /// Session encryption key generation failed
    SessionEncryptionKeyGenerateFailed = 141557913,

    /// Firmware IO timed out
    IoTimedOut = 141557914,

    /// Firmware IO drain is in progress
    IoDrainInProgress = 141557915,

    /// Firmware IO channel pipe delete error
    IoChannelPipeDeleteError = 141557916,

    /// Firmware IPC response decode error
    IpcResponseDecodeError = 141557917,

    /// Firmware Unknown self-test request received
    UnknownSelfTestRequestReceived = 141557918,

    /// Firmware self-test missing instance
    SelfTestMissingInstance = 141557919,

    /// Firmware failed to wipe PKA memory
    FailedToWipePkaMemory = 141557920,

    /// Firmware IO drain ready
    IoDrainReady = 141557921,

    /// Invalid FW package information in memory map
    InvalidPackageInfo = 141557922,

    /// ECC Gen Key PCT validation failed
    PctValidationEccGenKeyFailed = 141557923,

    /// Get Establish Credential Encryption Key PCT validation failed
    PctValidationEstablishCredEncKeyFailed = 141557924,

    /// Get Session Encryption Key PCT validation failed
    PctValidationSessionEncKeyFailed = 141557925,

    /// Get Unwrapping Key PCT validation failed
    PctValidationUnwrappingKeyFailed = 141557926,

    /// RSA Unwrap ECC Key PCT validation failed
    PctValidationRsaUnwrapEccKeyFailed = 141557927,

    /// RSA Unwrap RSA Key PCT validation failed
    PctValidationRsaUnwrapRsaKeyFailed = 141557928,

    /// Non FIPS approved digest passed to a FIPS approved module
    NonFipsApprovedDigest = 141557929,

    /// Digest hash algorithm mismatches the ECC curve used
    DigestHashMismatchWithEccCurve = 141557930,

    /// Unsupported Digest hash algorithm used
    UnsupportedDigestHashAlgorithm = 141557931,

    /// Firmware failed to begin ECC public key validation
    FailedToStartPublicKeyValidation = 141557932,

    /// Firmware failed to end ECC public key validation
    FailedToEndEccPublicKeyValidation = 141557933,

    /// ECC Point validation failed
    EccPointValidationFailed = 141557934,

    /// ECC Public key validation failed
    EccPublicKeyValidationFailed = 141557935,

    /// Ecc DER key length is shorter than the curve length
    EccDerKeyShorterThanCurve = 141557936,

    /// RSA unwrap invalid request
    RsaUnwrapInvalidRequest = 141557937,

    /// RSA unwrap invalid KEK
    RsaUnwrapInvalidKek = 141557938,

    /// RSA unwrap OAEP decode failed
    RsaUnwrapOaepDecodeFailed = 141557939,

    /// RSA unwrap invalid AES unwrap state
    RsaUnwrapInvalidAesUnwrapState = 141557940,

    /// RSA unwrap AES unwrap failed
    RsaUnwrapAesUnwrapFailed = 141557941,

    /// Attestation report encoding failed
    AttestationReportEncodeFailed = 141557942,

    /// COSE Key encoding failed
    CoseKeyEncodeFailed = 141557943,

    /// Attestation key internal error
    AttestKeyInternalError = 141557944,

    /// Masked key length is invalid
    MaskedKeyInvalidLength = 141557950,

    /// Masked key pre-encode failed
    MaskedKeyPreEncodeFailed = 141557951,

    /// Masked key encode failed
    MaskedKeyEncodeFailed = 141557952,

    /// Masked key decode failed
    MaskedKeyDecodeFailed = 141557953,
}

/// DDI Key Class
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiKeyClass {
    /// RSA
    Rsa = 1,

    /// RSA CRT
    RsaCrt = 2,

    /// AES
    Aes = 3,

    /// AES Bulk
    AesBulk = 4,

    /// ECC
    Ecc = 5,
}

/// DDI Key Type
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiKeyType {
    /// RSA 2048-bit Private Key.
    Rsa2kPrivate = 1,

    /// RSA 3072-bit Private Key.
    Rsa3kPrivate = 2,

    /// RSA 4096-bit Private Key.
    Rsa4kPrivate = 3,

    /// RSA 2048-bit Private CRT Key.
    Rsa2kPrivateCrt = 4,

    /// RSA 3072-bit Private CRT Key.
    Rsa3kPrivateCrt = 5,

    /// RSA 4096-bit Private CRT Key.
    Rsa4kPrivateCrt = 6,

    /// ECC 256 Private Key
    Ecc256Private = 7,

    /// ECC 384 Private Key
    Ecc384Private = 8,

    /// ECC 521 Private Key
    Ecc521Private = 9,

    /// AES 128-bit Key
    Aes128 = 10,

    /// AES 192-bit Key
    Aes192 = 11,

    /// AES 256-bit Key
    Aes256 = 12,

    /// AES Bulk 256-bit Key
    AesBulk256 = 13,

    /// 256-bit Secret to use in derivation
    Secret256 = 14,

    /// 384-bit Secret to use in derivation
    Secret384 = 15,

    /// 521-bit Secret to use in derivation
    Secret521 = 16,

    /// RSA 2048-bit Public Key.
    Rsa2kPublic = 17,

    /// RSA 3072-bit Public Key.
    Rsa3kPublic = 18,

    /// RSA 4096-bit Public Key.
    Rsa4kPublic = 19,

    /// ECC 256 Public Key
    Ecc256Public = 20,

    /// ECC 384 Public Key
    Ecc384Public = 21,

    /// ECC 521 Public Key
    Ecc521Public = 22,

    /// HMAC 256 Key
    HmacSha256 = 23,

    /// HMAC 384 Key
    HmacSha384 = 24,

    /// HMAC 512 Key
    HmacSha512 = 25,
}

/// DDI Session Kind Enumeration
pub enum DdiSessionKind {
    /// No Session
    None,

    /// User Session
    User,
}

impl From<DdiOp> for DdiSessionKind {
    /// Converts to this type from the input type.
    fn from(value: DdiOp) -> Self {
        match value {
            DdiOp::Invalid
            | DdiOp::GetApiRev
            | DdiOp::GetDeviceInfo
            | DdiOp::GetCertChainInfo
            | DdiOp::GetCertificate
            | DdiOp::GetEstablishCredEncryptionKey
            | DdiOp::EstablishCredential
            | DdiOp::GetSessionEncryptionKey
            | DdiOp::OpenSession => DdiSessionKind::None,

            _ => DdiSessionKind::User,
        }
    }
}

/// DDI Error
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MborError {
    /// CBOR decode error
    DecodeError,

    /// CBOR encode error
    EncodeError,
}

/// DDI DER Public Key
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Clone, PartialEq, Eq)]
#[ddi(map)]
pub struct DdiDerPublicKey {
    /// DER-encoded public key
    #[ddi(id = 1)]
    #[ddi(pre_encode_fn = "pub_key_der_pre_encode")]
    #[ddi(post_decode_fn = "pub_key_der_post_decode")]
    pub der: MborByteArray<768>,

    /// Key type
    #[ddi(id = 2)]
    pub key_kind: DdiKeyType,
}

impl DdiDerPublicKey {
    #[cfg(feature = "post_decode")]
    pub fn pub_key_der_post_decode(
        &self,
        input_array: &MborByteArray<768>,
    ) -> Result<MborByteArray<768>, MborDecodeError> {
        let mut output_array = [0u8; 768];

        let output_vec = match self.key_kind {
            DdiKeyType::Rsa2kPublic | DdiKeyType::Rsa3kPublic | DdiKeyType::Rsa4kPublic => {
                let e_len = 4;
                let n_len = match self.key_kind {
                    DdiKeyType::Rsa2kPublic => 256,
                    DdiKeyType::Rsa3kPublic => 384,
                    DdiKeyType::Rsa4kPublic => 512,
                    _ => Err(MborDecodeError::InvalidKeyData)?,
                };

                let data = input_array.data();
                let key_data = RsaPublicKeyData {
                    e: data[n_len..n_len + e_len].to_vec(),
                    n: data[..n_len].to_vec(),
                    little_endian: true,
                };
                rsa_pub_key_raw_to_der(key_data).map_err(|e| {
                    tracing::error!("Failed to convert RSA public key to DER: {:?}", e);
                    e
                })?
            }
            DdiKeyType::Ecc256Public | DdiKeyType::Ecc384Public | DdiKeyType::Ecc521Public => {
                let (pka_curve_len, der_curve_len, ddi_curve) = match self.key_kind {
                    DdiKeyType::Ecc256Public => (32, 32, DdiEccCurve::P256),
                    DdiKeyType::Ecc384Public => (48, 48, DdiEccCurve::P384),
                    DdiKeyType::Ecc521Public => (68, 66, DdiEccCurve::P521),
                    _ => Err(MborDecodeError::InvalidKeyType)?,
                };
                if input_array.len() != pka_curve_len * 2 {
                    Err(MborDecodeError::InvalidKeyData)?
                }

                // Convert components to big endian
                let data = input_array.data();
                let mut x = [0u8; MAX_ECC_DER_COMPONENT_SIZE];
                reverse_copy(&mut x, &data[..der_curve_len]);

                let mut y = [0u8; MAX_ECC_DER_COMPONENT_SIZE];
                reverse_copy(&mut y, &data[pka_curve_len..pka_curve_len + der_curve_len]);

                let key_data = EccPublicKeyData {
                    x,
                    y,
                    curve: ddi_curve,
                };
                ecc_pub_key_raw_to_der(key_data).map_err(|e| {
                    tracing::error!("Failed to convert ECC public key to DER: {:?}", e);
                    e
                })?
            }
            unexpected_key_type => {
                tracing::error!("Unexpected DdiDerPublicKey kind: {:?}", unexpected_key_type);
                Err(MborDecodeError::InvalidKeyType)?
            }
        };

        output_array[..output_vec.len()].copy_from_slice(&output_vec[..output_vec.len()]);
        Ok(MborByteArray::new(output_array, output_vec.len())?)
    }

    #[cfg(feature = "pre_encode")]
    pub fn pub_key_der_pre_encode(
        &self,
        input_array: &MborByteArray<768>,
    ) -> Result<MborByteArray<768>, MborEncodeError> {
        // Only support pre_encode for Ecc public
        let mut output_array = [0u8; 768];

        let key_data = ecc_pub_key_der_to_raw(&input_array.data()[..input_array.len()])?;

        let (pka_curve_len, der_curve_len) = match self.key_kind {
            DdiKeyType::Ecc256Public => {
                if key_data.curve != DdiEccCurve::P256 {
                    Err(MborEncodeError::DerDecodeFailed)?
                }
                (32, 32)
            }
            DdiKeyType::Ecc384Public => {
                if key_data.curve != DdiEccCurve::P384 {
                    Err(MborEncodeError::DerDecodeFailed)?
                }
                (48, 48)
            }
            DdiKeyType::Ecc521Public => {
                if key_data.curve != DdiEccCurve::P521 {
                    Err(MborEncodeError::DerDecodeFailed)?
                }
                (68, 66)
            }
            _ => Err(MborEncodeError::DerDecodeFailed)?,
        };

        // Convert x and y to little endian
        reverse_copy(
            &mut output_array[..der_curve_len],
            &key_data.x[..der_curve_len],
        );
        reverse_copy(
            &mut output_array[pka_curve_len..pka_curve_len + der_curve_len],
            &key_data.y[..der_curve_len],
        );

        Ok(MborByteArray::new(output_array, pka_curve_len * 2)?)
    }
}

/// DDI Hash Algorithm Enumeration.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiHashAlgorithm {
    /// SHA1
    Sha1 = 1,

    /// SHA256
    Sha256 = 2,

    /// SHA384
    Sha384 = 3,

    /// SHA512
    Sha512 = 4,
}

/// DDI Key Usage Enumeration
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiKeyUsage {
    /// The key may be used for signing and verification
    SignVerify = 1,

    /// The key may be used for encryption and decryption
    EncryptDecrypt = 2,

    /// The key may be used for wrapping and unwrapping
    WrapUnwrap = 3,

    /// The key may be used for ECDH or key derivation. This flag is invalid for RSA/AES key types.
    Derive = 4,
}

/// Enumeration of all DDI key availability
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Eq, PartialEq, Clone)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiKeyAvailability {
    /// The key will be available for all sessions for the current app.
    App = 1,

    /// The key will be only available for the current session.
    Session = 2,
}

/// DDI Key Properties Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[ddi(map)]
pub struct DdiKeyProperties {
    /// Key Usage
    #[ddi(id = 1)]
    pub key_usage: DdiKeyUsage,

    /// Key Availability
    #[ddi(id = 2)]
    pub key_availability: DdiKeyAvailability,

    /// Key label
    #[ddi(id = 3)]
    pub key_label: MborByteArray<DDI_MAX_KEY_LABEL_LENGTH>,
}

/// Enumeration of all DDI device kind
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Eq, PartialEq, Clone)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiDeviceKind {
    /// Virtual Device.
    Virtual = 1,

    /// Physical Device.
    Physical = 2,
}

/// Trait all DDI request structures must implement
pub trait DdiOpReq: MborEncode + MborLen + Sized {
    /// Response type
    type OpResp: for<'a> MborDecode<'a>;

    /// Get opcode from the hdr
    fn get_opcode(&self) -> DdiOp;

    /// Get session id from the hdr
    fn get_session_id(&self) -> Option<u16>;
}

/// DDI API revision Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone, Copy)]
#[ddi(map)]
pub struct DdiApiRev {
    /// Major version
    #[ddi(id = 1)]
    pub major: u32,

    /// Minor version
    #[ddi(id = 2)]
    pub minor: u32,
}

impl PartialOrd for DdiApiRev {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        if self.major == other.major {
            // If major versions are equal, compare minor versions
            self.minor.partial_cmp(&other.minor)
        } else {
            // Otherwise, compare major versions
            self.major.partial_cmp(&other.major)
        }
    }
}

/// DDI request header structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiReqHdr {
    /// API revision (optional)
    #[ddi(id = 1)]
    pub rev: Option<DdiApiRev>,

    /// DDI operation
    #[ddi(id = 2)]
    pub op: DdiOp,

    /// Session ID (optional)
    #[ddi(id = 3)]
    pub sess_id: Option<u16>,
}

/// DDI request extension structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiReqExt {}

/// DDI response header structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiRespHdr {
    /// API revision (optional)
    #[ddi(id = 1)]
    pub rev: Option<DdiApiRev>,

    /// DDI operation
    #[ddi(id = 2)]
    pub op: DdiOp,

    /// Session ID (optional)
    #[ddi(id = 3)]
    pub sess_id: Option<u16>,

    /// DDI Status code
    #[ddi(id = 4)]
    pub status: DdiStatus,

    /// FIPS approval status indication of this DDI operation
    #[ddi(id = 5)]
    pub fips_approved: bool,
}

/// DDI response extension structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiRespExt {}

#[macro_export]
macro_rules! ddi_op_req_resp {
    ($name:ident) => {
        paste::paste! {
            #[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdReq>] {
                /// Request header
                #[ddi(id = 0)]
                pub hdr: DdiReqHdr,

                /// Request data
                #[ddi(id = 1)]
                pub data: [<$name Req>],

                /// Request Extension
                #[ddi(id = 2)]
                pub ext: Option<DdiReqExt>,
            }

            #[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdResp>] {
                /// Response header
                #[ddi(id = 0)]
                pub hdr: DdiRespHdr,

                /// Response data
                #[ddi(id = 1)]
                pub data: [<$name Resp>],

                /// Response Extension
                #[ddi(id = 2)]
                pub ext: Option<DdiRespExt>,
            }

            impl DdiOpReq for [<$name CmdReq>] {
                type OpResp = [<$name CmdResp>];

                // Return the opcode from the request
                // header
                fn get_opcode(&self) -> DdiOp {
                    self.hdr.op
                }

                // Get the session id from the request
                // header
                fn get_session_id(&self) -> Option<u16> {
                    self.hdr.sess_id
                }
            }
        }
    };
}
