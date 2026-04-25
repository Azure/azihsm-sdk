// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

use azihsm_fw_ddi_derive::Ddi;
use open_enum::open_enum;
use pastey::paste;

pub mod error;
pub mod sessctrl;

// ── Per-command modules ────────────────────────────────────────────────
pub mod aes_encrypt_decrypt;
pub mod aes_generate_key;
pub mod attest_key;
pub mod change_pin;
pub mod close_session;
pub mod delete_key;
pub mod derive_hkdf;
pub mod derive_kbkdf;
pub mod ecc_generate_key_pair;
pub mod ecc_sign;
pub mod ecdh_key_exchange;
pub mod establish_credential;
pub mod get_api_rev;
pub mod get_cert_chain_info;
pub mod get_certificate;
pub mod get_device_info;
pub mod get_establish_cred_encryption_key;
pub mod get_sealed_bk3;
pub mod get_session_encryption_key;
pub mod get_unwrapping_key;
pub mod hmac;
pub mod init_bk3;
pub mod open_key;
pub mod open_session;
pub mod reopen_session;
pub mod rsa_mod_exp;
pub mod rsa_unwrap;
pub mod set_sealed_bk3;
pub mod unmask_key;

// Re-export codec types.
pub use azihsm_fw_ddi::DdiDecoder;
pub use azihsm_fw_ddi::DdiEncoder;
pub use azihsm_fw_ddi::MborError;
pub use error::DdiErrResp;
// Re-export per-command types.
pub use get_api_rev::*;
pub use get_device_info::*;

/// Maximum key label length in bytes.
pub const DDI_MAX_KEY_LABEL_LENGTH: usize = 128;

// ── DDI operation codes ────────────────────────────────────────────────

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiOp {
    Invalid = 1001,
    GetApiRev = 1002,
    GetDeviceInfo = 1003,
    DeleteKey = 1014,
    OpenKey = 1015,
    AttestKey = 1016,
    RsaModExp = 1031,
    RsaUnwrap = 1035,
    GetUnwrappingKey = 1051,
    EccGenerateKeyPair = 1061,
    EccSign = 1062,
    AesGenerateKey = 1071,
    AesEncryptDecrypt = 1072,
    EcdhKeyExchange = 1074,
    HkdfDerive = 1075,
    KbkdfCounterHmacDerive = 1076,
    Hmac = 1077,
    GetEstablishCredEncryptionKey = 1101,
    EstablishCredential = 1102,
    GetSessionEncryptionKey = 1103,
    OpenSession = 1104,
    CloseSession = 1105,
    ChangePin = 1106,
    UnmaskKey = 1107,
    GetCertChainInfo = 1108,
    GetCertificate = 1109,
    ReopenSession = 1110,
    InitBk3 = 1111,
    GetSealedBk3 = 1112,
    SetSealedBk3 = 1113,
}

// ── DDI status codes ───────────────────────────────────────────────────

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiStatus {
    Success = 0,
    InvalidArg = 134217731,
    InternalError = 134217736,
    UnsupportedCmd = 134217737,
    DdiEncodeFailed = 141033473,
    DdiDecodeFailed = 141033474,
    VaultSessionLimitReached = 141557761,
    SessionNotExpected = 141557762,
    SessionExpected = 141557763,
    SessionNotFound = 141557764,
    InvalidManagerCredentials = 141557766,
    InvalidAppCredentials = 141557767,
    VaultNotFound = 141557768,
    AppAlreadyExists = 141557769,
    AppNotFound = 141557770,
    KeyNotFound = 141557774,
    InvalidKeyType = 141557775,
    KeyDecodeFailed = 141557776,
    RsaEncryptFailed = 141557777,
    RsaDecryptFailed = 141557778,
    RsaSignFailed = 141557779,
    FileHandleSessionLimitReached = 141557790,
    FileHandleNoExistingSession = 141557791,
    FileHandleSessionIdDoesNotMatch = 141557792,
    KeyTagAlreadyExists = 141557793,
    InvalidPermissions = 141557794,
    EccSignFailed = 141557795,
    EccVerifyFailed = 141557796,
    AesEncryptFailed = 141557797,
    AesDecryptFailed = 141557798,
    FunctionNotEnabled = 141557799,
    AnotherKeyInUse = 141557800,
    KeyNotInUse = 141557801,
    UnsupportedRevision = 141557802,
    DerAndKeyTypeMismatch = 141557803,
    VaultAppLimitReached = 141557804,
    NotEnoughSpace = 141557805,
    ReachedMaxKeys = 141557806,
    CannotDeleteKeyInUse = 141557807,
    CannotDeleteSomeKeysInUse = 141557808,
    CannotCloseSessionInUse = 141557809,
    CannotCloseSomeSessionsInUse = 141557810,
    CannotDeleteKeyAndCloseSessionInUse = 141557811,
    InvalidKeyNumber = 141557812,
    FunctionNotFound = 141557814,
    RsaToDerError = 141557815,
    RsaGenerateError = 141557816,
    RsaGetModulusError = 141557817,
    RsaGetPublicExponentError = 141557818,
    RsaInvalidKeyLength = 141557819,
    EccToDerError = 141557820,
    EccGenerateError = 141557821,
    EccDeriveError = 141557822,
    EccGetCurveError = 141557823,
    EccGetCoordinatesError = 141557824,
    ShaError = 141557825,
    AesGenerateError = 141557826,
    CoseSign1UnexpectedSignature = 141557827,
    CannotUseDefaultCredentials = 141557828,
    HkdfError = 141557829,
    KbkdfError = 141557830,
    RsaUnwrapError = 141557831,
    AttestKeyError = 141557832,
    InvalidShortAppId = 141557833,
    NoShortAppIdCreated = 141557834,
    NoTagProvided = 141557835,
    AesGcmInvalidBufferSize = 141557836,
    AesGcmDecryptTagDoesNotMatch = 141557837,
    AesXtsInvalidBufferSize = 141557838,
    AesXtsInvalidDul = 141557839,
    EccInvalidKeyLength = 141557840,
    AesInvalidKeyLength = 141557841,
    InvalidCertificate = 141557842,
    PendingKeyGeneration = 141557843,
    CannotDeleteInternalKeys = 141557844,
    FailedToSendSoftAesRequest = 141557845,
    HmacError = 141557846,
    PinDecryptionFailed = 141557847,
    ReachedMaxAesBulkKeys = 141557848,
    HmacInvalidInputSize = 141557849,
    RngError = 141557850,
    NonceMismatch = 141557851,
    EstablishCredEncryptionKeyGenerateFailed = 141557852,
    HkdfInvalidInputParam = 141557853,
    KbkdfInvalidInputParam = 141557854,
    LoginFailed = 141557855,
    FailedSoftAesResponse = 141557856,
    KeyStructuralValidationFailed = 141557857,
    PendingIo = 141557858,
    ReceivedEmptyIoEvent = 141557859,
    IoChannelReceiveError = 141557860,
    IoChannelDecodeError = 141557861,
    IoChannelUnknownOp = 141557862,
    IoChannelInvalidSrcLen = 141557863,
    IoChannelInvalidDstLen = 141557864,
    PartitionNotEnabled = 141557865,
    IoChannePipelNotEnabled = 141557866,
    IoChannePipeNotValid = 141557867,
    DmaBufferAllocFailure = 141557868,
    IoChannelInvalidBufferDescriptor = 141557869,
    DmaHardwareEmptyCompletionFound = 141557870,
    DmaCompletedWithError = 141557871,
    DmaIoIdentifierMismatch = 141557872,
    IoChannelPipeNotFound = 141557873,
    FailedToAssociateIoWithPartition = 141557874,
    FailedToStartDmaTransaction = 141557875,
    IoChannelFailedToSendResponse = 141557876,
    FailedToIdentifyDmaBuffer = 141557877,
    IoChannelRequestDecodeError = 141557878,
    IoCommandNotFound = 141557879,
    IoChannelInvalidSrcAlignment = 141557880,
    IoChannelInvalidDstAlignment = 141557881,
    IoCommandError = 141557882,
    SpuriousIpcMessageReceived = 141557883,
    InvalidIpcMessageReceived = 141557884,
    FailedToDecodeIpcMessage = 141557885,
    InvalidIpcMessageOpCodeFound = 141557886,
    IoChannelTxEmptyCompletionFound = 141557887,
    FailedToAssociateIoWithCompletion = 141557888,
    IoChannelFailedToSendCompletion = 141557889,
    DefragmentationNeeded = 141557890,
    InvalidSessionControlOpcode = 141557891,
    DerDecodeFailed = 141557892,
    InvalidMemoryMapEntry = 141557893,
    ProcessedInvalidIoEvent = 141557894,
    ProcessedIoEventInInvalidState = 141557895,
    CannotAssociateIoWithPkaCompletion = 141557896,
    IdentifiedPkaEngineNotBusy = 141557897,
    IdentifiedEccCalculationFailure = 141557898,
    FailedToGenerateEccPublicKey = 141557899,
    IdentifiedRsaCalculationFailure = 141557900,
    FailedToBeginRsaCalculation = 141557901,
    FailedToPerformRsaMultiplication = 141557902,
    FailedToEndRsaCalculation = 141557903,
    FailedToPerformRsaModularInverse = 141557904,
    FailedToComputeEcdhSharedSecret = 141557905,
    FailedToIdentifyIoChannelPipe = 141557906,
    IdentifiedInvalidIoChannelPipe = 141557907,
    FailedToSendIpMessage = 141557908,
    IpcResponseFailure = 141557909,
    KeyDerivationFailure = 141557910,
    DerDecodeFailedForAesBulkKey = 141557911,
    InvalidIpcShutdownMessage = 141557912,
    SessionEncryptionKeyGenerateFailed = 141557913,
    IoTimedOut = 141557914,
    IoDrainInProgress = 141557915,
    IoChannelPipeDeleteError = 141557916,
    IpcResponseDecodeError = 141557917,
    UnknownSelfTestRequestReceived = 141557918,
    SelfTestMissingInstance = 141557919,
    FailedToWipePkaMemory = 141557920,
    IoDrainReady = 141557921,
    InvalidPackageInfo = 141557922,
    PctValidationEccGenKeyFailed = 141557923,
    PctValidationEstablishCredEncKeyFailed = 141557924,
    PctValidationSessionEncKeyFailed = 141557925,
    PctValidationUnwrappingKeyFailed = 141557926,
    PctValidationRsaUnwrapEccKeyFailed = 141557927,
    PctValidationRsaUnwrapRsaKeyFailed = 141557928,
    NonFipsApprovedDigest = 141557929,
    DigestHashMismatchWithEccCurve = 141557930,
    UnsupportedDigestHashAlgorithm = 141557931,
    FailedToStartPublicKeyValidation = 141557932,
    FailedToEndEccPublicKeyValidation = 141557933,
    EccPointValidationFailed = 141557934,
    EccPublicKeyValidationFailed = 141557935,
    EccDerKeyShorterThanCurve = 141557936,
    RsaUnwrapInvalidRequest = 141557937,
    RsaUnwrapInvalidKek = 141557938,
    RsaUnwrapOaepDecodeFailed = 141557939,
    RsaUnwrapInvalidAesUnwrapState = 141557940,
    RsaUnwrapAesUnwrapFailed = 141557941,
    AttestationReportEncodeFailed = 141557942,
    CoseKeyEncodeFailed = 141557943,
    AttestKeyInternalError = 141557944,
    MaskedKeyInvalidLength = 141557950,
    MaskedKeyPreEncodeFailed = 141557951,
    MaskedKeyEncodeFailed = 141557952,
    MaskedKeyDecodeFailed = 141557953,
    InvalidAlgorithm = 141557954,
    InsufficientBuffer = 141557955,
    InvalidKeyLength = 141557956,
    MetadataEncodeFailed = 141557957,
    MetadataDecodeFailed = 141557958,
    SessionNeedsRenegotiation = 141557959,
    BkBootGenerationFailed = 141557960,
    MaskingBk3Failed = 141557961,
    UnmaskingBk3Failed = 141557962,
    MaskingBkBootFailed = 141557963,
    UnmaskingBkBootFailed = 141557964,
    MaskedBkBootNotPresent = 141557965,
    SealedBk3TooLarge = 141557966,
    PartitionAlreadyProvisioned = 141557967,
    SealedBk3NotPresent = 141557968,
    CredentialsNotEstablished = 141557969,
    InvalidAliasKey = 141557970,
    UnmaskUnwrappingKeyNotAllowed = 141557971,
    InvalidPartitionIdContent = 141557972,
    PartitionNotProvisioned = 141557973,
    Bk3AlreadyInitialized = 141557974,
    SealedBk3AlreadySet = 141557975,
    PartitionIdKeyGenerationPctFailed = 141557976,
}

// ── Key and crypto enums ───────────────────────────────────────────────

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiKeyType {
    Rsa2kPrivate = 1,
    Rsa3kPrivate = 2,
    Rsa4kPrivate = 3,
    Rsa2kPrivateCrt = 4,
    Rsa3kPrivateCrt = 5,
    Rsa4kPrivateCrt = 6,
    Ecc256Private = 7,
    Ecc384Private = 8,
    Ecc521Private = 9,
    Aes128 = 10,
    Aes192 = 11,
    Aes256 = 12,
    AesXtsBulk256 = 13,
    AesGcmBulk256 = 14,
    AesGcmBulk256Unapproved = 15,
    Secret256 = 16,
    Secret384 = 17,
    Secret521 = 18,
    Rsa2kPublic = 19,
    Rsa3kPublic = 20,
    Rsa4kPublic = 21,
    Ecc256Public = 22,
    Ecc384Public = 23,
    Ecc521Public = 24,
    HmacSha256 = 25,
    HmacSha384 = 26,
    HmacSha512 = 27,
    AesCbc256Hmac384 = 28,
    KbKdfSecretSha384 = 29,
    VarHmac256 = 30,
    VarHmac384 = 31,
    VarHmac512 = 32,
    RsaUnwrap = 0xffff,
}

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiKeyClass {
    Rsa = 1,
    RsaCrt = 2,
    Aes = 3,
    AesXtsBulk = 4,
    AesGcmBulk = 5,
    AesGcmBulkUnapproved = 6,
    Ecc = 7,
}

#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiHashAlgorithm {
    Sha1 = 1,
    Sha256 = 2,
    Sha384 = 3,
    Sha512 = 4,
}

#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiKeyUsage {
    SignVerify = 1,
    EncryptDecrypt = 2,
    Unwrap = 3,
    Derive = 4,
}

#[open_enum]
#[derive(Debug, Ddi, Copy, Eq, PartialEq, Clone)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiKeyAvailability {
    App = 1,
    Session = 2,
}

#[open_enum]
#[derive(Debug, Ddi, Copy, Eq, PartialEq, Clone)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiDeviceKind {
    Virtual = 1,
    Physical = 2,
}

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiEccCurve {
    P256 = 1,
    P384 = 2,
    P521 = 3,
}

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiRsaOpType {
    Decrypt = 1,
    Sign = 2,
}

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiRsaCryptoPadding {
    Oaep = 1,
}

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiAesOp {
    Encrypt = 1,
    Decrypt = 2,
}

#[open_enum]
#[derive(Debug, Ddi, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiAesKeySize {
    Aes128 = 1,
    Aes192 = 2,
    Aes256 = 3,
    AesXtsBulk256 = 4,
    AesGcmBulk256 = 5,
    AesGcmBulk256Unapproved = 6,
}

// ── Session kind ───────────────────────────────────────────────────────

pub enum DdiSessionKind {
    None,
    User,
}

impl From<DdiOp> for DdiSessionKind {
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
            | DdiOp::OpenSession
            | DdiOp::InitBk3
            | DdiOp::GetSealedBk3
            | DdiOp::SetSealedBk3 => DdiSessionKind::None,
            _ => DdiSessionKind::User,
        }
    }
}

// ── Shared structs ─────────────────────────────────────────────────────

#[derive(Debug, Ddi, PartialEq, Eq, Clone, Copy)]
#[ddi(map)]
pub struct DdiApiRev {
    #[ddi(id = 1)]
    pub major: u32,
    #[ddi(id = 2)]
    pub minor: u32,
}

impl PartialOrd for DdiApiRev {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        if self.major == other.major {
            self.minor.partial_cmp(&other.minor)
        } else {
            self.major.partial_cmp(&other.major)
        }
    }
}

#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiReqHdr {
    #[ddi(id = 1)]
    pub rev: Option<DdiApiRev>,
    #[ddi(id = 2)]
    pub op: DdiOp,
    #[ddi(id = 3)]
    pub sess_id: Option<u16>,
}

#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiReqExt {}

#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiRespHdr {
    #[ddi(id = 1)]
    pub rev: Option<DdiApiRev>,
    #[ddi(id = 2)]
    pub op: DdiOp,
    #[ddi(id = 3)]
    pub sess_id: Option<u16>,
    #[ddi(id = 4)]
    pub status: DdiStatus,
    #[ddi(id = 5)]
    pub fips_approved: bool,
}

#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiRespExt {}

/// Public key data (raw bytes, no DER conversion).
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiPublicKey<'a> {
    #[ddi(id = 1, max_len = 768)]
    pub raw: &'a [u8],
    #[ddi(id = 2)]
    pub key_kind: DdiKeyType,
}

/// Key properties for target key creation.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiKeyProperties<'a> {
    #[ddi(id = 1)]
    pub key_usage: DdiKeyUsage,
    #[ddi(id = 2)]
    pub key_availability: DdiKeyAvailability,
    #[ddi(id = 3, max_len = 128)]
    pub key_label: &'a [u8],
}

/// Target key metadata (16-byte bitflag blob).
#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiTargetKeyMetadata {
    #[ddi(id = 1)]
    pub blob: [u8; 16],
}

/// Target key properties for key creation/unwrap.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTargetKeyProperties<'a> {
    #[ddi(id = 1)]
    pub key_metadata: DdiTargetKeyMetadata,
    #[ddi(id = 2, max_len = 128)]
    pub key_label: &'a [u8],
}

// ── ddi_op_req_resp! macro ─────────────────────────────────────────────

/// Trait for DDI operation requests.
pub trait DdiOpReq {
    type OpResp;
    fn get_opcode(&self) -> DdiOp;
    fn get_session_id(&self) -> Option<u16>;
}

#[macro_export]
macro_rules! ddi_op_req_resp {
    ($name:ident) => {
        paste! {
            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdReq>] {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiReqHdr,
                #[ddi(id = 1)]
                pub data: [<$name Req>],
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiReqExt>,
            }

            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdResp>] {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiRespHdr,
                #[ddi(id = 1)]
                pub data: [<$name Resp>],
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiRespExt>,
            }

            impl $crate::DdiOpReq for [<$name CmdReq>] {
                type OpResp = [<$name CmdResp>];
                fn get_opcode(&self) -> $crate::DdiOp { self.hdr.op }
                fn get_session_id(&self) -> Option<u16> { self.hdr.sess_id }
            }
        }
    };
    ($name:ident, $lt:lifetime) => {
        paste! {
            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdReq>]<$lt> {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiReqHdr,
                #[ddi(id = 1)]
                pub data: [<$name Req>]<$lt>,
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiReqExt>,
            }

            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdResp>]<$lt> {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiRespHdr,
                #[ddi(id = 1)]
                pub data: [<$name Resp>]<$lt>,
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiRespExt>,
            }

            impl<$lt> $crate::DdiOpReq for [<$name CmdReq>]<$lt> {
                type OpResp = [<$name CmdResp>]<$lt>;
                fn get_opcode(&self) -> $crate::DdiOp { self.hdr.op }
                fn get_session_id(&self) -> Option<u16> { self.hdr.sess_id }
            }
        }
    };
    // Variant: Req has no lifetime, Resp has lifetime
    ($name:ident,resp $lt:lifetime) => {
        paste! {
            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdReq>] {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiReqHdr,
                #[ddi(id = 1)]
                pub data: [<$name Req>],
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiReqExt>,
            }

            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdResp>]<$lt> {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiRespHdr,
                #[ddi(id = 1)]
                pub data: [<$name Resp>]<$lt>,
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiRespExt>,
            }

            impl $crate::DdiOpReq for [<$name CmdReq>] {
                type OpResp = [<$name CmdResp>]<'static>;
                fn get_opcode(&self) -> $crate::DdiOp { self.hdr.op }
                fn get_session_id(&self) -> Option<u16> { self.hdr.sess_id }
            }
        }
    };
    // Variant: Req has lifetime, Resp has no lifetime
    ($name:ident,req $lt:lifetime) => {
        paste! {
            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdReq>]<$lt> {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiReqHdr,
                #[ddi(id = 1)]
                pub data: [<$name Req>]<$lt>,
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiReqExt>,
            }

            #[derive(Ddi, Debug)]
            #[ddi(map)]
            pub struct [<$name CmdResp>] {
                #[ddi(id = 0)]
                pub hdr: $crate::DdiRespHdr,
                #[ddi(id = 1)]
                pub data: [<$name Resp>],
                #[ddi(id = 2)]
                pub ext: Option<$crate::DdiRespExt>,
            }

            impl<$lt> $crate::DdiOpReq for [<$name CmdReq>]<$lt> {
                type OpResp = [<$name CmdResp>];
                fn get_opcode(&self) -> $crate::DdiOp { self.hdr.op }
                fn get_session_id(&self) -> Option<u16> { self.hdr.sess_id }
            }
        }
    };
}
