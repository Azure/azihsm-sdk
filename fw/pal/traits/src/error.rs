// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM error / status type.
//!
//! [`HsmError`] is the universal error type used across PAL traits, core
//! handlers, and the DDI protocol layer. It is an open `u32` enum with
//! named variants matching the DDI protocol status codes.
//!
//! Custom diagnostic codes (e.g. for internal telemetry) can use values
//! outside the named variant range.

use open_enum::open_enum;

/// HSM error / status code.
///
/// An open `u32` enum. Named variants match the DDI protocol status
/// codes. Unknown values are preserved — the type is "open" like a C enum.
#[open_enum]
#[derive(Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
pub enum HsmError {
    InvalidArg = 0x08000003,
    InternalError = 0x08000008,
    UnsupportedCmd = 0x08000009,
    DdiEncodeFailed = 0x08680001,
    DdiDecodeFailed = 0x08680002,
    VaultSessionLimitReached = 0x08700001,
    SessionNotExpected = 0x08700002,
    SessionExpected = 0x08700003,
    SessionNotFound = 0x08700004,
    InvalidManagerCredentials = 0x08700006,
    InvalidAppCredentials = 0x08700007,
    VaultNotFound = 0x08700008,
    AppAlreadyExists = 0x08700009,
    AppNotFound = 0x0870000A,
    KeyNotFound = 0x0870000E,
    InvalidKeyType = 0x0870000F,
    KeyDecodeFailed = 0x08700010,
    RsaEncryptFailed = 0x08700011,
    RsaDecryptFailed = 0x08700012,
    RsaSignFailed = 0x08700013,
    FileHandleSessionLimitReached = 0x0870001E,
    FileHandleNoExistingSession = 0x0870001F,
    FileHandleSessionIdDoesNotMatch = 0x08700020,
    KeyTagAlreadyExists = 0x08700021,
    InvalidPermissions = 0x08700022,
    EccSignFailed = 0x08700023,
    EccVerifyFailed = 0x08700024,
    AesEncryptFailed = 0x08700025,
    AesDecryptFailed = 0x08700026,

    FunctionNotEnabled = 0x08700027,
    AnotherKeyInUse = 0x08700028,
    KeyNotInUse = 0x08700029,
    UnsupportedRevision = 0x0870002A,
    DerAndKeyTypeMismatch = 0x0870002B,
    VaultAppLimitReached = 0x0870002C,
    NotEnoughSpace = 0x0870002D,
    ReachedMaxKeys = 0x0870002E,
    CannotDeleteKeyInUse = 0x0870002F,
    CannotDeleteSomeKeysInUse = 0x08700030,
    CannotCloseSessionInUse = 0x08700031,
    CannotCloseSomeSessionsInUse = 0x08700032,
    CannotDeleteKeyAndCloseSessionInUse = 0x08700033,
    InvalidKeyNumber = 0x08700034,
    FunctionNotFound = 0x08700036,
    RsaToDerError = 0x08700037,
    RsaGenerateError = 0x08700038,
    RsaGetModulusError = 0x08700039,
    RsaGetPublicExponentError = 0x0870003A,
    RsaInvalidKeyLength = 0x0870003B,
    EccToDerError = 0x0870003C,
    EccGenerateError = 0x0870003D,
    EccDeriveError = 0x0870003E,
    EccGetCurveError = 0x0870003F,
    EccGetCoordinatesError = 0x08700040,
    ShaError = 0x08700041,
    AesGenerateError = 0x08700042,
    CoseSign1UnexpectedSignature = 0x08700043,
    CannotUseDefaultCredentials = 0x08700044,
    HkdfError = 0x08700045,
    KbkdfError = 0x08700046,
    RsaUnwrapError = 0x08700047,
    AttestKeyError = 0x08700048,
    InvalidShortAppId = 0x08700049,
    NoShortAppIdCreated = 0x0870004A,
    NoTagProvided = 0x0870004B,
    AesGcmInvalidBufferSize = 0x0870004C,
    AesGcmDecryptTagDoesNotMatch = 0x0870004D,
    AesXtsInvalidBufferSize = 0x0870004E,
    AesXtsInvalidDul = 0x0870004F,
    EccInvalidKeyLength = 0x08700050,
    AesInvalidKeyLength = 0x08700051,
    InvalidCertificate = 0x08700052,
    PendingKeyGeneration = 0x08700053,
    CannotDeleteInternalKeys = 0x08700054,
    FailedToSendSoftAesRequest = 0x08700055,
    HmacError = 0x08700056,
    PinDecryptionFailed = 0x08700057,
    ReachedMaxAesBulkKeys = 0x08700058,
    HmacInvalidInputSize = 0x08700059,
    RngError = 0x0870005A,
    NonceMismatch = 0x0870005B,
    EstablishCredEncryptionKeyGenerateFailed = 0x0870005C,
    HkdfInvalidInputParam = 0x0870005D,
    KbkdfInvalidInputParam = 0x0870005E,
    LoginFailed = 0x0870005F,
    FailedSoftAesResponse = 0x08700060,
    KeyStructuralValidationFailed = 0x08700061,
    PendingIo = 0x08700062,
    ReceivedEmptyIoEvent = 0x08700063,
    IoChannelReceiveError = 0x08700064,
    IoChannelDecodeError = 0x08700065,
    IoChannelUnknownOp = 0x08700066,
    IoChannelInvalidSrcLen = 0x08700067,
    IoChannelInvalidDstLen = 0x08700068,
    PartitionNotEnabled = 0x08700069,
    IoChannePipelNotEnabled = 0x0870006A,
    IoChannePipeNotValid = 0x0870006B,
    DmaBufferAllocFailure = 0x0870006C,
    IoChannelInvalidBufferDescriptor = 0x0870006D,
    DmaHardwareEmptyCompletionFound = 0x0870006E,
    DmaCompletedWithError = 0x0870006F,
    DmaIoIdentifierMismatch = 0x08700070,
    IoChannelPipeNotFound = 0x08700071,
    FailedToAssociateIoWithPartition = 0x08700072,
    FailedToStartDmaTransaction = 0x08700073,
    IoChannelFailedToSendResponse = 0x08700074,
    FailedToIdentifyDmaBuffer = 0x08700075,
    IoChannelRequestDecodeError = 0x08700076,
    IoCommandNotFound = 0x08700077,
    IoChannelInvalidSrcAlignment = 0x08700078,
    IoChannelInvalidDstAlignment = 0x08700079,
    IoCommandError = 0x0870007A,
    SpuriousIpcMessageReceived = 0x0870007B,
    InvalidIpcMessageReceived = 0x0870007C,
    FailedToDecodeIpcMessage = 0x0870007D,
    InvalidIpcMessageOpCodeFound = 0x0870007E,
    IoChannelTxEmptyCompletionFound = 0x0870007F,
    FailedToAssociateIoWithCompletion = 0x08700080,
    IoChannelFailedToSendCompletion = 0x08700081,
    DefragmentationNeeded = 0x08700082,
    InvalidSessionControlOpcode = 0x08700083,
    DerDecodeFailed = 0x08700084,
    InvalidMemoryMapEntry = 0x08700085,
    ProcessedInvalidIoEvent = 0x08700086,
    ProcessedIoEventInInvalidState = 0x08700087,
    CannotAssociateIoWithPkaCompletion = 0x08700088,
    IdentifiedPkaEngineNotBusy = 0x08700089,
    IdentifiedEccCalculationFailure = 0x0870008A,
    FailedToGenerateEccPublicKey = 0x0870008B,
    IdentifiedRsaCalculationFailure = 0x0870008C,
    FailedToBeginRsaCalculation = 0x0870008D,
    FailedToPerformRsaMultiplication = 0x0870008E,
    FailedToEndRsaCalculation = 0x0870008F,
    FailedToPerformRsaModularInverse = 0x08700090,
    FailedToComputeEcdhSharedSecret = 0x08700091,
    FailedToIdentifyIoChannelPipe = 0x08700092,
    IdentifiedInvalidIoChannelPipe = 0x08700093,
    FailedToSendIpMessage = 0x08700094,
    IpcResponseFailure = 0x08700095,
    KeyDerivationFailure = 0x08700096,
    DerDecodeFailedForAesBulkKey = 0x08700097,
    InvalidIpcShutdownMessage = 0x08700098,
    SessionEncryptionKeyGenerateFailed = 0x08700099,
    IoTimedOut = 0x0870009A,
    IoDrainInProgress = 0x0870009B,
    IoChannelPipeDeleteError = 0x0870009C,
    IpcResponseDecodeError = 0x0870009D,
    UnknownSelfTestRequestReceived = 0x0870009E,
    SelfTestMissingInstance = 0x0870009F,
    FailedToWipePkaMemory = 0x087000A0,
    IoDrainReady = 0x087000A1,
    InvalidPackageInfo = 0x087000A2,
    PctValidationEccGenKeyFailed = 0x087000A3,
    PctValidationEstablishCredEncKeyFailed = 0x087000A4,
    PctValidationSessionEncKeyFailed = 0x087000A5,
    PctValidationUnwrappingKeyFailed = 0x087000A6,
    PctValidationRsaUnwrapEccKeyFailed = 0x087000A7,
    PctValidationRsaUnwrapRsaKeyFailed = 0x087000A8,
    NonFipsApprovedDigest = 0x087000A9,
    DigestHashMismatchWithEccCurve = 0x087000AA,
    UnsupportedDigestHashAlgorithm = 0x087000AB,
    FailedToStartPublicKeyValidation = 0x087000AC,
    FailedToEndEccPublicKeyValidation = 0x087000AD,
    EccPointValidationFailed = 0x087000AE,
    EccPublicKeyValidationFailed = 0x087000AF,
    EccDerKeyShorterThanCurve = 0x087000B0,
    RsaUnwrapInvalidRequest = 0x087000B1,
    RsaUnwrapInvalidKek = 0x087000B2,
    RsaUnwrapOaepDecodeFailed = 0x087000B3,
    RsaUnwrapInvalidAesUnwrapState = 0x087000B4,
    RsaUnwrapAesUnwrapFailed = 0x087000B5,
    AttestationReportEncodeFailed = 0x087000B6,
    CoseKeyEncodeFailed = 0x087000B7,
    AttestKeyInternalError = 0x087000B8,
    MaskedKeyInvalidLength = 0x087000BE,
    MaskedKeyPreEncodeFailed = 0x087000BF,
    MaskedKeyEncodeFailed = 0x087000C0,
    MaskedKeyDecodeFailed = 0x087000C1,
    InvalidAlgorithm = 0x087000C2,
    InsufficientBuffer = 0x087000C3,
    InvalidKeyLength = 0x087000C4,
    MetadataEncodeFailed = 0x087000C5,
    MetadataDecodeFailed = 0x087000C6,
    SessionNeedsRenegotiation = 0x087000C7,
    BkBootGenerationFailed = 0x087000C8,
    MaskingBk3Failed = 0x087000C9,
    UnmaskingBk3Failed = 0x087000CA,
    MaskingBkBootFailed = 0x087000CB,
    UnmaskingBkBootFailed = 0x087000CC,
    MaskedBkBootNotPresent = 0x087000CD,
    SealedBk3TooLarge = 0x087000CE,
    PartitionAlreadyProvisioned = 0x087000CF,
    SealedBk3NotPresent = 0x087000D0,
    CredentialsNotEstablished = 0x087000D1,
    InvalidAliasKey = 0x087000D2,
    UnmaskUnwrappingKeyNotAllowed = 0x087000D3,
    InvalidPartitionIdContent = 0x087000D4,
    PartitionNotProvisioned = 0x087000D5,
    Bk3AlreadyInitialized = 0x087000D6,
    SealedBk3AlreadySet = 0x087000D7,
    PartitionIdKeyGenerationPctFailed = 0x087000D8,

    // ── AES Key Wrap errors ────────────────────────────────────────
    AesUnwrapFailed = 0x087000D9,

    // ── Session establishment protocol ─────────────────────────────
    SessionAuthFailure = 0x087000DA,
    InvalidPskId = 0x087000DB,
    SessionNotPending = 0x087000DC,
    AeadEnvelopeAuthFailed = 0x087000DD,
    AeadEnvelopeDecodeFailed = 0x087000DE,
    InvalidSessionType = 0x087000DF,

    // ── Core lifecycle / transport diagnostics ─────────────────────
    SqeInvalidPsdt = 0x087000E0,
    RecvTaskFailure = 0x087000E1,
    PollIoFailure = 0x087000E2,
    SendTaskFailure = 0x087000E3,
    CompleteIoFailure = 0x087000E4,
    DropIoFailure = 0x087000E5,

    /// In-session command rejected because the calling role's
    /// partition PSK is still the well-known compiled-in default.
    /// The only in-session commands permitted in this state are
    /// session tear-down (`CloseSession`) and the PSK rotation
    /// itself (`ChangePsk`); rotate the PSK once and retry.
    DefaultPskMustRotate = 0x087000E6,

    /// `OpenSessionInit` rejected the caller-supplied `suite_id`
    /// because no such suite is implemented (or it has been retired).
    /// See [`SessionSuite`] for the registered values.
    UnsupportedSessionSuite = 0x087000E7,

    /// X.509 DER parsing failed (malformed structure, bad tag/length,
    /// or unsupported field encoding).
    X509ParseError = 0x087000F0,

    /// The root certificate is not self-signed (issuer ≠ subject).
    X509NotSelfSigned = 0x087000F1,

    /// The certificate's issuer does not match the previous certificate's subject.
    X509IssuerMismatch = 0x087000F2,

    /// The ECDSA signature did not verify.
    X509SignatureInvalid = 0x087000F3,

    /// The certificate's AKID does not match the previous certificate's SKID.
    X509AkidSkidMismatch = 0x087000F4,

    /// An intermediate certificate does not have cA=true in BasicConstraints.
    X509NotCa = 0x087000F5,

    /// The chain exceeds the maximum path length from BasicConstraints.
    X509PathLenExceeded = 0x087000F6,

    /// A CA certificate does not have the keyCertSign bit set in KeyUsage.
    X509KeyUsageInvalid = 0x087000F7,

    /// The signature algorithm is not a supported ECDSA variant.
    X509UnsupportedAlgorithm = 0x087000F8,

    /// The certificate contains an unrecognized critical extension.
    X509UnrecognizedCriticalExtension = 0x087000F9,

    /// `step()` was called after the chain was already fully validated.
    X509AlreadyComplete = 0x087000FA,

    /// Failed to export an ECC key to HSM wire format (raw scalar /
    /// coordinate bytes).  This is **not** a DER encoding error — the
    /// HSM ECC format is the raw padded scalar/coordinate bytes
    /// produced by `ExportableHsmKey::to_hsm_bytes` (see
    /// `HsmEccCurve::wire_coord_len`).
    EccExportError = 0x087000FB,

    // ── Partition initialization (PartInit) ────────────────────────
    /// `PartInit` rejected because a Partition Trust Anchor key has
    /// already been bound to this partition incarnation.  One-shot
    /// enforcement: the only path to a fresh PTA binding is via a
    /// full partition free/realloc cycle.
    PtaKeyAlreadySet = 0x087000FC,

    /// `PartInit` rejected because a Unique Machine Secret (UMS) key
    /// has already been bound to this partition incarnation.
    /// One-shot enforcement matching [`Self::PtaKeyAlreadySet`]: the
    /// only path to a fresh UMS binding is via a full partition
    /// free/realloc cycle.
    UmsKeyAlreadySet = 0x087000FD,

    /// A partition operation required the Unique Machine Secret (UMS)
    /// vault key but `PartInit` has not yet successfully bound one
    /// for this incarnation.  Returned by
    /// [`HsmPartitionManager::part_ums_key_id`](crate::HsmPartitionManager::part_ums_key_id)
    /// when the slot is empty.
    UmsKeyNotSet = 0x087000FE,
}

impl core::fmt::Debug for HsmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HsmError({:#010x})", self.0)
    }
}

impl From<u32> for HsmError {
    #[inline]
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl From<HsmError> for u32 {
    #[inline]
    fn from(e: HsmError) -> Self {
        e.0
    }
}

/// A specialized [`Result`] type for HSM operations.
pub type HsmResult<T> = Result<T, HsmError>;
