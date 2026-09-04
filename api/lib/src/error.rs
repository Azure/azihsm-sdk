// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::error::Error;
use std::fmt::Debug;
use std::fmt::Display;

pub(crate) trait HsmErrorMapper<T, E> {
    fn map_hsm_err(self, hsm_err: HsmError) -> Result<T, HsmError>;
}

impl<T, E: Debug> HsmErrorMapper<T, E> for Result<T, E> {
    fn map_hsm_err(self, hsm_err: HsmError) -> Result<T, HsmError> {
        match self {
            Ok(t) => Ok(t),
            Err(err) => {
                tracing::debug!("Mapping error {:?} to HSM error: {:?}", err, hsm_err);
                Err(hsm_err)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum HsmError {
    Success = 0,
    InvalidArgument = -1,
    InvalidHandle = -2,
    IndexOutOfRange = -3,
    BufferTooSmall = -4,
    InternalError = -5,
    RngError = -6,
    InvalidKeySize = -7,
    DdiCmdFailure = -8,
    PropertyNotPresent = -9,
    KeyClassNotSpecified = -10,
    KeyKindNotSpecified = -11,
    InvalidKey = -12,
    UnsupportedKeyKind = -13,
    UnsupportedAlgorithm = -14,
    InvalidSignature = -15,
    InvalidKeyProps = -16,
    UnsupportedProperty = -17,
    CertChainChanged = -18,
    InvalidTweak = -19,
    NotFound = -20,
    IoAborted = -21,
    IoAbortInProgress = -22,
    CredentialsNotEstablished = -23,
    NonceMismatch = -24,
    PartitionNotProvisioned = -25,
    MaskedKeyDecodeFailed = -26,
    EccVerifyFailed = -27,
    SessionNeedsRenegotiation = -29,
    PendingKeyGeneration = -30,
    KeyNotFound = -31,
    PartitionAlreadyProvisioned = -33,
    VaultAppLimitReached = -34,
    RetryExhausted = -35,
    DeviceNotReady = -36,
    CannotDeleteInternalKeys = -37,
    UnsupportedApiRevision = -38,
    DeviceNotAccessible = -39,
    InvalidContextState = -40,
    Bk3AlreadyInitialized = -41,
    InvalidSession = -42,
    SdAlreadyInitialized = -43,
    SdPeerCloningNotAllowed = -44,
    UnsupportedKeyOperation = -45,

    // -- CPT (CryptoController) host-facing errors ----------
    // 1:1 mirror of the TborStatus/HsmError (FW) CPT range.

    // Software validation / PAL / runtime errors.
    CryptoNotInitialized = -46,
    CryptoBufferTooSmall = -47,
    CryptoInputTooLarge = -48,
    CryptoInvalidAlg = -49,
    CryptoTimeout = -50,
    CryptoUnalignedCptr = -51,
    CryptoInvalidArg = -52,
    CryptoInvalidIvLength = -53,
    CryptoInvalidKeyLength = -54,
    CryptoInvalidDataLength = -55,
    CryptoInvalidContextLength = -56,
    CryptoInvalidPartialContext = -57,
    CryptoUnsupportedMode = -58,
    CryptoUnalignedBuffer = -59,
    CryptoNotSupported = -60,
    CryptoHardwareError = -61,

    // CPT hardware completion codes.
    CryptoCptRsaUcErrModLenInvalid = -62,
    CryptoCptRsaUcErrExpLenInvalid = -63,
    CryptoCptRsaUcErrDataLenInvalid = -64,
    CryptoCptGcUcErrDataLenInvalid = -65,
    CryptoCptGcUcErrCipherUnsupported = -66,
    CryptoCptGcUcErrAuthUnsupported = -67,
    CryptoCptGcUcErrHashModeUnsupported = -68,
    CryptoCptGcUcErrIcvMiscompare = -69,
    CryptoCptGcUcErrKeyLenInvalid = -70,
    CryptoCptRsaUcErrPkcsDecoding = -71,
    CryptoCptRsaUcErrPkcsSignatureInvalid = -72,

    // CPT completion status errors.
    CryptoCptFault = -73,
    CryptoCptSwErr = -74,
    CryptoCptHwErr = -75,
    CryptoCptInstErr = -76,
    CryptoCptSwWarn = -77,
    Panic = i32::MIN,
}

impl Display for HsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for HsmError {}
