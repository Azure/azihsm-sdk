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
                tracing::error!("Mapping error {:?} to HSM error: {:?}", err, hsm_err);
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
    Panic = i32::MIN,
}

impl Display for HsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for HsmError {}
