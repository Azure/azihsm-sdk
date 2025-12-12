// Copyright (C) Microsoft Corporation. All rights reserved.

//! Errors for attestation operations.

use crypto::CryptoError;
use thiserror::Error;

/// Errors returned by attestation operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestationError {
    /// The argument is invalid.
    #[error("Invalid argument")]
    InvalidArgument,

    /// CBOR encoding error.
    #[error("CBOR encoding failed")]
    CborEncodeError,

    /// CBOR decoding error.
    #[error("CBOR decoding failed")]
    CborDecodeError,

    /// Failed to get ECC curve.
    #[error("Failed to get ECC curve")]
    EccGetCurveError,

    /// Failed to get ECC coordinates.
    #[error("Failed to get ECC coordinates")]
    EccGetCoordinatesError,

    /// ECC signature verification failed.
    #[error("ECC signature verification failed")]
    EccVerifyFailed,

    /// ECC signature generation failed.
    #[error("ECC signature generation failed")]
    EccSignFailed,

    /// Unexpected signature size in COSE_Sign1.
    #[error("Unexpected signature size in COSE_Sign1")]
    CoseSign1UnexpectedSignature,

    /// Other unexpected Cryptographic operation failed.
    #[error("Other unexpected Cryptographic operation failed")]
    OtherCryptoError,

    /// Report signature mismatch.
    #[error("Report signature doesn't match leaf cert")]
    ReportSignatureMismatch,
}

impl From<CryptoError> for AttestationError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::InvalidParameter => Self::InvalidArgument,
            CryptoError::EccGetCurveError => Self::EccGetCurveError,
            CryptoError::EccGetCoordinatesError => Self::EccGetCoordinatesError,
            CryptoError::EccVerifyFailed => Self::EccVerifyFailed,
            CryptoError::EccSignFailed => Self::EccSignFailed,
            _ => Self::OtherCryptoError,
        }
    }
}

impl From<minicbor::decode::Error> for AttestationError {
    fn from(_err: minicbor::decode::Error) -> Self {
        Self::CborDecodeError
    }
}

impl<E> From<minicbor::encode::Error<E>> for AttestationError {
    fn from(_err: minicbor::encode::Error<E>) -> Self {
        Self::CborEncodeError
    }
}
