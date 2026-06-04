// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Device Driver Interface (DDI) library - Error module

use std::convert::Infallible;

use azihsm_ddi_mbor_types::DdiStatus;
use azihsm_ddi_mbor_types::MborError;
use thiserror::Error;

use crate::*;

/// HSM Error
#[derive(Error, Debug)]
pub enum DdiError {
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

    /// HSM device not ready
    #[error("device not ready")]
    DeviceNotReady,

    /// Device Driver interface message encoding fault
    #[error("device driver interface message encoding fault")]
    DdiEncodingFault(#[from] minicbor::encode::Error<Infallible>),

    /// Device Driver interface message decoding fault
    #[error("device driver interface message decoding fault")]
    DdiDecodingFault(#[from] minicbor::decode::Error),

    /// Device driver interface error
    #[error("device driver interface error")]
    DdiError(u32),

    /// MCR CBOR Error
    #[error("MCR Cbor Error")]
    MborError(MborError),

    /// Manticore device error
    #[error("Manticore device error")]
    DdiStatus(DdiStatus),

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
    IoError(#[from] std::io::Error),

    /// Invalid API Version
    #[error("invalid api version")]
    InvalidApiVersion,

    /// Lion Fast path error
    #[error("Lion fast path operation error")]
    FpError(u32),

    /// Lion fast path command specific error
    #[error("Lion fast path command error")]
    FpCmdSpecificError(u32),

    /// device info ioctl parameter errors
    #[error("Invalid data in device info ioctl")]
    DeviceInfoIoctlInvalidData,

    /// Driver error
    #[error("Driver error")]
    DriverError(DriverError),

    /// Reset Device error
    #[error("Reset Device operation error")]
    ResetDeviceError(u32),

    /// Host-side backend does not support the requested wire encoding
    /// (e.g., a TBOR request was issued against a backend that has not
    /// been wired for TBOR yet). Distinct from a device-side
    /// `DdiStatus::UnsupportedCmd`, which indicates the firmware
    /// rejected an otherwise well-formed request.
    #[error("host backend does not support the requested wire encoding")]
    UnsupportedEncoding,

    /// TBOR wire-format encode failure on the host. Indicates the
    /// outgoing request could not be serialised — typically a buffer
    /// sizing issue or a programmer error in the request type.
    /// Distinct from [`DdiError::MborError`] so callers debugging a
    /// TBOR command can tell which codec failed.
    #[error("TBOR encode error")]
    TborEncodeError,

    /// TBOR wire-format decode failure on the host. Indicates the
    /// incoming response was malformed or did not match the schema.
    /// Distinct from [`DdiError::MborError`] for the same reason as
    /// [`DdiError::TborEncodeError`].
    #[error("TBOR decode error")]
    TborDecodeError,
}

// ── Codec error → DdiError conversions ──────────────────────────────
//
// Wire encode/decode failures convert into per-codec variants so `?`
// works on every `encode`/`decode` call site in the backends without
// per-call `.map_err(...)` boilerplate, and so a host-side failure
// preserves which codec produced it. The structured error payload is
// intentionally dropped: the host treats wire-level failures uniformly
// and the codec-specific detail is recovered from logs / tracing.

impl From<MborError> for DdiError {
    #[inline]
    fn from(e: MborError) -> Self {
        Self::MborError(e)
    }
}

impl From<azihsm_ddi_tbor_codec::EncodeError> for DdiError {
    #[inline]
    fn from(_: azihsm_ddi_tbor_codec::EncodeError) -> Self {
        Self::TborEncodeError
    }
}

impl From<azihsm_ddi_tbor_codec::DecodeError> for DdiError {
    #[inline]
    fn from(e: azihsm_ddi_tbor_codec::DecodeError) -> Self {
        match e {
            // FW-signalled error: surface the typed HsmError discriminant
            // so callers can match on specific codes (InvalidSessionType,
            // AeadEnvelopeAuthFailed, etc.) instead of losing the detail to a
            // generic `TborDecodeError`.
            azihsm_ddi_tbor_codec::DecodeError::FwError(status) => Self::DdiError(status),
            _ => Self::TborDecodeError,
        }
    }
}
