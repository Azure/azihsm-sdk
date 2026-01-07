// Copyright (C) Microsoft Corporation. All rights reserved.

//! Device Driver Interface (DDI) library - Error module

use std::convert::Infallible;

use azihsm_ddi_types::DdiStatus;
use azihsm_ddi_types::MborError;
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
}
