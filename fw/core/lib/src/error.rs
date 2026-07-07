// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(dead_code)]
//! Core CQE host status codes and IO error handling.

use azihsm_fw_hsm_core_tracing::*;
use azihsm_fw_hsm_pal_traits::*;

// ── Host status codes (CQE DW3 bits 27:17) ─────────────────────────
//
// Layout: `(type << 8) | code` where type = GENERIC = 0.

/// CQE host status codes written to DW3.
pub(crate) struct HostStatus;

impl HostStatus {
    pub const SUCCESS: u16 = 0x000;

    pub const INVALID_COMMAND_OPCODE: u16 = 0x001;

    pub const INVALID_FIELD_IN_COMMAND: u16 = 0x002;

    pub const INTERNAL_ERROR: u16 = 0x007;

    pub const INVALID_PSDT: u16 = 0x0C0;

    pub const INVALID_SRC_LEN: u16 = 0x0C1;

    pub const INVALID_DST_LEN: u16 = 0x0C2;

    pub const INVALID_SRC_PRP: u16 = 0x0C3;

    pub const INVALID_DST_PRP: u16 = 0x0C4;

    pub const DMA_TXN_ERROR: u16 = 0x0C6;

    pub const REQ_HDR_DECODE_ERR: u16 = 0x0C8;

    pub const ALLOC_ERR: u16 = 0x0C9;

    pub const INVALID_OOB_LEN: u16 = 0x0CA;

    pub const INVALID_OOB_PRP: u16 = 0x0CB;
}

// ── OpError: pairs HsmError (for logging) with host status (for CQE) ─

/// IO handler error carrying both diagnostic and CQE status codes.
///
/// `err` is logged via the `error!` macro for firmware diagnostics.
/// `status` is written to CQE DW3 for the host driver.
#[derive(Debug)]
pub(crate) struct OpError {
    /// Internal diagnostic code (logged as `[err:XXXXXXXX]`).
    pub err: HsmError,

    /// Host-visible status code for CQE DW3.
    pub status: u16,
}

impl OpError {
    /// Create a new OpError pairing a diagnostic code with a host status.
    pub const fn new(err: HsmError, status: u16) -> Self {
        Self { err, status }
    }

    /// Log the error and return self — for use with `return Err(...)`.
    #[allow(unused_variables)]
    pub fn logged(err: HsmError, status: u16, tag: &str) -> Self {
        error!(tag, err, "failed");
        Self { err, status }
    }
}

/// Extension trait for converting any `Result<T, E>` into `Result<T, OpError>`
/// with logging.
pub(crate) trait ResultOpErrExt<T> {
    /// Log and convert to [`OpError`], replacing the error code.
    fn op_err(self, tag: &str, err: HsmError, status: u16) -> Result<T, OpError>;
}

/// Extension trait for `HsmResult<T>` that preserves the original error.
pub(crate) trait ResultOpStatusExt<T> {
    /// Log and convert to [`OpError`], keeping the original [`HsmError`].
    fn op_status(self, status: u16) -> Result<T, OpError>;
}

impl<T, E: core::fmt::Debug> ResultOpErrExt<T> for Result<T, E> {
    #[inline]
    fn op_err(self, _tag: &str, err: HsmError, status: u16) -> Result<T, OpError> {
        self.map_err(|_e| {
            error!(_tag, err, "{:?}", _e);
            OpError::new(err, status)
        })
    }
}

impl<T> ResultOpStatusExt<T> for HsmResult<T> {
    #[inline]
    fn op_status(self, status: u16) -> Result<T, OpError> {
        self.map_err(|e| {
            error!("op_status", e, "failed");
            OpError::new(e, status)
        })
    }
}
