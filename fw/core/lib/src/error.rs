// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(dead_code)]
//! Core error codes and CQE host status codes.

use azihsm_fw_hsm_core_tracing::*;
use azihsm_fw_hsm_pal_traits::HsmError;

const ID: u16 = 0x001;

// ── Lifecycle errors (not part of IO hot path) ─────────────────────

/// Failed to spawn the recv task.
pub const RECV_TASK_FAILURE: HsmError = HsmError::make_core(ID, 0x01);

/// Poll IO failure — no receive buffers available.
pub const POLL_IO_FAILURE: HsmError = HsmError::make_core(ID, 0x02);

/// Failed to spawn a send task for an IO.
pub const SEND_TASK_FAILURE: HsmError = HsmError::make_core(ID, 0x03);

/// IO completion failed.
pub const COMPLETE_IO_FAILURE: HsmError = HsmError::make_core(ID, 0x04);

/// IO dropped because the partition is not enabled.
pub const PART_NOT_ENABLED: HsmError = HsmError::make_core(ID, 0x05);

/// IO dropped failed to free resources.
pub const DROP_IO_FAILURE: HsmError = HsmError::make_core(ID, 0x06);

// ── IO handler HsmError codes (logged, paired with HostStatus) ─────

/// SQE has unsupported PSDT value (must be 0 = PRP).
pub const SQE_INVALID_PSDT: HsmError = HsmError::make_core(ID, 0x07);

/// SQE has unknown opcode.
pub const SQE_UNKNOWN_OP: HsmError = HsmError::make_core(ID, 0x08);

/// Source length out of range (must be 1..=4096).
pub const SQE_INVALID_SRC_LEN: HsmError = HsmError::make_core(ID, 0x09);

/// Destination length out of range (must be 1..=8192).
pub const SQE_INVALID_DST_LEN: HsmError = HsmError::make_core(ID, 0x0A);

/// Source PRP address is not 4K-aligned.
pub const SQE_INVALID_SRC_PRP_ALIGN: HsmError = HsmError::make_core(ID, 0x0B);

/// Destination PRP address is not 4K-aligned.
pub const SQE_INVALID_DST_PRP_ALIGN: HsmError = HsmError::make_core(ID, 0x0C);

/// Inbound DMA (host → HSM) failed.
pub const DMA_IN_FAILURE: HsmError = HsmError::make_core(ID, 0x0D);

/// Outbound DMA (HSM → host) failed.
pub const DMA_OUT_FAILURE: HsmError = HsmError::make_core(ID, 0x0E);

/// DDI request header decode failed.
pub const DDI_DECODE_FAILURE: HsmError = HsmError::make_core(ID, 0x10);

/// DDI opcode not recognized.
pub const DDI_UNKNOWN_OP: HsmError = HsmError::make_core(ID, 0x11);

/// DDI response encode failed.
pub const DDI_ENCODE_FAILURE: HsmError = HsmError::make_core(ID, 0x12);

/// DDI request has unsupported API revision.
pub const DDI_UNSUPPORTED_REV: HsmError = HsmError::make_core(ID, 0x13);

/// Invalid argument (session hijack protection).
pub const DDI_INVALID_ARGUMENT: HsmError = HsmError::make_core(ID, 0x14);

/// Session not expected for this operation.
pub const DDI_SESSION_NOT_EXPECTED: HsmError = HsmError::make_core(ID, 0x15);

/// Opcode not implemented by the handler.
pub const OP_UNIMPL: HsmError = HsmError::make_core(ID, 0xFF);

// ── Host status codes (CQE DW3 bits 27:17) ─────────────────────────
//
// Layout matches mcr-hsm: `(type << 8) | code` where type = GENERIC = 0.

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

/// Extension trait for `Result<T, HsmError>` that preserves the original error.
pub(crate) trait ResultOpStatusExt<T> {
    /// Log and convert to [`OpError`], keeping the original [`HsmError`].
    fn op_status(self, tag: &str, status: u16) -> Result<T, OpError>;
}

impl<T, E: core::fmt::Debug> ResultOpErrExt<T> for Result<T, E> {
    #[inline]
    #[allow(unused_variables)]
    fn op_err(self, tag: &str, err: HsmError, status: u16) -> Result<T, OpError> {
        self.map_err(|e| {
            error!(tag, err, "{:?}", e);
            OpError::new(err, status)
        })
    }
}

impl<T> ResultOpStatusExt<T> for Result<T, HsmError> {
    #[inline]
    #[allow(unused_variables)]
    fn op_status(self, tag: &str, status: u16) -> Result<T, OpError> {
        self.map_err(|e| {
            error!(tag, e, "failed");
            OpError::new(e, status)
        })
    }
}
