// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Core-side SQE/CQE concerns layered on the shared I/O ABI.
//!
//! The typed SQE/CQE *layout* (read/write accessors, builders, bitfield
//! dwords, opcode constants) lives in [`azihsm_fw_hsm_io`] and is
//! re-exported here so the rest of the core keeps importing it via
//! `crate::op::*`. This module adds the firmware-only concerns that
//! depend on core types:
//!
//! - [`SqeValidateExt`] — SQE field validation (returns [`OpError`]).
//! - [`SessionCtrl`] — session-control classification from DDI opcodes.
//! - [`HsmOpStatus`] — opcode-handler result carrying the CQE session
//!   dwords back to `handle_io`.

// Re-export the shared SQE/CQE layout so `crate::op::{Sqe, Cqe, ...}`
// keeps resolving for the rest of the core.
pub use azihsm_fw_hsm_io::*;
use azihsm_fw_hsm_pal_traits::HsmDmaAddr;

use super::*;
use crate::error::HostStatus;
use crate::error::OpError;

// ── Validation constants ────────────────────────────────────────────

/// 4K page size.
const PAGE_4K: u32 = 4096;

/// Maximum source buffer length (one 4K page).
const MAX_SRC_LEN: u32 = PAGE_4K;

/// Maximum destination buffer length (one 4K page).
const MAX_DST_LEN: u32 = PAGE_4K;

/// Returns true if the 64-bit DMA address is 4K-page-aligned.
#[inline]
fn is_aligned_4k(addr: HsmDmaAddr) -> bool {
    addr.lo & (PAGE_4K - 1) == 0
}

// ── SQE validation (firmware) ───────────────────────────────────────

/// Firmware-side validation for the shared [`Sqe`] read view.
///
/// Lives in the core (not [`azihsm_fw_hsm_io`]) because it returns the
/// core's [`OpError`] / [`HostStatus`] types.
pub trait SqeValidateExt {
    /// Validate common SQE fields (all opcodes).
    ///
    /// Checks:
    /// - `cmd.psdt` must be 0 (PRP only)
    fn validate(&self) -> Result<(), OpError>;

    /// Validate fields specific to MBOR / TBOR opcodes that carry an
    /// inbound + outbound DDI body via DMA.
    ///
    /// Checks:
    /// - Source length must be 1..=4096
    /// - Destination length must be 1..=4096
    /// - Source PRP1 must be 4K-aligned
    /// - Destination PRP1 must be 4K-aligned
    ///
    /// Call [`validate`](Self::validate) first for common checks.
    fn validate_io_op(&self) -> Result<(), OpError>;
}

impl SqeValidateExt for Sqe<'_> {
    fn validate(&self) -> Result<(), OpError> {
        let cmd = self.cmd();
        if cmd.psdt() != 0 {
            error!(
                "core",
                HsmError::SqeInvalidPsdt,
                "Invalid PSDT value: {}",
                cmd.psdt()
            );
            return Err(OpError::new(
                HsmError::SqeInvalidPsdt,
                HostStatus::INVALID_PSDT,
            ));
        }

        Ok(())
    }

    fn validate_io_op(&self) -> Result<(), OpError> {
        if self.src_len() == 0 || self.src_len() > MAX_SRC_LEN {
            error!(
                "core",
                HsmError::IoChannelInvalidSrcLen,
                "Invalid source length: {}",
                self.src_len()
            );
            return Err(OpError::new(
                HsmError::IoChannelInvalidSrcLen,
                HostStatus::INVALID_SRC_LEN,
            ));
        }

        if self.dst_len() == 0 || self.dst_len() > MAX_DST_LEN {
            error!(
                "core",
                HsmError::IoChannelInvalidDstLen,
                "Invalid destination length: {}",
                self.dst_len()
            );
            return Err(OpError::new(
                HsmError::IoChannelInvalidDstLen,
                HostStatus::INVALID_DST_LEN,
            ));
        }

        if !is_aligned_4k(self.src_prp1()) {
            error!(
                "core",
                HsmError::IoChannelInvalidSrcAlignment,
                "Invalid source PRP alignment: {:?}",
                self.src_prp1()
            );
            return Err(OpError::new(
                HsmError::IoChannelInvalidSrcAlignment,
                HostStatus::INVALID_SRC_PRP,
            ));
        }

        if !is_aligned_4k(self.dst_prp1()) {
            error!(
                "core",
                HsmError::IoChannelInvalidDstAlignment,
                "Invalid destination PRP alignment: {:?}",
                self.dst_prp1()
            );
            return Err(OpError::new(
                HsmError::IoChannelInvalidDstAlignment,
                HostStatus::INVALID_DST_PRP,
            ));
        }

        Ok(())
    }
}

// ── Session control ─────────────────────────────────────────────────

/// Session control kind — derived from the DDI opcode.
///
/// Values align with CQE DW0 session_ctrl field (2 bits).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SessionCtrl {
    /// No session required (e.g., GetApiRev, GetDeviceInfo).
    #[default]
    NoSession = 0,

    /// Opens a new session (OpenSession).
    Open = 1,

    /// Closes a session (CloseSession).
    Close = 2,

    /// Command within an existing session.
    InSession = 3,
}

impl SessionCtrl {
    /// Map a DDI opcode to its session control kind.
    pub fn from_op(op: azihsm_fw_ddi_mbor_types::DdiOp) -> Self {
        use azihsm_fw_ddi_mbor_types::DdiOp;
        match op {
            DdiOp::GetApiRev
            | DdiOp::GetDeviceInfo
            | DdiOp::GetCertChainInfo
            | DdiOp::GetCertificate
            | DdiOp::GetEstablishCredEncryptionKey
            | DdiOp::GetSessionEncryptionKey
            | DdiOp::GetSealedBk3
            | DdiOp::InitBk3
            | DdiOp::SetSealedBk3
            | DdiOp::EstablishCredential
            | DdiOp::ShaDigest => Self::NoSession,
            DdiOp::OpenSession => Self::Open,
            DdiOp::CloseSession => Self::Close,
            _ => Self::InSession,
        }
    }

    /// Map a TBOR opcode to its session control kind.
    ///
    /// `GetApiRev` is session-less.
    ///
    /// `OpenSessionInit` is classified as `Open` — it initiates the
    /// session-open flow; the SQE carries no session id (the FW
    /// allocates a pending slot and returns its id in the response).
    ///
    /// `OpenSessionFinish`, `ChangePsk`, and `PartInit` reference the
    /// pending/active slot, so the SQE must carry the slot's
    /// `session_id` (`InSession`).  `CloseSession` carries the slot
    /// id and is classified as `Close` so the CQE flags signal the
    /// slot transition to the host.
    ///
    /// Unknown opcodes default to `NoSession` so that dispatch can
    /// surface `HsmError::UnsupportedCmd` from the handler layer
    /// rather than being rejected as a session-flag mismatch first.
    pub fn from_tbor_opcode(opcode: u8) -> Self {
        use crate::ddi::tbor::opcode;
        match opcode {
            opcode::GET_API_REV => Self::NoSession,
            opcode::OPEN_SESSION_INIT => Self::Open,
            opcode::OPEN_SESSION_FINISH | opcode::CHANGE_PSK | opcode::PART_INIT => Self::InSession,
            opcode::CLOSE_SESSION => Self::Close,
            _ => Self::NoSession,
        }
    }
}

// ── HsmOpStatus ─────────────────────────────────────────────────────

/// HSM Operation Status — returned by opcode handlers.
///
/// Carries the response length and pre-built CQE session dwords back to
/// `handle_io`, which writes them directly to the CQE. Session fields
/// are packed into `cqe_dw0` and `cqe_dw1` at construction time to
/// minimize the async future size (2 × u32 vs 5 scattered fields).
#[derive(Default, Debug)]
pub(crate) struct HsmOpStatus {
    /// Encoded response length in smem (written to CQE DW0 dst_len).
    pub(crate) resp_len: u16,

    /// Pre-built CQE DW0 session bits (ctrl, id_valid, vault_valid, closed).
    /// `handle_io` merges this with `resp_len` via `with_dst_len()`.
    pub(crate) cqe_dw0_session: u32,

    /// Pre-built CQE DW1 (session_id + app_vault_id).
    pub(crate) cqe_dw1: u32,
}

impl HsmOpStatus {
    /// Build from session state.
    pub(crate) fn new(
        resp_len: usize,
        session_ctrl: SessionCtrl,
        session_id: Option<u16>,
        app_vault_id: Option<u8>,
        session_closed: bool,
    ) -> Self {
        let dw0 = CqeDw0::new()
            .with_session_ctrl(session_ctrl as u8)
            .with_session_id_valid(session_id.is_some())
            .with_app_vault_id_valid(app_vault_id.is_some())
            .with_session_closed(session_closed);
        let dw1 = CqeDw1::new()
            .with_session_id(session_id.unwrap_or(0))
            .with_app_vault_id(app_vault_id.unwrap_or(0));
        Self {
            resp_len: resp_len as u16,
            cqe_dw0_session: u32::from(dw0),
            cqe_dw1: u32::from(dw1),
        }
    }

    /// Build for no-session commands (most common path).
    #[allow(dead_code)]
    pub(crate) fn no_session(resp_len: usize) -> Self {
        Self {
            resp_len: resp_len as u16,
            cqe_dw0_session: 0,
            cqe_dw1: 0,
        }
    }
}
