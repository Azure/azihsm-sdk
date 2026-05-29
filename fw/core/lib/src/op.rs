// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Lightweight typed wrappers around [`HsmSqe`] and [`HsmCqe`].
//!
//! [`Sqe`] borrows the raw `[u32; 16]` submission queue entry and
//! provides named read accessors for every field.
//!
//! [`Cqe`] borrows the raw `[u32; 4]` completion queue entry and
//! provides named read/write accessors for every field.
//!
//! Bitfield dwords are parsed with `bitfield-struct`; plain dwords
//! are read/written directly.
//!
//! # SQE Layout
//!
//! | DWORD   | Field(s)                                       |
//! |---------|------------------------------------------------|
//! | DW0     | cmd: op, set, psdt, id                         |
//! | DW1     | src.len                                        |
//! | DW2–3   | src.prp1 (lo/hi)                               |
//! | DW4–5   | src.prp2 (lo/hi)                               |
//! | DW6     | dst.len                                        |
//! | DW7–8   | dst.prp1 (lo/hi)                               |
//! | DW9–10  | dst.prp2 (lo/hi)                               |
//! | DW11    | session_flags: ctrl, id_valid, etc.            |
//! | DW12    | session_id (low 16 bits)                       |
//! | DW13–15 | reserved                                       |
//!
//! # CQE Layout
//!
//! | DWORD | Field(s)                                         |
//! |-------|--------------------------------------------------|
//! | DW0   | dst_len, session_flags                           |
//! | DW1   | session_id, app_vault_id                         |
//! | DW2   | sq_head, sq_id                                   |
//! | DW3   | cmd_id, psf (phase, status)                      |

use azihsm_fw_hsm_pal_traits::HsmSqe;
use bitfield_struct::bitfield;

use super::*;
use crate::error::HostStatus;
use crate::error::OpError;

// ── Opcode constants ────────────────────────────────────────────────

/// MBOR opcode — standard IO command carrying an MBOR-encoded DDI body.
pub const OP_MBOR: u16 = 0;

/// Flush opcode — flush pending IO.
pub const OP_FLUSH: u16 = 1;

/// TBOR opcode — standard IO command carrying a TBOR-encoded DDI body.
pub const OP_TBOR: u16 = 2;

// ── Constants ───────────────────────────────────────────────────────

/// 4K page size.
const PAGE_4K: u32 = 4096;

/// Maximum source buffer length (one 4K page).
const MAX_SRC_LEN: u32 = PAGE_4K;

/// Maximum destination buffer length (one 4K page).
const MAX_DST_LEN: u32 = PAGE_4K;

/// Command dword (DW0) bitfield.
#[bitfield(u32)]
#[derive(PartialEq, Eq)]
pub struct CmdDword {
    /// Opcode (0 = MBOR, 1 = Flush, 2 = TBOR).
    #[bits(10)]
    pub op: u16,

    /// Command set.
    #[bits(4)]
    pub set: u8,

    /// PRP or SGL data transfer format.
    #[bits(2)]
    pub psdt: u8,

    /// Command identifier.
    #[bits(16)]
    pub id: u16,
}

/// Session flags dword (DW11) bitfield.
#[bitfield(u32)]
#[derive(PartialEq, Eq)]
pub struct SessionFlags {
    /// Session control kind.
    #[bits(2)]
    pub ctrl: u8,

    /// Session ID is valid.
    #[bits(1)]
    pub id_valid: bool,

    /// App vault ID is valid.
    #[bits(1)]
    pub app_vault_id_valid: bool,

    /// Session is closed.
    #[bits(1)]
    pub session_closed: bool,

    /// Reserved.
    #[bits(3)]
    _rsvd0: u8,

    /// Reserved.
    #[bits(24)]
    _rsvd1: u32,
}

/// Typed read-only wrapper around an [`HsmSqe`].
///
/// Zero-cost — borrows the underlying `[u32; 16]` and reads fields
/// on demand via bitfield parsing or direct indexing.
#[derive(Debug)]
pub struct Sqe<'a>(&'a HsmSqe);

impl<'a> From<&'a HsmSqe> for Sqe<'a> {
    #[inline]
    fn from(sqe: &'a HsmSqe) -> Self {
        Self(sqe)
    }
}

#[allow(dead_code)]
impl<'a> Sqe<'a> {
    // ── DW0: command ────────────────────────────────────────────

    /// Returns the parsed command dword (DW0).
    #[inline]
    pub fn cmd(&self) -> CmdDword {
        CmdDword::from(self.0[0])
    }

    /// Shorthand for `cmd().op()`.
    #[inline]
    pub fn op(&self) -> u16 {
        self.cmd().op()
    }

    /// Shorthand for `cmd().id()`.
    #[inline]
    pub fn cmd_id(&self) -> u16 {
        self.cmd().id()
    }

    // ── DW1: source length ──────────────────────────────────────

    /// Source DMA buffer length in bytes (DW1).
    #[inline]
    pub fn src_len(&self) -> u32 {
        self.0[1]
    }

    // ── DW2–5: source PRP pair ──────────────────────────────────

    /// Source PRP1 address (DW2–3).
    #[inline]
    pub fn src_prp1(&self) -> HsmDmaAddr {
        HsmDmaAddr {
            lo: self.0[2],
            hi: self.0[3],
        }
    }

    /// Source PRP2 address (DW4–5).
    #[inline]
    pub fn src_prp2(&self) -> HsmDmaAddr {
        HsmDmaAddr {
            lo: self.0[4],
            hi: self.0[5],
        }
    }

    // ── DW6: destination length ─────────────────────────────────

    /// Destination DMA buffer length in bytes (DW6).
    #[inline]
    pub fn dst_len(&self) -> u32 {
        self.0[6]
    }

    // ── DW7–10: destination PRP pair ────────────────────────────

    /// Destination PRP1 address (DW7–8).
    #[inline]
    pub fn dst_prp1(&self) -> HsmDmaAddr {
        HsmDmaAddr {
            lo: self.0[7],
            hi: self.0[8],
        }
    }

    /// Destination PRP2 address (DW9–10).
    #[inline]
    pub fn dst_prp2(&self) -> HsmDmaAddr {
        HsmDmaAddr {
            lo: self.0[9],
            hi: self.0[10],
        }
    }

    // ── DW11: session flags ─────────────────────────────────────

    /// Returns the parsed session flags dword (DW11).
    #[inline]
    pub fn session_flags(&self) -> SessionFlags {
        SessionFlags::from(self.0[11])
    }

    // ── DW12: session ID ────────────────────────────────────────

    /// Session ID (DW12, low 16 bits).
    #[inline]
    pub fn session_id(&self) -> u16 {
        self.0[12] as u16
    }

    // ── Validation ──────────────────────────────────────────────

    /// Validate common SQE fields (all opcodes).
    ///
    /// Checks:
    /// - `cmd.psdt` must be 0 (PRP only)
    pub fn validate(&self) -> Result<(), OpError> {
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
    pub fn validate_io_op(&self) -> Result<(), OpError> {
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

        if !self.is_aligned_4k(self.src_prp1()) {
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

        if !self.is_aligned_4k(self.dst_prp1()) {
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

    /// Returns true if the 64-bit DMA address is 4K-page-aligned.
    #[inline]
    fn is_aligned_4k(&self, addr: HsmDmaAddr) -> bool {
        addr.lo & (PAGE_4K - 1) == 0
    }
}

// ═══════════════════════════════════════════════════════════════════
// CQE wrapper
// ═══════════════════════════════════════════════════════════════════

/// CQE DW0 bitfield: dst_len + session flags.
#[bitfield(u32)]
#[derive(PartialEq, Eq)]
pub struct CqeDw0 {
    /// Length of data copied to destination buffer.
    #[bits(16)]
    pub dst_len: u16,

    /// Session control kind.
    #[bits(2)]
    pub session_ctrl: u8,

    /// Session ID is valid.
    #[bits(1)]
    pub session_id_valid: bool,

    /// App vault ID is valid.
    #[bits(1)]
    pub app_vault_id_valid: bool,

    /// Session is closed.
    #[bits(1)]
    pub session_closed: bool,

    /// Reserved.
    #[bits(3)]
    _rsvd0: u8,

    /// Reserved.
    #[bits(8)]
    _rsvd1: u8,
}

/// CQE DW1 bitfield: session_id + app_vault_id.
#[bitfield(u32)]
#[derive(PartialEq, Eq)]
pub struct CqeDw1 {
    /// Session identifier.
    #[bits(16)]
    pub session_id: u16,

    /// Application vault identifier.
    #[bits(8)]
    pub app_vault_id: u8,

    /// Reserved.
    #[bits(8)]
    _rsvd: u8,
}

/// CQE DW2 bitfield: sq_head + sq_id.
#[bitfield(u32)]
#[derive(PartialEq, Eq)]
pub struct CqeDw2 {
    /// Submission queue head pointer.
    #[bits(16)]
    pub sq_head: u16,

    /// Submission queue identifier.
    #[bits(16)]
    pub sq_id: u16,
}

/// CQE DW3 bitfield: cmd_id + phase/status.
#[bitfield(u32)]
#[derive(PartialEq, Eq)]
pub struct CqeDw3 {
    /// Command identifier (echoed from SQE).
    #[bits(16)]
    pub cmd_id: u16,

    /// Phase bit.
    #[bits(1)]
    pub phase: bool,

    /// Host status code.
    #[bits(11)]
    pub status: u16,

    /// Reserved.
    #[bits(4)]
    _rsvd: u8,
}

/// Typed read/write wrapper around an [`HsmCqe`].
///
/// Zero-cost — borrows the underlying `[u32; 4]` mutably and
/// reads/writes fields on demand via bitfield parsing or direct
/// indexing.
#[derive(Debug)]
pub struct Cqe<'a>(&'a mut HsmCqe);

impl<'a> From<&'a mut HsmCqe> for Cqe<'a> {
    #[inline]
    fn from(cqe: &'a mut HsmCqe) -> Self {
        Self(cqe)
    }
}

#[allow(dead_code)]
impl<'a> Cqe<'a> {
    /// Zero all dwords.
    #[inline]
    pub fn clear(&mut self) {
        self.0.fill(0);
    }

    // ── DW0: dst_len + session flags ────────────────────────────

    /// Returns the parsed DW0.
    #[inline]
    pub fn dw0(&self) -> CqeDw0 {
        CqeDw0::from(self.0[0])
    }

    /// Overwrites DW0 from a [`CqeDw0`] bitfield.
    #[inline]
    pub fn set_dw0(&mut self, v: CqeDw0) {
        self.0[0] = v.into();
    }

    /// Sets the destination length (DW0[15:0]).
    #[inline]
    pub fn set_dst_len(&mut self, len: u16) {
        self.0[0] = self.dw0().with_dst_len(len).into();
    }

    /// Sets session control flags in DW0.
    #[inline]
    pub fn set_session_ctrl(&mut self, ctrl: u8) {
        self.0[0] = self.dw0().with_session_ctrl(ctrl).into();
    }

    /// Sets session ID valid flag in DW0.
    #[inline]
    pub fn set_session_id_valid(&mut self, valid: bool) {
        self.0[0] = self.dw0().with_session_id_valid(valid).into();
    }

    /// Sets app vault ID valid flag in DW0.
    #[inline]
    pub fn set_app_vault_id_valid(&mut self, valid: bool) {
        self.0[0] = self.dw0().with_app_vault_id_valid(valid).into();
    }

    /// Sets session closed flag in DW0.
    #[inline]
    pub fn set_session_closed(&mut self, closed: bool) {
        self.0[0] = self.dw0().with_session_closed(closed).into();
    }

    // ── DW1: session_id + app_vault_id ──────────────────────────

    /// Returns the parsed DW1.
    #[inline]
    pub fn dw1(&self) -> CqeDw1 {
        CqeDw1::from(self.0[1])
    }

    /// Overwrites DW1 from a [`CqeDw1`] bitfield.
    #[inline]
    pub fn set_dw1(&mut self, v: CqeDw1) {
        self.0[1] = v.into();
    }

    /// Sets the session ID (DW1[15:0]).
    #[inline]
    pub fn set_session_id(&mut self, id: u16) {
        self.0[1] = self.dw1().with_session_id(id).into();
    }

    /// Sets the app vault ID (DW1[23:16]).
    #[inline]
    pub fn set_app_vault_id(&mut self, id: u8) {
        self.0[1] = self.dw1().with_app_vault_id(id).into();
    }

    // ── DW2: sq_head + sq_id ────────────────────────────────────

    /// Returns the parsed DW2.
    #[inline]
    pub fn dw2(&self) -> CqeDw2 {
        CqeDw2::from(self.0[2])
    }

    /// Overwrites DW2 from a [`CqeDw2`] bitfield.
    #[inline]
    pub fn set_dw2(&mut self, v: CqeDw2) {
        self.0[2] = v.into();
    }

    /// Sets the submission queue head pointer (DW2[15:0]).
    #[inline]
    pub fn set_sq_head(&mut self, head: u16) {
        self.0[2] = self.dw2().with_sq_head(head).into();
    }

    /// Sets the submission queue ID (DW2[31:16]).
    #[inline]
    pub fn set_sq_id(&mut self, id: u16) {
        self.0[2] = self.dw2().with_sq_id(id).into();
    }

    // ── DW3: cmd_id + phase/status ──────────────────────────────

    /// Returns the parsed DW3.
    #[inline]
    pub fn dw3(&self) -> CqeDw3 {
        CqeDw3::from(self.0[3])
    }

    /// Overwrites DW3 from a [`CqeDw3`] bitfield.
    #[inline]
    pub fn set_dw3(&mut self, v: CqeDw3) {
        self.0[3] = v.into();
    }

    /// Sets the command ID (DW3[15:0]).
    #[inline]
    pub fn set_cmd_id(&mut self, id: u16) {
        self.0[3] = self.dw3().with_cmd_id(id).into();
    }

    /// Sets the phase bit (DW3[16]).
    #[inline]
    pub fn set_phase(&mut self, phase: bool) {
        self.0[3] = self.dw3().with_phase(phase).into();
    }

    /// Sets the host status code (DW3[27:17]).
    #[inline]
    pub fn set_status(&mut self, status: u16) {
        self.0[3] = self.dw3().with_status(status).into();
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
}

// ── HsmOpStatus ────────────────────────────────────────────────────

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
