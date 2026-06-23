// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

//! Typed SQE / CQE layout — the HSM I/O ABI.
//!
//! Submission and completion queue entries are fixed-size dword arrays
//! ([`HsmSqe`] = `[u32; 16]`, [`HsmCqe`] = `[u32; 4]`) whose *raw shape*
//! is defined by the platform-abstraction crate
//! [`azihsm_fw_hsm_pal_traits`]. This crate adds the *semantic layout* on
//! top: typed, zero-cost accessors and builders for the individual
//! fields, shared by every party that sits on the SQE/CQE boundary:
//!
//! - the firmware core reads the SQE and writes the CQE,
//! - host transports (in-process emulator, socket server) build the SQE
//!   and read the CQE.
//!
//! Keeping the bit layout in one place avoids the drift bugs that arise
//! when the same packing is hand-rolled in multiple consumers.
//!
//! Higher-level concerns that depend on application types — SQE field
//! *validation* (which needs the core's error types) and session-control
//! classification (which needs the DDI opcode enums) — deliberately live
//! in `azihsm_fw_hsm_core`, layered on top of this crate.
//!
//! # SQE layout
//!
//! | DWORD | Field(s)                                          |
//! |-------|---------------------------------------------------|
//! | DW0   | [`CmdDword`] — op, set, psdt, cmd id               |
//! | DW1   | source length (bytes)                             |
//! | DW2-3 | source PRP1 ([`HsmDmaAddr`])                       |
//! | DW4-5 | source PRP2                                        |
//! | DW6   | destination length (bytes)                        |
//! | DW7-8 | destination PRP1                                   |
//! | DW9-10| destination PRP2                                   |
//! | DW11  | [`SessionFlags`]                                   |
//! | DW12  | session id (low 16 bits)                          |
//!
//! # CQE layout
//!
//! | DWORD | Field(s)                                          |
//! |-------|---------------------------------------------------|
//! | DW0   | [`CqeDw0`] — dst_len, session flags                |
//! | DW1   | [`CqeDw1`] — session id, app vault id              |
//! | DW2   | [`CqeDw2`] — sq head, sq id                        |
//! | DW3   | [`CqeDw3`] — cmd id, phase, status                 |

use azihsm_fw_hsm_pal_traits::HsmCqe;
use azihsm_fw_hsm_pal_traits::HsmDmaAddr;
use azihsm_fw_hsm_pal_traits::HsmSqe;
use bitfield_struct::bitfield;

// ── Opcode constants ────────────────────────────────────────────────

/// MBOR opcode — standard IO command carrying an MBOR-encoded DDI body.
pub const OP_MBOR: u16 = 0;

/// Flush opcode — flush pending IO.
pub const OP_FLUSH: u16 = 1;

/// TBOR opcode — standard IO command carrying a TBOR-encoded DDI body.
pub const OP_TBOR: u16 = 2;

// ── SQE bitfield dwords ─────────────────────────────────────────────

/// Command dword (SQE DW0) bitfield.
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

/// Session flags dword (SQE DW11) bitfield.
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

// ── CQE bitfield dwords ─────────────────────────────────────────────

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

// ── SQE read view ───────────────────────────────────────────────────

/// Typed read-only wrapper around an [`HsmSqe`].
///
/// Zero-cost — borrows the underlying `[u32; 16]` and reads fields on
/// demand via bitfield parsing or direct indexing.
#[derive(Debug)]
pub struct Sqe<'a>(&'a HsmSqe);

impl<'a> From<&'a HsmSqe> for Sqe<'a> {
    #[inline]
    fn from(sqe: &'a HsmSqe) -> Self {
        Self(sqe)
    }
}

#[allow(dead_code)]
impl Sqe<'_> {
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
}

// ── SQE builder (host side) ─────────────────────────────────────────

/// Fluent builder for an [`HsmSqe`].
///
/// Host transports use this to construct a submission entry referencing
/// host DMA buffers, exactly as the IIC DMA engine would deliver one to
/// the firmware.
#[derive(Debug, Default)]
pub struct SqeBuilder(HsmSqe);

impl SqeBuilder {
    /// Start a new zeroed SQE.
    #[inline]
    pub fn new() -> Self {
        Self([0u32; 16])
    }

    /// Set the command dword (DW0: op, set, psdt, cmd id).
    #[inline]
    pub fn cmd(mut self, cmd: CmdDword) -> Self {
        self.0[0] = cmd.into();
        self
    }

    /// Set the source (DW1) and destination (DW6) buffer lengths.
    #[inline]
    pub fn buf_lens(mut self, src_len: u32, dst_len: u32) -> Self {
        self.0[1] = src_len;
        self.0[6] = dst_len;
        self
    }

    /// Set the source PRP1 address (DW2–3).
    #[inline]
    pub fn src_prp1(mut self, addr: u64) -> Self {
        self.0[2] = addr as u32;
        self.0[3] = (addr >> 32) as u32;
        self
    }

    /// Set the destination PRP1 address (DW7–8).
    #[inline]
    pub fn dst_prp1(mut self, addr: u64) -> Self {
        self.0[7] = addr as u32;
        self.0[8] = (addr >> 32) as u32;
        self
    }

    /// Set the session flags dword (DW11).
    #[inline]
    pub fn session_flags(mut self, flags: SessionFlags) -> Self {
        self.0[11] = flags.into();
        self
    }

    /// Set the session ID (DW12, low 16 bits).
    #[inline]
    pub fn session_id(mut self, id: u16) -> Self {
        self.0[12] = u32::from(id);
        self
    }

    /// Finish and return the raw [`HsmSqe`].
    #[inline]
    pub fn build(self) -> HsmSqe {
        self.0
    }
}

// ── CQE read/write view ─────────────────────────────────────────────

/// Typed read/write wrapper around an [`HsmCqe`].
///
/// Zero-cost — borrows the underlying `[u32; 4]` mutably and reads/writes
/// fields on demand via bitfield parsing or direct indexing. The firmware
/// uses the setters to populate a completion; host transports use the
/// read accessors ([`dst_len`](Self::dst_len), [`status`](Self::status),
/// [`cmd_id`](Self::cmd_id)) on a returned completion.
#[derive(Debug)]
pub struct Cqe<'a>(&'a mut HsmCqe);

impl<'a> From<&'a mut HsmCqe> for Cqe<'a> {
    #[inline]
    fn from(cqe: &'a mut HsmCqe) -> Self {
        Self(cqe)
    }
}

#[allow(dead_code)]
impl Cqe<'_> {
    /// Zero all dwords.
    #[inline]
    pub fn clear(&mut self) {
        self.0.fill(0);
    }

    // ── Convenience read accessors (host side) ──────────────────

    /// Length of data the firmware wrote to the destination buffer
    /// (DW0[15:0]).
    #[inline]
    pub fn dst_len(&self) -> u16 {
        self.dw0().dst_len()
    }

    /// Host status code (DW3[27:17]); 0 = success.
    #[inline]
    pub fn status(&self) -> u16 {
        self.dw3().status()
    }

    /// Command id echoed from the SQE (DW3[15:0]).
    #[inline]
    pub fn cmd_id(&self) -> u16 {
        self.dw3().cmd_id()
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
