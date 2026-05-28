// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed SQE / CQE wrappers mirroring `fw/core/lib/src/op.rs`.

use azihsm_fw_hsm_pal_traits::HsmCqe;
use azihsm_fw_hsm_pal_traits::HsmSqe;
use bitfield_struct::bitfield;

// ── SQE opcode constants ───────────────────────────────────────────

/// SQE opcode carrying an MBOR-encoded DDI body.
pub(crate) const OP_MBOR: u16 = 0;

/// SQE opcode carrying a TBOR-encoded DDI body.
pub(crate) const OP_TBOR: u16 = 2;

// ── SQE bitfield dwords ────────────────────────────────────────────

/// SQE command dword (DW0) bitfield.
#[bitfield(u32)]
pub(crate) struct CmdDword {
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

/// SQE session flags dword (DW11) bitfield.
#[bitfield(u32)]
pub(crate) struct SessionFlags {
    /// Session control kind (NoSession=0, Open=1, Close=2, InSession=3).
    #[bits(2)]
    pub ctrl: u8,
    /// Session ID is valid.
    #[bits(1)]
    pub id_valid: bool,
    #[bits(29)]
    _rsvd: u32,
}

// ── CQE bitfield dwords ────────────────────────────────────────────

/// CQE DW0 bitfield: dst_len + session flags.
#[bitfield(u32)]
struct CqeDw0 {
    /// Length of data copied to destination buffer.
    #[bits(16)]
    dst_len: u16,
    #[bits(16)]
    _rsvd: u16,
}

/// CQE DW3 bitfield: cmd_id + phase/status.
#[bitfield(u32)]
struct CqeDw3 {
    /// Command identifier (echoed from SQE).
    #[bits(16)]
    cmd_id: u16,
    /// Phase bit.
    #[bits(1)]
    phase: bool,
    /// Host status code.
    #[bits(11)]
    status: u16,
    #[bits(4)]
    _rsvd: u8,
}

// ── SQE builder ────────────────────────────────────────────────────

/// Typed SQE builder.
///
/// | DWORD   | Field(s)                                |
/// |---------|-----------------------------------------|
/// | DW0     | [`CmdDword`]: op, set, psdt, id         |
/// | DW1     | src length                              |
/// | DW2–3   | src PRP1 (lo/hi)                        |
/// | DW6     | dst length                              |
/// | DW7–8   | dst PRP1 (lo/hi)                        |
/// | DW11    | [`SessionFlags`]: ctrl, id_valid         |
/// | DW12    | session id (low 16 bits)                |
pub(crate) struct Sqe(HsmSqe);

impl Sqe {
    /// Start with an all-zero SQE.
    pub fn new() -> Self {
        Self([0u32; 16])
    }

    /// DW0: command dword — opcode + command id.
    pub fn cmd(mut self, cmd: CmdDword) -> Self {
        self.0[0] = cmd.into();
        self
    }

    /// DW1 / DW6: source and destination buffer lengths.
    pub fn buf_lens(mut self, src_len: u32, dst_len: u32) -> Self {
        self.0[1] = src_len;
        self.0[6] = dst_len;
        self
    }

    /// DW2–3: source PRP1 address (raw host pointer).
    pub fn src_prp1(mut self, addr: u64) -> Self {
        self.0[2] = addr as u32;
        self.0[3] = (addr >> 32) as u32;
        self
    }

    /// DW7–8: destination PRP1 address (raw host pointer).
    pub fn dst_prp1(mut self, addr: u64) -> Self {
        self.0[7] = addr as u32;
        self.0[8] = (addr >> 32) as u32;
        self
    }

    /// DW11: session flags — control kind + id_valid.
    pub fn session_flags(mut self, flags: SessionFlags) -> Self {
        self.0[11] = flags.into();
        self
    }

    /// DW12: session id (low 16 bits).
    pub fn session_id(mut self, id: u16) -> Self {
        self.0[12] = u32::from(id);
        self
    }

    /// Consume the builder and return the raw `[u32; 16]`.
    pub fn build(self) -> HsmSqe {
        self.0
    }
}

// ── CQE reader ─────────────────────────────────────────────────────

/// Typed read-only wrapper around an [`HsmCqe`].
///
/// | DWORD | Field(s)                                         |
/// |-------|--------------------------------------------------|
/// | DW0   | [`CqeDw0`]: dst_len, session flags               |
/// | DW3   | [`CqeDw3`]: cmd_id, phase, status                |
pub(crate) struct Cqe(HsmCqe);

impl Cqe {
    pub fn new(raw: HsmCqe) -> Self {
        Self(raw)
    }

    /// Response length copied to the destination buffer.
    pub fn resp_len(&self) -> usize {
        CqeDw0::from(self.0[0]).dst_len() as usize
    }

    /// Host status code (0 = success).
    pub fn status(&self) -> u16 {
        CqeDw3::from(self.0[3]).status()
    }
}
