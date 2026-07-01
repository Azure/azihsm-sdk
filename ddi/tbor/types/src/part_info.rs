// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `PartInfo` command.
//!
//! `PartInfo` is an **out-of-session** info command. It combines the
//! device-level fields of the MBOR `GetDeviceInfo` command with the
//! partition identity (Partition ID + identity public key). A single
//! round-trip lets a host learn both what device it is talking to and
//! the identity and lifecycle posture of the partition it is bound to,
//! without first establishing a session.
//!
//! Both the request and response wire schemas are shared with the
//! firmware handler via `azihsm_fw_ddi_tbor_types::part_info`
//! (`fw/core/ddi/tbor/types/src/part_info.rs`); this module adds the
//! host-facing value types so [`exec_op_tbor`] returns owned response
//! values rather than borrowing `View<'a>` accessors.
//!
//! [`exec_op_tbor`]: ../../azihsm_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use crate::tbor;
use crate::tbor_int::U32;
use crate::tbor_int::U64;
use crate::tbor_int::U8;

/// TBOR opcode for `PartInfo`.
pub const TBOR_OP_PART_INFO: u8 = 0x02;

/// Length of the opaque partition identity blob (PID).
pub const PID_LEN: usize = 16;

/// Length of the raw ECC-P384 identity public key (`x ‖ y`), with each
/// 48-byte coordinate in little-endian (HSM wire format; SEC1 `0x04` prefix stripped).
pub const PID_PUB_KEY_LEN: usize = 96;

/// Host-facing TBOR `PartInfo` request. Carries no per-call data.
#[tbor(opcode = TBOR_OP_PART_INFO, session_ctrl = no_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborPartInfoReq;

impl TborPartInfoReq {
    /// Construct a `PartInfo` request.
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

/// Host-facing TBOR `PartInfo` response.
///
/// Field order mirrors the firmware schema in
/// `azihsm_fw_ddi_tbor_types::part_info`; the two MUST stay in sync so
/// the TOC layouts match.
///
/// The module-wide FIPS approval status is carried in the standard TBOR
/// response header flag, not as a body field, so it is not declared
/// here.
#[tbor(response)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TborPartInfoResp {
    /// Device kind, matching MBOR `DdiDeviceKind` (`2` = Physical).
    pub device_kind: U8,

    /// Partition lifecycle state, matching the firmware `PartState`
    /// discriminant (`0` = Unallocated, `1` = Allocated, `2` = Enabled,
    /// …).
    pub part_state: U8,

    /// Monotonic partition generation counter, incremented on every
    /// allocate/free cycle.
    pub generation: U32,

    /// Owner-seed (BKS2) selector currently in effect.
    pub owner_svn: U64,

    /// Manufacturer-seed (BKS1) selector — the current firmware SVN.
    pub mfgr_svn: U64,

    /// Opaque 16-byte partition identity (PID).
    pub pid: [u8; PID_LEN],

    /// Raw ECC-P384 identity public-key coordinates (`x ‖ y`, 96 B).
    pub pid_pub_key: [u8; PID_PUB_KEY_LEN],
}
