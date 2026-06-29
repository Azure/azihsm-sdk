// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `PartInfo` wire schema.
//!
//! `PartInfo` is an out-of-session info command. The host sends an
//! empty request; the firmware responds with device-level fields (kind,
//! FIPS status) plus the partition's lifecycle and identity: state,
//! generation counter, owner/manufacturer SVN selectors, the opaque
//! Partition ID (PID), and the raw ECC-P384 identity public key. It is
//! the TBOR analogue of the MBOR `GetDeviceInfo` command combined with
//! the partition identity (Partition ID + identity public key).
//!
//! The byte fields are declared as `&[u8]` slices with `len`
//! constraints so handler code can pass borrows from the partition
//! store straight to the encoder.

use azihsm_fw_ddi_tbor_api::tbor;

/// TBOR opcode for `PartInfo`.
pub const TBOR_OP_PART_INFO: u8 = 0x32;

/// Length of the opaque partition identity blob (PID).
pub const PID_LEN: usize = 16;

/// Length of the raw ECC-P384 identity public key (`x ‖ y`), with each
/// 48-byte coordinate in little-endian (HSM wire format; SEC1 `0x04`
/// prefix stripped).
pub const PID_PUB_KEY_LEN: usize = 96;

/// `PartInfo` request schema.
///
/// The body carries no semantic data. On the wire the derive emits a
/// single `none` TOC placeholder to satisfy the TBOR codec's
/// `toc_count >= 1` requirement; the decoder verifies that placeholder
/// is present and the opcode matches.
///
/// The `tbor` derive requires an integer literal here, so the opcode is
/// spelled out rather than referencing [`TBOR_OP_PART_INFO`]; the two
/// MUST stay in sync (both `0x32`).
#[tbor(opcode = 0x32)]
pub struct TborPartInfoReq;

/// `PartInfo` response schema.
///
/// Field order MUST stay in sync with the host value type in
/// `azihsm_ddi_tbor_types::part_info` so the TOC layouts match.
///
/// The module-wide FIPS approval status is carried in the standard TBOR
/// response header flag (set via the `encode` builder), not as a body
/// field, so it is not declared here.
#[tbor(response)]
pub struct TborPartInfoResp<'a> {
    /// Device kind, matching MBOR `DdiDeviceKind` (`2` = Physical).
    pub device_kind: u8,

    /// Partition lifecycle state (`PartState` discriminant).
    pub part_state: u8,

    /// Monotonic partition generation counter.
    pub generation: u32,

    /// Owner-seed (BKS2) selector currently in effect.
    pub owner_svn: u64,

    /// Manufacturer-seed (BKS1) selector — the current firmware SVN.
    pub mfgr_svn: u64,

    /// Opaque 16-byte partition identity (PID).
    #[tbor(len = 16)]
    pub pid: &'a [u8],

    /// Raw ECC-P384 identity public-key coordinates (`x ‖ y`, 96 B).
    #[tbor(len = 96)]
    pub pid_pub_key: &'a [u8],
}
