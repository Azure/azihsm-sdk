// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `PartInit` command.
//!
//! `PartInit` is a CO-session command that derives the partition's
//! deterministic PTA keypair, persists the caller-asserted
//! `PartPolicy` + POTA thumbprint into partition state, and returns
//! the PTA CSR + COSE_Sign1 PTA key-attestation report.  See
//! `azihsm_fw_ddi_tbor_types::part_init` for the full wire schema.

use alloc::vec::Vec;

use open_enum::open_enum;

use crate::tbor;

/// TBOR opcode for `PartInit`.
pub const TBOR_OP_PART_INIT: u8 = 0x30;

/// Length of the raw `mach_seed` plaintext (32 B).
pub const MACH_SEED_LEN: usize = 32;

/// AAD label prefix bound into the `mach_seed_envelope` AAD.
pub const PART_INIT_MACH_SEED_AAD_LABEL: &[u8; 17] = b"part-init-seed-v1";

/// Total AAD length bound into the `mach_seed_envelope` (label + session_id LE + zero-padding).
pub const PART_INIT_MACH_SEED_AAD_LEN: usize = 32;

/// Maximum on-the-wire length of the `mach_seed_envelope`.
pub const MACH_SEED_ENVELOPE_MAX_LEN: usize = 160;

/// Wire-pinned `PartPolicy` byte length.
pub const PART_POLICY_LEN: usize = 167;

/// Length of the SHA-384 POTA thumbprint (48 B).
pub const POTA_THUMBPRINT_LEN: usize = 48;

/// Maximum on-the-wire length of the PTA CSR (`pta_csr` response field).
pub const PTA_CSR_MAX_LEN: usize = 512;

/// Maximum on-the-wire length of the PTA attestation report (`pta_report` response field).
pub const PTA_REPORT_MAX_LEN: usize = 1024;

/// Discriminants for the `PolicyPubKey::kind` field within the wire
/// [`PartPolicy`] bytes.
///
/// Stored in the wire layout as little-endian `[u8; 2]`.  Host-side
/// mirror of `azihsm_fw_ddi_tbor_types::policy::PolicyKeyKind` —
/// defined locally so this crate has no firmware dependency.  Open
/// enum so a future spec value gets a new associated `pub const`
/// without breaking exhaustive matches in older code.
#[repr(u16)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKeyKind {
    /// ECC P-384 public key.
    Ecc384 = 0,
}

/// Host-facing TBOR `PartInit` request.
///
/// Field sizes are pinned to the FW schema; passing a slice of the
/// wrong length produces a host-side encode error before the request
/// reaches the device.
#[tbor(opcode = TBOR_OP_PART_INIT, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborPartInitReq {
    /// CO session id this request is bound to.  Cross-checked
    /// against the SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// AEAD-GCM envelope wrapping the 32-byte `mach_seed` plaintext
    /// under the active session's `param_key`.  Construct via the
    /// `encrypt_mach_seed_envelope` test harness helper, or by sealing
    /// directly under the canonical AAD layout
    /// pinned by [`PART_INIT_MACH_SEED_AAD_LABEL`] /
    /// [`PART_INIT_MACH_SEED_AAD_LEN`].
    #[tbor(max_len = 160)]
    pub mach_seed_envelope: Vec<u8>,

    /// Caller-asserted `PartPolicy` bytes (167 B, alignment-1 fixed
    /// layout pinned by the FW schema).
    pub part_policy: [u8; PART_POLICY_LEN],

    /// SHA-384 thumbprint of the POTA certificate the partition is
    /// being provisioned under.
    pub pota_thumbprint: [u8; POTA_THUMBPRINT_LEN],
}

impl Default for TborPartInitReq {
    fn default() -> Self {
        Self {
            session_id: 0,
            mach_seed_envelope: Vec::new(),
            part_policy: [0u8; PART_POLICY_LEN],
            pota_thumbprint: [0u8; POTA_THUMBPRINT_LEN],
        }
    }
}

/// Host-facing TBOR `PartInit` response.
///
/// Both byte fields are owned `Vec<u8>` so callers don't have to
/// carry max-sized padding buffers around.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborPartInitResp {
    /// DER-encoded PKCS#10 CertificationRequest for the PTA pubkey.
    #[tbor(max_len = 512)]
    pub pta_csr: Vec<u8>,

    /// COSE_Sign1 PTA key-attestation report signed by the PID.
    #[tbor(max_len = 1024)]
    pub pta_report: Vec<u8>,
}
