// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `PartInit` command.
//!
//! `PartInit` is a CO-session command that derives the partition's
//! deterministic PTA keypair and records the merged security-domain
//! configuration params.  It persists the caller-asserted unified
//! `PartPolicy` (partition + security-domain fields) plus the POTA /
//! SATA / optional SAPOTA thumbprints, and returns the PTA CSR and the
//! COSE_Sign1 PTA key-attestation report.  The security-domain local
//! masking keys are derived later by a future part-final command.  See
//! `azihsm_fw_ddi_tbor_types::part_init` for the full wire schema.

use alloc::vec::Vec;

use crate::policy::PartPolicy;
use crate::tbor;

/// TBOR opcode for `PartInit`.
pub const TBOR_OP_PART_INIT: u8 = 0x07;

/// Length of the raw `mach_seed` plaintext (32 B).
pub const MACH_SEED_LEN: usize = 32;

/// AAD label prefix bound into the `mach_seed_envelope` AAD.
pub const PART_INIT_MACH_SEED_AAD_LABEL: &[u8; 17] = b"part-init-seed-v1";

/// Total AAD length bound into the `mach_seed_envelope` (label + session_id LE + zero-padding).
pub const PART_INIT_MACH_SEED_AAD_LEN: usize = 32;

/// Maximum on-the-wire length of the `mach_seed_envelope`.
pub const MACH_SEED_ENVELOPE_MAX_LEN: usize = 160;

/// Wire-pinned unified `PartPolicy` byte length.
pub use crate::policy::PART_POLICY_LEN;

/// Length of the SHA-384 POTA thumbprint (48 B).
pub const POTA_THUMBPRINT_LEN: usize = 48;

/// Length of the SHA-384 SATA thumbprint (48 B).
pub const SATA_THUMBPRINT_LEN: usize = 48;

/// Length of the SHA-384 SAPOTA thumbprint (48 B).
pub const SAPOTA_THUMBPRINT_LEN: usize = 48;

/// Maximum on-the-wire length of the PTA CSR (`pta_csr` response field).
pub const PTA_CSR_MAX_LEN: usize = 512;

/// Maximum on-the-wire length of the PTA attestation report (`pta_report` response field).
pub const PTA_REPORT_MAX_LEN: usize = 1024;

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

    /// Caller-asserted unified [`PartPolicy`], encoded as its 484-byte
    /// alignment-1 little-endian image pinned by the FW schema.
    pub part_policy: PartPolicy,

    /// SHA-384 thumbprint of the POTA certificate the partition is
    /// being provisioned under.
    pub pota_thumbprint: [u8; POTA_THUMBPRINT_LEN],

    /// SHA-384 thumbprint of the SATA certificate bound to the
    /// security domain.
    pub sata_thumbprint: [u8; SATA_THUMBPRINT_LEN],

    /// Optional SHA-384 thumbprint of the SAPOTA certificate.  Empty
    /// when the security domain has no SAPOTA binding.
    #[tbor(max_len = 48)]
    pub sapota_thumbprint: Vec<u8>,
}

impl Default for TborPartInitReq {
    fn default() -> Self {
        Self {
            session_id: 0,
            mach_seed_envelope: Vec::new(),
            part_policy: PartPolicy::zeroed(),
            pota_thumbprint: [0u8; POTA_THUMBPRINT_LEN],
            sata_thumbprint: [0u8; SATA_THUMBPRINT_LEN],
            sapota_thumbprint: Vec::new(),
        }
    }
}

/// Host-facing TBOR `PartInit` response.
///
/// All byte fields are owned `Vec<u8>` so callers don't have to
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
