// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `PartInit` wire schema (partition-provisioning Phase 1).
//!
//! `PartInit` is a CO-session command that derives the Partition Trust
//! Anchor (PTA) and Partition Identity (PID) keypairs, persists the
//! caller-asserted partition policy + POTA thumbprint, and returns the
//! PTA CSR plus the PTA key-attestation report (`PTAReport`).
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried CO session id; the dispatcher
//!   cross-checks it against the SQE-carried session id (parity with
//!   `PskChange` / `SessionClose`).
//! * `mach_seed` — 32-byte machine/host entropy contribution mixed
//!   into the partition's internal key-derivation.
//! * `part_policy` — caller-asserted partition policy bound into
//!   the partition's attested state.  Layout owned by
//!   [`crate::policy::PartPolicy`]; wire length pinned by
//!   [`PART_POLICY_LEN`].
//! * `pota_thumbprint` — 48-byte SHA-384 thumbprint of the POTA
//!   (Proof-of-Trust Attestation) certificate the partition is being
//!   provisioned under.
//!
//! Outputs:
//!
//! * `pta_csr` — DER-encoded PKCS#10 CertificationRequest for the PTA
//!   public key (≤ [`PTA_CSR_MAX_LEN`] bytes).
//! * `pta_report` — COSE_Sign1 PTA key-attestation report
//!   (≤ [`PTA_REPORT_MAX_LEN`] bytes).
//!
//! Byte fields are declared as `&[u8]` slices with `len` / `max_len`
//! constraints so handler code can pass and receive slices end-to-end
//! without materializing stack-allocated arrays at any layer.

use azihsm_fw_ddi_tbor_api::tbor;

/// TBOR opcode for `PartInit`.
pub const TBOR_OP_PART_INIT: u8 = 0x07;

/// Length of the machine/host entropy contribution mixed into the
/// partition's internal key-derivation.
pub const MACH_SEED_LEN: usize = 32;

/// Domain/version label embedded in the AEAD envelope's AAD that
/// wraps the `mach_seed` plaintext.  Pinned per spec to bind the
/// envelope to this command + version.
pub const PART_INIT_MACH_SEED_AAD_LABEL: &[u8; 17] = b"part-init-seed-v1";

/// Length of the AAD bound into the `mach_seed` AEAD envelope.
///
/// Pinned to 32 B to satisfy the AEAD-envelope crate's AAD-granularity
/// invariant.  Layout: `label(17) ‖ session_id(2 LE) ‖ rsv0(13)`.
pub const PART_INIT_MACH_SEED_AAD_LEN: usize = 32;

/// Exact on-the-wire length of the wrapped `mach_seed_envelope`.
///
/// The envelope is fully deterministic: an AEAD-GCM envelope around the
/// 32-byte `mach_seed` plaintext with a 32-byte AAD —
/// `header(8) + iv(12) + aad(32) + ct(32) + tag(16)` = 100 B. Pinned as
/// a fixed-length field so a malformed length is rejected at decode.
pub const MACH_SEED_ENVELOPE_LEN: usize = 8 + 12 + PART_INIT_MACH_SEED_AAD_LEN + 32 + 16;

// Pin the computed envelope length to the `#[tbor(... = 100)]` literal on
// the `mach_seed_envelope` field (the derive requires an integer
// literal). If the envelope layout changes, update both.
const _: () = assert!(MACH_SEED_ENVELOPE_LEN == 100);

/// Maximum bytes the wrapped `mach_seed_envelope` may occupy on the
/// wire.
///
/// Retained as the documented upper bound (and for the host encoder,
/// which keeps a permissive `max_len` so negative tests can ship
/// wrong-length envelopes). The firmware schema itself pins the exact
/// [`MACH_SEED_ENVELOPE_LEN`].
pub const MACH_SEED_ENVELOPE_MAX_LEN: usize = 160;

/// Byte length of the caller-asserted [`PartPolicy`] blob carried
/// on the `PartInit` wire.
///
/// Re-exported from [`crate::policy`] — single source of truth.  The
/// `#[tbor(len = 484)]` attribute on [`TborPartInitReq::part_policy`]
/// must remain a numeric literal (TBOR derive requirement); the
/// `const _: () = assert!(484 == PART_POLICY_LEN)` guard in the
/// `tests` module below fails the build if the two ever drift.
///
/// [`PartPolicy`]: crate::policy::PartPolicy
pub use crate::policy::PART_POLICY_LEN;

/// Length of the POTA certificate thumbprint (SHA-384).
pub const POTA_THUMBPRINT_LEN: usize = 48;

/// Length of the SATA (Sealing Authority Trust Anchor) certificate
/// thumbprint (SHA-384).
pub const SATA_THUMBPRINT_LEN: usize = 48;

/// Length of the SAPOTA (Sealing Authority's POTA) certificate
/// thumbprint (SHA-384).
pub const SAPOTA_THUMBPRINT_LEN: usize = 48;

/// Upper bound on the DER-encoded PTA CSR carried in the response.
///
/// Device-CSR template is 248 B of CertificationRequestInfo + outer
/// SEQUENCE wrapper + ECDSA-with-SHA384 AlgorithmIdentifier + BIT
/// STRING-wrapped DER signature (≤ 108 B); cap rounded up to 512 to
/// leave headroom for the KeyUsage extension the PTA CSR carries on
/// top of the device-CSR template.
pub const PTA_CSR_MAX_LEN: usize = 512;

/// Upper bound on the COSE_Sign1 PTA key-attestation report carried
/// in the response.
///
/// Sized for the worst-case PTAReport produced by
/// `azihsm_fw_core_crypto_key_report` (COSE_Sign1 fixed overhead +
/// max payload).  A cross-crate `const _` static assert in the
/// firmware handler module pins this to `COSE_SIGN1_MAX_LEN` from the
/// key-report crate (which `azihsm_fw_ddi_tbor_types` cannot depend
/// on directly due to layering).
pub const PTA_REPORT_MAX_LEN: usize = 1024;

/// `PartInit` request schema.
///
/// Initiates partition provisioning with the merged security-domain
/// configuration parameters: supplies the machine-seed entropy, the
/// unified caller-asserted [`PartPolicy`] (which carries both
/// partition-level and security-domain fields), and the POTA / SATA /
/// optional SAPOTA certificate thumbprints.  The security-domain local
/// masking keys are *not* derived here — that is deferred to a future
/// part-final command.
///
/// [`PartPolicy`]: crate::policy::PartPolicy
#[tbor(opcode = 0x07)]
pub struct TborPartInitReq<'a> {
    /// CO session id this request is bound to.  Typed
    /// [`SessionId`](azihsm_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// AEAD-GCM envelope wrapping the 32-byte `mach_seed` plaintext
    /// under the active session's `param_key`.  Fixed length
    /// [`MACH_SEED_ENVELOPE_LEN`] (100 B); a malformed length is
    /// rejected at decode with `TborInvalidFixedLength`.  AAD layout is
    /// pinned to `label(17) ‖ session_id(2 LE) ‖ rsv0(13)` —
    /// see [`PART_INIT_MACH_SEED_AAD_LABEL`] and
    /// [`PART_INIT_MACH_SEED_AAD_LEN`].
    ///
    /// Marked `#[tbor(mutable)]` so the FW handler can AEAD-open the
    /// envelope in place — the field is exposed as the
    /// `mach_seed_envelope` member of the generated
    /// `TborPartInitReqViewMut` destructured view.
    #[tbor(buffer, len = 100, mutable)]
    pub mach_seed_envelope: &'a [u8],

    /// Caller-asserted unified [`PartPolicy`] blob bound into the
    /// partition's attested state.  Length pinned to
    /// [`PART_POLICY_LEN`].
    ///
    /// [`PartPolicy`]: crate::policy::PartPolicy
    #[tbor(buffer, len = 484)]
    pub part_policy: &'a [u8],

    /// SHA-384 thumbprint (48 B) of the POTA certificate the
    /// partition is being provisioned under.
    #[tbor(buffer, len = 48)]
    pub pota_thumbprint: &'a [u8],

    /// SHA-384 thumbprint (48 B) of the SATA (Sealing Authority Trust
    /// Anchor) certificate bound to this security domain.
    #[tbor(buffer, len = 48)]
    pub sata_thumbprint: &'a [u8],

    /// Optional SHA-384 thumbprint (48 B) of the SAPOTA (Sealing
    /// Authority's POTA) certificate.  An **empty** field means absent
    /// (the security domain has no SAPOTA binding); when non-empty it
    /// must be exactly [`SAPOTA_THUMBPRINT_LEN`] bytes.
    #[tbor(buffer, max_len = 48)]
    pub sapota_thumbprint: &'a [u8],
}

/// `PartInit` response schema.
///
/// Carries the DER-encoded PTA CSR and the COSE_Sign1 PTA
/// key-attestation report.
#[tbor(response)]
pub struct TborPartInitResp<'a> {
    /// DER-encoded PKCS#10 CertificationRequest for the PTA public
    /// key.  Variable length up to [`PTA_CSR_MAX_LEN`].
    #[tbor(buffer, max_len = 512)]
    pub pta_csr: &'a [u8],

    /// COSE_Sign1 PTA key-attestation report.  Variable length up to
    /// [`PTA_REPORT_MAX_LEN`].
    #[tbor(buffer, max_len = 1024)]
    pub pta_report: &'a [u8],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_policy_len_matches_pinned_value() {
        // The `#[tbor(len = 484)]` attribute on `part_policy` must
        // remain a numeric literal; this pins it against the
        // canonical `PART_POLICY_LEN` from `crate::policy`.
        const _: () = assert!(484 == PART_POLICY_LEN);
        assert_eq!(PART_POLICY_LEN, 484);
    }

    #[test]
    fn pta_csr_and_report_caps_within_tbor_data_limits() {
        // TBOR `MAX_DATA_SIZE` is 8191; our two response buffers must
        // sum to comfortably less than that.
        const { assert!(PTA_CSR_MAX_LEN + PTA_REPORT_MAX_LEN < 8191) };
    }
}
