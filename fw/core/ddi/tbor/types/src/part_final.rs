// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `PartFinal` (FinalizePart) wire schema — partition-provisioning
//! Phase 2.
//!
//! `PartFinal` is a CO-session command that finalizes a partition after
//! [`PartInit`](crate::part_init) by installing the POTA-endorsed PTA
//! certificate chain and deriving the partition's local masking keys
//! (bound to the cert-chain digest).  It generates — or restores from a
//! caller-supplied prior backup — the partition local masking key
//! (`local_mk`) and returns its current backup (`local_mk_backup`).
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried CO session id; cross-checked against the
//!   SQE-carried session id (parity with the other in-session commands).
//! * `part_policy` — the same unified [`PartPolicy`] the caller asserted
//!   in `PartInit`, re-supplied so the handler can recover `POTAPubKey`
//!   for cert-chain validation.  The handler verifies
//!   `SHA-384(part_policy) == ` the stored policy hash before trusting
//!   it.  Layout owned by [`crate::policy::PartPolicy`]; length pinned by
//!   [`PART_POLICY_LEN`].
//! * `cert_descriptors` — a packed list of [`CertDescriptor`] entries
//!   `(offset, length)` describing where each DER certificate of the PTA
//!   chain lives in the **side-band** data buffer (the certificate bytes
//!   are transferred out of band, not in the TBOR message).  The number
//!   of certificates is `cert_descriptors.len() / CERT_DESCRIPTOR_LEN`,
//!   capped at [`MAX_CERTS`](crate::evidence::MAX_CERTS).
//! * `prev_local_mk_backup` — optional previously-generated `local_mk`
//!   backup envelope to restore.  An **empty** field means absent — the
//!   handler then generates a fresh `local_mk` and returns its backup.
//!
//! Outputs:
//!
//! * `local_mk_backup` — current `local_mk` backup envelope
//!   (`CurrPartLocalKMKBackup`), to be persisted by the host and replayed
//!   as `prev_local_mk_backup` on subsequent launches.

use azihsm_fw_ddi_tbor_api::tbor;

use crate::evidence::CertDescriptor;

/// TBOR opcode for `PartFinal`.
pub const TBOR_OP_PART_FINAL: u8 = 0x08;

/// Byte length of the caller-asserted [`PartPolicy`] blob re-supplied on
/// the `PartFinal` wire.  Single source of truth re-exported from
/// [`crate::policy`].
///
/// [`PartPolicy`]: crate::policy::PartPolicy
pub use crate::policy::PART_POLICY_LEN;

/// Exact on-the-wire length of a `local_mk` backup envelope
/// (`prev_local_mk_backup` / `local_mk_backup`).
///
/// The envelope is fully deterministic: an AES-256-GCM `MaskedKey`
/// envelope around the 32-byte `local_mk` plaintext —
/// `header(8) + iv(12) + MaskedKeyMetadata aad(96) + ct(32) + tag(16)`
/// = 164 B. `prev_local_mk_backup` is **optional** (an empty field means
/// absent; otherwise exactly this length); `local_mk_backup` is always
/// exactly this length.
pub const LOCAL_MK_BACKUP_LEN: usize = 8 + 12 + 96 + 32 + 16;

// Pin the computed envelope length to the `#[tbor(... = 164)]` literals
// on the `prev_local_mk_backup` / `local_mk_backup` fields (the derive
// requires integer literals). If the envelope layout changes, update
// both the breakdown above and the field attributes.
const _: () = assert!(LOCAL_MK_BACKUP_LEN == 164);

/// `PartFinal` request schema.
///
/// Finalizes the partition: re-supplies the unified [`PartPolicy`] (for
/// `POTAPubKey` recovery), the PTA cert-chain descriptor list (pointing
/// into the side-band buffer), and an optional prior `local_mk` backup
/// to restore.
///
/// [`PartPolicy`]: crate::policy::PartPolicy
#[tbor(opcode = 0x08)]
pub struct TborPartFinalReq<'a> {
    /// CO session id this request is bound to.  Typed
    /// [`SessionId`](azihsm_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Caller-asserted unified [`PartPolicy`] blob, re-supplied from
    /// `PartInit` so the handler can recover `POTAPubKey` for cert-chain
    /// validation.  Length pinned to [`PART_POLICY_LEN`].
    ///
    /// Carried as a raw `&[u8]`: the handler hashes it
    /// (`SHA-384(part_policy) == policy_hash`) and, when it needs typed
    /// access, casts/validates the same bytes via
    /// `super::policy::from_bytes`.
    ///
    /// [`PartPolicy`]: crate::policy::PartPolicy
    #[tbor(buffer, len = 484)]
    pub part_policy: &'a [u8],

    /// Packed list of [`CertDescriptor`] entries `(offset, length)` for
    /// the PTA certificate chain in the side-band buffer.  Decoded as a
    /// zero-copy typed slice; because [`CertDescriptor`] is `Unaligned`
    /// (alignment 1) the `&[CertDescriptor]` cast is sound at any offset,
    /// so no alignment padding is inserted.  Byte length is a non-zero
    /// multiple of [`CERT_DESCRIPTOR_LEN`](crate::evidence::CERT_DESCRIPTOR_LEN), up to
    /// [`CERT_DESCRIPTORS_MAX_LEN`](crate::evidence::CERT_DESCRIPTORS_MAX_LEN).
    #[tbor(buffer, min_len = 1, max_len = 8)]
    pub cert_descriptors: &'a [CertDescriptor],

    /// Optional previously-generated `local_mk` backup envelope to
    /// restore.  An **empty** field means absent; when present it is
    /// exactly [`LOCAL_MK_BACKUP_LEN`] (164 B).
    #[tbor(buffer, max_len = 164)]
    pub prev_local_mk_backup: &'a [u8],
}

/// `PartFinal` response schema.
///
/// Carries the current `local_mk` backup envelope.
#[tbor(response)]
pub struct TborPartFinalResp<'a> {
    /// Current `local_mk` backup envelope (`CurrPartLocalKMKBackup`).
    /// Always exactly [`LOCAL_MK_BACKUP_LEN`] (164 B).
    #[tbor(buffer, len = 164)]
    pub local_mk_backup: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use zerocopy::IntoBytes;

    use super::*;
    use crate::evidence::CERT_DESCRIPTOR_LEN;
    use crate::tbor_int::U16;

    #[test]
    fn part_policy_len_matches_pinned_value() {
        // The `#[tbor(len = 484)]` attribute on `part_policy` must remain
        // a numeric literal; this pins it against the canonical
        // `PART_POLICY_LEN` from `crate::policy`.
        const _: () = assert!(484 == PART_POLICY_LEN);
        assert_eq!(PART_POLICY_LEN, 484);
    }

    #[test]
    fn encoder_accepts_part_policy_and_typed_descriptors() {
        use azihsm_fw_ddi_tbor_api::SessionId;

        let policy = [0u8; PART_POLICY_LEN];
        let descs = [
            CertDescriptor {
                offset: U16::new(16),
                length: U16::new(32),
            },
            CertDescriptor {
                offset: U16::new(48),
                length: U16::new(64),
            },
        ];

        let mut buf = [0u8; 2048];
        let frame = TborPartFinalReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .part_policy(&policy)
            .unwrap()
            .cert_descriptors(&descs)
            .unwrap()
            .prev_local_mk_backup(&[])
            .unwrap()
            .finish();

        // The encoder serialized `&[CertDescriptor]` to its raw bytes:
        // two 4-byte descriptors, little-endian.
        let raw = frame.cert_descriptors();
        assert_eq!(raw.len(), descs.len() * CERT_DESCRIPTOR_LEN);
        assert_eq!(raw, IntoBytes::as_bytes(&descs[..]));
    }
}
