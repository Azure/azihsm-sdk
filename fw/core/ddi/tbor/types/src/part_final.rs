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
//!   `(index, length)` referencing where each DER certificate of the PTA
//!   chain is carried **out of band** as an SGL Data Block (the
//!   certificate bytes are transferred out of band, not in the TBOR
//!   message).  Decoded as a `&[CertDescriptor]`, so the certificate
//!   count is `cert_descriptors.len()`, capped at
//!   [`MAX_CERTS`](crate::evidence::MAX_CERTS).
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

// Pin the `cert_descriptors` `#[tbor(min_len/max_len)]` literals to their
// descriptor-size constants (the derive requires integer literals): a
// single descriptor (`min_len`) and `MAX_CERTS` descriptors (`max_len`).
// If a descriptor size or `MAX_CERTS` changes, update the field attribute.
const _: () = assert!(crate::evidence::CERT_DESCRIPTOR_LEN == 3);
const _: () = assert!(crate::evidence::CERT_DESCRIPTORS_MAX_LEN == 6);

/// `PartFinal` request schema.
///
/// Finalizes the partition: re-supplies the unified [`PartPolicy`] (for
/// `POTAPubKey` recovery), the PTA cert-chain descriptor list
/// (referencing out-of-band SGL Data Blocks), and an optional prior
/// `local_mk` backup to restore.
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

    /// Packed list of [`CertDescriptor`] entries `(index, length)` for
    /// the PTA certificate chain carried out of band.  Decoded as a
    /// zero-copy typed slice; because [`CertDescriptor`] is `Unaligned`
    /// (alignment 1) the `&[CertDescriptor]` cast is sound at any offset,
    /// so no alignment padding is inserted.
    ///
    /// `min_len`/`max_len` are a coarse wire-size guard bounding the byte
    /// length to `[CERT_DESCRIPTOR_LEN, CERT_DESCRIPTORS_MAX_LEN]` =
    /// `[3, 6]`; they cannot by themselves enforce a whole-descriptor
    /// multiple.  A wire length that is not a multiple of
    /// [`CERT_DESCRIPTOR_LEN`](crate::evidence::CERT_DESCRIPTOR_LEN) (e.g.
    /// 4 or 5 B) fails the zero-copy cast and decodes as an **empty**
    /// slice — the derive does **not** reject it
    /// (`try_ref_from_bytes(..).unwrap_or(&[])`); the PartFinal handler is
    /// therefore responsible for treating an empty `cert_descriptors` as a
    /// malformed request.
    #[tbor(buffer, min_len = 3, max_len = 6)]
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
                index: 0,
                length: U16::new(32),
            },
            CertDescriptor {
                index: 1,
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
        // two 3-byte descriptors, little-endian.
        let raw = frame.cert_descriptors();
        assert_eq!(raw.len(), descs.len() * CERT_DESCRIPTOR_LEN);
        assert_eq!(raw, IntoBytes::as_bytes(&descs[..]));
    }
}
