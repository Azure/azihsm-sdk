// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdResealRemoteBackup` wire schema.
//!
//! `SdResealRemoteBackup` is an in-session command run by a Sealing Authority
//! that **reseals** a remote security-domain backup from a source
//! recipient to a destination recipient (manticore §3.3.7 Reseal). It
//! HPKE-unseals the caller-supplied `src_remote_backup` with the masked
//! receiver key (recovering the BKS3), then HPKE-reseals that BKS3 to the
//! destination receiver, returning `dst_remote_backup`.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher (parity with the other
//!   in-session commands).
//! * `masked_sealing_key` — the masked SD-sealing key (from
//!   [`SdSealingKeyGen`](crate::sd_sealing_key_gen)), exactly
//!   [`MASKED_SEALING_KEY_LEN`] (180 B). Unmasked on-device to recover the
//!   receiver's private HPKE key; the same key both unseals the source and
//!   authenticates the reseal to the destination (never a vault handle).
//! * `policy` — the unified [`PartPolicy`] the source and destination must
//!   share. Length pinned to [`PART_POLICY_LEN`] (484 B); its SHA-384
//!   digest is checked against each report's v2 `policy_hash`.
//! * `src_evidence` — source **sender** attestation evidence
//!   ([`Evidence`](crate::evidence::Evidence) field group); its attested
//!   key is the sender public key that sealed `src_remote_backup`.
//! * `dest_evidence` — destination **receiver** attestation evidence
//!   ([`Evidence`](crate::evidence::Evidence) field group); its attested
//!   key is the recipient public key for the reseal.
//! * `src_remote_backup` — the source remote backup to reseal: an
//!   HPKE-Auth seal, exactly [`POK_REMOTE_BACKUP_LEN`] (161 B).
//!
//! Output:
//!
//! * `dst_remote_backup` — the resealed remote backup, exactly
//!   [`POK_REMOTE_BACKUP_LEN`] (161 B): an HPKE-Auth seal of the same BKS3
//!   to the destination receiver under `DHKemP384Sha384AesGcm256`.

use azihsm_fw_ddi_tbor_api::tbor;

use crate::evidence::*;
pub use crate::policy::PART_POLICY_LEN;
pub use crate::sd_create_remote_backup::POK_REMOTE_BACKUP_LEN;
pub use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;

/// TBOR opcode for `SdResealRemoteBackup`.
pub const TBOR_OP_SD_RESEAL_REMOTE_BACKUP: u8 = 0x0B;

// `policy` carries the unified `PartPolicy`; the derive needs an integer
// literal on the field, so the length is spelled out as `484` and pinned
// against the canonical value here.
const _: () = assert!(PART_POLICY_LEN == 484);

// `masked_sealing_key` is a masked SD-sealing key; the derive needs an
// integer literal on the field, so the length is spelled out as `180` and
// pinned against the canonical `MASKED_SEALING_KEY_LEN` here.
const _: () = assert!(MASKED_SEALING_KEY_LEN == 180);

// `src_remote_backup` / `dst_remote_backup` are HPKE-Auth seals; the derive
// needs an integer literal on the field, so the length is spelled out as
// `161` and pinned against `POK_REMOTE_BACKUP_LEN` here.
const _: () = assert!(POK_REMOTE_BACKUP_LEN == 161);

/// `SdResealRemoteBackup` request schema.
#[tbor(opcode = 0x0B)]
pub struct TborSdResealRemoteBackupReq<'a> {
    /// Session id this request is bound to.  Typed
    /// [`SessionId`](azihsm_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The masked SD-sealing key (from `SdSealingKeyGen`), exactly
    /// [`MASKED_SEALING_KEY_LEN`] (180 B).  Unmasked on-device to recover
    /// the receiver's private HPKE key (used to both unseal the source and
    /// authenticate the reseal to the destination); never a vault handle.
    #[tbor(buffer, len = 180)]
    pub masked_sealing_key: &'a [u8],

    /// Caller-asserted unified [`PartPolicy`] the source and destination
    /// must share.  Length pinned to [`PART_POLICY_LEN`] (484 B); its
    /// SHA-384 digest is checked against each report's v2 `policy_hash`.
    ///
    /// [`PartPolicy`]: crate::policy::PartPolicy
    #[tbor(buffer, len = 484)]
    pub policy: &'a [u8],

    /// Source **sender** attestation evidence (manufacturer / owner /
    /// partition-owner certificate chains plus the attestation report).
    /// Spliced in as the [`Evidence`](crate::evidence::Evidence) field
    /// group's four TOC entries; its attested key is the sender public key
    /// that sealed `src_remote_backup`.
    #[tbor(include)]
    pub src_evidence: Evidence<'a>,

    /// Destination **receiver** attestation evidence (manufacturer / owner /
    /// partition-owner certificate chains plus the attestation report).
    /// Spliced in as the [`Evidence`](crate::evidence::Evidence) field
    /// group's four TOC entries; its attested key is the recipient public
    /// key for the reseal.
    #[tbor(include)]
    pub dest_evidence: Evidence<'a>,

    /// Source remote backup to reseal.  An HPKE-Auth seal, exactly
    /// [`POK_REMOTE_BACKUP_LEN`] (161 B).
    #[tbor(buffer, len = 161)]
    pub src_remote_backup: &'a [u8],
}

/// `SdResealRemoteBackup` response schema.
#[tbor(response)]
pub struct TborSdResealRemoteBackupResp<'a> {
    /// Resealed remote backup (an HPKE-Auth seal of the same BKS3 to the
    /// destination receiver).  Always exactly [`POK_REMOTE_BACKUP_LEN`]
    /// (161 B).
    #[tbor(buffer, len = 161)]
    pub dst_remote_backup: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let masked = [0xABu8; MASKED_SEALING_KEY_LEN];
        let policy = [0u8; PART_POLICY_LEN];
        let src_backup = [0xCDu8; POK_REMOTE_BACKUP_LEN];
        let cert = CertDescriptor {
            index: 0,
            length: crate::tbor_int::U16::new(8),
        };
        let report = ReportDescriptor {
            index: 1,
            length: crate::tbor_int::U16::new(16),
        };
        let chain = [cert];
        let mut buf = [0u8; 1024];
        let frame = TborSdResealRemoteBackupReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .masked_sealing_key(&masked)
            .unwrap()
            .policy(&policy)
            .unwrap()
            .src_evidence(|e| {
                e.mfgr_cert_chain(&chain)?
                    .owner_cert_chain(&chain)?
                    .part_owner_cert_chain(&chain)?
                    .evidence(&report)
            })
            .unwrap()
            .dest_evidence(|e| {
                e.mfgr_cert_chain(&chain)?
                    .owner_cert_chain(&chain)?
                    .part_owner_cert_chain(&chain)?
                    .evidence(&report)
            })
            .unwrap()
            .src_remote_backup(&src_backup)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_sealing_key().len(), MASKED_SEALING_KEY_LEN);
        assert_eq!(frame.policy().len(), PART_POLICY_LEN);
        assert_eq!(frame.src_remote_backup().len(), POK_REMOTE_BACKUP_LEN);
    }

    #[test]
    fn response_round_trips_dst_remote_backup() {
        let sealed = [0xABu8; POK_REMOTE_BACKUP_LEN];
        let mut buf = [0u8; 512];
        let frame = TborSdResealRemoteBackupResp::encode(&mut buf, 0, true)
            .unwrap()
            .dst_remote_backup(&sealed)
            .unwrap()
            .finish();
        assert_eq!(frame.dst_remote_backup().len(), POK_REMOTE_BACKUP_LEN);
    }
}
