// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdRestorePeerBackup` wire schema.
//!
//! `SdRestorePeerBackup` is an in-session command that restores a security
//! domain from a **peer** backup (manticore §3.3.11): it HPKE-Auth-opens
//! the caller-supplied `pok_peer_backup` (an HPKE seal of BKS3) with the
//! receiver's masked SD-sealing key — authenticated by the sender peer's
//! attested key — recovers `SDMK` from `prev_sd_mk_backup`, and returns the
//! device-local backups (`pok_local_backup`, `sd_mk_backup`) so the
//! security domain can later be restored locally without the peer.
//!
//! It is [`SdRestoreRemoteBackup`](crate::sd_restore_remote_backup) plus a
//! peer-cloning policy gate (`allow_peer_cloning`); the backup recovered
//! here originates from a peer partition rather than a remote sealing
//! authority.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher (parity with the other
//!   in-session commands).
//! * `masked_sealing_key` — the **receiver's** masked SD-sealing key (from
//!   [`SdSealingKeyGen`](crate::sd_sealing_key_gen)), exactly
//!   [`MASKED_SEALING_KEY_LEN`] (180 B).  Unmasked on-device to recover the
//!   receiver's private HPKE key (`RcvrPriv`) that opens the backup; never
//!   a vault handle.
//! * `policy` — the unified [`PartPolicy`] describing the security domain
//!   being restored.  Length pinned to [`PART_POLICY_LEN`] (484 B); its
//!   SHA-384 digest must equal the partition's bound `policy_hash` and each
//!   report's v2 `policy_hash`.
//! * `src_evidence` — **source** peer side-band attestation evidence
//!   ([`Evidence`](crate::evidence::Evidence) field group); its attested
//!   key is the sender public key that sealed `pok_peer_backup`.
//! * `pok_peer_backup` — the peer backup to restore: an HPKE-Auth seal of
//!   BKS3, exactly [`POK_REMOTE_BACKUP_LEN`] (161 B).
//! * `prev_sd_mk_backup` — the previous security-domain masking-key backup
//!   (SDMK masked under the derived SDBMK), exactly [`SD_MK_BACKUP_LEN`]
//!   (164 B), from which `SDMK` is recovered.
//!
//! Output:
//!
//! * `pok_local_backup` — the local partition-owner-key backup (BKS3 masked
//!   under `PartLocalMK`), exactly [`MASKED_SD_LEN`] (180 B).
//! * `sd_mk_backup` — the refreshed security-domain masking-key backup
//!   envelope, exactly [`SD_MK_BACKUP_LEN`] (164 B).

use azihsm_fw_ddi_tbor_api::tbor;

use crate::evidence::*;
pub use crate::policy::PART_POLICY_LEN;
pub use crate::sd_create_remote_backup::MASKED_SD_LEN;
pub use crate::sd_create_remote_backup::POK_REMOTE_BACKUP_LEN;
pub use crate::sd_create_remote_backup::SD_MK_BACKUP_LEN;
pub use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;

/// TBOR opcode for `SdRestorePeerBackup`.
pub const TBOR_OP_SD_RESTORE_PEER_BACKUP: u8 = 0x0F;

// `masked_sealing_key` is a masked SD-sealing key; the derive needs an
// integer literal on the field, so the length is spelled out as `180` and
// pinned against the canonical `MASKED_SEALING_KEY_LEN` here.
const _: () = assert!(MASKED_SEALING_KEY_LEN == 180);

// `policy` carries the unified `PartPolicy`; the derive needs an integer
// literal on the field, so the length is spelled out as `484` and pinned
// against the canonical value here.
const _: () = assert!(PART_POLICY_LEN == 484);

// `pok_peer_backup` is an HPKE-Auth seal; the derive needs an integer
// literal on the field, so the length is spelled out as `161` and pinned
// against `POK_REMOTE_BACKUP_LEN` here.
const _: () = assert!(POK_REMOTE_BACKUP_LEN == 161);

// `pok_local_backup` is a masked BKS3 envelope; the derive needs an integer
// literal on the field, so the length is spelled out as `180` and pinned
// against the canonical value here.
const _: () = assert!(MASKED_SD_LEN == 180);

// `prev_sd_mk_backup` / `sd_mk_backup` are SD masking-key backup envelopes;
// the derive needs an integer literal on the field, so the length is
// spelled out as `164` and pinned against the canonical value here.
const _: () = assert!(SD_MK_BACKUP_LEN == 164);

/// `SdRestorePeerBackup` request schema.
#[tbor(opcode = 0x0F)]
pub struct TborSdRestorePeerBackupReq<'a> {
    /// Session id this request is bound to.  Typed
    /// [`SessionId`](azihsm_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The receiver's masked SD-sealing key (from `SdSealingKeyGen`),
    /// exactly [`MASKED_SEALING_KEY_LEN`] (180 B).  Unmasked on-device to
    /// recover the receiver's private HPKE key (`RcvrPriv`).
    #[tbor(buffer, len = 180)]
    pub masked_sealing_key: &'a [u8],

    /// Caller-asserted unified [`PartPolicy`] describing the security
    /// domain being restored.  Length pinned to [`PART_POLICY_LEN`]
    /// (484 B).
    ///
    /// [`PartPolicy`]: crate::policy::PartPolicy
    #[tbor(buffer, len = 484)]
    pub policy: &'a [u8],

    /// Source peer side-band attestation evidence (manufacturer / owner /
    /// partition-owner certificate chains plus the attestation report).
    /// Spliced in as the [`Evidence`](crate::evidence::Evidence) field
    /// group's four TOC entries; its attested key is the sender public key
    /// that sealed `pok_peer_backup`.
    #[tbor(include)]
    pub src_evidence: Evidence<'a>,

    /// Peer backup to restore: an HPKE-Auth seal of BKS3.  Always exactly
    /// [`POK_REMOTE_BACKUP_LEN`] (161 B).
    #[tbor(buffer, len = 161)]
    pub pok_peer_backup: &'a [u8],

    /// Previous security-domain masking-key backup (SDMK masked under the
    /// derived SDBMK).  Always exactly [`SD_MK_BACKUP_LEN`] (164 B).
    #[tbor(buffer, len = 164)]
    pub prev_sd_mk_backup: &'a [u8],
}

/// `SdRestorePeerBackup` response schema.
#[tbor(response)]
pub struct TborSdRestorePeerBackupResp<'a> {
    /// Partition-owner-key backup re-wrapped under the device-local key.
    /// Always exactly [`MASKED_SD_LEN`] (180 B).
    #[tbor(buffer, len = 180)]
    pub pok_local_backup: &'a [u8],

    /// Security-domain masking-key backup envelope.  Always exactly
    /// [`SD_MK_BACKUP_LEN`] (164 B).
    #[tbor(buffer, len = 164)]
    pub sd_mk_backup: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let masked = [0u8; MASKED_SEALING_KEY_LEN];
        let policy = [0u8; PART_POLICY_LEN];
        let pok_peer = [0xABu8; POK_REMOTE_BACKUP_LEN];
        let prev_sd_mk = [0xCDu8; SD_MK_BACKUP_LEN];
        let cert = CertDescriptor {
            index: 0,
            length: crate::tbor_int::U16::new(8),
        };
        let report = ReportDescriptor {
            index: 1,
            length: crate::tbor_int::U16::new(16),
        };
        let chain = [cert];
        let mut buf = [0u8; 2048];
        let frame = TborSdRestorePeerBackupReq::encode(&mut buf)
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
            .pok_peer_backup(&pok_peer)
            .unwrap()
            .prev_sd_mk_backup(&prev_sd_mk)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_sealing_key().len(), MASKED_SEALING_KEY_LEN);
        assert_eq!(frame.policy().len(), PART_POLICY_LEN);
        assert_eq!(frame.pok_peer_backup().len(), POK_REMOTE_BACKUP_LEN);
        assert_eq!(frame.prev_sd_mk_backup().len(), SD_MK_BACKUP_LEN);
    }

    #[test]
    fn response_round_trips_backups() {
        let pok_local = [0xABu8; MASKED_SD_LEN];
        let sd_mk = [0xCDu8; SD_MK_BACKUP_LEN];
        let mut buf = [0u8; 512];
        let frame = TborSdRestorePeerBackupResp::encode(&mut buf, 0, true)
            .unwrap()
            .pok_local_backup(&pok_local)
            .unwrap()
            .sd_mk_backup(&sd_mk)
            .unwrap()
            .finish();
        assert_eq!(frame.pok_local_backup().len(), MASKED_SD_LEN);
        assert_eq!(frame.sd_mk_backup().len(), SD_MK_BACKUP_LEN);
    }
}
