// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdCreatePeerBackup` wire schema.
//!
//! `SdCreatePeerBackup` is an in-session command that creates a
//! **peer-transferable** backup of a security domain (manticore §3.3.10):
//! it recovers BKS3 from the caller's device-local backup
//! (`pok_local_backup`) and HPKE-Auth-seals it to a destination peer —
//! named by `dst_evidence` and authenticated by the sender's own masked
//! SD-sealing key — returning the peer backup (`pok_peer_backup`).  The
//! command is **stateless**: nothing is persisted.
//!
//! Peer cloning is gated by the security domain's policy
//! (`allow_peer_cloning`).
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher (parity with the other
//!   in-session commands).
//! * `masked_sealing_key` — the **sender's** masked SD-sealing key (from
//!   [`SdSealingKeyGen`](crate::sd_sealing_key_gen)), exactly
//!   [`MASKED_SEALING_KEY_LEN`] (180 B).  Unmasked on-device to recover the
//!   sender's private HPKE key (`SndrPriv`) that authenticates the seal;
//!   never a vault handle.
//! * `policy` — the unified [`PartPolicy`] describing the security domain
//!   being backed up.  Length pinned to [`PART_POLICY_LEN`] (484 B); its
//!   SHA-384 digest must equal the partition's bound `policy_hash` and the
//!   receiver report's v2 `policy_hash`.
//! * `dst_evidence` — **destination** peer side-band attestation evidence
//!   ([`Evidence`](crate::evidence::Evidence) field group); its attested
//!   key is the receiver public key (`RcvrPub`) the backup is sealed to.
//! * `pok_local_backup` — the device-local partition-owner-key backup (a
//!   masked BKS3 wrapped under `PartLocalMK`), exactly [`MASKED_SD_LEN`]
//!   (180 B), from which BKS3 is recovered.
//!
//! Output:
//!
//! * `pok_peer_backup` — the peer backup: an HPKE-Auth seal of BKS3,
//!   exactly [`POK_REMOTE_BACKUP_LEN`] (161 B).

use azihsm_fw_ddi_tbor_api::tbor;

use crate::evidence::*;
pub use crate::policy::PART_POLICY_LEN;
pub use crate::sd_create_remote_backup::MASKED_SD_LEN;
pub use crate::sd_create_remote_backup::POK_REMOTE_BACKUP_LEN;
pub use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;

/// TBOR opcode for `SdCreatePeerBackup`.
pub const TBOR_OP_SD_CREATE_PEER_BACKUP: u8 = 0x0E;

// `masked_sealing_key` is a masked SD-sealing key; the derive needs an
// integer literal on the field, so the length is spelled out as `180` and
// pinned against the canonical `MASKED_SEALING_KEY_LEN` here.
const _: () = assert!(MASKED_SEALING_KEY_LEN == 180);

// `policy` carries the unified `PartPolicy`; the derive needs an integer
// literal on the field, so the length is spelled out as `484` and pinned
// against the canonical value here.
const _: () = assert!(PART_POLICY_LEN == 484);

// `pok_local_backup` is a masked BKS3 envelope; the derive needs an integer
// literal on the field, so the length is spelled out as `180` and pinned
// against the canonical value here.
const _: () = assert!(MASKED_SD_LEN == 180);

// `pok_peer_backup` is an HPKE-Auth seal; the derive needs an integer
// literal on the field, so the length is spelled out as `161` and pinned
// against `POK_REMOTE_BACKUP_LEN` here.
const _: () = assert!(POK_REMOTE_BACKUP_LEN == 161);

/// `SdCreatePeerBackup` request schema.
#[tbor(opcode = 0x0E)]
pub struct TborSdCreatePeerBackupReq<'a> {
    /// Session id this request is bound to.  Typed
    /// [`SessionId`](azihsm_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The sender's masked SD-sealing key (from `SdSealingKeyGen`), exactly
    /// [`MASKED_SEALING_KEY_LEN`] (180 B).  Unmasked on-device to recover
    /// the sender's private HPKE key (`SndrPriv`) that authenticates the
    /// seal.
    #[tbor(buffer, len = 180)]
    pub masked_sealing_key: &'a [u8],

    /// Caller-asserted unified [`PartPolicy`] describing the security
    /// domain being backed up.  Length pinned to [`PART_POLICY_LEN`]
    /// (484 B).
    ///
    /// [`PartPolicy`]: crate::policy::PartPolicy
    #[tbor(buffer, len = 484)]
    pub policy: &'a [u8],

    /// Destination peer side-band attestation evidence (manufacturer /
    /// owner / partition-owner certificate chains plus the attestation
    /// report).  Spliced in as the [`Evidence`](crate::evidence::Evidence)
    /// field group's four TOC entries; its attested key is the receiver
    /// public key the backup is sealed to.
    #[tbor(include)]
    pub dst_evidence: Evidence<'a>,

    /// Device-local partition-owner-key backup (a masked BKS3 wrapped under
    /// `PartLocalMK`) from which BKS3 is recovered.  Always exactly
    /// [`MASKED_SD_LEN`] (180 B).
    #[tbor(buffer, len = 180)]
    pub pok_local_backup: &'a [u8],
}

/// `SdCreatePeerBackup` response schema.
#[tbor(response)]
pub struct TborSdCreatePeerBackupResp<'a> {
    /// Peer backup: an HPKE-Auth seal of BKS3.  Always exactly
    /// [`POK_REMOTE_BACKUP_LEN`] (161 B).
    #[tbor(buffer, len = 161)]
    pub pok_peer_backup: &'a [u8],
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
        let pok_local = [0xABu8; MASKED_SD_LEN];
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
        let frame = TborSdCreatePeerBackupReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .masked_sealing_key(&masked)
            .unwrap()
            .policy(&policy)
            .unwrap()
            .dst_evidence(|e| {
                e.mfgr_cert_chain(&chain)?
                    .owner_cert_chain(&chain)?
                    .part_owner_cert_chain(&chain)?
                    .evidence(&report)
            })
            .unwrap()
            .pok_local_backup(&pok_local)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_sealing_key().len(), MASKED_SEALING_KEY_LEN);
        assert_eq!(frame.policy().len(), PART_POLICY_LEN);
        assert_eq!(frame.pok_local_backup().len(), MASKED_SD_LEN);
    }

    #[test]
    fn response_round_trips_pok_peer_backup() {
        let pok_peer = [0xABu8; POK_REMOTE_BACKUP_LEN];
        let mut buf = [0u8; 512];
        let frame = TborSdCreatePeerBackupResp::encode(&mut buf, 0, true)
            .unwrap()
            .pok_peer_backup(&pok_peer)
            .unwrap()
            .finish();
        assert_eq!(frame.pok_peer_backup().len(), POK_REMOTE_BACKUP_LEN);
    }
}
