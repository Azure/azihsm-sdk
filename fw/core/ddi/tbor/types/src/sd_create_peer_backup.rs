// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdCreatePeerBackup` wire schema.
//!
//! `SdCreatePeerBackup` is an in-session command that creates a
//! peer-transferable backup of a security domain: it takes the local
//! partition-owner-key backup (`pok_local_backup`), re-masks it for the
//! destination peer named by `dst_evidence` under the named sealing key,
//! and returns the peer backup (`pok_peer_backup`).
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher (parity with the other
//!   in-session commands).
//! * `sealing_key_id` — vault id
//!   ([`KeyId`](azihsm_fw_ddi_tbor_api::KeyId), TOC entry type 1) of the
//!   sealing key the `pok_local_backup` is bound to.
//! * `dst_evidence` — destination peer side-band attestation evidence
//!   ([`Evidence`](crate::evidence::Evidence) field group).
//! * `policy` — the unified [`PartPolicy`] describing the security domain
//!   being backed up.  Length pinned to [`PART_POLICY_LEN`] (484 B).
//! * `pok_local_backup` — the local partition-owner-key backup to
//!   re-mask (a masked BKS3 wrapped under the device-local key), exactly
//!   [`MASKED_SD_LEN`] (180 B).
//!
//! Output:
//!
//! * `pok_peer_backup` — the partition-owner-key backup re-masked for the
//!   destination peer, exactly [`MASKED_SD_LEN`] (180 B).

use azihsm_fw_ddi_tbor_api::tbor;

use crate::evidence::*;
pub use crate::policy::PART_POLICY_LEN;
pub use crate::sd_create_remote_backup::MASKED_SD_LEN;

/// TBOR opcode for `SdCreatePeerBackup`.
pub const TBOR_OP_SD_CREATE_PEER_BACKUP: u8 = 0x0E;

// `policy` carries the unified `PartPolicy`; the derive needs an integer
// literal on the field, so the length is spelled out as `484` and pinned
// against the canonical value here.
const _: () = assert!(PART_POLICY_LEN == 484);

// `pok_local_backup` / `pok_peer_backup` are masked BKS3 envelopes; the
// derive needs an integer literal on the field, so the length is spelled
// out as `180` and pinned against the canonical value here.
const _: () = assert!(MASKED_SD_LEN == 180);

/// `SdCreatePeerBackup` request schema.
#[tbor(opcode = 0x0E)]
pub struct TborSdCreatePeerBackupReq<'a> {
    /// Session id this request is bound to.  Typed
    /// [`SessionId`](azihsm_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Vault id ([`HsmKeyId`](azihsm_fw_hsm_pal_traits::HsmKeyId)) of the
    /// sealing key the `pok_local_backup` is bound to.  Carried as a
    /// [`KeyId`](azihsm_fw_ddi_tbor_api::KeyId) (TOC entry type 1).
    #[tbor(key_id)]
    pub sealing_key_id: KeyId,

    /// Destination peer side-band attestation evidence (manufacturer /
    /// owner / partition-owner certificate chains plus the attestation
    /// report).  Spliced in as the [`Evidence`](crate::evidence::Evidence)
    /// field group's four TOC entries.
    #[tbor(include)]
    pub dst_evidence: Evidence<'a>,

    /// Caller-asserted unified [`PartPolicy`] describing the security
    /// domain being backed up.  Length pinned to [`PART_POLICY_LEN`]
    /// (484 B).
    ///
    /// [`PartPolicy`]: crate::policy::PartPolicy
    #[tbor(buffer, len = 484)]
    pub policy: &'a [u8],

    /// Local partition-owner-key backup to re-mask (a masked BKS3 wrapped
    /// under the device-local key).  Always exactly [`MASKED_SD_LEN`]
    /// (180 B).
    #[tbor(buffer, len = 180)]
    pub pok_local_backup: &'a [u8],
}

/// `SdCreatePeerBackup` response schema.
#[tbor(response)]
pub struct TborSdCreatePeerBackupResp<'a> {
    /// Partition-owner-key backup re-masked for the destination peer.
    /// Always exactly [`MASKED_SD_LEN`] (180 B).
    #[tbor(buffer, len = 180)]
    pub pok_peer_backup: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::KeyId;
    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let policy = [0u8; PART_POLICY_LEN];
        let pok_local = [0xABu8; MASKED_SD_LEN];
        let cert = CertDescriptor {
            offset: crate::tbor_int::U16::new(0),
            length: crate::tbor_int::U16::new(8),
        };
        let report = ReportDescriptor {
            offset: crate::tbor_int::U16::new(8),
            length: crate::tbor_int::U16::new(16),
        };
        let chain = [cert];
        let mut buf = [0u8; 1024];
        let frame = TborSdCreatePeerBackupReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .sealing_key_id(KeyId(0x5678))
            .unwrap()
            .dst_evidence(|e| {
                e.mfgr_cert_chain(&chain)?
                    .owner_cert_chain(&chain)?
                    .part_owner_cert_chain(&chain)?
                    .evidence(&report)
            })
            .unwrap()
            .policy(&policy)
            .unwrap()
            .pok_local_backup(&pok_local)
            .unwrap()
            .finish();
        assert_eq!(frame.policy().len(), PART_POLICY_LEN);
        assert_eq!(frame.pok_local_backup().len(), MASKED_SD_LEN);
    }

    #[test]
    fn response_round_trips_pok_peer_backup() {
        let pok_peer = [0xABu8; MASKED_SD_LEN];
        let mut buf = [0u8; 512];
        let frame = TborSdCreatePeerBackupResp::encode(&mut buf, 0, true)
            .unwrap()
            .pok_peer_backup(&pok_peer)
            .unwrap()
            .finish();
        assert_eq!(frame.pok_peer_backup().len(), MASKED_SD_LEN);
    }
}
