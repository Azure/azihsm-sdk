// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdCreateRemoteBackup` wire schema.
//!
//! `SdCreateRemoteBackup` is an in-session **Crypto Officer** command
//! that creates a new security domain under the active session's
//! partition from the caller-supplied unified [`PartPolicy`], returning
//! the remote partition-owner-key backup (`pok_remote_backup`).
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried CO session id; cross-checked against the
//!   SQE-carried session id by the dispatcher (parity with the other
//!   in-session commands).
//! * `sender_key` — sender key id ([`KeyId`](azihsm_fw_ddi_tbor_api::KeyId),
//!   TOC entry type 1) the masked security domain is wrapped under.
//! * `receiver_evidence` — receiver side-band attestation evidence
//!   ([`Evidence`](crate::evidence::Evidence) field group: manufacturer /
//!   owner / partition-owner certificate chains plus the attestation
//!   report).
//! * `policy` — the unified [`PartPolicy`] describing the security domain
//!   to create.  Length pinned to [`PART_POLICY_LEN`] (484 B).
//!
//! Output:
//!
//! * `pok_remote_backup` — the remote partition-owner-key backup (a
//!   masked BKS3), exactly [`MASKED_SD_LEN`] (180 B): an AEAD-GCM-256
//!   masked-key envelope whose plaintext is the 48-byte BKS3 and whose
//!   AAD is the 96-byte `MaskedKeyMetadata`.

use azihsm_fw_ddi_tbor_api::tbor;

use crate::evidence::*;
pub use crate::policy::PART_POLICY_LEN;

/// TBOR opcode for `SdCreateRemoteBackup`.
pub const TBOR_OP_SD_CREATE_REMOTE_BACKUP: u8 = 0x0A;

// `policy` carries the unified `PartPolicy`; the derive needs an integer
// literal on the field, so the length is spelled out as `484` and pinned
// against the canonical value here.
const _: () = assert!(PART_POLICY_LEN == 484);

/// Exact on-the-wire length of the masked security-domain blob.
///
/// Sized as a masked BKS3: an AEAD-GCM-256 masked-key envelope
/// (`header(8) ‖ iv(12) ‖ aad(96) ‖ pt(48) ‖ tag(16)`) where the
/// plaintext is the 48-byte BKS3 and the AAD is the 96-byte
/// `MaskedKeyMetadata`.
pub const MASKED_SD_LEN: usize = 8 + 12 + 96 + 48 + 16;
const _: () = assert!(MASKED_SD_LEN == 180);

/// `SdCreateRemoteBackup` request schema.
#[tbor(opcode = 0x0A)]
pub struct TborSdCreateRemoteBackupReq<'a> {
    /// CO session id this request is bound to.  Typed
    /// [`SessionId`](azihsm_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The sender key id.
    #[tbor(key_id)]
    pub sender_key: KeyId,

    /// Side-band attestation evidence (manufacturer / owner /
    /// partition-owner certificate chains plus the attestation report).
    /// Spliced in as the [`Evidence`](crate::evidence::Evidence) field
    /// group's four TOC entries.
    #[tbor(include)]
    pub receiver_evidence: Evidence<'a>,

    /// Caller-asserted unified [`PartPolicy`] describing the security
    /// domain to create.  Length pinned to [`PART_POLICY_LEN`] (484 B).
    ///
    /// [`PartPolicy`]: crate::policy::PartPolicy
    #[tbor(buffer, len = 484)]
    pub policy: &'a [u8],
}

/// `SdCreateRemoteBackup` response schema.
#[tbor(response)]
pub struct TborSdCreateRemoteBackupResp<'a> {
    /// Remote partition-owner-key backup (a masked BKS3).  Always exactly
    /// [`MASKED_SD_LEN`] (180 B).
    #[tbor(buffer, len = 180)]
    pub pok_remote_backup: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::KeyId;
    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn masked_sd_len_matches_masked_bks3_envelope() {
        // header(8) + iv(12) + meta-aad(96) + bks3(48) + tag(16).
        const _: () = assert!(MASKED_SD_LEN == 180);
        assert_eq!(MASKED_SD_LEN, 180);
    }

    #[test]
    fn request_round_trips_policy() {
        let policy = [0u8; PART_POLICY_LEN];
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
        let frame = TborSdCreateRemoteBackupReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .sender_key(KeyId(0x5678))
            .unwrap()
            .receiver_evidence(|e| {
                e.mfgr_cert_chain(&chain)?
                    .owner_cert_chain(&chain)?
                    .part_owner_cert_chain(&chain)?
                    .evidence(&report)
            })
            .unwrap()
            .policy(&policy)
            .unwrap()
            .finish();
        assert_eq!(frame.policy().len(), PART_POLICY_LEN);
    }

    #[test]
    fn response_round_trips_pok_remote_backup() {
        let masked = [0xABu8; MASKED_SD_LEN];
        let mut buf = [0u8; 512];
        let frame = TborSdCreateRemoteBackupResp::encode(&mut buf, 0, true)
            .unwrap()
            .pok_remote_backup(&masked)
            .unwrap()
            .finish();
        assert_eq!(frame.pok_remote_backup().len(), MASKED_SD_LEN);
    }
}
