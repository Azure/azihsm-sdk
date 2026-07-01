// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdResealBackup` wire schema.
//!
//! `SdResealBackup` is an in-session command that re-masks an
//! existing security-domain blob (`pok_remote_backup`) for a new recipient: it
//! unmasks the caller-supplied `pok_remote_backup` under the named sealing key
//! and re-masks it under the destination, returning a freshly resealed
//! `pok_remote_backup`.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher (parity with the other
//!   in-session commands).
//! * `sealing_key_handle` — vault id
//!   ([`KeyId`](azihsm_fw_ddi_tbor_api::KeyId), TOC entry type 1) of the
//!   sealing key the source `pok_remote_backup` is bound to.
//! * `policy` — the unified [`PartPolicy`] describing the security domain
//!   being resealed.  Length pinned to [`PART_POLICY_LEN`] (484 B).
//! * `src_evidence` — source side-band attestation evidence
//!   ([`Evidence`](crate::evidence::Evidence) field group).
//! * `dest_evidence` — destination side-band attestation evidence
//!   ([`Evidence`](crate::evidence::Evidence) field group).
//! * `pok_remote_backup` — the source masked security-domain blob to reseal,
//!   exactly [`MASKED_SD_LEN`] (180 B).
//!
//! Output:
//!
//! * `pok_remote_backup` — the resealed security-domain blob, exactly
//!   [`MASKED_SD_LEN`] (180 B): an AEAD-GCM-256 masked-key envelope whose
//!   plaintext is the 48-byte BKS3 and whose AAD is the 96-byte
//!   `MaskedKeyMetadata`.

use azihsm_fw_ddi_tbor_api::tbor;

use crate::evidence::*;
pub use crate::policy::PART_POLICY_LEN;
pub use crate::sd_create_remote_backup::MASKED_SD_LEN;

/// TBOR opcode for `SdResealBackup`.
pub const TBOR_OP_SD_RESEAL_BACKUP: u8 = 0x0B;

// `policy` carries the unified `PartPolicy`; the derive needs an integer
// literal on the field, so the length is spelled out as `484` and pinned
// against the canonical value here.
const _: () = assert!(PART_POLICY_LEN == 484);

// `pok_remote_backup` is a masked BKS3 envelope; the derive needs an integer
// literal on the field, so the length is spelled out as `180` and pinned
// against the canonical value here.
const _: () = assert!(MASKED_SD_LEN == 180);

/// `SdResealBackup` request schema.
#[tbor(opcode = 0x0B)]
pub struct TborSdResealBackupReq<'a> {
    /// Session id this request is bound to.  Typed
    /// [`SessionId`](azihsm_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Vault id ([`HsmKeyId`](azihsm_fw_hsm_pal_traits::HsmKeyId)) of the
    /// sealing key the source `pok_remote_backup` is bound to.  Carried as a
    /// [`KeyId`](azihsm_fw_ddi_tbor_api::KeyId) (TOC entry type 1).
    #[tbor(key_id)]
    pub sealing_key_handle: KeyId,

    /// Caller-asserted unified [`PartPolicy`] describing the security
    /// domain being resealed.  Length pinned to [`PART_POLICY_LEN`]
    /// (484 B).
    ///
    /// [`PartPolicy`]: crate::policy::PartPolicy
    #[tbor(buffer, len = 484)]
    pub policy: &'a [u8],

    /// Source side-band attestation evidence (manufacturer / owner /
    /// partition-owner certificate chains plus the attestation report).
    /// Spliced in as the [`Evidence`](crate::evidence::Evidence) field
    /// group's four TOC entries.
    #[tbor(include)]
    pub src_evidence: Evidence<'a>,

    /// Destination side-band attestation evidence (manufacturer / owner /
    /// partition-owner certificate chains plus the attestation report).
    /// Spliced in as the [`Evidence`](crate::evidence::Evidence) field
    /// group's four TOC entries.
    #[tbor(include)]
    pub dest_evidence: Evidence<'a>,

    /// Source masked security-domain blob to reseal.  Always exactly
    /// [`MASKED_SD_LEN`] (180 B), sized as a masked BKS3.
    #[tbor(buffer, len = 180)]
    pub pok_remote_backup: &'a [u8],
}

/// `SdResealBackup` response schema.
#[tbor(response)]
pub struct TborSdResealBackupResp<'a> {
    /// Resealed security-domain blob.  Always exactly [`MASKED_SD_LEN`]
    /// (180 B), sized as a masked BKS3.
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
    fn request_round_trips_fields() {
        let policy = [0u8; PART_POLICY_LEN];
        let masked = [0xABu8; MASKED_SD_LEN];
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
        let frame = TborSdResealBackupReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .sealing_key_handle(KeyId(0x5678))
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
            .pok_remote_backup(&masked)
            .unwrap()
            .finish();
        assert_eq!(frame.policy().len(), PART_POLICY_LEN);
        assert_eq!(frame.pok_remote_backup().len(), MASKED_SD_LEN);
    }

    #[test]
    fn response_round_trips_pok_remote_backup() {
        let masked = [0xABu8; MASKED_SD_LEN];
        let mut buf = [0u8; 512];
        let frame = TborSdResealBackupResp::encode(&mut buf, 0, true)
            .unwrap()
            .pok_remote_backup(&masked)
            .unwrap()
            .finish();
        assert_eq!(frame.pok_remote_backup().len(), MASKED_SD_LEN);
    }
}
