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
//! * `masked_sealing_key` — the sender's masked SD-sealing key (the
//!   `masked_key` returned by
//!   [`SdSealingKeyGen`](crate::sd_sealing_key_gen)), exactly
//!   [`MASKED_SEALING_KEY_LEN`] (180 B).  Unmasked on-device to recover
//!   the sender's private ECDH key (`SndrPriv`); never a vault handle.
//! * `receiver_evidence` — receiver side-band attestation evidence
//!   ([`Evidence`](crate::evidence::Evidence) field group: manufacturer /
//!   owner / partition-owner certificate-chain descriptors plus the
//!   attestation-report descriptor).  The report descriptor indexes the
//!   receiver's `KeyReport` in the out-of-band SGL page; its COSE_Key
//!   supplies the recipient public key (`RcvrPub`).
//! * `policy` — the unified [`PartPolicy`] describing the security domain
//!   to create.  Length pinned to [`PART_POLICY_LEN`] (484 B).
//!
//! Output:
//!
//! * `pok_remote_backup` — the remote partition-owner-key backup: an
//!   **HPKE-Auth seal** of the fresh 48-byte BKS3 to `RcvrPub` with
//!   `SndrPriv` as the sender-authentication key, exactly
//!   [`POK_REMOTE_BACKUP_LEN`] (161 B) = `enc(97) ‖ ct(64)` under the
//!   `DHKemP384Sha384AesGcm256` suite.
//! * `pok_local_backup` — the local partition-owner-key backup: the same
//!   fresh BKS3 masked under the partition-local masking key
//!   (`PartLocalMK`), exactly [`MASKED_SD_LEN`] (180 B).  Persisted by
//!   the host and replayed to recover the security domain locally.
//! * `sd_mk_backup` — the security-domain masking-key backup: the freshly
//!   minted `SDMK` masked under the derived `SDBMK`, exactly
//!   [`LOCAL_MK_BACKUP_LEN`] (164 B).  Persisted by the host and replayed
//!   on restore.

use azihsm_fw_ddi_tbor_api::tbor;

use crate::evidence::*;
pub use crate::part_final::LOCAL_MK_BACKUP_LEN;
pub use crate::policy::PART_POLICY_LEN;
pub use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;

/// TBOR opcode for `SdCreateRemoteBackup`.
pub const TBOR_OP_SD_CREATE_REMOTE_BACKUP: u8 = 0x0A;

// `policy` carries the unified `PartPolicy`; the derive needs an integer
// literal on the field, so the length is spelled out as `484` and pinned
// against the canonical value here.
const _: () = assert!(PART_POLICY_LEN == 484);

// `masked_sealing_key` is spelled out as `180` on the field (the derive
// needs an integer literal) and pinned against the canonical
// `MASKED_SEALING_KEY_LEN` here.
const _: () = assert!(MASKED_SEALING_KEY_LEN == 180);

/// Exact on-the-wire length of a **masked** security-domain blob (a
/// masked BKS3): an AEAD-GCM-256 masked-key envelope
/// (`header(8) ‖ iv(12) ‖ aad(96) ‖ pt(48) ‖ tag(16)`) whose plaintext
/// is the 48-byte BKS3 and whose AAD is the 96-byte `MaskedKeyMetadata`.
///
/// Retained here as the shared length authority for the rest of the
/// Security-Domain backup family (`SdReseal`, `SdRestore*`,
/// `SdCreatePeerBackup`), which re-export it.  **This command's**
/// response is an HPKE-Auth seal sized by [`POK_REMOTE_BACKUP_LEN`], not
/// a masked blob.
pub const MASKED_SD_LEN: usize = 8 + 12 + 96 + 48 + 16;
const _: () = assert!(MASKED_SD_LEN == 180);

/// Exact on-the-wire length of the remote partition-owner-key backup.
///
/// An HPKE-Auth seal under `DHKemP384Sha384AesGcm256`: the encapsulated
/// key `enc` (P-384 SEC1 uncompressed, 97 B) followed by the AEAD
/// ciphertext `ct` over the 48-byte BKS3 plus the 16-byte GCM tag
/// (`48 + 16 = 64`).
pub const POK_REMOTE_BACKUP_LEN: usize = 97 + (48 + 16);
const _: () = assert!(POK_REMOTE_BACKUP_LEN == 161);

/// Exact on-the-wire length of the **SD masking-key backup** envelope
/// (`sd_mk_backup`): the 32-byte SD masking key (`SDMK`) wrapped as a
/// `local_mk`-style AEAD-GCM-256 masked-key envelope.  Equal to
/// [`LOCAL_MK_BACKUP_LEN`] because both wrap a 32-byte key in the same
/// envelope format, but named SD-specifically — and re-exported by the
/// rest of the SD backup family — so the intent is explicit at each sizing
/// site and the two can diverge without silent copy/paste breakage.
pub const SD_MK_BACKUP_LEN: usize = LOCAL_MK_BACKUP_LEN;
const _: () = assert!(SD_MK_BACKUP_LEN == 164);

/// `SdCreateRemoteBackup` request schema.
#[tbor(opcode = 0x0A)]
pub struct TborSdCreateRemoteBackupReq<'a> {
    /// CO session id this request is bound to.  Typed
    /// [`SessionId`](azihsm_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The sender's masked SD-sealing key (from `SdSealingKeyGen`),
    /// exactly [`MASKED_SEALING_KEY_LEN`] (180 B).  Unmasked on-device to
    /// recover `SndrPriv`.
    ///
    /// Marked `#[tbor(mutable)]` so the FW handler can AEAD-open (unmask)
    /// the blob **in place** in the request buffer via
    /// [`decode_mut`](TborSdCreateRemoteBackupReq::decode_mut), avoiding a
    /// scratch copy.  The `#[tbor(include)]` evidence group that follows is
    /// omitted from the generated `ViewMut` (its accessors remain on the
    /// shared [`decode`](TborSdCreateRemoteBackupReq::decode) view), so the
    /// handler reads evidence via `decode` and unmasks via `decode_mut`.
    #[tbor(buffer, len = 180, mutable)]
    pub masked_sealing_key: &'a [u8],

    /// Side-band attestation evidence (manufacturer / owner /
    /// partition-owner certificate-chain descriptors plus the attestation
    /// report descriptor).  Spliced in as the
    /// [`Evidence`](crate::evidence::Evidence) field group's four TOC
    /// entries.
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
    /// Remote partition-owner-key backup (an HPKE-Auth seal of BKS3).
    /// Always exactly [`POK_REMOTE_BACKUP_LEN`] (161 B).
    #[tbor(buffer, len = 161)]
    pub pok_remote_backup: &'a [u8],

    /// Local partition-owner-key backup: the fresh BKS3 masked under the
    /// partition-local masking key (`PartLocalMK`), to be persisted by
    /// the host and replayed to recover the security domain locally.
    /// Always exactly [`MASKED_SD_LEN`] (180 B).
    #[tbor(buffer, len = 180)]
    pub pok_local_backup: &'a [u8],

    /// Security-domain masking-key backup: the freshly minted `SDMK`
    /// masked under the derived `SDBMK`, to be persisted by the host and
    /// replayed on restore.  Always exactly [`LOCAL_MK_BACKUP_LEN`]
    /// (164 B).
    #[tbor(buffer, len = 164)]
    pub sd_mk_backup: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn pok_remote_backup_len_matches_hpke_auth_seal() {
        // enc(97) + ct(BKS3 48 + GCM tag 16 = 64).
        const _: () = assert!(POK_REMOTE_BACKUP_LEN == 161);
        assert_eq!(POK_REMOTE_BACKUP_LEN, 161);
    }

    #[test]
    fn request_round_trips_masked_key_and_policy() {
        let masked = [0u8; MASKED_SEALING_KEY_LEN];
        let policy = [0u8; PART_POLICY_LEN];
        let cert = CertDescriptor {
            index: 0,
            length: crate::tbor_int::U16::new(8),
        };
        let report = ReportDescriptor {
            index: 8,
            length: crate::tbor_int::U16::new(16),
        };
        let chain = [cert];
        let mut buf = [0u8; 1024];
        let frame = TborSdCreateRemoteBackupReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .masked_sealing_key(&masked)
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
        assert_eq!(frame.masked_sealing_key().len(), MASKED_SEALING_KEY_LEN);
        assert_eq!(frame.policy().len(), PART_POLICY_LEN);
    }

    #[test]
    fn response_round_trips_backups() {
        let remote = [0xABu8; POK_REMOTE_BACKUP_LEN];
        let local = [0xCDu8; MASKED_SD_LEN];
        let sd_mk = [0xEFu8; LOCAL_MK_BACKUP_LEN];
        let mut buf = [0u8; 1024];
        let frame = TborSdCreateRemoteBackupResp::encode(&mut buf, 0, true)
            .unwrap()
            .pok_remote_backup(&remote)
            .unwrap()
            .pok_local_backup(&local)
            .unwrap()
            .sd_mk_backup(&sd_mk)
            .unwrap()
            .finish();
        assert_eq!(frame.pok_remote_backup().len(), POK_REMOTE_BACKUP_LEN);
        assert_eq!(frame.pok_local_backup().len(), MASKED_SD_LEN);
        assert_eq!(frame.sd_mk_backup().len(), LOCAL_MK_BACKUP_LEN);
    }
}
