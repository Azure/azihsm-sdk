// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdRestoreRemoteBackup` handler.
//!
//! Restores a security domain from a **remote** backup (manticore §3.3.8):
//! it HPKE-Auth-opens the caller-supplied `src_remote_backup` (an HPKE seal
//! of BKS3) with the receiver's masked SD-sealing key — authenticated by
//! the sender's attested key — recovers `SDMK` from `prev_sd_mk_backup`,
//! and returns the device-local backups so the security domain can later be
//! restored locally without the sender.
//!
//! It is **reseal's open front-end + the shared SD provisioning back-end**:
//! the open half mirrors [`SdResealRemoteBackup`](super::sd_reseal_remote_backup),
//! and the provisioning half is shared with
//! [`SdRestoreLocalBackup`](super::sd_restore_local_backup) via
//! [`sd_backup::reprovision_sd_from_bks3`](super::sd_backup::reprovision_sd_from_bks3).
//!
//! Flow:
//!
//! 1. Decode; gate to a Crypto-Officer, `Active` session on an
//!    `Initialized` partition, and fail-fast if the SD is already
//!    initialized ([`SdAlreadyInitialized`](HsmError::SdAlreadyInitialized)).
//! 2. Bind the caller-supplied [`PartPolicy`] to the partition's fixed
//!    `policy_hash`, then verify the **sender** evidence against it: its
//!    cert chains are validated and anchored to the policy SATA key, its
//!    report's v2 `policy_hash` must equal `SHA-384(policy)`, and its
//!    attested COSE_Key is recovered as `SndrPub`.
//! 3. Unmask `masked_sealing_key` → `RcvrPriv` (must be an
//!    [`SdSealing`](HsmVaultKeyKind::SdSealing) key) and derive `RcvrPub`.
//! 4. HPKE-Auth-open `src_remote_backup` (`sk_r = RcvrPriv`, sender-auth
//!    `SndrPub`) → **BKS3**.
//! 5. Recover `SDMK` from `prev_sd_mk_backup`, re-mask both backups, vault
//!    `SDMK`, and mark the partition SD-initialized — undo-guarded (shared
//!    [`reprovision_sd_from_bks3`](super::sd_backup::reprovision_sd_from_bks3)).
//!    `RcvrPriv`, BKS3, SDMK, and SDBMK are zeroized before returning.
//!
//! **Stateful & one-shot** (parity with the other SD-provisioning
//! commands).  This command is **Crypto-Officer-only**.
//!
//! [`PartPolicy`]: super::policy

use azihsm_fw_core_crypto_hpke::open;
use azihsm_fw_core_crypto_hpke::HpkeOpenConfig;
use azihsm_fw_core_crypto_hpke::HpkeSuite;
use azihsm_fw_core_crypto_key_masking::aead::peek_metadata;
use azihsm_fw_core_crypto_key_masking::aead::unmask;
use azihsm_fw_core_crypto_key_report::POLICY_HASH_LEN;
use azihsm_fw_core_evidence::verify_evidence;
use azihsm_fw_core_evidence::EvidenceRefs;
use azihsm_fw_core_evidence::TrustAnchors;
use azihsm_fw_core_evidence::ATTESTED_KEY_LEN;
use azihsm_fw_ddi_tbor_types::policy::PolicyKeyKind;
use azihsm_fw_ddi_tbor_types::policy::POLICY_MAX_KEY_LEN;
use azihsm_fw_ddi_tbor_types::TborSdRestoreRemoteBackupReq;
use azihsm_fw_ddi_tbor_types::TborSdRestoreRemoteBackupResp;
use azihsm_fw_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_fw_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use azihsm_fw_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use azihsm_fw_ddi_tbor_types::SD_MK_BACKUP_LEN;
use azihsm_fw_hsm_oob::OobPtr;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::PartState;
use azihsm_fw_hsm_undo::UndoLog;

use super::masking_key_id_for_scope;
use super::part_final::verify_policy_hash;
use super::sd_backup;
use super::validate_crypto_officer_active_session;
use crate::part_state;

/// NIST curve for the SD sealing keys and the remote-backup HPKE seal.
const SD_CURVE: HsmEccCurve = HsmEccCurve::P384;

/// HPKE ciphersuite for the remote-backup seal.
const HPKE_SUITE: HpkeSuite = HpkeSuite::DHKemP384Sha384AesGcm256;

/// Length of the BKS3 carried inside the remote backup.
const BKS3_LEN: usize = 48;

/// SEC1 uncompressed point tag (`0x04 ‖ X ‖ Y`).
const SEC1_UNCOMPRESSED: u8 = 0x04;

/// Length of the HPKE encapsulated key `enc` (P-384 SEC1 uncompressed).
const SD_ENC_LEN: usize = 1 + 2 * 48;

// A remote backup is `enc(97) ‖ ct(BKS3 48 + GCM tag 16 = 64)` = 161 B.
const _: () = assert!(SD_ENC_LEN + (BKS3_LEN + 16) == POK_REMOTE_BACKUP_LEN);

/// Handle a TBOR `SdRestoreRemoteBackup` request.
///
/// **Stateful**: re-provisions the security-domain masking key (`SDMK`) in
/// the vault and marks the partition security-domain-initialized, guarded
/// by the per-command `undo` log.  The one-shot `SD_INITIALIZED` claim is
/// the race-winner gate against a concurrently-dispatched create/restore.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
    oob: Option<OobPtr>,
    undo: &mut UndoLog<'p>,
) -> HsmResult<&'p DmaBuf> {
    // Session/state gating + masking-key routing use only the shared
    // `decode` view.  `mk_key_id` is `Copy`, so it outlives the view.
    let mk_key_id = {
        let req = TborSdRestoreRemoteBackupReq::decode(&*req_buf)?;
        let sess_id = HsmSessId::from(u16::from(req.session_id()));
        validate_crypto_officer_active_session(pal, io, sess_id)?;

        // The SD masking keys / policy hash are provisioned by `PartFinal`,
        // so the partition must be finalized (`Initialized`).
        if part_state::part_state(pal, io)? != PartState::Initialized {
            return Err(HsmError::InvalidArg);
        }

        // Fail-fast: a restore onto an already-initialized security domain
        // is rejected.  The atomic `SD_INITIALIZED` claim in the commit
        // phase is the authoritative race-winner gate.
        if part_state::part_is_sd_initialized(pal, io)? {
            return Err(HsmError::SdAlreadyInitialized);
        }

        // Route the masked receiver key to its masking key via the
        // cleartext, tag-bound metadata (before unmasking).
        let scope = peek_metadata(req.masked_sealing_key())?
            .usage_flags()
            .scope();
        masking_key_id_for_scope(pal, io, scope)?
    };

    // The sender attestation evidence is mandatory side-band data carried
    // in the out-of-band SGL page.
    let oob = oob.ok_or(HsmError::InvalidArg)?;

    // Allocate the two fixed-size response backups in the IO scope so they
    // survive the crypto scratch allocator's reset.
    let pok_local_out = pal.dma_alloc(io, MASKED_SD_LEN)?;
    let sd_mk_out = pal.dma_alloc(io, SD_MK_BACKUP_LEN)?;

    pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
        let coord = SD_CURVE.priv_key_len();
        let (svn, owner) = sd_backup::platform_svn_owner(pal)?;

        // `pk_sndr` (the attested `SndrPub`) is recovered by the evidence
        // check in phase 1 and consumed by the HPKE open in phase 2.
        let pk_sndr = alloc.dma_alloc(ATTESTED_KEY_LEN)?;

        // ── Phase 1: policy binding + sender evidence (shared view) ──
        {
            let req = TborSdRestoreRemoteBackupReq::decode(&*req_buf)?;
            let policy = req.policy();

            // The re-supplied policy must match the one bound at `PartInit`.
            verify_policy_hash(pal, io, alloc, policy).await?;
            let part_policy = super::policy::from_bytes(policy)?;
            let sata = &part_policy.sata_pub_key;
            if sata.kind() != PolicyKeyKind::Ecc384 || sata.len() != POLICY_MAX_KEY_LEN {
                return Err(HsmError::InvalidArg);
            }

            // The sender's report must attest to the same policy.
            let expected = alloc.dma_alloc(POLICY_HASH_LEN)?;
            pal.hash(io, HsmHashAlgo::Sha384, policy, expected, true)
                .await?;

            let src_hash = alloc.dma_alloc(POLICY_HASH_LEN)?;
            {
                let ev = req.sender_evidence();
                verify_evidence(
                    pal,
                    io,
                    &oob,
                    &EvidenceRefs {
                        mfgr_chain: ev.mfgr_cert_chain(),
                        owner_chain: ev.owner_cert_chain(),
                        part_owner_chain: ev.part_owner_cert_chain(),
                        report: ev.evidence(),
                    },
                    &TrustAnchors {
                        sata: &sata.data[..POLICY_MAX_KEY_LEN],
                    },
                    pk_sndr,
                    Some(src_hash),
                )
                .await?;
            }
            if src_hash[..POLICY_HASH_LEN] != expected[..POLICY_HASH_LEN] {
                return Err(HsmError::InvalidArg);
            }
        }

        // ── Phase 2: recover RcvrPriv, HPKE-open the source backup, and
        // re-provision the SD.  The masked key, source backup, and previous
        // masking-key backup are copied into crypto scratch so the
        // request-buffer borrow is confined; every recovered secret is
        // scrubbed on EVERY exit path (scope rewind does not clear DMA).
        let masking_key = pal.vault_key(io, mk_key_id)?;

        let blob = alloc.dma_alloc(MASKED_SEALING_KEY_LEN)?;
        let src_backup = alloc.dma_alloc(POK_REMOTE_BACKUP_LEN)?;
        let prev_sd_mk = alloc.dma_alloc(SD_MK_BACKUP_LEN)?;
        {
            let req = TborSdRestoreRemoteBackupReq::decode(&*req_buf)?;
            blob.copy_from_slice(req.masked_sealing_key());
            src_backup.copy_from_slice(req.src_remote_backup());
            prev_sd_mk.copy_from_slice(req.prev_sd_mk_backup());
        }

        // Unmask into `blob`, copy the recovered private key out into its
        // own scratch, then scrub `blob` immediately.
        let unmask_res = async {
            let view = unmask(pal, io, masking_key, blob).await?;
            let rcvr_priv = alloc.dma_alloc(view.target_key.len())?;
            rcvr_priv.copy_from_slice(view.target_key);
            Ok::<_, HsmError>((view.key_kind, rcvr_priv))
        }
        .await;
        blob.zeroize();
        let (key_kind, rcvr_priv) = unmask_res?;

        let crypto_res = async {
            if !matches!(key_kind, HsmVaultKeyKind::SdSealing) {
                return Err(HsmError::UnsupportedKeyType);
            }

            // Receiver public key (`RcvrPub`) in SEC1 BE, derived on-device
            // from the recovered private key.
            let pk_r = alloc.dma_alloc(1 + 2 * coord)?;
            pal.ecc_pub_from_priv(io, SD_CURVE, rcvr_priv, &mut pk_r[1..1 + 2 * coord])
                .await?;
            pk_r[0] = SEC1_UNCOMPRESSED;
            pk_r[1..1 + coord].reverse();
            pk_r[1 + coord..1 + 2 * coord].reverse();

            // HPKE `open` needs a plaintext buffer at least the ciphertext
            // length (`ct` = BKS3 + GCM tag = 64 B); the recovered BKS3
            // occupies its first `BKS3_LEN` bytes.  Both hold secret
            // material and are scrubbed on all paths.
            let pt_buf = alloc.dma_alloc(POK_REMOTE_BACKUP_LEN - SD_ENC_LEN)?;
            let bks3 = alloc.dma_alloc(BKS3_LEN)?;
            let inner = async {
                // ── Open the source backup with RcvrPriv, authenticated by
                // the sender key (`SndrPub`).
                let (enc, ct) = src_backup.split_at(SD_ENC_LEN);
                let open_cfg = HpkeOpenConfig::auth(HPKE_SUITE, rcvr_priv, pk_r, &[], &[], pk_sndr);
                let pt_len =
                    open(pal, io, &open_cfg, enc, ct, Some(&mut pt_buf[..]), alloc).await?;
                if pt_len != BKS3_LEN {
                    return Err(HsmError::InvalidArg);
                }
                bks3.copy_from_slice(&pt_buf[..BKS3_LEN]);

                // ── Recover SDMK, re-mask both backups, and commit the SD
                // to the vault (shared with the local restore).
                sd_backup::reprovision_sd_from_bks3(
                    pal,
                    io,
                    alloc,
                    undo,
                    svn,
                    owner,
                    bks3,
                    prev_sd_mk,
                    pok_local_out,
                    sd_mk_out,
                )
                .await
            }
            .await;

            bks3.zeroize();
            pt_buf.zeroize();
            prev_sd_mk.zeroize();
            inner
        }
        .await;

        // Scrub the recovered receiver private key on every path.
        rcvr_priv.zeroize();
        crypto_res?;

        Ok(())
    })
    .await?;

    encode_response(pal, io, pok_local_out, sd_mk_out)
}

/// Encode the `SdRestoreRemoteBackup` response around the local backups.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    pok_local: &DmaBuf,
    sd_mk: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborSdRestoreRemoteBackupResp::encode(buf, 0, false)?
            .pok_local_backup(pok_local)?
            .sd_mk_backup(sd_mk)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
