// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdResealRemoteBackup` handler.
//!
//! Reseals a security-domain **remote backup** from a source recipient to
//! a destination recipient (manticore §3.3.7 Reseal), run by a Sealing
//! Authority.  The caller-supplied `src_remote_backup` is HPKE-Auth-opened
//! with the masked receiver key (recovering the 48-byte BKS3), then
//! HPKE-Auth-sealed to the destination receiver, returning
//! `dst_remote_backup`.  The same receiver private key is used both to
//! open the source and to authenticate the reseal ("for simplicity, the
//! same HPKE private key" — manticore).
//!
//! Flow:
//!
//! 1. Decode the request; gate to a Crypto-Officer, `Active` session on an
//!    `Initialized` partition (parity with the other SD commands).
//! 2. Verify **both** attestation evidences against the **request** policy
//!    (not the local one): each of the source-sender and destination-
//!    receiver evidence's three certificate chains is validated and
//!    anchored to the request policy's SATA key, and each report's v2
//!    `policy_hash` must equal `SHA-384(policy)`.  This binds both sides to
//!    the same policy (whose digest covers the POTA key).  The attested
//!    COSE_Keys are recovered as `SndrPub` (source sender) and `DstRcvrPub`
//!    (destination receiver).
//! 3. Unmask the `masked_sealing_key` to recover the receiver private key
//!    `RcvrPriv` (must be an [`SdSealing`](HsmVaultKeyKind::SdSealing) key)
//!    and derive `RcvrPub` on-device.
//! 4. HPKE-Auth-open `src_remote_backup` (`sk_r = RcvrPriv`, sender
//!    auth-key `SndrPub`) to recover the BKS3.
//! 5. HPKE-Auth-seal the recovered BKS3 to `DstRcvrPub` with `RcvrPriv` as
//!    the sender-authentication key, returning `dst_remote_backup`
//!    (161 B).  BKS3 and the recovered `RcvrPriv` are zeroized before
//!    returning.
//!
//! **Stateless:** nothing is persisted, no vault writes, no undo log.
//!
//! This command is **Crypto-Officer-only**.

use azihsm_fw_core_crypto_hpke::open;
use azihsm_fw_core_crypto_hpke::seal;
use azihsm_fw_core_crypto_hpke::AuthParams;
use azihsm_fw_core_crypto_hpke::HpkeOpenConfig;
use azihsm_fw_core_crypto_hpke::HpkeSealConfig;
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
use azihsm_fw_ddi_tbor_types::TborSdResealRemoteBackupReq;
use azihsm_fw_ddi_tbor_types::TborSdResealRemoteBackupResp;
use azihsm_fw_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use azihsm_fw_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
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

use super::masking_key_id_for_scope;
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

/// Handle a TBOR `SdResealRemoteBackup` request.
///
/// No partition lock or undo log is required: the command **persists
/// nothing** — it validates evidence, unmasks the caller-supplied receiver
/// key, HPKE-opens the source backup, and returns a freshly resealed
/// backup.  It makes no observable state change.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
    oob: Option<OobPtr>,
) -> HsmResult<&'p DmaBuf> {
    // Session/state gating + masking-key routing use only the shared
    // `decode` view.  `mk_key_id` is `Copy`, so it outlives the view.
    let mk_key_id = {
        let req = TborSdResealRemoteBackupReq::decode(&*req_buf)?;
        let sess_id = HsmSessId::from(u16::from(req.session_id()));
        validate_crypto_officer_active_session(pal, io, sess_id)?;

        // The SD masking keys are provisioned by `PartFinal`, so the
        // partition must be finalized (`Initialized`).
        if part_state::part_state(pal, io)? != PartState::Initialized {
            return Err(HsmError::InvalidArg);
        }

        // Route the masked receiver key to its masking key via the
        // cleartext, tag-bound metadata (before unmasking).
        let scope = peek_metadata(req.masked_sealing_key())?
            .usage_flags()
            .scope();
        masking_key_id_for_scope(pal, io, scope)?
    };

    // Both attestation evidences are mandatory side-band data carried in
    // the out-of-band SGL page.
    let oob = oob.ok_or(HsmError::InvalidArg)?;

    // Allocate the fixed-size resealed backup in the IO scope so it
    // survives the crypto scratch allocator's reset.
    let pok = pal.dma_alloc(io, POK_REMOTE_BACKUP_LEN)?;

    pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
        let coord = SD_CURVE.priv_key_len();

        // Attested keys recovered in phase 1 and consumed by the crypto in
        // phase 2: `pk_sndr` is the source sender's key (the unseal's
        // sender-auth key); `pk_dst` is the destination receiver's key (the
        // reseal's recipient).
        let pk_sndr = alloc.dma_alloc(ATTESTED_KEY_LEN)?;
        let pk_dst = alloc.dma_alloc(ATTESTED_KEY_LEN)?;

        // ── Phase 1: bind both evidences to the request policy ──────────
        {
            let req = TborSdResealRemoteBackupReq::decode(&*req_buf)?;
            let policy = req.policy();

            // The source and destination must share this policy: each v2
            // report's `policy_hash` must equal its SHA-384 digest.
            let expected = alloc.dma_alloc(POLICY_HASH_LEN)?;
            pal.hash(io, HsmHashAlgo::Sha384, policy, expected, true)
                .await?;

            let part_policy = super::policy::from_bytes(policy)?;
            let sata = &part_policy.sata_pub_key;
            if sata.kind() != PolicyKeyKind::Ecc384 || sata.len() != POLICY_MAX_KEY_LEN {
                return Err(HsmError::InvalidArg);
            }

            // Source **sender** evidence → `SndrPub`; its report's policy
            // digest must match the request policy.
            let src_hash = alloc.dma_alloc(POLICY_HASH_LEN)?;
            {
                let ev = req.src_evidence();
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

            // Destination **receiver** evidence → `DstRcvrPub`; its report's
            // policy digest must match the request policy too (so source and
            // destination provably share it, including the POTA key it
            // embeds).
            let dst_hash = alloc.dma_alloc(POLICY_HASH_LEN)?;
            {
                let ev = req.dest_evidence();
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
                    pk_dst,
                    Some(dst_hash),
                )
                .await?;
            }
            if dst_hash[..POLICY_HASH_LEN] != expected[..POLICY_HASH_LEN] {
                return Err(HsmError::InvalidArg);
            }
        }

        // ── Phase 2: recover RcvrPriv, then HPKE open (source) → seal
        // (destination).  The masked key and source backup are copied into
        // crypto scratch so the request-buffer borrow is confined; the
        // recovered private key and the BKS3 are secret material scrubbed
        // on EVERY exit path (scope rewind does not clear DMA memory).
        let masking_key = pal.vault_key(io, mk_key_id)?;

        let blob = alloc.dma_alloc(MASKED_SEALING_KEY_LEN)?;
        let src_backup = alloc.dma_alloc(POK_REMOTE_BACKUP_LEN)?;
        {
            let req = TborSdResealRemoteBackupReq::decode(&*req_buf)?;
            let msk = req.masked_sealing_key();
            if msk.len() != blob.len() {
                return Err(HsmError::InvalidArg);
            }
            blob.copy_from_slice(msk);
            src_backup.copy_from_slice(req.src_remote_backup());
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
            // from the recovered private key.  The PAL emits wire-LE
            // `X ‖ Y` into the coordinate region; reversing each coordinate
            // in place yields SEC1 `0x04 ‖ X_be ‖ Y_be`.
            let pk_r = alloc.dma_alloc(1 + 2 * coord)?;
            pal.ecc_pub_from_priv(io, SD_CURVE, rcvr_priv, &mut pk_r[1..1 + 2 * coord])
                .await?;
            pk_r[0] = SEC1_UNCOMPRESSED;
            pk_r[1..1 + coord].reverse();
            pk_r[1 + coord..1 + 2 * coord].reverse();

            // HPKE `open` requires a plaintext buffer at least the
            // ciphertext length (`ct` = BKS3 + GCM tag = 64 B); the recovered
            // BKS3 occupies its first `BKS3_LEN` bytes.  Both buffers hold
            // secret material and are scrubbed on all paths.
            let pt_buf = alloc.dma_alloc(POK_REMOTE_BACKUP_LEN - SD_ENC_LEN)?;
            let bks3 = alloc.dma_alloc(BKS3_LEN)?;
            let inner = async {
                // ── Open the source backup with RcvrPriv, authenticated by
                // the source sender key (`SndrPub`).
                let (enc, ct) = src_backup.split_at(SD_ENC_LEN);
                let open_cfg = HpkeOpenConfig::auth(HPKE_SUITE, rcvr_priv, pk_r, &[], &[], pk_sndr);
                let pt_len =
                    open(pal, io, &open_cfg, enc, ct, Some(&mut pt_buf[..]), alloc).await?;
                if pt_len != BKS3_LEN {
                    return Err(HsmError::InvalidArg);
                }
                bks3.copy_from_slice(&pt_buf[..BKS3_LEN]);

                // ── Reseal the BKS3 to the destination receiver
                // (`DstRcvrPub`) with RcvrPriv as the sender-auth key.
                let seal_cfg = HpkeSealConfig::auth(
                    HPKE_SUITE,
                    pk_dst,
                    &[],
                    &[],
                    AuthParams {
                        sk_s: rcvr_priv,
                        pk_s: pk_r,
                    },
                );
                let sizes = seal(pal, io, &seal_cfg, bks3, None, None, alloc).await?;
                if sizes.enc_len + sizes.ct_len != POK_REMOTE_BACKUP_LEN {
                    return Err(HsmError::InternalError);
                }
                let (enc_o, ct_o) = pok.split_at_mut(sizes.enc_len);
                seal(pal, io, &seal_cfg, bks3, Some(enc_o), Some(ct_o), alloc).await?;
                Ok::<(), HsmError>(())
            }
            .await;

            bks3.zeroize();
            pt_buf.zeroize();
            inner
        }
        .await;

        // Scrub the recovered receiver private key on every path.
        rcvr_priv.zeroize();
        crypto_res?;

        Ok(())
    })
    .await?;

    encode_response(pal, io, pok)
}

/// Encode the `SdResealRemoteBackup` response around the resealed backup.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    pok: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborSdResealRemoteBackupResp::encode(buf, 0, false)?
            .dst_remote_backup(pok)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
