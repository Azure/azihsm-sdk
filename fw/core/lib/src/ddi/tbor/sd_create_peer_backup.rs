// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdCreatePeerBackup` handler.
//!
//! Creates a **peer-transferable** backup of a security domain (manticore
//! §3.3.10): it recovers BKS3 from the caller's device-local backup
//! (`pok_local_backup`) and HPKE-Auth-seals it to a destination peer —
//! named by `dst_evidence` and authenticated by the sender's own masked
//! SD-sealing key — returning the peer backup (`pok_peer_backup`).
//!
//! It is **[`SdCreateRemoteBackup`](super::sd_create_remote_backup)'s
//! HPKE-Auth-seal front-end over a recovered (not freshly minted) BKS3**,
//! sharing [`recover_bks3_from_pok_local`](super::sd_backup::recover_bks3_from_pok_local)
//! with the local restore.  Peer cloning is gated by the security domain's
//! `allow_peer_cloning` policy flag.
//!
//! Flow:
//!
//! 1. Decode; gate to a Crypto-Officer, `Active` session on an
//!    `Initialized` partition (`PartLocalMK` and the policy hash are bound
//!    by `PartFinal`).  Unlike the restores this is **not** one-shot and
//!    does not touch `SDMK`, so it neither requires nor sets the
//!    SD-initialized flag — a rebooted partition can clone to a peer after
//!    `PartFinal` without first restoring the SD locally.
//! 2. Bind the caller-supplied [`PartPolicy`] to the partition's fixed
//!    `policy_hash`, require its `allow_peer_cloning` flag
//!    ([`SdPeerCloningNotAllowed`](HsmError::SdPeerCloningNotAllowed)), then
//!    verify the **destination** peer evidence against it: its cert chains
//!    are validated and anchored to the policy SATA key, its report's v2
//!    `policy_hash` must equal `SHA-384(policy)`, and its attested COSE_Key
//!    is recovered as `RcvrPub`.
//! 3. Unmask `masked_sealing_key` → `SndrPriv` (must be an
//!    [`SdSealing`](HsmVaultKeyKind::SdSealing) key) and derive `SndrPub`.
//! 4. Recover BKS3 from `pok_local_backup` under `PartLocalMK` (shared
//!    [`recover_bks3_from_pok_local`](super::sd_backup::recover_bks3_from_pok_local)).
//! 5. HPKE-Auth-seal BKS3 to `RcvrPub` with `SndrPriv` as the
//!    sender-authentication key, returning `pok_peer_backup` (161 B).
//!    `SndrPriv` and BKS3 are zeroized before returning.
//!
//! **Stateless:** nothing is persisted, no vault writes, no undo log.  This
//! command is **Crypto-Officer-only**.
//!
//! [`PartPolicy`]: super::policy

use azihsm_fw_core_crypto_hpke::seal;
use azihsm_fw_core_crypto_hpke::AuthParams;
use azihsm_fw_core_crypto_hpke::HpkeSealConfig;
use azihsm_fw_core_crypto_hpke::HpkeSuite;
use azihsm_fw_core_crypto_key_masking::aead::peek_metadata;
use azihsm_fw_core_crypto_key_masking::aead::unmask;
use azihsm_fw_core_crypto_key_report::POLICY_HASH_LEN;
use azihsm_fw_core_evidence::verify_evidence;
use azihsm_fw_core_evidence::EvidenceRefs;
use azihsm_fw_core_evidence::TrustAnchors;
use azihsm_fw_ddi_tbor_types::policy::PolicyKeyKind;
use azihsm_fw_ddi_tbor_types::policy::POLICY_MAX_KEY_LEN;
use azihsm_fw_ddi_tbor_types::TborSdCreatePeerBackupReq;
use azihsm_fw_ddi_tbor_types::TborSdCreatePeerBackupResp;
use azihsm_fw_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_fw_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use azihsm_fw_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use azihsm_fw_hsm_oob::OobPtr;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::PartState;

use super::masking_key_id_for_scope;
use super::part_final::verify_policy_hash;
use super::sd_backup;
use super::validate_crypto_officer_active_session;
use crate::part_state;

/// NIST curve for the SD sealing keys and the peer-backup HPKE seal.
const SD_CURVE: HsmEccCurve = HsmEccCurve::P384;

/// HPKE ciphersuite for the peer-backup seal.
const HPKE_SUITE: HpkeSuite = HpkeSuite::DHKemP384Sha384AesGcm256;

/// Length of the BKS3 sealed into the peer backup.
const BKS3_LEN: usize = 48;

/// SEC1 uncompressed point tag (`0x04 ‖ X ‖ Y`).
const SEC1_UNCOMPRESSED: u8 = 0x04;

/// Handle a TBOR `SdCreatePeerBackup` request.
///
/// **Stateless**: recovers BKS3 from the caller's local backup and re-seals
/// it to the destination peer; no vault writes, no partition-state
/// mutation, no undo log.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
    oob: Option<OobPtr>,
) -> HsmResult<&'p DmaBuf> {
    let mk_key_id = gate_request(pal, io, req_buf)?;

    // The destination attestation evidence is mandatory side-band data
    // carried in the out-of-band SGL page.
    let oob = oob.ok_or(HsmError::InvalidArg)?;

    // Allocate the fixed-size peer-backup response in the IO scope so it
    // survives the crypto scratch allocator's reset.
    let pok_peer_out = pal.dma_alloc(io, POK_REMOTE_BACKUP_LEN)?;

    pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
        let coord = SD_CURVE.priv_key_len();
        let (svn, _owner) = sd_backup::platform_svn_owner(pal)?;

        // `pk_r` (the attested `RcvrPub`) is recovered by the evidence check
        // in phase 1 and consumed by the seal in phase 2.
        let pk_r = alloc.dma_alloc(1 + 2 * coord)?;

        // ── Phase 1: policy binding + peer-cloning gate + receiver evidence ──
        {
            let req = TborSdCreatePeerBackupReq::decode(&*req_buf)?;
            let policy = req.policy();

            // The re-supplied policy must match the one bound at `PartInit`.
            verify_policy_hash(pal, io, alloc, policy).await?;
            let part_policy = super::policy::from_bytes(policy)?;

            // Peer cloning is gated by the (now authenticated) SD policy.
            if !part_policy.flags.allow_peer_cloning() {
                return Err(HsmError::SdPeerCloningNotAllowed);
            }

            let sata = &part_policy.sata_pub_key;
            if sata.kind() != PolicyKeyKind::Ecc384 || sata.len() != POLICY_MAX_KEY_LEN {
                return Err(HsmError::InvalidArg);
            }

            // The destination peer's report must attest to the same policy.
            let expected = alloc.dma_alloc(POLICY_HASH_LEN)?;
            pal.hash(io, HsmHashAlgo::Sha384, policy, expected, true)
                .await?;

            let dst_hash = alloc.dma_alloc(POLICY_HASH_LEN)?;
            {
                let ev = req.dst_evidence();
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
                    pk_r,
                    Some(dst_hash),
                )
                .await?;
            }
            if dst_hash[..POLICY_HASH_LEN] != expected[..POLICY_HASH_LEN] {
                return Err(HsmError::InvalidArg);
            }
        }

        // ── Phase 2: recover SndrPriv + BKS3, then HPKE-Auth-seal the BKS3
        // to RcvrPub.  The masked sealing key and the local backup are
        // copied into crypto scratch so the request-buffer borrow is
        // confined; every recovered secret is scrubbed on EVERY exit path
        // (scope rewind does not clear DMA).
        let masking_key = pal.vault_key(io, mk_key_id)?;

        let blob = alloc.dma_alloc(MASKED_SEALING_KEY_LEN)?;
        let pok_scratch = alloc.dma_alloc(MASKED_SD_LEN)?;
        {
            let req = TborSdCreatePeerBackupReq::decode(&*req_buf)?;
            blob.copy_from_slice(req.masked_sealing_key());
            pok_scratch.copy_from_slice(req.pok_local_backup());
        }

        // Unmask into `blob`, copy the recovered private key out into its
        // own scratch, then scrub `blob` immediately.
        let unmask_res = async {
            let view = unmask(pal, io, masking_key, blob).await?;
            let sndr_priv = alloc.dma_alloc(view.target_key.len())?;
            sndr_priv.copy_from_slice(view.target_key);
            Ok::<_, HsmError>((view.key_kind, sndr_priv))
        }
        .await;
        blob.zeroize();
        let (key_kind, sndr_priv) = unmask_res?;

        let crypto_res = async {
            if !matches!(key_kind, HsmVaultKeyKind::SdSealing) {
                return Err(HsmError::UnsupportedKeyType);
            }

            // Sender public key (`SndrPub`) in SEC1 BE, derived on-device
            // from the recovered private key.
            let pk_s = alloc.dma_alloc(1 + 2 * coord)?;
            pal.ecc_pub_from_priv(io, SD_CURVE, sndr_priv, &mut pk_s[1..1 + 2 * coord])
                .await?;
            pk_s[0] = SEC1_UNCOMPRESSED;
            pk_s[1..1 + coord].reverse();
            pk_s[1 + coord..1 + 2 * coord].reverse();

            // Recover BKS3 from the caller's local backup (unmask under
            // `PartLocalMK`), copy it out, then scrub the staging buffer.
            // `recover_bks3_from_pok_local` validates the recovered length is
            // `BKS3_LEN`, so the copy below cannot mismatch.
            let bks3 = alloc.dma_alloc(BKS3_LEN)?;
            let recover_res = async {
                let recovered =
                    sd_backup::recover_bks3_from_pok_local(pal, io, svn, pok_scratch).await?;
                bks3.copy_from_slice(recovered);
                Ok::<_, HsmError>(())
            }
            .await;
            pok_scratch.zeroize();
            recover_res?;

            // ── HPKE-Auth-seal the recovered BKS3 to RcvrPub ───────────
            let cfg = HpkeSealConfig::auth(
                HPKE_SUITE,
                pk_r,
                &[],
                &[],
                AuthParams {
                    sk_s: sndr_priv,
                    pk_s,
                },
            );
            let seal_res = async {
                // Size query, then split the peer-backup response buffer into
                // the `enc` and `ct` regions the seal writes.
                let sizes = seal(pal, io, &cfg, bks3, None, None, alloc).await?;
                if sizes.enc_len + sizes.ct_len != POK_REMOTE_BACKUP_LEN {
                    return Err(HsmError::InternalError);
                }
                let (enc, ct) = pok_peer_out.split_at_mut(sizes.enc_len);
                seal(pal, io, &cfg, bks3, Some(enc), Some(ct), alloc).await?;
                Ok::<_, HsmError>(())
            }
            .await;
            bks3.zeroize();
            seal_res
        }
        .await;

        // Scrub the recovered sender private key on every path.
        sndr_priv.zeroize();
        crypto_res?;

        Ok(())
    })
    .await?;

    encode_response(pal, io, pok_peer_out)
}

/// Gate the initial session/state checks and resolve the masking-key ID for
/// the caller-supplied `masked_sealing_key`.
///
/// Validates that the session is an active Crypto-Officer session and that
/// the partition is `Initialized` (so `PartLocalMK` and the policy hash are
/// available), then routes the masked sealing key to its masking key.
/// Unlike the create/restore provisioning commands, this is **not**
/// one-shot: it neither requires nor sets the SD-initialized flag.
fn gate_request<P: HsmPal>(pal: &P, io: &impl HsmIo, req_buf: &DmaBuf) -> HsmResult<HsmKeyId> {
    let req = TborSdCreatePeerBackupReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));
    validate_crypto_officer_active_session(pal, io, sess_id)?;

    // `PartLocalMK` and the policy hash are provisioned by `PartFinal`, so
    // the partition must be finalized (`Initialized`).
    if part_state::part_state(pal, io)? != PartState::Initialized {
        return Err(HsmError::InvalidArg);
    }

    // Route the masked sealing key to its masking key via the cleartext,
    // tag-bound metadata (before unmasking).
    let scope = peek_metadata(req.masked_sealing_key())?
        .usage_flags()
        .scope();
    masking_key_id_for_scope(pal, io, scope)
}

/// Encode the `SdCreatePeerBackup` response around the peer backup.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    pok_peer: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborSdCreatePeerBackupResp::encode(buf, 0, false)?
            .pok_peer_backup(pok_peer)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
