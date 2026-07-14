// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdCreateRemoteBackup` handler.
//!
//! Creates a security-domain **remote backup**: a fresh 48-byte BKS3
//! HPKE-Auth-sealed to the *receiver's* SD sealing public key
//! (`RcvrPub`), authenticated by the *sender's* SD sealing private key
//! (`SndrPriv`).  Maps to manticore `CreateSD`, reduced to its remote
//! backup output.
//!
//! Flow:
//!
//! 1. Decode the request; gate to a Crypto-Officer, `Active` session on
//!    an `Initialized` partition (parity with `SdSealingKeyGen` /
//!    `KeyReport`).
//! 2. Bind the caller-supplied [`PartPolicy`] to the one fixed at
//!    `PartInit` (`SHA-384(policy) == policy_hash`), validate it, and
//!    verify it names this partition as the backing partition
//!    (`backup_part_id == PID`, `backup_part_pub_key == PID pubkey`;
//!    the caller populated both from `PartInfo` before `PartInit`).
//! 3. Copy the receiver's `KeyReport` and its supporting certificate
//!    chains from the out-of-band SGL page and validate the attestation
//!    **evidence** via [`verify_evidence`]: the three cert chains
//!    (manufacturer / owner / partition-owner) are verified and the
//!    partition-owner chain is anchored to the policy SATA key; the
//!    attested COSE_Key is then recovered as `RcvrPub`.
//! 4. Unmask the sender's `masked_sealing_key` to recover `SndrPriv`
//!    (must be an [`SdSealing`](HsmVaultKeyKind::SdSealing) key) and
//!    derive `SndrPub` on-device.
//! 5. Generate a fresh BKS3 and HPKE-Auth-seal it to `RcvrPub` under the
//!    `DHKemP384Sha384AesGcm256` suite, returning
//!    `pok_remote_backup = enc ‖ ct` (161 B).  BKS3 and `SndrPriv` are
//!    zeroized before returning.
//!
//! **Stateless:** nothing is persisted, no vault writes, no undo log —
//! the same shape as `KeyReport` / `SdSealingKeyGen`.
//!
//! This command is **Crypto-Officer-only**.
//!
//! [`PartPolicy`]: super::policy

use azihsm_fw_core_crypto_hpke::seal;
use azihsm_fw_core_crypto_hpke::AuthParams;
use azihsm_fw_core_crypto_hpke::HpkeSealConfig;
use azihsm_fw_core_crypto_hpke::HpkeSuite;
use azihsm_fw_core_crypto_key_masking::aead::peek_metadata;
use azihsm_fw_core_crypto_key_masking::aead::unmask;
use azihsm_fw_core_evidence::verify_evidence;
use azihsm_fw_core_evidence::EvidenceRefs;
use azihsm_fw_core_evidence::TrustAnchors;
use azihsm_fw_ddi_tbor_types::policy::PartPolicy;
use azihsm_fw_ddi_tbor_types::policy::PolicyKeyKind;
use azihsm_fw_ddi_tbor_types::policy::POLICY_MAX_KEY_LEN;
use azihsm_fw_ddi_tbor_types::TborSdCreateRemoteBackupReq;
use azihsm_fw_ddi_tbor_types::TborSdCreateRemoteBackupResp;
use azihsm_fw_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use azihsm_fw_hsm_oob::OobPtr;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::PartState;

use super::masking_key_id_for_scope;
use super::part_final::verify_policy_hash;
use super::validate_crypto_officer_active_session;
use crate::part_state;

/// NIST curve for the SD sealing keys and the remote-backup HPKE seal.
const SD_CURVE: HsmEccCurve = HsmEccCurve::P384;

/// HPKE ciphersuite for the remote-backup seal.
const HPKE_SUITE: HpkeSuite = HpkeSuite::DHKemP384Sha384AesGcm256;

/// Length of the fresh BKS3 sealed into the remote backup.
const BKS3_LEN: usize = 48;

/// SEC1 uncompressed point tag (`0x04 ‖ X ‖ Y`).
const SEC1_UNCOMPRESSED: u8 = 0x04;

/// Verify the policy names **this** partition as the backing partition.
///
/// `backup_part_id` must equal the partition PID and `backup_part_pub_key`
/// must equal its PID public key (raw P-384 `X ‖ Y`, 96 B).  Both policy
/// fields were populated by the caller from `PartInfo` before `PartInit`
/// (same `part_state` source), so this is a direct byte comparison — no
/// endianness conversion.
fn verify_backing_partition<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    policy: &PartPolicy,
) -> HsmResult<()> {
    let pid = part_state::part_id(pal, io)?;
    if pid[..] != policy.backup_part_id[..] {
        return Err(HsmError::InvalidArg);
    }

    let key = &policy.backup_part_pub_key;
    if key.kind() != PolicyKeyKind::Ecc384 || key.len() != POLICY_MAX_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }
    let pid_pub = part_state::part_id_pub_key(pal, io)?;
    if pid_pub[..] != key.data[..] {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

/// Handle a TBOR `SdCreateRemoteBackup` request.
///
/// No partition lock or undo log is required: the command **persists
/// nothing** — it validates evidence, unmasks the caller-supplied sealing
/// key, and returns a freshly sealed backup.  It makes no observable state
/// change, so a concurrently-dispatched command (IOs run in a task pool
/// and interleave at await points) can neither observe it half-done nor
/// require its rollback on failure.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
    oob: Option<OobPtr>,
) -> HsmResult<&'p DmaBuf> {
    // Session/state gating + masking-key routing use only the shared
    // `decode` view.  Confine that borrow to this block so the request
    // buffer can be borrowed mutably later to unmask the sealing key in
    // place.  `mk_key_id` is `Copy`, so it outlives the view.
    let mk_key_id = {
        let req = TborSdCreateRemoteBackupReq::decode(&*req_buf)?;
        let sess_id = HsmSessId::from(u16::from(req.session_id()));
        validate_crypto_officer_active_session(pal, io, sess_id)?;

        // The SD masking keys / policy hash are provisioned by `PartFinal`,
        // so the partition must be finalized (`Initialized`).
        if part_state::part_state(pal, io)? != PartState::Initialized {
            return Err(HsmError::InvalidArg);
        }

        // Route the masked sealing key to its masking key via the
        // cleartext, tag-bound metadata (before unmasking).
        let scope = peek_metadata(req.masked_sealing_key())?
            .usage_flags()
            .scope();
        masking_key_id_for_scope(pal, io, scope)?
    };

    // The receiver attestation evidence — three certificate chains
    // (manufacturer / owner / partition-owner) plus a COSE_Sign1 report —
    // is mandatory side-band data carried in the out-of-band SGL page.
    let oob = oob.ok_or(HsmError::InvalidArg)?;

    // Allocate the fixed-size response backup in the IO scope so it
    // survives the crypto scratch allocator's reset.
    let pok = pal.dma_alloc(io, POK_REMOTE_BACKUP_LEN)?;

    pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
        // `pk_r` (the attested `RcvrPub`) is recovered by the evidence
        // check in phase 1 and consumed by the seal in phase 2, so it is
        // allocated up front to span both phases.  `coord` is likewise
        // reused for the `SndrPub` (`pk_s`) buffer below.
        let coord = SD_CURVE.priv_key_len();
        let pk_r = alloc.dma_alloc(1 + 2 * coord)?;

        // ── Phase 1: policy binding + receiver evidence (shared view) ──
        // Everything that reads the `receiver_evidence` field group goes
        // through the shared `decode` view (the group is intentionally
        // absent from `ViewMut`).  The borrow is confined to this block so
        // the sealing key can be unmasked in place afterwards.
        {
            let req = TborSdCreateRemoteBackupReq::decode(&*req_buf)?;

            // The re-supplied policy must match the one bound at `PartInit`.
            let policy = req.policy();
            verify_policy_hash(pal, io, alloc, policy).await?;
            let part_policy = super::policy::from_bytes(policy)?;

            // SD-policy identity binding (manticore `CreateSD` step a): the
            // policy names this partition as the backing partition.  The
            // caller populated `backup_part_id` / `backup_part_pub_key`
            // from `PartInfo` (available in `Initializing`, before
            // `PartInit`), so they must equal this partition's PID and PID
            // public key.
            verify_backing_partition(pal, io, part_policy)?;

            // Validate all three certificate chains, bind the
            // partition-owner chain to the policy SATA anchor, require one
            // shared leaf key across the chains, and confirm that leaf key
            // endorses the attestation report — then recover the attested
            // `RcvrPub` into `pk_r`.
            let sata = &part_policy.sata_pub_key;
            if sata.kind() != PolicyKeyKind::Ecc384 || sata.len() != POLICY_MAX_KEY_LEN {
                return Err(HsmError::InvalidArg);
            }
            let evidence = req.receiver_evidence();
            verify_evidence(
                pal,
                io,
                &oob,
                &EvidenceRefs {
                    mfgr_chain: evidence.mfgr_cert_chain(),
                    owner_chain: evidence.owner_cert_chain(),
                    part_owner_chain: evidence.part_owner_cert_chain(),
                    report: evidence.evidence(),
                },
                &TrustAnchors {
                    sata: &sata.data[..POLICY_MAX_KEY_LEN],
                },
                pk_r,
            )
            .await?;
        }

        // ── Phase 2: unmask SndrPriv in place, derive SndrPub, and
        // HPKE-Auth seal a fresh BKS3 to RcvrPub.  `unmask` decrypts the
        // sealing key in place in the request buffer and BKS3 is fresh
        // secret material; scope rewind does not clear DMA memory, so both
        // are scrubbed on EVERY exit path below.  The crypto runs in an
        // inner scope so `SndrPriv`'s borrow of the request buffer ends
        // before it is re-borrowed mutably to wipe the decrypted region.
        let crypto_res = async {
            let sndr_priv = {
                let req_mut = TborSdCreateRemoteBackupReq::decode_mut(req_buf)?;
                let masking_key = pal.vault_key(io, mk_key_id)?;
                let view = unmask(pal, io, masking_key, req_mut.masked_sealing_key).await?;
                if !matches!(view.key_kind, HsmVaultKeyKind::SdSealing) {
                    return Err(HsmError::UnsupportedKeyType);
                }
                view.target_key
            };

            // Sender public key (SndrPub) in SEC1 BE, derived on-device
            // from the recovered private key.  The PAL emits wire-LE
            // `X ‖ Y` directly into the coordinate region of `pk_s`;
            // reversing each coordinate in place then yields SEC1
            // `0x04 ‖ X_be ‖ Y_be` with no separate scratch buffer or copy.
            let pk_s = alloc.dma_alloc(1 + 2 * coord)?;
            pal.ecc_pub_from_priv(io, SD_CURVE, sndr_priv, &mut pk_s[1..1 + 2 * coord])
                .await?;
            pk_s[0] = SEC1_UNCOMPRESSED;
            pk_s[1..1 + coord].reverse();
            pk_s[1 + coord..1 + 2 * coord].reverse();

            // ── Fresh BKS3 + HPKE-Auth seal to RcvrPub ───────────────
            let bks3 = alloc.dma_alloc(BKS3_LEN)?;
            pal.rng_fill_bytes(io, bks3)?;

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

            // Size query, then split the fixed response buffer into the
            // `enc` and `ct` regions the seal writes.
            let seal_res = async {
                let sizes = seal(pal, io, &cfg, bks3, None, None, alloc).await?;
                if sizes.enc_len + sizes.ct_len != POK_REMOTE_BACKUP_LEN {
                    return Err(HsmError::InternalError);
                }
                let (enc, ct) = pok.split_at_mut(sizes.enc_len);
                seal(pal, io, &cfg, bks3, Some(enc), Some(ct), alloc).await?;
                Ok::<(), HsmError>(())
            }
            .await;

            // Wipe the fresh BKS3 on both success and failure before the
            // borrow of the request buffer (via `SndrPriv`) is released.
            bks3.zeroize();
            seal_res
        }
        .await;

        // Scrub the in-place-decrypted SndrPriv from the request buffer on
        // every path (success, unsupported-kind, or seal failure) — the
        // borrow held by `SndrPriv` has now ended.
        if let Ok(req_mut) = TborSdCreateRemoteBackupReq::decode_mut(req_buf) {
            req_mut.masked_sealing_key.zeroize();
        }
        crypto_res?;

        Ok(())
    })
    .await?;

    encode_response(pal, io, pok)
}

/// Encode the `SdCreateRemoteBackup` response around the sealed backup.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    pok: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborSdCreateRemoteBackupResp::encode(buf, 0, false)?
            .pok_remote_backup(pok)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
