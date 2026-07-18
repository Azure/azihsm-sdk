// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared security-domain backup mechanics.
//!
//! Both `SdCreateRemoteBackup` (which *mints* the SD key material) and
//! `SdRestoreLocalBackup` (which *recovers* it) produce the same two
//! on-device backup envelopes and provision the same vaulted `SDMK`, so
//! the derivation / masking / commit primitives live here and are shared
//! between the two handlers to keep their SD semantics identical.
//!
//! Key hierarchy:
//!
//! * `BKS3` (48 B) — the security-domain partition-owner seed.
//! * `SDBMK` — the SD backup masking key, `KBKDF(BKS3, mfgr_seed[svn] ‖
//!   owner_seed[owner] ‖ policy_hash)`; derived on demand, never vaulted.
//! * `SDMK` (32 B) — the live SecurityDomain-scope masking key, vaulted.
//!
//! Envelopes:
//!
//! * `pok_local_backup` (180 B) = `mask(BKS3, PartLocalMK)`.
//! * `sd_mk_backup` (164 B) = `mask(SDMK, SDBMK)`.

use azihsm_fw_core_crypto_key_derive::derive_masking_key;
use azihsm_fw_core_crypto_key_masking::aead::mask;
use azihsm_fw_core_crypto_key_masking::aead::AeadAlg;
use azihsm_fw_core_crypto_key_masking::aead::MaskParams;
use azihsm_fw_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_fw_ddi_tbor_types::SD_MK_BACKUP_LEN;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyScope;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::PartPropId;
use azihsm_fw_hsm_undo::UndoLog;

use crate::part_state;

/// Length of the random security-domain masking key (`SDMK`) — 32 B
/// AES-256-GCM.
pub(super) const SDMK_LEN: usize = 32;

/// Length of the partition owner seed (`BKS3`) — 48 B.
pub(super) const BKS3_LEN: usize = 48;

/// Length of the derived security-domain backup masking key (`SDBMK`) —
/// 32 B AES-256-GCM (the key that masks `SDMK` into `sd_mk_backup`).
const SDBMK_LEN: usize = 32;

/// KBKDF label selecting the `SDBMK` derivation purpose (keyed on BKS3,
/// with the partition `policy_hash` as extra context).
const SDBMK_LABEL: &[u8] = b"AZIHSM-SdCreate-SDBMK-v1";

/// Opaque envelope label stamped into the `sd_mk_backup`
/// `MaskedKeyMetadata` (informational; bound by the AEAD tag).
const SDMK_ENVELOPE_LABEL: &[u8] = b"SDMK";

/// Opaque envelope label stamped into the `pok_local_backup`
/// `MaskedKeyMetadata` (informational; bound by the AEAD tag).
const POK_LOCAL_ENVELOPE_LABEL: &[u8] = b"BKS3";

/// Vault attributes for the provisioned `SDMK`: SecurityDomain scope,
/// on-device, internal, never extractable.
const SDMK_ATTRS: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_local(true)
    .with_internal(true)
    .with_never_extractable(true)
    .with_scope(HsmKeyScope::SecurityDomain);

/// Vault attributes stamped into the `sd_mk_backup` / `pok_local_backup`
/// metadata: on-device, internal, never extractable.
const SD_BACKUP_ATTRS: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_local(true)
    .with_internal(true)
    .with_never_extractable(true);

/// Read the platform identity `{svn, owner}` that binds the backup
/// envelopes and the `SDBMK` derivation: SVN (BKS1 lineage) and owner-seed
/// id (BKS2 lineage).
pub(super) fn platform_svn_owner<P: HsmPal>(pal: &P) -> HsmResult<(u64, u16)> {
    let svn = part_state::part_mfgr_svn(pal);
    let owner = u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
    Ok((svn, owner))
}

/// Derive `SDBMK` for `bks3` at `{svn, owner}` into a fresh scoped buffer.
///
/// `SDBMK = KBKDF(BKS3, mfgr_seed[svn] ‖ owner_seed[owner] ‖ policy_hash)`.
/// Binding the partition `policy_hash` proves the backup was produced by a
/// Manticore wielding the same policy.  Both the create and restore paths
/// key on the same label so the derived key round-trips.
pub(super) async fn derive_sdbmk<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    bks3: &DmaBuf,
    svn: u64,
    owner: u16,
) -> HsmResult<&'a mut DmaBuf> {
    let sdbmk = alloc.dma_alloc(SDBMK_LEN)?;
    // Stage the stored policy hash in scratch so the extra context does not
    // hold a borrow of partition state across the derivation await.
    let policy_hash = {
        let stored = part_state::part_policy_hash(pal, io)?;
        let ph = alloc.dma_alloc(stored.len())?;
        ph.copy_from_slice(stored);
        ph
    };
    derive_masking_key(
        pal,
        io,
        bks3,
        SDBMK_LABEL,
        &policy_hash[..],
        svn,
        owner,
        sdbmk,
    )
    .await?;
    Ok(sdbmk)
}

/// Mask `sdmk` under `sdbmk` into `out`, producing the `sd_mk_backup`
/// envelope (exactly [`SD_MK_BACKUP_LEN`], 164 B).
#[allow(clippy::too_many_arguments)]
pub(super) async fn mask_sd_mk_backup<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    sdbmk: &DmaBuf,
    sdmk: &DmaBuf,
    svn: u64,
    owner: u16,
    out: &mut DmaBuf,
) -> HsmResult<()> {
    let label = alloc.dma_alloc(SDMK_ENVELOPE_LABEL.len())?;
    label.copy_from_slice(SDMK_ENVELOPE_LABEL);
    let params = MaskParams {
        key_kind: HsmVaultKeyKind::SdMasking,
        key_attrs: SDMK_ATTRS,
        svn,
        owner_seed_id: owner,
        key_label: label,
    };
    let n = mask(
        pal,
        io,
        alloc,
        AeadAlg::AesGcm256,
        sdbmk,
        &params,
        sdmk,
        Some(out),
    )
    .await?;
    if n != SD_MK_BACKUP_LEN {
        return Err(HsmError::InternalError);
    }
    Ok(())
}

/// Mask `bks3` under the partition-local masking key (`PartLocalMK`) into
/// `out`, producing the `pok_local_backup` envelope (exactly
/// [`MASKED_SD_LEN`], 180 B).
pub(super) async fn mask_pok_local_backup<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    bks3: &DmaBuf,
    svn: u64,
    owner: u16,
    out: &mut DmaBuf,
) -> HsmResult<()> {
    let local_mk_id = part_state::part_local_mk_key_id(pal, io)?;
    let local_mk = pal.vault_key(io, local_mk_id)?;
    let label = alloc.dma_alloc(POK_LOCAL_ENVELOPE_LABEL.len())?;
    label.copy_from_slice(POK_LOCAL_ENVELOPE_LABEL);
    let params = MaskParams {
        key_kind: HsmVaultKeyKind::SdPartitionOwnerSeed,
        key_attrs: SD_BACKUP_ATTRS,
        svn,
        owner_seed_id: owner,
        key_label: label,
    };
    let m = mask(
        pal,
        io,
        alloc,
        AeadAlg::AesGcm256,
        local_mk,
        &params,
        bks3,
        Some(out),
    )
    .await?;
    if m != MASKED_SD_LEN {
        return Err(HsmError::InternalError);
    }
    Ok(())
}

/// Commit the security domain: mark it initialized, vault the `SDMK`, and
/// record its key id.  Every mutation is pushed to `undo` so a failure
/// rolls back all changes.
pub(super) async fn commit_sd_to_vault<'p, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    undo: &mut UndoLog<'p>,
    sdmk: &DmaBuf,
) -> HsmResult<()> {
    // Atomic one-shot claim first (the race-winner gate); the recorded
    // inverse clears the flag on rollback.
    part_state::part_mark_sd_initialized(pal, io)?;
    if let Err(e) = undo.push_prop_restore_scalar(PartPropId::SD_INITIALIZED, 0) {
        // The claim succeeded but its rollback inverse could not be
        // recorded (e.g. `UndoLogFull`); clear the flag now (best-effort)
        // so a full undo log cannot permanently wedge the partition's
        // one-shot SD gate.  Safe against a concurrent create/restore: this
        // task owns the just-made claim and there is no await between the
        // mark and here.
        let _ = part_state::part_clear_sd_initialized(pal, io);
        return Err(e);
    }

    // Vault SDMK as the partition's SecurityDomain-scope masking key, then
    // record its id so `masking_key_id_for_scope` resolves it.
    let sdmk_id = pal
        .vault_key_create(io, sdmk, HsmVaultKeyKind::SdMasking, None, SDMK_ATTRS)
        .await?;
    if let Err(e) = undo.push_vault_create(sdmk_id) {
        // The key exists but could not be tracked for rollback (e.g.
        // `UndoLogFull`); best-effort delete it so a full undo log does not
        // leak the vault slot for an untracked key.
        let _ = pal.vault_key_delete(io, sdmk_id).await;
        return Err(e);
    }
    undo.push_prop_restore_absent(part_state::part_sd_mk_key_id_prop_id())?;
    part_state::part_set_sd_mk_key_id(pal, io, sdmk_id)?;
    Ok(())
}
