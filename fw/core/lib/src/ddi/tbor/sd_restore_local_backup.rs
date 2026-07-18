// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdRestoreLocalBackup` handler.
//!
//! Restores a security domain from its **device-local** backups
//! (manticore §3.3.9 RestoreSDLocalBackup) — the local-reboot recovery
//! path.  Unlike the remote/peer restores it needs no sender, no HPKE, no
//! attestation evidence, and no out-of-band data: it simply unmasks the
//! two host-replayed backups with keys the device already holds, re-masks
//! them at the current platform identity, and re-provisions the SD.
//!
//! It is **CreateSD in reverse** — it *recovers* the SD key material a
//! prior `SdCreateRemoteBackup` *minted*, and shares that command's
//! provisioning primitives via [`sd_backup`](super::sd_backup).
//!
//! Flow:
//!
//! 1. Decode; gate to a Crypto-Officer, `Active` session on an
//!    `Initialized` partition, and fail-fast if the security domain is
//!    already initialized ([`SdAlreadyInitialized`](HsmError::SdAlreadyInitialized)).
//! 2. Unmask `pok_local_backup` under the partition-local masking key
//!    (`PartLocalMK`, from `PartFinal`) → **BKS3**.  The blob must be an
//!    [`SdPartitionOwnerSeed`](HsmVaultKeyKind::SdPartitionOwnerSeed)
//!    envelope, and its bound SVN must not be newer than the current
//!    firmware SVN ([`SdBackupSvnRollback`](HsmError::SdBackupSvnRollback)).
//! 3. Derive `SDBMK` from BKS3 + the partition `policy_hash` at the
//!    `sd_mk_backup`'s *own* `{svn, owner}` (peeked from its metadata, so an
//!    older-SVN backup unmasks on newer firmware), then unmask `sd_mk_backup`
//!    under `SDBMK` → **SDMK** (must be an
//!    [`SdMasking`](HsmVaultKeyKind::SdMasking) envelope; same anti-rollback).
//! 4. Re-mask both at the current `{svn, owner}`: `CurrSDLocalBackup =
//!    mask(BKS3, PartLocalMK)` and `CurrSDKMKBackup = mask(SDMK, SDBMK)`.
//! 5. **Commit** ([`commit_sd_to_vault`](super::sd_backup::commit_sd_to_vault)):
//!    vault `SDMK` (SecurityDomain scope), record `SD_MK_KEY_ID`, and mark
//!    the partition SD-initialized — undo-guarded.  BKS3, SDMK, and SDBMK
//!    are zeroized before returning.
//!
//! **Stateful & one-shot** (parity with `SdCreateRemoteBackup`): a second
//! restore/create on the same partition incarnation is rejected.
//!
//! This command is **Crypto-Officer-only**.

use azihsm_fw_core_crypto_key_masking::aead::peek_metadata;
use azihsm_fw_core_crypto_key_masking::aead::unmask;
use azihsm_fw_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use azihsm_fw_ddi_tbor_types::TborSdRestoreLocalBackupResp;
use azihsm_fw_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_fw_ddi_tbor_types::SD_MK_BACKUP_LEN;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::PartState;
use azihsm_fw_hsm_undo::UndoLog;

use super::sd_backup;
use super::validate_crypto_officer_active_session;
use crate::part_state;

/// Handle a TBOR `SdRestoreLocalBackup` request.
///
/// **Stateful**: re-provisions the security-domain masking key (`SDMK`) in
/// the vault and marks the partition security-domain-initialized, guarded
/// by the per-command `undo` log.  The one-shot `SD_INITIALIZED` claim is
/// the race-winner gate against a concurrently-dispatched create/restore.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
    undo: &mut UndoLog<'p>,
) -> HsmResult<&'p DmaBuf> {
    // Session/state gating uses only the shared `decode` view; confine the
    // borrow so the request buffer is free afterwards.
    {
        let req = TborSdRestoreLocalBackupReq::decode(&*req_buf)?;
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
    }

    // Allocate the two fixed-size response backups in the IO scope so they
    // survive the crypto scratch allocator's reset.
    let pok_local_out = pal.dma_alloc(io, MASKED_SD_LEN)?;
    let sd_mk_out = pal.dma_alloc(io, SD_MK_BACKUP_LEN)?;

    pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
        let (svn, owner) = sd_backup::platform_svn_owner(pal)?;

        // Stage the two masked backups in scratch so they can be unmasked
        // (decrypted) in place without borrowing the request buffer across
        // the re-mask / vault steps.
        let pok_scratch = alloc.dma_alloc(MASKED_SD_LEN)?;
        let mk_scratch = alloc.dma_alloc(SD_MK_BACKUP_LEN)?;
        {
            let req = TborSdRestoreLocalBackupReq::decode(&*req_buf)?;
            pok_scratch.copy_from_slice(req.pok_local_backup());
            mk_scratch.copy_from_slice(req.sd_mk_backup());
        }

        // BKS3 and SDMK are recovered into `pok_scratch` / `mk_scratch`;
        // scope rewind does not clear DMA memory, so both are scrubbed on
        // EVERY exit path below.
        let res = async {
            // ── Recover BKS3 from pok_local_backup under PartLocalMK ──
            let bks3 = {
                let local_mk_id = part_state::part_local_mk_key_id(pal, io)?;
                let local_mk = pal.vault_key(io, local_mk_id)?;
                let view = unmask(pal, io, local_mk, pok_scratch).await?;
                if !matches!(view.key_kind, HsmVaultKeyKind::SdPartitionOwnerSeed) {
                    return Err(HsmError::UnsupportedKeyType);
                }
                // Anti-rollback: a backup minted under a newer SVN cannot be
                // restored on this (older) firmware.  Enforced after the
                // AEAD tag authenticates the envelope, so a tampered
                // cleartext SVN fails the tag rather than spoofing this.
                if view.svn > svn {
                    return Err(HsmError::SdBackupSvnRollback);
                }
                // Firmware invariant: the AEAD tag has authenticated the
                // envelope, so a genuine backup always carries a `BKS3_LEN`
                // seed; a mismatch signals corruption / a sizing bug, not a
                // client error.  Mirrors `restore_part_local_mk` in `part_final`.
                if view.target_key.len() != sd_backup::BKS3_LEN {
                    return Err(HsmError::InternalError);
                }
                view.target_key
            };

            // ── Recover SDMK, re-mask, and commit ──
            // Re-derive the SDBMK that masked `sd_mk_backup` at the backup's
            // OWN {svn, owner} (peeked from its cleartext metadata) so an
            // older-SVN backup unmasks on newer firmware — the versioned device
            // seeds are forward-derivable, and deriving at the current SVN would
            // fail the AEAD tag.  The peeked values are authenticated by the
            // `unmask` tag below; the anti-rollback check is deferred until
            // after it.  A second SDBMK at the current {svn, owner} re-masks the
            // refreshed backup.  Both are their own scratch allocations (not
            // views into the scrubbed staging buffers) and scope rewind does not
            // clear DMA memory, so both are zeroized on EVERY path below.
            // Mirrors `restore_part_local_mk` in `part_final`.
            let (prev_svn, prev_owner) = {
                let meta = peek_metadata(mk_scratch)?;
                (meta.svn.get(), meta.owner_seed_id.get())
            };
            let sdbmk_prev =
                sd_backup::derive_sdbmk(pal, io, alloc, bks3, prev_svn, prev_owner).await?;
            let sdbmk_curr = sd_backup::derive_sdbmk(pal, io, alloc, bks3, svn, owner).await?;
            let inner = async {
                let sdmk = {
                    let view = unmask(pal, io, sdbmk_prev, mk_scratch).await?;
                    if !matches!(view.key_kind, HsmVaultKeyKind::SdMasking) {
                        return Err(HsmError::UnsupportedKeyType);
                    }
                    // Anti-rollback on the now-authenticated `view.svn`.
                    if view.svn > svn {
                        return Err(HsmError::SdBackupSvnRollback);
                    }
                    // Firmware invariant (tag-authenticated): a genuine backup
                    // always carries an `SDMK_LEN` key; a mismatch signals
                    // corruption / a sizing bug, not a client error.
                    if view.target_key.len() != sd_backup::SDMK_LEN {
                        return Err(HsmError::InternalError);
                    }
                    view.target_key
                };

                // ── Re-mask both at the current {svn, owner} ──
                sd_backup::mask_pok_local_backup(pal, io, alloc, bks3, svn, owner, pok_local_out)
                    .await?;
                sd_backup::mask_sd_mk_backup(
                    pal, io, alloc, sdbmk_curr, sdmk, svn, owner, sd_mk_out,
                )
                .await?;

                // ── Commit: vault SDMK, mark SD-initialized (undo-guarded) ──
                sd_backup::commit_sd_to_vault(pal, io, undo, sdmk).await
            }
            .await;
            sdbmk_curr.zeroize();
            sdbmk_prev.zeroize();
            inner
        }
        .await;

        // Scrub the recovered BKS3 / SDMK plaintext from scratch on every
        // path before the buffers return to the per-IO pool.
        pok_scratch.zeroize();
        mk_scratch.zeroize();
        res
    })
    .await?;

    encode_response(pal, io, pok_local_out, sd_mk_out)
}

/// Encode the `SdRestoreLocalBackup` response around the refreshed backups.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    pok_local: &DmaBuf,
    sd_mk: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborSdRestoreLocalBackupResp::encode(buf, 0, false)?
            .pok_local_backup(pok_local)?
            .sd_mk_backup(sd_mk)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
