// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `PartFinal` (FinalizePart + ConfigPartSD) handler —
//! partition-provisioning Phase 2.
//!
//! `PartFinal` is a CO-session command that finalizes a partition after
//! [`PartInit`](super::part_init).  It is the firmware realization of the
//! manticore `FinalizePart` primitive; the security-domain-local key
//! material of `ConfigPartSD` (SDLocalMK) is out of scope for now.
//!
//! Flow:
//!
//! 1. **Parse + gate** — CO-only; partition must be in
//!    [`PartState::Initializing`]; the re-supplied `part_policy` must hash
//!    to the stored `policy_hash`.  Certificate-chain walking
//!    (`cert_descriptors`) is **not yet implemented** and is ignored.
//! 2. **FinalizePart core** — derive `UPS` from the partition root (UMS),
//!    then `PartLocalBMK`; generate a fresh `PartLocalMK` or restore it
//!    from `prev_local_mk_backup`; provision the random `EphemeralMK`.
//! 3. **Commit** — vault the new keys (recording their ids), replace UMS
//!    with UPS in the partition root slot, and advance the lifecycle to
//!    [`PartState::Initialized`].
//! 4. **Respond** — return the current `local_mk_backup`.

use azihsm_fw_core_crypto_key_derive::derive_masking_key;
use azihsm_fw_core_crypto_key_masking::aead::mask;
use azihsm_fw_core_crypto_key_masking::aead::unmask;
use azihsm_fw_core_crypto_key_masking::aead::AeadAlg;
use azihsm_fw_core_crypto_key_masking::aead::MaskParams;
use azihsm_fw_ddi_tbor_types::TborPartFinalReq;
use azihsm_fw_ddi_tbor_types::TborPartFinalResp;
use azihsm_fw_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::PartPropId;
use azihsm_fw_hsm_pal_traits::PartState;
use azihsm_fw_hsm_pal_traits::SessionRole;

use super::*;

/// SHA-384 digest length (policy-hash comparison).
const SHA384_LEN: usize = 48;

/// AES-256-GCM masking-key length (the v2 AEAD envelope key).
const MASKING_KEY_LEN: usize = 32;

/// KDF labels and key-material lengths, mirroring the `part_init`
/// `kdf` submodule naming (`AZIHSM-<Command>-<Purpose>-v<N>`).
mod kdf {
    /// UDS-root → UPS derivation (KBKDF).  Context is empty for now
    /// because PTA certificate-chain walking is deferred; when it lands,
    /// `PTACertChainHash` becomes the KBKDF context.
    pub const UPS_LABEL: &[u8] = b"AZIHSM-PartFinal-UPS-v1";

    /// UPS length (HMAC-SHA-384-sized, matching `PartRoot`).
    pub const UPS_LEN: usize = 48;

    /// UPS → `PartLocalBMK` masking-key derivation (KBKDF).
    pub const PART_LOCAL_BMK_LABEL: &[u8] = b"AZIHSM-PartFinal-PartLocalBMK-v1";

    /// `PartLocalMK` length (the masked plaintext / `local_mk`).
    pub const PART_LOCAL_MK_LEN: usize = 32;

    /// `EphemeralMK` length (random masking key).
    pub const EPHEMERAL_MK_LEN: usize = 32;

    /// Opaque envelope label stamped into the `local_mk_backup`
    /// `MaskedKeyMetadata` (informational; bound by the AEAD tag).
    pub const PART_LOCAL_MK_ENVELOPE_LABEL: &[u8] = b"PartLocalMK";
}

/// Vault attributes for the partition root secret (UPS), mirroring the
/// `PartInit` `PartRoot` attributes: on-device, internal, never
/// extractable.
const PART_ROOT_ATTRS: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_local(true)
    .with_internal(true)
    .with_never_extractable(true);

/// Vault attributes for `PartLocalMK` — partition-local scope.
const PART_LOCAL_MK_ATTRS: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_local(true)
    .with_internal(true)
    .with_never_extractable(true);

/// Vault attributes for `EphemeralMK` — ephemeral scope (revoked on
/// partition reset).
const EPHEMERAL_MK_ATTRS: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_local(true)
    .with_internal(true)
    .with_never_extractable(true);

/// Handle a TBOR `PartFinal` request.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = parse_request(req_buf)?;

    // Lifecycle gate: PartFinal only runs against a partition that
    // `PartInit` left in `Initializing`.
    if super::super::part_state::part_state(pal, io)? != PartState::Initializing {
        return Err(HsmError::InvalidArg);
    }

    pal.alloc_scoped_async(io, async |alloc| {
        // Integrity gate: the re-supplied policy must match the one
        // bound at `PartInit` (`SHA-384(part_policy) == policy_hash`).
        verify_policy_hash(pal, io, alloc, req.part_policy).await?;

        // Validate the typed policy (rejects malformed input).
        super::policy::from_bytes(req.part_policy)?;

        // Platform identity that binds the masking keys / backup
        // envelope: SVN (BKS1 lineage) and owner-seed id (BKS2 lineage).
        let svn = super::super::part_state::part_mfgr_svn(pal);
        let owner = u16::try_from(super::super::part_state::part_owner_svn(pal))
            .map_err(|_| HsmError::InvalidArg)?;

        // ── UPS derivation ────────────────────────────────────────────
        // Read the vaulted partition root (UMS — note the slot is
        // historically named `ups_key_id` but holds UMS until this
        // handler replaces it) and derive UPS = KBKDF(UMS, UPS_LABEL).
        let ums_key_id = super::super::part_state::part_ups_key_id(pal, io)?;
        let ups = alloc.dma_alloc(kdf::UPS_LEN)?;
        {
            // Inner scope: `ums` must be dropped before `commit` calls
            // vault operations on the same slot.
            let ums = pal.vault_key(io, ums_key_id)?;
            let label = alloc.dma_alloc(kdf::UPS_LABEL.len())?;
            label.copy_from_slice(kdf::UPS_LABEL);
            pal.sp800_108_kdf(io, HsmHashAlgo::Sha384, ums, Some(label), None, ups)
                .await?;
        }

        // ── PartLocalMK: fresh or restored ───────────────────────────
        let part_local_mk = alloc.dma_alloc(kdf::PART_LOCAL_MK_LEN)?;
        match req.prev_local_mk_backup {
            None => {
                pal.rng_fill_bytes(io, &mut part_local_mk[..])?;
            }
            Some(prev) => {
                restore_part_local_mk(pal, io, alloc, ups, svn, prev, part_local_mk).await?;
            }
        }

        // Always (re)mask at the current `{svn, owner}` so the returned
        // backup advances to the current platform identity.
        let curr_backup = alloc.dma_alloc(LOCAL_MK_BACKUP_LEN)?;
        mask_part_local_mk(pal, io, alloc, ups, svn, owner, part_local_mk, curr_backup).await?;

        // ── EphemeralMK (random) ─────────────────────────────────────
        let ephemeral_mk = alloc.dma_alloc(kdf::EPHEMERAL_MK_LEN)?;
        pal.rng_fill_bytes(io, &mut ephemeral_mk[..])?;

        // ── Commit + respond ──────────────────────────────────────────
        commit(pal, io, ums_key_id, ups, part_local_mk, ephemeral_mk).await?;
        encode_response(pal, io, curr_backup)
    })
    .await
}

/// Parsed-and-validated `PartFinal` request fields.
struct ParsedRequest<'a> {
    #[allow(dead_code)]
    sess_id: HsmSessId,
    /// Re-supplied unified `PartPolicy` blob (484 B), as a sub-view of
    /// the inbound buffer.
    part_policy: &'a DmaBuf,
    /// Optional previous `local_mk` backup to restore (`None` when the
    /// field is empty; otherwise exactly [`LOCAL_MK_BACKUP_LEN`]).
    prev_local_mk_backup: Option<&'a DmaBuf>,
}

/// Decode the wire request, enforce the CO-only role gate, and
/// length-check the optional `prev_local_mk_backup`.
///
/// `cert_descriptors` is intentionally **ignored**: PTA certificate-chain
/// walking is not yet implemented.
fn parse_request<'a>(req_buf: &'a DmaBuf) -> HsmResult<ParsedRequest<'a>> {
    let req = TborPartFinalReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));

    // PartFinal is CO-only (parity with PartInit).
    if sess_id.role() != SessionRole::CryptoOfficer {
        return Err(HsmError::InvalidPermissions);
    }

    // The `part_policy` (484 B) length is pinned by the schema and was
    // already rejected at decode if malformed.  The optional
    // `prev_local_mk_backup` is variable (empty = absent); when present
    // it must be exactly the backup-envelope length.
    let prev = req.prev_local_mk_backup();
    let prev_local_mk_backup = match prev.len() {
        0 => None,
        n if n == LOCAL_MK_BACKUP_LEN => Some(prev),
        _ => return Err(HsmError::InvalidArg),
    };

    Ok(ParsedRequest {
        sess_id,
        part_policy: req.part_policy(),
        prev_local_mk_backup,
    })
}

/// Derives `PartLocalBMK` for `{svn, owner}` into a fresh scoped buffer.
///
/// Both restore and mask paths key on the same label (`PART_LOCAL_BMK_LABEL`)
/// and empty extra context; this helper avoids repeating that boilerplate.
async fn derive_local_bmk<'a, P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    ups: &DmaBuf,
    svn: u64,
    owner: u16,
) -> HsmResult<&'a mut DmaBuf> {
    let local_bmk = alloc.dma_alloc(MASKING_KEY_LEN)?;
    derive_masking_key(
        pal,
        io,
        ups,
        kdf::PART_LOCAL_BMK_LABEL,
        &[],
        svn,
        owner,
        local_bmk,
    )
    .await?;
    Ok(local_bmk)
}

/// Verify `SHA-384(part_policy)` equals the partition's stored
/// `policy_hash` (bound at `PartInit`).
async fn verify_policy_hash<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    part_policy: &DmaBuf,
) -> HsmResult<()> {
    let digest = alloc.dma_alloc(SHA384_LEN)?;
    pal.hash(io, HsmHashAlgo::Sha384, part_policy, digest, true)
        .await?;

    let stored = super::super::part_state::part_policy_hash(pal, io)?;
    if digest[..] != stored[..] {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

/// Restore `PartLocalMK` from a prior `local_mk_backup`.
///
/// Reads the `{svn, owner}` the blob was masked under from its (cleartext
/// but tag-bound) metadata, re-derives the matching `PartLocalBMK`, and
/// unmasks the blob.  Rejects a blob from a *newer* SVN (anti-rollback);
/// older-or-equal SVNs are accepted (the masking key is re-derivable from
/// the versioned device seeds).
async fn restore_part_local_mk<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    ups: &DmaBuf,
    cur_svn: u64,
    prev: &DmaBuf,
    out_mk: &mut DmaBuf,
) -> HsmResult<()> {
    let (prev_svn, prev_owner) = peek_backup_svn_owner(prev)?;
    if prev_svn > cur_svn {
        // Anti-rollback: a backup minted under a newer SVN cannot be
        // restored on this (older) firmware.
        return Err(HsmError::InvalidArg);
    }

    let local_bmk = derive_local_bmk(pal, io, alloc, ups, prev_svn, prev_owner).await?;

    // `unmask` decrypts in place; stage a mutable copy of the blob.
    let blob = alloc.dma_alloc(prev.len())?;
    blob.copy_from_slice(prev);
    let view = unmask(pal, io, local_bmk, blob).await?;
    if view.target_key.len() != out_mk.len() {
        return Err(HsmError::InvalidArg);
    }
    out_mk.copy_from_slice(view.target_key);
    Ok(())
}

/// Mask `part_local_mk` under the `PartLocalBMK` derived for the
/// current `{svn, owner}`, producing the `local_mk_backup` envelope.
async fn mask_part_local_mk<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    ups: &DmaBuf,
    svn: u64,
    owner: u16,
    part_local_mk: &DmaBuf,
    out: &mut DmaBuf,
) -> HsmResult<()> {
    let local_bmk = derive_local_bmk(pal, io, alloc, ups, svn, owner).await?;

    let key_label = alloc.dma_alloc(kdf::PART_LOCAL_MK_ENVELOPE_LABEL.len())?;
    key_label.copy_from_slice(kdf::PART_LOCAL_MK_ENVELOPE_LABEL);

    let params = MaskParams {
        key_kind: HsmVaultKeyKind::PartitionLocalMaskingKey,
        key_attrs: PART_LOCAL_MK_ATTRS,
        svn,
        owner_seed_id: owner,
        key_label,
    };

    mask(
        pal,
        io,
        alloc,
        AeadAlg::AesGcm256,
        local_bmk,
        &params,
        part_local_mk,
        Some(out),
    )
    .await?;
    Ok(())
}

/// Read the `{svn, owner_seed_id}` from a `local_mk_backup`'s
/// `MaskedKeyMetadata` AAD (cleartext, tag-bound) without the masking
/// key.  Offsets are fixed by the AES-256-GCM envelope layout
/// (`header(8) ‖ iv(12) ‖ metadata(96)`), pinned by the
/// [`LOCAL_MK_BACKUP_LEN`] length check.
fn peek_backup_svn_owner(blob: &DmaBuf) -> HsmResult<(u64, u16)> {
    if blob.len() != LOCAL_MK_BACKUP_LEN {
        return Err(HsmError::InvalidArg);
    }
    let b: &[u8] = &blob[..];
    // header(8) + iv(12) = 20; within MaskedKeyMetadata: svn @16, owner @24.
    const SVN_OFF: usize = 20 + 16;
    const OWNER_OFF: usize = 20 + 24;
    let svn = u64::from_le_bytes(
        b[SVN_OFF..SVN_OFF + 8]
            .try_into()
            .map_err(|_| HsmError::InvalidArg)?,
    );
    let owner = u16::from_le_bytes(
        b[OWNER_OFF..OWNER_OFF + 2]
            .try_into()
            .map_err(|_| HsmError::InvalidArg)?,
    );
    Ok((svn, owner))
}

/// Commit the finalized partition state: vault the live masking keys and
/// record their ids, replace UMS with UPS in the root slot, and advance
/// the lifecycle to [`PartState::Initialized`].
async fn commit<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    ums_key_id: HsmKeyId,
    ups: &DmaBuf,
    part_local_mk: &DmaBuf,
    ephemeral_mk: &DmaBuf,
) -> HsmResult<()> {
    use super::super::part_state;

    // Vault the partition-local + ephemeral masking keys; record ids.
    let local_id = pal
        .vault_key_create(
            io,
            part_local_mk,
            HsmVaultKeyKind::PartitionLocalMaskingKey,
            None,
            PART_LOCAL_MK_ATTRS,
        )
        .await?;
    part_state::part_set_local_mk_key_id(pal, io, local_id)?;

    let ephemeral_id = pal
        .vault_key_create(
            io,
            ephemeral_mk,
            HsmVaultKeyKind::PartitionEphemeralMaskingKey,
            None,
            EPHEMERAL_MK_ATTRS,
        )
        .await?;
    part_state::part_set_ephemeral_mk_key_id(pal, io, ephemeral_id)?;

    // Replace UMS → UPS in the partition root slot.  The id slot is
    // write-once, so clear it before re-pointing; then free the old UMS
    // vault key.
    let ups_id = pal
        .vault_key_create(
            io,
            ups,
            HsmVaultKeyKind::PartitionUniqueSecret,
            None,
            PART_ROOT_ATTRS,
        )
        .await?;
    pal.part_prop_clear(io, PartPropId::UPS_KEY_ID)?;
    part_state::part_set_ups_key_id(pal, io, ups_id)?;
    pal.vault_key_delete(io, ums_key_id).await?;

    // Finalize the lifecycle.
    part_state::part_set_state(pal, io, PartState::Initialized)
}

/// Encode the `TborPartFinalResp` into a fresh IO-scoped DmaBuf.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    backup: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborPartFinalResp::encode(buf, 0, false)?
            .local_mk_backup(&backup[..])?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
