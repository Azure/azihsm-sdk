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
//!    to the stored `policy_hash`; and the supplied PTA certificate chain
//!    (`cert_descriptors`, read out of band) must be anchored to the
//!    policy `POTAPubKey` with its terminal (PTA) certificate's public
//!    key equal to the partition's PTA key.
//! 2. **FinalizePart core** — derive `UPS` from the partition root (UMS),
//!    then `PartLocalBMK`; generate a fresh `PartLocalMK` or restore it
//!    from `prev_local_mk_backup`; provision the random `EphemeralMK`.
//! 3. **Commit** — vault the new keys (recording their ids), replace UMS
//!    with UPS in the partition root slot, and advance the lifecycle to
//!    [`PartState::Initialized`].
//! 4. **Respond** — return the current `local_mk_backup`.

use azihsm_fw_core_crypto_key_derive::derive_masking_key;
use azihsm_fw_core_crypto_key_masking::aead::mask;
use azihsm_fw_core_crypto_key_masking::aead::peek_metadata;
use azihsm_fw_core_crypto_key_masking::aead::unmask;
use azihsm_fw_core_crypto_key_masking::aead::AeadAlg;
use azihsm_fw_core_crypto_key_masking::aead::MaskParams;
use azihsm_fw_core_crypto_x509_chain::validate_chain;
use azihsm_fw_ddi_tbor_types::evidence::CertDescriptor;
use azihsm_fw_ddi_tbor_types::evidence::MAX_CERTS;
use azihsm_fw_ddi_tbor_types::policy::PartPolicy;
use azihsm_fw_ddi_tbor_types::policy::POLICY_MAX_KEY_LEN;
use azihsm_fw_ddi_tbor_types::TborPartFinalReq;
use azihsm_fw_ddi_tbor_types::TborPartFinalResp;
use azihsm_fw_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
use azihsm_fw_hsm_oob::copy_oob;
use azihsm_fw_hsm_oob::OobPtr;
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
    /// UMS (the partition root secret in the `ups_key_id` slot) → UPS
    /// derivation (KBKDF).  Context is empty for now: the handler already
    /// walks and validates the PTA certificate chain, but binding its hash
    /// (`PTACertChainHash`) into this derivation is deferred; when it
    /// lands, that hash becomes the KBKDF context.
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
    oob: Option<OobPtr>,
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

        // Validate the typed policy (rejects malformed input) and recover
        // the `POTAPubKey` trust anchor for cert-chain validation.
        let policy = super::policy::from_bytes(req.part_policy)?;

        // Trust gate: walk the supplied PTA certificate chain, proving it
        // chains to the policy `POTAPubKey` and that its terminal (PTA)
        // certificate carries this partition's PTA key.
        validate_pta_chain(pal, io, alloc, oob, req.cert_descriptors, &policy).await?;

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
    /// PTA certificate-chain descriptors (`(index, length)` into the OOB
    /// SGL page), root → leaf.  The schema pins `1..=MAX_CERTS` entries.
    cert_descriptors: &'a [CertDescriptor],
    /// Optional previous `local_mk` backup to restore (`None` when the
    /// field is empty; otherwise exactly [`LOCAL_MK_BACKUP_LEN`]).  A
    /// **mutable** sub-view so the envelope can be AEAD-unmasked in place.
    prev_local_mk_backup: Option<&'a mut DmaBuf>,
}

/// Decode the wire request, enforce the CO-only role gate, extract the
/// PTA `cert_descriptors`, and length-check the optional
/// `prev_local_mk_backup`.
fn parse_request<'a>(req_buf: &'a mut DmaBuf) -> HsmResult<ParsedRequest<'a>> {
    let req = TborPartFinalReq::decode_mut(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id));

    // PartFinal is CO-only (parity with PartInit).
    if sess_id.role() != SessionRole::CryptoOfficer {
        return Err(HsmError::InvalidPermissions);
    }

    // `decode_mut`'s view exposes shared (non-mutable) buffer fields as
    // raw `&DmaBuf` bytes, so reinterpret the packed `cert_descriptors`
    // bytes as a typed slice here; a byte length that is not a whole
    // number of descriptors fails the cast and is rejected as `InvalidArg`.
    let cert_descriptors =
        <[CertDescriptor] as zerocopy::TryFromBytes>::try_ref_from_bytes(req.cert_descriptors)
            .map_err(|_| HsmError::InvalidArg)?;

    // The `part_policy` (484 B) length is pinned by the schema and was
    // already rejected at decode if malformed.  The optional
    // `prev_local_mk_backup` is variable (empty = absent); when present
    // it must be exactly the backup-envelope length.
    let prev = req.prev_local_mk_backup;
    let prev_local_mk_backup = match prev.len() {
        0 => None,
        n if n == LOCAL_MK_BACKUP_LEN => Some(prev),
        _ => return Err(HsmError::InvalidArg),
    };

    Ok(ParsedRequest {
        sess_id,
        part_policy: req.part_policy,
        cert_descriptors,
        prev_local_mk_backup,
    })
}

/// Walk the supplied PTA certificate chain and prove partition trust.
///
/// The chain travels **out of band** (each certificate read via
/// [`copy_oob`] by its descriptor `index`), and is walked root → leaf by
/// the firmware [`validate_chain`] state machine.  Two conditions gate
/// finalization:
///
/// 1. **Anchoring** — some non-leaf certificate's public key must equal
///    the policy `POTAPubKey`, binding the chain to the partition owner's
///    trust anchor.
/// 2. **PTA identity** — the chain's terminal certificate (the PTA
///    intermediate CA) must carry this partition's PTA public key.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — no OOB region, a bad descriptor count, or
///   a malformed / unanchored chain.
/// * [`HsmError::PartFinalPtaMismatch`] — the chain is valid and
///   POTA-anchored, but its terminal (PTA) certificate's key is not the
///   partition PTA key.
/// * Any [`HsmError`] surfaced by certificate parsing or signature
///   verification.
async fn validate_pta_chain<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    oob: Option<OobPtr>,
    cert_descriptors: &[CertDescriptor],
    policy: &PartPolicy,
) -> HsmResult<()> {
    // The PTA chain travels out of band; without an OOB region there is
    // nothing to read.
    let oob = oob.ok_or(HsmError::InvalidArg)?;

    if cert_descriptors.is_empty() || cert_descriptors.len() > MAX_CERTS {
        return Err(HsmError::InvalidArg);
    }

    // Snapshot the expected PTA identity (partition PTA key) up front so
    // the property-store borrow is not held across the chain walk.
    let pta = super::super::part_state::part_pta_pub_key(pal, io)?;
    if pta.len() != POLICY_MAX_KEY_LEN {
        return Err(HsmError::InternalError);
    }

    // Policy `POTAPubKey` trust anchor (raw P-384 `X ‖ Y`, big-endian);
    // `from_bytes` has already pinned its length to a full Ecc384 key.
    let anchor = &policy.pota_pub_key.data[..POLICY_MAX_KEY_LEN];

    let mut pta_from_chain = [0u8; POLICY_MAX_KEY_LEN];
    validate_chain(
        pal,
        io,
        alloc,
        cert_descriptors,
        Some(anchor),
        &mut pta_from_chain,
        async |index, buf| copy_oob(pal, io, &oob, index, buf).await,
    )
    .await?;

    // The chain is cryptographically valid and POTA-anchored; its
    // terminal (PTA) certificate must carry this partition's PTA key.
    // Compare as byte slices (`pta` is a `DmaBuf` DST over `[u8]`).
    let expected_pta: &[u8] = pta;
    if &pta_from_chain[..] != expected_pta {
        return Err(HsmError::PartFinalPtaMismatch);
    }

    Ok(())
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
/// unmasks the blob.  The anti-rollback policy (reject a blob from a
/// *newer* SVN; older-or-equal SVNs are accepted since the masking key is
/// re-derivable from the versioned device seeds) is enforced **after**
/// `unmask` authenticates the metadata, so a tampered cleartext SVN fails
/// the AEAD tag rather than spoofing the rollback error.
async fn restore_part_local_mk<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    ups: &DmaBuf,
    cur_svn: u64,
    prev: &mut DmaBuf,
    out_mk: &mut DmaBuf,
) -> HsmResult<()> {
    // Peek the cleartext `{svn, owner}` bindings.  These are needed *now*
    // to re-derive the unmasking key, but they are NOT yet authenticated
    // (`peek_metadata`'s result must not be trusted until `unmask` verifies
    // the tag), so the anti-rollback policy below is deferred until after
    // `unmask` succeeds.
    let (prev_svn, prev_owner) = peek_backup_svn_owner(prev)?;

    let local_bmk = derive_local_bmk(pal, io, alloc, ups, prev_svn, prev_owner).await?;

    // `unmask` decrypts the envelope in place in the request buffer — no
    // scratch staging copy needed.  On success it has verified the AEAD tag
    // over the AAD, so `{prev_svn, prev_owner}` are now authenticated.
    let view = unmask(pal, io, local_bmk, prev).await?;
    let len_ok = view.target_key.len() == out_mk.len();
    if len_ok {
        out_mk.copy_from_slice(view.target_key);
    }
    // `view`'s borrow of `prev` ends at its last use above, so we can now
    // wipe the recovered plaintext `PartLocalMK` left in the request DMA
    // buffer so it does not linger (until the IO slot is recycled) longer
    // than necessary.
    prev.fill(0);

    // Anti-rollback, enforced on the now-authenticated `svn`: a backup
    // minted under a newer SVN cannot be restored on this (older)
    // firmware.  Enforcing this only after the tag is verified means a
    // tampered cleartext `svn` fails `unmask` (generic AEAD error) rather
    // than being able to spoof this specific rollback error.
    if prev_svn > cur_svn {
        // Don't hand back / leave the recovered key on a rejected restore.
        out_mk.fill(0);
        return Err(HsmError::PartFinalBackupSvnRollback);
    }
    if !len_ok {
        // Firmware invariant: the AEAD tag has already verified the
        // envelope, so a genuine (firmware-minted) backup always holds a
        // `PART_LOCAL_MK_LEN` key — a mismatch signals corruption / a
        // sizing bug, not a client-supplied error.
        return Err(HsmError::InternalError);
    }
    Ok(())
}

/// Mask `part_local_mk` under the `PartLocalBMK` derived for the
/// current `{svn, owner}`, producing the `local_mk_backup` envelope.
#[allow(clippy::too_many_arguments)]
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
    // Read the `{svn, owner_seed_id}` platform-identity bindings from the
    // envelope's cleartext metadata.  These are tag-bound but not yet
    // authenticated here — the subsequent `unmask` verifies the tag.
    // `prev`'s exact length is already enforced by `parse_request`, and
    // `peek_metadata` surfaces any malformed envelope (bad magic /
    // version / too short) as `MaskedKeyDecodeFailed`.
    let meta = peek_metadata(blob)?;
    Ok((meta.svn.get(), meta.owner_seed_id.get()))
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
            HsmVaultKeyKind::UniquePartitionSecret,
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
            .local_mk_backup(backup)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
