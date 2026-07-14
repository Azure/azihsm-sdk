// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared masked-key envelope helpers for key-creating and
//! key-importing handlers.
//!
//! After a handler lands a key in the vault it returns an opaque
//! `masked_key` blob the host can persist and later re-import.  The
//! blob is an AES-CBC-256 + HMAC-SHA-384 envelope produced by
//! [`mask`](azihsm_fw_core_crypto_key_masking::cbc::mask) under a
//! masking key chosen by scope:
//!
//! * **session-scoped** keys are enveloped under the per-session
//!   masking key, so the blob is only re-importable while that
//!   session lives;
//! * **persistent** keys are enveloped under the partition masking
//!   key (`MK`), so the blob survives across sessions.
//!
//! The helpers here factor out the parts every handler shares —
//! resolving the masking key and assembling the cleartext
//! [`DdiMaskedKeyMetadata`] — leaving each handler to point its
//! response's `masked_key` field at the returned slice.

use azihsm_fw_core_crypto_key_masking::cbc::mask;
use azihsm_fw_ddi_mbor_types::masked_key::DdiMaskedKeyMetadata;
use azihsm_fw_ddi_mbor_types::DdiKeyType;

use super::*;

/// Resolve the 80-byte masking key for the key being enveloped.
///
/// `session_scoped` selects the source: the per-session masking key
/// (borrowed zero-copy from the session schedule) when set, otherwise
/// the partition masking key (`MK`) from the vault.
///
/// # Errors
///
/// - the partition has no `MK` (persistent key requested before
///   `EstablishCredential`), surfaced by
///   [`part_mk_key_id`](crate::part_state::part_mk_key_id);
/// - any error from the session / vault PAL calls.
pub(crate) fn resolve_masking_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    sess_id: HsmSessId,
    session_scoped: bool,
) -> HsmResult<&'p DmaBuf> {
    if session_scoped {
        pal.session_masking_key(io, sess_id)
    } else {
        let mk_id = crate::part_state::part_mk_key_id(pal, io)?;
        pal.vault_key(io, mk_id)
    }
}

/// Assemble the cleartext [`DdiMaskedKeyMetadata`] embedded in (and
/// authenticated by) a masked-key blob.
///
/// `key_type` is the on-wire tag the host re-imports the key as
/// (usually [`from_pal::vault_kind_ddi`](super::from_pal::vault_kind_ddi),
/// but e.g. [`DdiKeyType::RsaUnwrap`] for the unwrapping key);
/// `attrs` are the vault attributes to re-apply on import; `key_length`
/// is the plaintext primary-key length in bytes (for ECC, the
/// private-scalar length — the public point is recovered from the
/// curve).
pub(crate) fn masked_metadata<'a>(
    pal: &impl HsmPal,
    key_type: DdiKeyType,
    attrs: HsmVaultKeyAttrs,
    key_label: &'a [u8],
    key_length: u16,
) -> HsmResult<DdiMaskedKeyMetadata<'a>> {
    let bks2_id =
        u16::try_from(crate::part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
    Ok(DdiMaskedKeyMetadata {
        svn: crate::part_state::part_mfgr_svn(pal),
        key_type,
        key_attributes: attrs.into(),
        // Always-Some on new masking; Option-typed only for backward
        // compatibility with legacy blobs masked with `None`.
        bks2_index: Some(bks2_id),
        rsvd: None,
        key_label,
        key_length,
    })
}

/// Per-key inputs to [`mask_blob`]: how the masked blob's metadata is
/// assembled and how the key is later re-imported.
pub(crate) struct MaskSpec<'a> {
    /// Vault attributes to re-apply on import; also selects the
    /// masking key (session vs partition) via
    /// [`HsmVaultKeyAttrs::session`].
    pub attrs: HsmVaultKeyAttrs,
    /// On-wire re-import key-type tag.
    pub key_type: DdiKeyType,
    /// Role label embedded in the metadata.
    pub key_label: &'a [u8],
    /// Plaintext primary-key length in bytes (for ECC, the
    /// private-scalar length; the public point is appended to the
    /// masked `plaintext`).
    pub key_length: u16,
}

/// Produce a complete masked-key envelope for `plaintext` into a fresh
/// DMA buffer and return the written slice.
///
/// Resolves the masking key, assembles the metadata, size-queries the
/// envelope, then fills a zeroed scratch buffer.  Handlers whose
/// response carries the masked key as an ordinary `&[u8]` field point
/// that field at the returned slice.
pub(crate) async fn mask_blob<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    sess_id: HsmSessId,
    spec: MaskSpec<'_>,
    plaintext: &[u8],
) -> HsmResult<&'p [u8]> {
    let masking_key = resolve_masking_key(pal, io, sess_id, spec.attrs.session())?;
    let metadata = masked_metadata(
        pal,
        spec.key_type,
        spec.attrs,
        spec.key_label,
        spec.key_length,
    )?;
    let masked_len = mask(pal, io, masking_key, plaintext, &metadata, None).await?;
    let out = pal.dma_alloc_zeroed(io, masked_len)?;
    mask(pal, io, masking_key, plaintext, &metadata, Some(out)).await?;
    Ok(&out[..masked_len])
}
