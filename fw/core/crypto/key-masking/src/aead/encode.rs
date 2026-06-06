// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Masking pipeline ([`mask`]): wrap a target key under a 32-byte
//! AES-256 masking key into a self-contained AEAD blob.
//!
//! Follows the firmware **query-size-then-fill** convention: pass
//! `out = None` to learn the required blob length without performing
//! any crypto work, then call again with `Some(&mut buf)` of at least
//! that length to actually mask.
//!
//! Mirrors the call shape of `build_bmk_session` in the TBOR session
//! handler — the canonical AEAD-seal pattern in this firmware — by
//! taking a scoped allocator for the small IV / AAD / target-key-copy
//! `DmaBuf`s that [`aead_envelope::seal`] requires as separate
//! inputs.

use azihsm_fw_core_crypto_aead_envelope::seal as aead_seal;
use azihsm_fw_core_crypto_aead_envelope::AeadAlg;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmCrypto;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use zerocopy::IntoBytes;

use crate::aead::format::blob_len;
use crate::aead::format::MaskedKeyMetadata;
use crate::aead::format::KEY_LABEL_MAX;
use crate::aead::format::META_LEN;

/// Caller-supplied parameters for a v1 masked-key blob.
///
/// Carries only the fields the caller owns; magic, version, padding,
/// and the reserved tail of [`MaskedKeyMetadata`] are produced by
/// [`mask`] and cannot be set by callers.
///
/// `key_kind` and `usage_flags` pass through unchanged to / from the
/// vault types — masked-key blobs are firmware-internal, so we carry
/// the same primitives the vault speaks
/// ([`vault_key_kind`](azihsm_fw_hsm_pal_traits::HsmVault::vault_key_kind),
/// [`vault_key_attrs`](azihsm_fw_hsm_pal_traits::HsmVault::vault_key_attrs)).
pub struct MaskParams<'a> {
    /// Vault kind tag for the masked key.
    pub key_kind: HsmVaultKeyKind,

    /// PKCS#11-style permission bitfield, identical to what the
    /// vault stores alongside live keys.
    pub key_attrs: HsmVaultKeyAttrs,

    /// Partition SVN at mask time (from `part_svn`). Bound by the
    /// AEAD tag so blobs cannot be replayed across SVN bumps.
    pub svn: u64,

    /// Owner-seed (BKS2) lineage identifier (from `part_bks2_id`).
    /// Bound by the AEAD tag so blobs cannot be replayed across
    /// owner-seed rotations.
    pub owner_seed_id: u16,

    /// Opaque caller-supplied label (e.g. `b"BK3"`, `b"MK"`). Length
    /// MUST be ≤ [`KEY_LABEL_MAX`].
    pub key_label: &'a DmaBuf,
}

/// Mask `target_key` under `key` into a self-contained masked-key
/// AEAD blob.
///
/// The blob is an [`aead_envelope`](azihsm_fw_core_crypto_aead_envelope)
/// envelope (algorithm chosen by `alg`) whose AAD is exactly one
/// fixed [`MaskedKeyMetadata`] record built from `params`. The
/// envelope binds every metadata byte (magic, version, `key_kind`,
/// `key_label_len`, `usage_flags`, `key_label`, reserved tail) to
/// the ciphertext via the AEAD tag.
///
/// # Parameters
///
/// * `crypto`        — PAL providing AES and RNG (any [`HsmCrypto`]).
/// * `io`         — caller's I/O context.
/// * `alloc`      — scoped allocator. Used internally to stage the
///   IV (12 B), AAD copy (96 B), and a target-key copy
///   (`target_key.len()` B). Mirrors the staging pattern used by
///   every other AEAD seal call site in the firmware (e.g.
///   `build_bmk_session`). All three buffers are freed when the
///   enclosing scope exits.
/// * `alg`        — AEAD algorithm for this blob (e.g.
///   [`AeadAlg::AesGcm256`]). Determines the required `key` length
///   via [`AeadAlg::key_len`].
/// * `key`        — AEAD masking key; length MUST equal
///   `alg.key_len()`. Ignored when `out == None`.
/// * `params`     — caller-supplied vault fields and label.
/// * `target_key` — raw key bytes to mask.
/// * `out`        — destination buffer of at least the required
///   blob length (which the caller discovers by invoking this
///   function with `out = None`), or `None` to perform that size
///   query without any crypto work.
///
/// # Returns
///
/// * `Ok(n)`  — the blob length in bytes. When `out == Some`, exactly
///   `n` bytes have been written to `&out[..n]`; trailing bytes are
///   untouched.
/// * `Err(HsmError::InvalidArg)` — `key.len() != alg.key_len()`,
///   `params.key_label.len() > KEY_LABEL_MAX`, or `out` is too small.
/// * `Err(HsmError::NotEnoughSpace)` — `alloc` exhausted.
/// * Any [`HsmError`] surfaced by the PAL RNG / AES drivers, or by
///   [`aead_envelope::seal`](aead_seal).
///
/// On any failure after `out` has been mutated, the prefix used by
/// the partial seal is zeroed before returning so the caller's
/// response staging area never retains `target_key` bytes or an
/// unauthenticated partial blob.
pub async fn mask(
    crypto: &impl HsmCrypto,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    alg: AeadAlg,
    key: &DmaBuf,
    params: &MaskParams<'_>,
    target_key: &DmaBuf,
    out: Option<&mut DmaBuf>,
) -> HsmResult<usize> {
    let total = blob_len(alg, target_key.len());

    // Size-query short-circuit — no crypto, no IO, no buffer writes,
    // no allocation.
    let Some(out) = out else {
        return Ok(total);
    };

    if key.len() != alg.key_len() || params.key_label.len() > KEY_LABEL_MAX || out.len() < total {
        return Err(HsmError::InvalidArg);
    }

    // Build the metadata record. new_v1 re-checks label length and
    // sets every protocol-fixed byte (magic, version, pad, reserved)
    // so the resulting record always satisfies validate_v1.
    let metadata = MaskedKeyMetadata::new_v1(
        params.key_kind,
        params.key_attrs,
        params.svn,
        params.owner_seed_id,
        params.key_label,
    )?;

    // Stage IV, AAD, and a target-key copy in scoped DMA buffers,
    // mirroring `build_bmk_session` in the TBOR session code path.
    // IV size is alg-dependent (alg.iv_len()).
    let iv = alloc.dma_alloc(alg.iv_len())?;
    crypto.rng_fill_bytes(io, &mut iv[..])?;

    let aad = alloc.dma_alloc(META_LEN)?;
    aad.copy_from_slice(metadata.as_bytes());

    let pt = alloc.dma_alloc(target_key.len())?;
    pt.copy_from_slice(target_key);

    // Seal into `out`. `aead_envelope::seal` writes exactly `total`
    // bytes and returns that count.
    let result = aead_seal(crypto, io, alg, key, iv, aad, pt, Some(out)).await;
    match result {
        Ok(n) => {
            debug_assert_eq!(n, total);
            Ok(n)
        }
        Err(e) => {
            // Best-effort wipe so a partial / unauthenticated blob is
            // never observable in the caller's response buffer.
            out[..total].fill(0);
            Err(e)
        }
    }
}
