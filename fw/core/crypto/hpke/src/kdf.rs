// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE LabeledExtract and LabeledExpand (RFC 9180 §4).
//!
//! These are thin wrappers that prepend HPKE domain-separation labels
//! before calling the PAL's HKDF Extract/Expand:
//!
//! ```text
//! labeled_ikm  = "HPKE-v1" || suite_id || label || ikm
//! labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
//! ```
//!
//! Both helpers assemble their labelled buffer from the caller's
//! [`HsmScopedAlloc`], while the PAL allocates any internal HKDF scratch
//! per call.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKdf;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::helpers::dma_copy_in;

// =============================================================================
// Constants
// =============================================================================

/// HPKE version string prepended to every labelled input (RFC 9180 §4).
const HPKE_V1: &[u8] = b"HPKE-v1";

// =============================================================================
// Helpers
// =============================================================================

/// Allocate a buffer from `alloc`, concatenate `parts` into it, and
/// return the filled slice.
///
/// The returned buffer is scoped to the surrounding PAL allocation
/// region and is released automatically when that alloc ends.
fn concat_alloc<'a>(parts: &[&[u8]], alloc: &'a impl HsmScopedAlloc) -> HsmResult<&'a mut DmaBuf> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let dst = alloc.dma_alloc(total)?;
    let mut pos = 0;
    for part in parts {
        dst[pos..pos + part.len()].copy_from_slice(part);
        pos += part.len();
    }
    Ok(dst)
}

// =============================================================================
// Labelled Extract / Expand
// =============================================================================

/// HPKE `LabeledExtract` (RFC 9180 §4):
///
/// ```text
/// labeled_ikm = "HPKE-v1" || suite_id || label || ikm
/// PRK         = Extract(salt, labeled_ikm)
/// ```
///
/// Allocates `labeled_ikm` and the output scratch from `alloc`,
/// while the PAL allocates its internal HKDF scratch per call.
///
/// # Type parameters
///
/// * `P` — any [`HsmKdf`] PAL implementation.
///
/// # Parameters
///
/// * `pal` — PAL providing the underlying HKDF.
/// * `io` — caller's I/O context (per-IO scope).
/// * `algo` — hash algorithm used by HKDF (selects `Nh`).
/// * `suite_id` — HPKE suite identifier (`"HPKE" || I2OSP(kem_id,
///   2) || …`, opaque to this function).
/// * `salt` — HKDF salt (may be empty).
/// * `label` — context-specific label (e.g. `b"eae_prk"`).
/// * `ikm` — input keying material.
/// * `prk_out` — destination buffer for the pseudo-random key;
///   must be at least `algo.digest_len()` bytes.  Only the leading
///   `digest_len` bytes are written.
/// * `alloc` — scoped allocator used for the labelled input buffer
///   and output scratch.
///
/// # Returns
///
/// * `Ok(())` — `prk_out[..digest_len]` populated.
/// * `Err(HsmError::NotEnoughSpace)` — one of the required scoped
///   allocations could not be satisfied.
/// * `Err(HsmError)` — propagated from
///   [`HsmKdf::hkdf_extract`].
pub async fn labeled_extract<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    algo: HsmHashAlgo,
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
    prk_out: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmKdf + HsmAlloc + 'a,
{
    let labeled_ikm = concat_alloc(&[HPKE_V1, suite_id, label, ikm], alloc)?;
    let salt_dma = dma_copy_in(alloc, salt)?;
    let prk_scratch = alloc.dma_alloc(prk_out.len())?;
    pal.hkdf_extract(io, algo, Some(salt_dma), labeled_ikm, prk_scratch)
        .await?;
    prk_out.copy_from_slice(prk_scratch);
    Ok(())
}

/// HPKE `LabeledExpand` (RFC 9180 §4):
///
/// ```text
/// labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
/// out          = Expand(prk, labeled_info, L)
/// ```
///
/// Allocates `labeled_info` and the output scratch from `alloc`,
/// while the PAL allocates its internal HKDF scratch per call.
///
/// # Type parameters
///
/// * `P` — any [`HsmKdf`] PAL implementation.
///
/// # Parameters
///
/// * `pal` — PAL providing the underlying HKDF.
/// * `io` — caller's I/O context (per-IO scope).
/// * `algo` — hash algorithm used by HKDF.
/// * `suite_id` — HPKE suite identifier.
/// * `prk` — pseudo-random key from a prior
///   [`labeled_extract`] call.
/// * `label` — context-specific label (e.g. `b"shared_secret"`).
/// * `info` — application-specific context bytes (may be empty).
/// * `out` — destination buffer; `L = out.len()` is encoded as a
///   2-byte big-endian prefix in `labeled_info`.  RFC 9180 caps
///   `L` at `255 * Nh`.
/// * `alloc` — scoped allocator used for the labelled input buffer
///   and output scratch.
///
/// # Returns
///
/// * `Ok(())` — `out` filled with the derived key bytes.
/// * `Err(HsmError::InvalidArg)` — `out.len() > 255 * Nh`
///   (propagated from `hkdf_expand`).
/// * `Err(HsmError::NotEnoughSpace)` — one of the required scoped
///   allocations could not be satisfied.
/// * `Err(HsmError)` — propagated from
///   [`HsmKdf::hkdf_expand`].
pub async fn labeled_expand<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    algo: HsmHashAlgo,
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<()>
where
    P: HsmKdf + HsmAlloc + 'a,
{
    let l_bytes = (out.len() as u16).to_be_bytes();
    let prk_dma = dma_copy_in(alloc, prk)?;
    let labeled_info = concat_alloc(&[&l_bytes, HPKE_V1, suite_id, label, info], alloc)?;
    let out_scratch = alloc.dma_alloc(out.len())?;
    pal.hkdf_expand(io, algo, prk_dma, Some(labeled_info), out_scratch)
        .await?;
    out.copy_from_slice(out_scratch);
    Ok(())
}
