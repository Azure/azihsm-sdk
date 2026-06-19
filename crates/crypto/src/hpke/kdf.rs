// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE LabeledExtract and LabeledExpand (RFC 9180 §4).
//!
//! Thin wrappers around [`HkdfAlgo`] that prepend HPKE domain-
//! separation labels:
//!
//! ```text
//! labeled_ikm  = "HPKE-v1" ‖ suite_id ‖ label ‖ ikm
//! labeled_info = I2OSP(L, 2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖ info
//! ```
//!
//! Both helpers allocate small `Vec`s for the labelled buffers — the
//! crate is `std` only and we trade the per-call allocation for a
//! significantly simpler API than the firmware's scoped-allocator
//! equivalent.

use crate::CryptoError;
use crate::DeriveOp;
use crate::ExportableKey;
use crate::GenericSecretKey;
use crate::HashAlgo;
use crate::HkdfAlgo;
use crate::HkdfMode;
use crate::ImportableKey;

/// HPKE version string prepended to every labelled input (RFC 9180 §4).
const HPKE_V1: &[u8] = b"HPKE-v1";

/// `LabeledExtract(salt, label, ikm)` per RFC 9180 §4.
///
/// Returns a fresh `Vec<u8>` of length `algo.size()` (the PRK).
pub(crate) fn labeled_extract(
    algo: &HashAlgo,
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut labeled_ikm =
        Vec::with_capacity(HPKE_V1.len() + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(HPKE_V1);
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    let ikm_key = GenericSecretKey::from_bytes(&labeled_ikm)?;
    let hkdf = HkdfAlgo::new(HkdfMode::Extract, algo, Some(salt), None);
    let prk = hkdf.derive(&ikm_key, algo.size())?;

    extract_bytes(&prk, algo.size())
}

/// `LabeledExpand(prk, label, info, L)` per RFC 9180 §4.
///
/// Returns a fresh `Vec<u8>` of length `out_len`. RFC 9180 caps
/// `out_len` at `255 * Nh`.
pub(crate) fn labeled_expand(
    algo: &HashAlgo,
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    if out_len > 255 * algo.size() {
        return Err(CryptoError::HpkeExportTooLarge);
    }

    let l_bytes = (out_len as u16).to_be_bytes();
    let mut labeled_info =
        Vec::with_capacity(2 + HPKE_V1.len() + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&l_bytes);
    labeled_info.extend_from_slice(HPKE_V1);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    let prk_key = GenericSecretKey::from_bytes(prk)?;
    let hkdf = HkdfAlgo::new(HkdfMode::Expand, algo, None, Some(&labeled_info));
    let okm = hkdf.derive(&prk_key, out_len)?;

    extract_bytes(&okm, out_len)
}

/// Helper to copy bytes out of a `GenericSecretKey` of known length.
fn extract_bytes(key: &GenericSecretKey, len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut out = vec![0u8; len];
    let written = key.to_bytes(Some(&mut out))?;
    out.truncate(written);
    Ok(out)
}
