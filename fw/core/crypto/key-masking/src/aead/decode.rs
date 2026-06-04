// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Unmasking pipeline ([`unmask`]): authenticate and
//! decrypt a masked-key AEAD blob in place, validate the embedded
//! [`MaskedKeyMetadata`], and hand the caller a borrowed
//! [`UnmaskedView`] covering the recovered plaintext.

use azihsm_fw_core_crypto_aead_envelope::open as aead_open;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmCrypto;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use zerocopy::FromBytes;

use crate::aead::format::MaskedKeyMetadata;
use crate::aead::format::META_LEN;

/// Borrowed view over a successfully unmasked blob.
///
/// All fields are sub-slices / references into the same `blob`
/// buffer passed to [`unmask`]; the `'a` lifetime ties them
/// back to that buffer.
#[derive(Debug)]
pub struct UnmaskedView<'a> {
    /// Vault key kind tag. Surfaced unchanged from the wire byte;
    /// values outside the known [`HsmVaultKeyKind`] variants appear
    /// as `Unknown(u8)` rather than failing decode, so callers can
    /// route or reject as they see fit.
    pub key_kind: HsmVaultKeyKind,

    /// Vault attribute bitfield (PKCS#11-style permissions).
    pub key_attrs: HsmVaultKeyAttrs,

    /// Partition SVN at mask time. Bound by the AEAD tag; the
    /// caller compares this against the current `part_svn` to
    /// enforce anti-rollback policy.
    pub svn: u64,

    /// Owner-seed (BKS2) lineage identifier at mask time. Bound by
    /// the AEAD tag; the caller compares this against the current
    /// `part_bks2_id` to enforce lineage policy.
    pub owner_seed_id: u16,

    /// Caller-supplied label bound by the GCM tag. Length matches
    /// the original `params.key_label` length passed to
    /// [`mask`](crate::aead::mask).
    pub key_label: &'a [u8],

    /// Recovered target-key bytes (decrypted in place inside the
    /// caller's `blob`).
    pub target_key: &'a [u8],
}

/// In-place unmask: parse, authenticate, decrypt, and validate a
/// masked-key blob.
///
/// `blob` MUST contain the complete blob produced by
/// [`mask`](crate::aead::mask) with the same `key`. `blob.len()` is taken
/// as the exact blob length.
///
/// `key`'s required length is determined by the AEAD algorithm byte
/// parsed from the blob's envelope header; mismatches surface as
/// [`HsmError::InvalidKeyLength`](azihsm_fw_hsm_pal_traits::HsmError::InvalidKeyLength).
///
/// # Returns
///
/// * `Ok(view)` — tag verified, ciphertext decrypted in place, every
///   metadata invariant satisfied.
/// * `Err(HsmError::AesGcmDecryptTagDoesNotMatch)` — tag mismatch
///   (tamper / wrong key / corrupted blob).
/// * `Err(HsmError::MaskedKeyDecodeFailed)` — any metadata
///   invariant violation: AAD length not 96, bad magic, unsupported
///   version, `key_label_len > KEY_LABEL_MAX`, non-zero pad after
///   the label, or non-zero reserved tail.
/// * Any [`HsmError`] surfaced by
///   [`aead_envelope::open`](aead_open).
pub async fn unmask<'a>(
    crypto: &impl HsmCrypto,
    io: &impl HsmIo,
    key: &DmaBuf,
    blob: &'a mut DmaBuf,
) -> HsmResult<UnmaskedView<'a>> {
    // aead_envelope::open parses the alg byte from the envelope
    // header, validates the key length against alg.key_len(),
    // verifies the AEAD tag, and decrypts the ciphertext region in
    // place. Tag mismatch surfaces as
    // HsmError::AesGcmDecryptTagDoesNotMatch.
    let env = aead_open(crypto, io, key, blob).await?;

    // Envelope-level schema check: only a 96 B metadata AAD is a
    // masked-key blob. The AEAD algorithm is unconstrained here —
    // the metadata format is alg-agnostic, so any AeadAlg supported
    // by aead_envelope is valid.
    if env.aad.len() != META_LEN {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }

    // Parse the 96 B AAD region as MaskedKeyMetadata. `ref_from_bytes`
    // never panics; the length check above guarantees a 96 B slice.
    let metadata =
        MaskedKeyMetadata::ref_from_bytes(env.aad).map_err(|_| HsmError::MaskedKeyDecodeFailed)?;

    metadata.validate_v1()?;

    // validate_v1 guarantees key_label_len ≤ KEY_LABEL_MAX, so this
    // accessor cannot return an error here.
    let key_label = metadata.key_label()?;

    Ok(UnmaskedView {
        key_label,
        key_kind: metadata.key_kind(),
        key_attrs: metadata.usage_flags(),
        svn: metadata.svn.get(),
        owner_seed_id: metadata.owner_seed_id.get(),
        target_key: env.payload,
    })
}
