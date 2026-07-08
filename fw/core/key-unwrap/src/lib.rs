// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Protocol-neutral RSA-AES key unwrap.
//!
//! This crate implements the *unwrap* half of `CKM_RSA_AES_KEY_WRAP`
//! *once*, independent of the wire protocol that drives it.  The wrapped
//! blob is
//!
//! ```text
//! [ RSA-OAEP(KEK) | AES-KWP_KEK(key material) ]
//! ```
//!
//! — a modulus-sized RSA-OAEP–encrypted ephemeral AES key-encryption key
//! (KEK) followed by the target key wrapped under that KEK with AES-KWP
//! (RFC 5649).  [`unwrap_key`] OAEP-decrypts the KEK with the partition's
//! unwrapping private key and AES-KWP unwraps the payload, returning the
//! *raw* recovered key material.
//!
//! *Classifying* that material into a vault key (and deriving the wire
//! public key) is a separate, reusable concern handled by the `key_decode`
//! crate; *persisting* it is the caller's job.  This crate does only the
//! crypto unwrap, so a future `DerKeyImport` path — which already has the
//! DER and needs no unwrap — shares the classifier without dragging in the
//! unwrap machinery.
//!
//! # Reuse
//!
//! The crate speaks only [`azihsm_fw_hsm_pal_traits`] — never an MBOR or
//! TBOR wire type.  Callers translate their protocol's request into
//! [`UnwrapParams`], then take the returned raw material onward, so a
//! single implementation backs both the MBOR `RsaUnwrap` handler (today)
//! and a future TBOR equivalent.  Concerns that *are* protocol- or
//! partition-specific stay with the caller:
//!
//! - resolving the partition's unwrapping key id (a `part_state` concern
//!   the leaf crate cannot see),
//! - classifying the recovered material and deriving vault attributes,
//!   validating any key tag, and **creating the vault key**, and
//! - response framing, including `masked_key`.

#![no_std]

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmRsaKey;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

/// Maximum key-encryption-key length recovered from OAEP — an AES-256 key.
const MAX_KEK_LEN: usize = 32;

/// Everything [`unwrap_key`] needs, independent of wire protocol.
///
/// The caller has already resolved the partition's unwrapping key
/// (`unwrap_key_id`); this crate performs the unwrapping-key kind /
/// permission checks and the crypto, returning the *raw* recovered key
/// material.  Classifying and persisting it is the caller's job (a raw AES
/// key, or a DER-encoded RSA / ECC private key — see the `key_decode`
/// crate).
pub struct UnwrapParams<'a> {
    /// Vault id of the partition's RSA-2048 unwrapping private key.
    pub unwrap_key_id: HsmKeyId,
    /// OAEP hash algorithm used to wrap the KEK.
    pub oaep_hash: HsmHashAlgo,
    /// The wrapped blob `[ RSA-OAEP(KEK) | AES-KWP(key material) ]`.
    pub wrapped_blob: &'a DmaBuf,
}

/// Unwrap a host-supplied `CKM_RSA_AES_KEY_WRAP` blob, returning the *raw*
/// recovered key material for the caller to classify and persist.
///
/// Steps: validate the unwrapping key (device-internal, locally generated
/// RSA-2048 with `unwrap` permission), split the blob, OAEP-decrypt the
/// KEK, then AES-KWP unwrap the payload.  The returned bytes are the
/// unwrapped target key exactly as the host wrapped it — a raw AES key, or
/// a DER-encoded RSA / ECC private key.  The buffer is returned *mutably*
/// so the caller (the `key_decode` crate) can convert it into the vault
/// representation in place, without allocating a second large DMA buffer.
///
/// # Errors
/// - [`HsmError::RsaUnwrapInvalidRequest`] — the unwrapping key is not a
///   device-internal, locally generated RSA-2048 private key, or the blob
///   is too short to hold a KEK.
/// - [`HsmError::InvalidPermissions`] — the key lacks the `unwrap`
///   permission.
/// - [`HsmError::RsaUnwrapInvalidKek`] — the OAEP-recovered KEK is empty
///   or larger than an AES-256 key.
/// - [`HsmError::RsaUnwrapAesUnwrapFailed`] — the AES-KWP AIV / padding
///   integrity check failed (wrong KEK, tampering, or corruption).
/// - [`HsmError::InvalidArg`] — the wrapped payload violates the AES-KWP
///   size constraints.
/// - Propagated OAEP / KWP failures.
pub async fn unwrap_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    params: UnwrapParams<'_>,
) -> HsmResult<&'p mut DmaBuf> {
    // The unwrapping key must be the partition's device-internal, locally
    // generated RSA-2048 private key that carries the `unwrap` permission.
    // `internal` is the load-bearing check: it is set *only* by the device
    // when it provisions the unwrapping key and by no host path, so no
    // host-supplied key can forge it.  `local` and `unwrap` are required
    // too and are consistent with that provenance — keys imported through
    // this engine are marked neither internal nor local.  This mirrors the
    // reference firmware, which isolates the unwrapping key in an
    // internal-keys vault.
    if pal.vault_key_kind(io, params.unwrap_key_id)? != HsmVaultKeyKind::Rsa2kPrivate {
        return Err(HsmError::RsaUnwrapInvalidRequest);
    }
    let attrs = pal.vault_key_attrs(io, params.unwrap_key_id)?;
    if !attrs.internal() || !attrs.local() {
        return Err(HsmError::RsaUnwrapInvalidRequest);
    }
    if !attrs.unwrap() {
        return Err(HsmError::InvalidPermissions);
    }

    // Split the blob into the OAEP-wrapped KEK (modulus-sized leading
    // segment) and the AES-KWP payload (the remainder).
    let modulus_len = HsmRsaKey::Rsa2048Priv.modulus_len();
    if params.wrapped_blob.len() <= modulus_len {
        return Err(HsmError::RsaUnwrapInvalidRequest);
    }
    let (oaep_ct, kwp_payload) = params.wrapped_blob.split_at(modulus_len);

    // 1. OAEP-decrypt the KEK with the unwrapping private key.  The std
    //    PAL driver flips the wire-LE ciphertext to big-endian for
    //    OpenSSL and decrypts through modulus-sized internal scratch,
    //    returning the recovered length.  The output buffer only needs to
    //    hold the recovered plaintext, so size it to the largest KEK we
    //    accept (an AES-256 key).  A longer recovered plaintext is rejected
    //    by the PAL as `RsaInvalidKeyLength`, which we remap to the
    //    command-specific `RsaUnwrapInvalidKek` (the wrong length is the
    //    KEK's, not the unwrapping key's); the `kek_len` check below rejects
    //    a zero-length KEK.
    let kek_buf = pal.dma_alloc(io, MAX_KEK_LEN)?;
    // The OAEP label is always empty here; carve a zero-length view off the
    // KEK buffer rather than a separate `dma_alloc(io, 0)` (which would still
    // advance the bump-allocator watermark via alignment padding, wasting the
    // scarce per-IO DMA budget).
    let (label, kek_buf) = kek_buf.split_at_mut(0);
    let kek_len = pal
        .alloc_scoped_async(io, async |a| -> HsmResult<usize> {
            let priv_key = pal.vault_key(io, params.unwrap_key_id)?;
            pal.rsa_oaep_decrypt(
                io,
                HsmRsaKey::Rsa2048Priv,
                params.oaep_hash,
                priv_key,
                oaep_ct,
                &*label,
                &mut *kek_buf,
                a,
            )
            .await
            // An oversized recovered KEK (plaintext larger than the
            // `MAX_KEK_LEN` output buffer) comes back as
            // `RsaInvalidKeyLength`; surface it as the KEK-specific error.
            .map_err(|e| match e {
                HsmError::RsaInvalidKeyLength => HsmError::RsaUnwrapInvalidKek,
                other => other,
            })
        })
        .await?;
    if kek_len == 0 || kek_len > MAX_KEK_LEN {
        return Err(HsmError::RsaUnwrapInvalidKek);
    }

    // 2. AES-KWP unwrap the payload with the recovered KEK.
    let payload_buf = pal.dma_alloc(io, kwp_payload.len())?;
    let payload_len = pal
        .aes_kwp_unwrap(io, &kek_buf[..kek_len], kwp_payload, payload_buf)
        .await
        // An AIV / padding integrity failure comes back as
        // `AesUnwrapFailed`; surface it as the unwrap-specific status (the
        // sim reports the same `RsaUnwrapAesUnwrapFailed`).  A malformed
        // payload length stays `InvalidArg` so size faults remain distinct.
        .map_err(|e| match e {
            HsmError::AesUnwrapFailed => HsmError::RsaUnwrapAesUnwrapFailed,
            other => other,
        })?;
    // Return the raw recovered key material *mutably* so the caller can
    // convert it into the vault representation in place (avoiding a second
    // large DMA buffer); see the `key_decode` crate.
    Ok(&mut payload_buf[..payload_len])
}
