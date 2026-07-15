// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! PAL trait type conversions shared by handlers.
//!
//! Sibling to [`from_ddi`](super::from_ddi): given a firmware-side
//! PAL type ([`HsmVaultKeyKind`], [`HsmEccCurve`], …), produce a
//! related firmware-side or on-wire DDI type that the handler needs
//! to drive the response or validate caller input.  Centralizing
//! these mappings keeps the per-curve / per-kind enum tables in
//! sync across handlers and pins the error code used for
//! non-matching variants in one place.
//!
//! Functions are intentionally bare-named (`ecc_curve`,
//! `assert_aes`, `ecc_private`, …) so call sites read as
//! `from_pal::ecc_curve(kind)` / `from_pal::ecc_private(curve)`.
//! The first parameter's type pins the conversion direction; function
//! names whose target type is a [`DdiKeyType`] (on-wire) carry a
//! `_ddi` suffix to distinguish them from vault-kind targets.

use azihsm_fw_ddi_mbor_types::DdiKeyType;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmRsaKey;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

// ── HsmVaultKeyKind → … ───────────────────────────────────────────

/// Map an HMAC vault kind to the hash algorithm whose digest length
/// is the MAC tag size.
///
/// Accepts both the fixed-length (`_HmacSha*`) and variable-length
/// (`VarLenHmacSha*`) HMAC kinds — mirroring the reference firmware's
/// `Hmac` handler.  Any non-HMAC kind returns
/// [`HsmError::InvalidKeyType`].
pub(crate) fn hmac_hash(kind: HsmVaultKeyKind) -> HsmResult<HsmHashAlgo> {
    match kind {
        HsmVaultKeyKind::_HmacSha256 | HsmVaultKeyKind::VarLenHmacSha256 => Ok(HsmHashAlgo::Sha256),
        HsmVaultKeyKind::_HmacSha384 | HsmVaultKeyKind::VarLenHmacSha384 => Ok(HsmHashAlgo::Sha384),
        HsmVaultKeyKind::_HmacSha512 | HsmVaultKeyKind::VarLenHmacSha512 => Ok(HsmHashAlgo::Sha512),
        _ => Err(HsmError::InvalidKeyType),
    }
}

/// Map an ECC private vault kind to its [`HsmEccCurve`].
/// Non-ECC kinds return [`HsmError::InvalidKeyType`].
pub(crate) fn ecc_curve(kind: HsmVaultKeyKind) -> HsmResult<HsmEccCurve> {
    match kind {
        HsmVaultKeyKind::Ecc256Private => Ok(HsmEccCurve::P256),
        HsmVaultKeyKind::Ecc384Private => Ok(HsmEccCurve::P384),
        HsmVaultKeyKind::Ecc521Private => Ok(HsmEccCurve::P521),
        _ => Err(HsmError::InvalidKeyType),
    }
}

/// Confirm a vault kind is a non-bulk AES key (128 / 192 / 256
/// bits).  Bulk AES variants (XTS / GCM) and any non-AES kind
/// return [`HsmError::InvalidKeyType`].
pub(crate) fn assert_aes(kind: HsmVaultKeyKind) -> HsmResult<()> {
    match kind {
        HsmVaultKeyKind::Aes128 | HsmVaultKeyKind::Aes192 | HsmVaultKeyKind::Aes256 => Ok(()),
        _ => Err(HsmError::InvalidKeyType),
    }
}

/// Map an RSA private vault kind (plain or CRT) to its [`HsmRsaKey`]
/// modulus-size selector.  Any non-RSA-private kind returns
/// [`HsmError::InvalidKeyType`].
pub(crate) fn rsa_key(kind: HsmVaultKeyKind) -> HsmResult<HsmRsaKey> {
    match kind {
        HsmVaultKeyKind::Rsa2kPrivate => Ok(HsmRsaKey::Rsa2048Priv),
        HsmVaultKeyKind::Rsa3kPrivate => Ok(HsmRsaKey::Rsa3072Priv),
        HsmVaultKeyKind::Rsa4kPrivate => Ok(HsmRsaKey::Rsa4096Priv),
        HsmVaultKeyKind::Rsa2kPrivateCrt => Ok(HsmRsaKey::Rsa2048CrtPriv),
        HsmVaultKeyKind::Rsa3kPrivateCrt => Ok(HsmRsaKey::Rsa3072CrtPriv),
        HsmVaultKeyKind::Rsa4kPrivateCrt => Ok(HsmRsaKey::Rsa4096CrtPriv),
        _ => Err(HsmError::InvalidKeyType),
    }
}

/// Map a vault key kind to the on-wire [`DdiKeyType`] tag recorded in
/// a masked-key blob's metadata.  Only the kinds that a key-creating
/// or key-importing handler can mask are accepted; public, internal,
/// and session-schedule kinds return [`HsmError::InvalidKeyType`].
///
/// The unwrapping key is an RSA private key in the vault but is
/// tagged `RsaUnwrap` in its masked metadata by the
/// [`get_unwrapping_key`](super::get_unwrapping_key) handler, which
/// passes that type explicitly rather than going through this map.
pub(crate) fn vault_kind_ddi(kind: HsmVaultKeyKind) -> HsmResult<DdiKeyType> {
    match kind {
        HsmVaultKeyKind::Rsa2kPrivate => Ok(DdiKeyType::Rsa2kPrivate),
        HsmVaultKeyKind::Rsa3kPrivate => Ok(DdiKeyType::Rsa3kPrivate),
        HsmVaultKeyKind::Rsa4kPrivate => Ok(DdiKeyType::Rsa4kPrivate),
        HsmVaultKeyKind::Rsa2kPrivateCrt => Ok(DdiKeyType::Rsa2kPrivateCrt),
        HsmVaultKeyKind::Rsa3kPrivateCrt => Ok(DdiKeyType::Rsa3kPrivateCrt),
        HsmVaultKeyKind::Rsa4kPrivateCrt => Ok(DdiKeyType::Rsa4kPrivateCrt),
        HsmVaultKeyKind::Ecc256Private => Ok(DdiKeyType::Ecc256Private),
        HsmVaultKeyKind::Ecc384Private => Ok(DdiKeyType::Ecc384Private),
        HsmVaultKeyKind::Ecc521Private => Ok(DdiKeyType::Ecc521Private),
        HsmVaultKeyKind::Aes128 => Ok(DdiKeyType::Aes128),
        HsmVaultKeyKind::Aes192 => Ok(DdiKeyType::Aes192),
        HsmVaultKeyKind::Aes256 => Ok(DdiKeyType::Aes256),
        HsmVaultKeyKind::AesXtsBulk256 => Ok(DdiKeyType::AesXtsBulk256),
        HsmVaultKeyKind::AesGcmBulk256 => Ok(DdiKeyType::AesGcmBulk256),
        HsmVaultKeyKind::AesGcmBulk256Unapproved => Ok(DdiKeyType::AesGcmBulk256Unapproved),
        HsmVaultKeyKind::Secret256 => Ok(DdiKeyType::Secret256),
        HsmVaultKeyKind::Secret384 => Ok(DdiKeyType::Secret384),
        HsmVaultKeyKind::Secret521 => Ok(DdiKeyType::Secret521),
        HsmVaultKeyKind::VarLenHmacSha256 => Ok(DdiKeyType::VarHmac256),
        HsmVaultKeyKind::VarLenHmacSha384 => Ok(DdiKeyType::VarHmac384),
        HsmVaultKeyKind::VarLenHmacSha512 => Ok(DdiKeyType::VarHmac512),
        _ => Err(HsmError::InvalidKeyType),
    }
}

// ── HsmEccCurve → … ───────────────────────────────────────────────

/// Map a [`HsmEccCurve`] to its private ECC vault kind.
pub(crate) fn ecc_private(curve: HsmEccCurve) -> HsmVaultKeyKind {
    match curve {
        HsmEccCurve::P256 => HsmVaultKeyKind::Ecc256Private,
        HsmEccCurve::P384 => HsmVaultKeyKind::Ecc384Private,
        HsmEccCurve::P521 => HsmVaultKeyKind::Ecc521Private,
    }
}

/// Map a [`HsmEccCurve`] to the ECDH shared-secret vault kind for
/// that curve's bit length.
pub(crate) fn ecdh_secret(curve: HsmEccCurve) -> HsmVaultKeyKind {
    match curve {
        HsmEccCurve::P256 => HsmVaultKeyKind::Secret256,
        HsmEccCurve::P384 => HsmVaultKeyKind::Secret384,
        HsmEccCurve::P521 => HsmVaultKeyKind::Secret521,
    }
}

/// Map a [`HsmEccCurve`] to the matching DDI public-key type tag
/// the host expects in an ECC response (or in a target-key request
/// field).
pub(crate) fn ecc_public_ddi(curve: HsmEccCurve) -> DdiKeyType {
    match curve {
        HsmEccCurve::P256 => DdiKeyType::Ecc256Public,
        HsmEccCurve::P384 => DdiKeyType::Ecc384Public,
        HsmEccCurve::P521 => DdiKeyType::Ecc521Public,
    }
}

/// Map a [`HsmEccCurve`] to the matching DDI shared-secret key type
/// tag the host requests as the ECDH derive target.
pub(crate) fn ecdh_secret_ddi(curve: HsmEccCurve) -> DdiKeyType {
    match curve {
        HsmEccCurve::P256 => DdiKeyType::Secret256,
        HsmEccCurve::P384 => DdiKeyType::Secret384,
        HsmEccCurve::P521 => DdiKeyType::Secret521,
    }
}
