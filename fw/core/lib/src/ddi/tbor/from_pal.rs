// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! PAL trait type conversions shared by TBOR handlers.
//!
//! The TBOR-side counterpart of the MBOR handlers' `from_pal` table.
//! It is intentionally a **separate** copy rather than a shared import:
//! keeping `tbor` independent of `mbor` (see [`crate::ddi`]) is worth a
//! small, self-contained table here, and TBOR-only vault kinds (e.g.
//! [`HsmVaultKeyKind::SdSealing`]) belong only in this table.

use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmRsaKey;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

/// Map an ECC-private vault key kind to its NIST curve, or `None` if the
/// kind is not an attestable ECC private key.
///
/// Includes [`HsmVaultKeyKind::SdSealing`] — the SD sealing key is a
/// P-384 key that TBOR `KeyReport` attests.  For the general crypto
/// commands (`EccSign` / `EcdhDerive`), which must reject non-ECC-private
/// blobs, use the stricter [`ecc_private_curve`] instead.
pub(crate) fn ecc_curve(kind: HsmVaultKeyKind) -> Option<HsmEccCurve> {
    match kind {
        HsmVaultKeyKind::Ecc256Private => Some(HsmEccCurve::P256),
        HsmVaultKeyKind::Ecc384Private | HsmVaultKeyKind::SdSealing => Some(HsmEccCurve::P384),
        HsmVaultKeyKind::Ecc521Private => Some(HsmEccCurve::P521),
        _ => None,
    }
}

/// Recover the NIST curve of an unmasked ECC **private** key from its
/// vault key kind, strictly.
///
/// Only the three ECC-private kinds are accepted; any other kind — a
/// public key, an ECDH secret, an [`HsmVaultKeyKind::SdSealing`] key, or a
/// non-ECC kind — maps to [`HsmError::InvalidKeyType`].  Unlike
/// [`ecc_curve`] (which admits `SdSealing` for `KeyReport` attestation),
/// this is the mapping the `EccSign` / `EcdhDerive` handlers use so a
/// masked blob of the wrong class is rejected before use — mirroring the
/// MBOR `from_pal::ecc_curve` precedent.
pub(crate) fn ecc_private_curve(kind: HsmVaultKeyKind) -> HsmResult<HsmEccCurve> {
    match kind {
        HsmVaultKeyKind::Ecc256Private => Ok(HsmEccCurve::P256),
        HsmVaultKeyKind::Ecc384Private => Ok(HsmEccCurve::P384),
        HsmVaultKeyKind::Ecc521Private => Ok(HsmEccCurve::P521),
        _ => Err(HsmError::InvalidKeyType),
    }
}

/// Map a NIST curve onto its ECC-private vault key kind (recorded in the
/// masked blob's metadata so `EccSign` / `EcdhDerive` can recover the
/// curve on unmask).
pub(crate) fn ecc_private(curve: HsmEccCurve) -> HsmVaultKeyKind {
    match curve {
        HsmEccCurve::P256 => HsmVaultKeyKind::Ecc256Private,
        HsmEccCurve::P384 => HsmVaultKeyKind::Ecc384Private,
        HsmEccCurve::P521 => HsmVaultKeyKind::Ecc521Private,
    }
}

/// Map a NIST curve onto its ECDH shared-secret vault key kind (recorded
/// in the derived-secret masked blob's metadata).
pub(crate) fn ecdh_secret(curve: HsmEccCurve) -> HsmVaultKeyKind {
    match curve {
        HsmEccCurve::P256 => HsmVaultKeyKind::Secret256,
        HsmEccCurve::P384 => HsmVaultKeyKind::Secret384,
        HsmEccCurve::P521 => HsmVaultKeyKind::Secret521,
    }
}

/// Map an RSA-private vault key kind (plain or CRT) to its PAL modulus
/// selector, strictly.
///
/// Only the six RSA-private kinds are accepted; any other kind — an RSA
/// public key, a non-RSA kind — maps to [`HsmError::InvalidKeyType`], so a
/// masked blob of the wrong class is rejected before use (mirrors the MBOR
/// `from_pal::rsa_key` precedent used by `RsaModExp`).
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
