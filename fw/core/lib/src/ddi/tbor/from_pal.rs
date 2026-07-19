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
/// P-384 key that TBOR `KeyReport` attests.
pub(crate) fn ecc_curve(kind: HsmVaultKeyKind) -> Option<HsmEccCurve> {
    match kind {
        HsmVaultKeyKind::Ecc256Private => Some(HsmEccCurve::P256),
        HsmVaultKeyKind::Ecc384Private | HsmVaultKeyKind::SdSealing => Some(HsmEccCurve::P384),
        HsmVaultKeyKind::Ecc521Private => Some(HsmEccCurve::P521),
        _ => None,
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
