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
