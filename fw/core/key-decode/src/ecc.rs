// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECC private-key decode path.
//!
//! Converts a PKCS#8 DER ECC private key into the PAL's vault
//! representation (HSM-format scalar bytes), classifies its curve, derives
//! its wire public key, and returns the [`DecodedKey`](super::DecodedKey)
//! the caller persists.
//!
//! The ECC vault stores the PAL's own HSM-format scalar bytes, so the
//! recovered PKCS#8 DER is converted (not stored as-is).  The crate is
//! `no_std` and cannot parse DER, so the parse + curve classification +
//! conversion is delegated to
//! [`HsmEcc::ecc_priv_der_to_vault`](azihsm_fw_hsm_pal_traits::HsmEcc::ecc_priv_der_to_vault).

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::DecodedKey;

/// Convert a DER-encoded ECC private key into the vault representation and
/// derive its wire public key.
pub(super) async fn decode<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    material: &DmaBuf,
) -> HsmResult<DecodedKey<'p>> {
    // Convert the recovered PKCS#8 DER into the vault representation (the
    // PAL parses and classifies the curve).  Query the length, then
    // serialize into a freshly allocated buffer that becomes the vault
    // material.
    let (vault_len, curve) = pal.ecc_priv_der_to_vault(io, material, None)?;
    let vault_buf = pal.dma_alloc(io, vault_len)?;
    pal.ecc_priv_der_to_vault(io, material, Some(&mut *vault_buf))?;

    let kind = vault_kind(curve);

    // Derive the wire public key (`x || y`) from the vault-format private
    // key, following the PAL's query/alloc/use convention.
    let pub_len = pal.ecc_priv_pub_key(io, vault_buf, None).await?;
    let pub_key = pal.dma_alloc(io, pub_len)?;
    pal.ecc_priv_pub_key(io, vault_buf, Some(&mut *pub_key))
        .await?;

    Ok(DecodedKey {
        kind,
        material: vault_buf,
        pub_key: Some(pub_key),
    })
}

/// Map an ECC curve to its private-key vault kind.
fn vault_kind(curve: HsmEccCurve) -> HsmVaultKeyKind {
    match curve {
        HsmEccCurve::P256 => HsmVaultKeyKind::Ecc256Private,
        HsmEccCurve::P384 => HsmVaultKeyKind::Ecc384Private,
        HsmEccCurve::P521 => HsmVaultKeyKind::Ecc521Private,
    }
}
