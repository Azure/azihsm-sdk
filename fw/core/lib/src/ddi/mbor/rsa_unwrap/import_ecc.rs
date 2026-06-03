// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECC-private-key import path of [`RsaUnwrap`](super::rsa_unwrap).
//!
//! Imports an ECC private key recovered from a successful unwrap as
//! **PKCS#8 DER** (the on-wire import encoding) into the partition
//! vault, and returns the vault guard + the response payload the
//! parent handler will encode.  The handler introspects the curve
//! via [`HsmEcc::ecc_priv_key_curve`] so a single `DdiKeyClass::Ecc`
//! request covers all three NIST curves; the matching vault kind and
//! DDI key-type tags are derived from the curve via
//! [`from_pal`](super::super::from_pal).
//!
//! Before storing, the DER key is re-encoded into the vault's raw
//! HSM scalar form via [`HsmEcc::ecc_priv_to_hsm`] so a later
//! `EccSign` / `EcdhKeyExchange` reads it back in the vault-native
//! encoding.  This mirrors the RSA import's DER → HSM conversion.
//!
//! The response also surfaces the wire-format public key so the
//! caller can verify the import bytewise without an extra DDI
//! round-trip.

use azihsm_fw_ddi_mbor_types::rsa_unwrap::DdiRsaUnwrapReq;
use azihsm_fw_ddi_mbor_types::rsa_unwrap::DdiRsaUnwrapResp;

use super::super::*;

pub(super) fn import<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    sess_id: u16,
    body: &DdiRsaUnwrapReq<'_>,
    key_bytes: &DmaBuf,
) -> HsmResult<(<P as HsmVault>::KeyGuard<'p>, DdiRsaUnwrapResp<'p>)> {
    let curve = pal.ecc_priv_key_curve(io, key_bytes)?;
    let vault_kind = super::super::from_pal::ecc_private(curve);
    let key_kind = super::super::from_pal::ecc_private_ddi(curve);
    let pub_kind = super::super::from_pal::ecc_public_ddi(curve);

    let attrs = super::super::key_attrs::prepare_ecc(
        curve,
        &body.key_properties.key_metadata,
        body.key_tag,
        /* local = */ false,
    )?;

    // Extract the wire-format pub key (`x_le || y_le`, P-521 padded
    // to 4-byte words) from the imported priv key so callers can
    // verify the import bytewise without an extra DDI round-trip.
    let pub_wire_len = pal.ecc_priv_pub_key(io, key_bytes, None)?;
    let pub_buf = pal.dma_alloc(io, pub_wire_len)?;
    pal.ecc_priv_pub_key(io, key_bytes, Some(pub_buf))?;

    // Convert the imported PKCS#8 DER private key into the vault's
    // raw HSM scalar form before storing, so a later EccSign/ECDH
    // reads it back via `from_hsm_bytes`.  Mirrors the RSA import's
    // DER → HSM conversion.
    let hsm_len = pal.ecc_priv_to_hsm(io, key_bytes, None)?;
    let hsm_buf = pal.dma_alloc(io, hsm_len)?;
    pal.ecc_priv_to_hsm(io, key_bytes, Some(hsm_buf))?;

    let session_binding = attrs.session().then_some(HsmSessId::from(sess_id));
    let guard = pal.vault_key_create(
        io,
        hsm_buf,
        vault_kind,
        session_binding,
        attrs,
        body.key_properties.key_label,
    )?;
    let key_id: u16 = guard.key_id().into();

    let resp = DdiRsaUnwrapResp {
        key_id,
        pub_key: Some(DdiPublicKey {
            raw: pub_buf,
            key_kind: pub_kind,
        }),
        bulk_key_id: None,
        kind: key_kind,
        masked_key: &[],
    };
    Ok((guard, resp))
}
