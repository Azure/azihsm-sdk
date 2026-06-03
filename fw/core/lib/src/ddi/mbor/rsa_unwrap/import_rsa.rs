// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA-private-key import path of [`RsaUnwrap`](super::rsa_unwrap).
//!
//! Imports a **non-CRT** RSA private key recovered from a successful
//! unwrap as **PKCS#8 DER** (the on-wire import encoding) into the
//! partition vault, and returns the vault guard + the response
//! payload the parent handler will encode.
//!
//! Before storing, the DER key is re-encoded into the vault's raw
//! non-CRT HSM form (`n || e || p || q`) via
//! [`HsmRsa::rsa_priv_to_hsm`] so a later `mod_exp_priv` /
//! `rsa_oaep_decrypt` reads it back in the vault-native encoding.
//! This mirrors the ECC import's DER → HSM conversion.
//!
//! CRT private keys use a larger vault layout that the crypto
//! crate's HSM CRT format does not yet match; `RsaUnwrap` rejects
//! `DdiKeyClass::RsaCrt` with `UnsupportedCmd` until that is
//! reconciled in a follow-up change.
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
    let rsa_key_size = pal.rsa_priv_key_size(io, key_bytes)?;
    // Non-CRT import only — `DdiKeyClass::RsaCrt` is rejected by the
    // dispatcher, so this path always tags the non-CRT vault kind.
    let vault_kind = super::super::from_pal::rsa_private(rsa_key_size, /* crt = */ false);
    let key_kind = super::super::from_pal::rsa_private_ddi(rsa_key_size, /* crt = */ false);
    let pub_kind = super::super::from_pal::rsa_public_ddi(rsa_key_size);

    let attrs = super::super::key_attrs::prepare_rsa(
        &body.key_properties.key_metadata,
        body.key_tag,
        /* local = */ false,
    )?;

    // Extract the wire-format pub key (`n_le || e_le`) from the
    // imported priv key so callers can verify the import bytewise
    // without an extra DDI round-trip.
    let pub_wire_len = pal.rsa_priv_pub_key(io, key_bytes, None)?;
    let pub_buf = pal.dma_alloc(io, pub_wire_len)?;
    pal.rsa_priv_pub_key(io, key_bytes, Some(pub_buf))?;

    // Convert the imported PKCS#8 DER private key into the vault's
    // raw non-CRT HSM form before storing, so a later private op
    // reads it back via `from_hsm_bytes`.
    let hsm_len = pal.rsa_priv_to_hsm(io, key_bytes, None)?;
    let hsm_buf = pal.dma_alloc(io, hsm_len)?;
    pal.rsa_priv_to_hsm(io, key_bytes, Some(hsm_buf))?;

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
