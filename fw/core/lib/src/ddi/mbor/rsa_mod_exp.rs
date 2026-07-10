// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI RsaModExp command handler.
//!
//! Within an open session, perform the RSA private-key primitive
//! `x = y^d mod n` using a vault-resident RSA private key (CRT or
//! non-CRT) and return the result.  This is the raw modular
//! exponentiation underlying RSA decrypt / sign — the host applies
//! and removes any padding.
//!
//! The key must be an RSA private key whose attributes permit the
//! requested operation: `Decrypt` requires `CKA_DECRYPT`, `Sign`
//! requires `CKA_SIGN`.  A non-RSA key is rejected with
//! `InvalidKeyType`, an unknown `key_id` with `KeyNotFound`, and a
//! key lacking the required usage with `InvalidPermissions`.  The
//! input `y` must be exactly the key's modulus length.

use azihsm_fw_ddi_mbor_types::rsa_mod_exp::DdiRsaModExpReq;
use azihsm_fw_ddi_mbor_types::rsa_mod_exp::DdiRsaModExpResp;
use azihsm_fw_ddi_mbor_types::DdiRsaOpType;

use super::*;

/// Handle `DdiRsaModExpCmd`.
///
/// No `partition_lock` is needed: this handler only reads vault state
/// (the RSA private key) and computes `y^d mod n` — it performs no
/// partition mutation.
pub(crate) async fn rsa_mod_exp<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiRsaModExpReq = decoder.decode_data()?;
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let key_id = HsmKeyId::from(body.key_id);

    // The key must be an RSA private key (plain or CRT); the size
    // selector also drives the modulus length below.  Non-RSA kinds
    // map to `InvalidKeyType`; an unknown id to `KeyNotFound`.
    let key_size = super::from_pal::rsa_key(pal.vault_key_kind(io, key_id)?)?;

    // The permitted operation depends on the key's usage attributes:
    // a decrypt primitive needs `CKA_DECRYPT`, a sign primitive needs
    // `CKA_SIGN`.
    let attrs = pal.vault_key_attrs(io, key_id)?;
    let permitted = match body.op_type {
        DdiRsaOpType::Decrypt => attrs.decrypt(),
        DdiRsaOpType::Sign => attrs.sign(),
        _ => return Err(HsmError::InvalidArg),
    };
    if !permitted {
        return Err(HsmError::InvalidPermissions);
    }

    // The input integer must be exactly the modulus length.
    let modulus_len = key_size.modulus_len();
    if body.y.len() != modulus_len {
        return Err(HsmError::InvalidArg);
    }

    // Compute `x = y^d mod n` directly into the response's `x` slot —
    // reserve the slot in the response buffer and hand it to the PAL, so
    // there is no separate scratch buffer or copy.
    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = super::encode_resp_hdr(
            &super::success_hdr_sess(hdr, DdiOp::RsaModExp, sess_id),
            buf,
        )?;
        let layout = DdiRsaModExpResp::reserve(&mut encoder, modulus_len)?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiRsaModExpResp::from_layout(resp, &layout);
    let key = pal.vault_key(io, key_id)?;
    pal.mod_exp_priv(io, key_size, key, body.y, frame.x).await?;

    Ok(resp)
}
