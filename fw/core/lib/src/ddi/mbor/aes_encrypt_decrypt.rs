// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI AesEncryptDecrypt command handler.
//!
//! Within an open session, AES-CBC encrypt or decrypt the host-
//! supplied message buffer using a vault-resident AES-128 / 192 /
//! 256 key and a host-supplied 16-byte IV.  The transformed message
//! plus the updated chaining IV are returned so the host can chain
//! subsequent CBC blocks.

use azihsm_fw_ddi_mbor_types::aes_encrypt_decrypt::DdiAesEncryptDecryptReq;
use azihsm_fw_ddi_mbor_types::aes_encrypt_decrypt::DdiAesEncryptDecryptResp;
use azihsm_fw_ddi_mbor_types::DdiAesOp;

use super::*;

/// AES-CBC block size in bytes — also the required IV length.
const AES_BLOCK_LEN: usize = 16;

/// Handle `DdiAesEncryptDecryptCmd`.
pub(crate) async fn aes_encrypt_decrypt<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiAesEncryptDecryptReq = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    let op = ddi_to_pal_aes_op(body.op)?;

    // IV must be exactly one block, message must be non-empty,
    // multiple of one block, and within the wire max (single source
    // of truth: `DdiAesEncryptDecryptReq::MAX_MSG_SIZE`).
    if body.iv.len() != AES_BLOCK_LEN {
        return Err(HsmError::InvalidArg);
    }
    if body.msg.is_empty()
        || !body.msg.len().is_multiple_of(AES_BLOCK_LEN)
        || body.msg.len() > DdiAesEncryptDecryptReq::MAX_MSG_SIZE
    {
        return Err(HsmError::InvalidArg);
    }
    let msg_len = body.msg.len();

    // Look up the vault key; reject anything that is not a non-bulk
    // AES key, or that lacks the attribute matching the requested
    // direction (Encrypt needs `encrypt`, Decrypt needs `decrypt`).
    let key_id = HsmKeyId::from(body.key_id);
    let vault_kind = pal.vault_key_kind(io, key_id)?;
    super::from_pal::assert_aes(vault_kind)?;
    let vault_attrs = pal.vault_key_attrs(io, key_id)?;
    let required_attr = match op {
        AesOp::Encrypt => vault_attrs.encrypt(),
        AesOp::Decrypt => vault_attrs.decrypt(),
    };
    if !required_attr {
        return Err(HsmError::InvalidPermissions);
    }
    let key = pal.vault_key(io, key_id)?;

    // Reserve the response with the exact wire sizes, then run the
    // AES-CBC transform with the slots wired up as follows:
    //   - request msg is staged into the response `msg` slot, which
    //     is then transformed in place;
    //   - request iv is consumed as the input IV (`iv_in`);
    //   - the updated chaining IV produced by the AES engine is
    //     written directly into the response `iv` slot.
    // No scratch buffers are needed: the encoder layout produces
    // disjoint `&mut DmaBuf` views for `msg` and `iv`, so we can
    // pass both to the PAL call without overlap.
    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = super::encode_resp_hdr(
            &super::success_hdr_sess(hdr, DdiOp::AesEncryptDecrypt, sess_id),
            buf,
        )?;
        let layout = DdiAesEncryptDecryptResp::reserve(&mut encoder, msg_len, AES_BLOCK_LEN)?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiAesEncryptDecryptResp::from_layout(resp, &layout);
    frame.msg.copy_from_slice(&body.msg[..msg_len]);
    pal.aes_cbc_enc_dec_in_place(io, op, key, frame.msg, body.iv, Some(frame.iv))
        .await?;

    Ok(resp)
}

/// Map a `DdiAesOp` to the PAL [`AesOp`].
fn ddi_to_pal_aes_op(op: DdiAesOp) -> HsmResult<AesOp> {
    match op {
        DdiAesOp::Encrypt => Ok(AesOp::Encrypt),
        DdiAesOp::Decrypt => Ok(AesOp::Decrypt),
        _ => Err(HsmError::InvalidArg),
    }
}
