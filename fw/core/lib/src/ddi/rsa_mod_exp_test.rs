// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_types::rsa_mod_exp_test::{DdiRsaModExpTestReq, DdiRsaModExpTestResp};

use super::*;

fn ddi_rsa_size_bytes(s: DdiRsaSize) -> HsmResult<usize> {
    match s {
        DdiRsaSize::Rsa2k => Ok(256),
        DdiRsaSize::Rsa3k => Ok(384),
        DdiRsaSize::Rsa4k => Ok(512),
        _ => Err(HsmError::InvalidArg),
    }
}

fn to_hsm_rsa_key(size: DdiRsaSize, kind: DdiRsaOpKind) -> HsmResult<HsmRsaKey> {
    match (size, kind) {
        (DdiRsaSize::Rsa2k, DdiRsaOpKind::Pub) => Ok(HsmRsaKey::Rsa2048Pub),
        (DdiRsaSize::Rsa2k, DdiRsaOpKind::Priv) => Ok(HsmRsaKey::Rsa2048Priv),
        (DdiRsaSize::Rsa3k, DdiRsaOpKind::Pub) => Ok(HsmRsaKey::Rsa3072Pub),
        (DdiRsaSize::Rsa3k, DdiRsaOpKind::Priv) => Ok(HsmRsaKey::Rsa3072Priv),
        (DdiRsaSize::Rsa4k, DdiRsaOpKind::Pub) => Ok(HsmRsaKey::Rsa4096Pub),
        (DdiRsaSize::Rsa4k, DdiRsaOpKind::Priv) => Ok(HsmRsaKey::Rsa4096Priv),
        _ => Err(HsmError::InvalidArg),
    }
}

pub(crate) async fn rsa_mod_exp_test<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiRsaModExpTestReq<'_> = decoder.decode_data()?;
    let n_len = ddi_rsa_size_bytes(body.size)?;
    let key_size = to_hsm_rsa_key(body.size, body.op_kind)?;

    if body.input.len() != n_len {
        return Err(HsmError::InvalidArg);
    }

    let key_dma = pal.dma_alloc(io, body.key.len())?;
    key_dma.copy_from_slice(body.key);

    let input_dma = pal.dma_alloc(io, n_len)?;
    input_dma.copy_from_slice(body.input);

    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = ddi::encode_resp_hdr(&ddi::success_hdr(hdr, DdiOp::RsaModExpTest), buf)?;
        let layout = DdiRsaModExpTestResp::reserve(&mut encoder, n_len)?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiRsaModExpTestResp::from_layout(resp, &layout);

    match body.op_kind {
        DdiRsaOpKind::Pub => {
            pal.mod_exp_pub(io, key_size, &*key_dma, &*input_dma, frame.output)
                .await?
        }
        DdiRsaOpKind::Priv => {
            pal.mod_exp_priv(io, key_size, &*key_dma, &*input_dma, frame.output)
                .await?
        }
        _ => return Err(HsmError::InvalidArg),
    }

    Ok(resp)
}
