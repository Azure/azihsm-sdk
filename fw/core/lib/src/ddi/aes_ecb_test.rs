// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_types::aes_ecb_test::{DdiAesEcbTestReq, DdiAesEcbTestResp};
use azihsm_fw_hsm_pal_traits::AesOp;

use super::*;

pub(crate) async fn aes_ecb_test<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiAesEcbTestReq<'_> = decoder.decode_data()?;

    match body.key.len() {
        16 | 24 | 32 => {}
        _ => return Err(HsmError::InvalidArg),
    }
    if body.data.is_empty() || body.data.len() % 16 != 0 {
        return Err(HsmError::InvalidArg);
    }

    let op = if body.encrypt {
        AesOp::Encrypt
    } else {
        AesOp::Decrypt
    };

    let key_dma = pal.dma_alloc(io, body.key.len())?;
    key_dma.copy_from_slice(body.key);

    let input_dma = pal.dma_alloc(io, body.data.len())?;
    input_dma.copy_from_slice(body.data);

    let output_dma = pal.dma_alloc(io, body.data.len())?;
    pal.aes_ecb_enc_dec(io, op, &*key_dma, &*input_dma, output_dma)
        .await?;

    let resp_data = DdiAesEcbTestResp {
        result: &output_dma[..],
    };

    let resp = pal.dma_alloc_var(io, |buf| {
        ddi::encode_resp(&ddi::success_hdr(hdr, DdiOp::AesEcbTest), &resp_data, buf)
    })?;
    Ok(resp)
}
