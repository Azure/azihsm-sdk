// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_types::aes_cbc_test::{DdiAesCbcTestReq, DdiAesCbcTestResp};
use azihsm_fw_hsm_pal_traits::AesOp;

use super::*;

pub(crate) async fn aes_cbc_test<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiAesCbcTestReq<'_> = decoder.decode_data()?;

    match body.key.len() {
        16 | 24 | 32 => {}
        _ => return Err(HsmError::InvalidArg),
    }
    if body.iv.len() != 16 || body.data.is_empty() || body.data.len() % 16 != 0 {
        return Err(HsmError::InvalidArg);
    }

    let op = if body.encrypt {
        AesOp::Encrypt
    } else {
        AesOp::Decrypt
    };
    let data_len = body.data.len();

    let key_dma = pal.dma_alloc(io, body.key.len())?;
    key_dma.copy_from_slice(body.key);

    let iv_dma = pal.dma_alloc(io, body.iv.len())?;
    iv_dma.copy_from_slice(body.iv);

    let input_dma = pal.dma_alloc(io, data_len)?;
    input_dma.copy_from_slice(body.data);

    let output_dma = pal.dma_alloc(io, data_len)?;
    pal.aes_cbc_enc_dec(io, op, &*key_dma, &*input_dma, &*iv_dma, output_dma, None)
        .await?;

    let iv_out: &[u8] = if body.encrypt {
        &output_dma[data_len - 16..]
    } else {
        &input_dma[data_len - 16..]
    };
    let resp_data = DdiAesCbcTestResp {
        result: &output_dma[..],
        iv_out,
    };

    let resp = pal.dma_alloc_var(io, |buf| {
        ddi::encode_resp(&ddi::success_hdr(hdr, DdiOp::AesCbcTest), &resp_data, buf)
    })?;
    Ok(resp)
}
