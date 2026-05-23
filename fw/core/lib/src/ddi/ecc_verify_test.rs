// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_types::ecc_verify_test::{DdiEccVerifyTestReq, DdiEccVerifyTestResp};

use super::*;

fn to_hsm_ecc_curve(ddi: DdiEccCurve) -> HsmResult<HsmEccCurve> {
    match ddi {
        DdiEccCurve::P256 => Ok(HsmEccCurve::P256),
        DdiEccCurve::P384 => Ok(HsmEccCurve::P384),
        DdiEccCurve::P521 => Ok(HsmEccCurve::P521),
        _ => Err(HsmError::InvalidArg),
    }
}

pub(crate) async fn ecc_verify_test<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiEccVerifyTestReq<'_> = decoder.decode_data()?;
    let curve = to_hsm_ecc_curve(body.curve)?;

    let pub_key_dma = pal.dma_alloc(io, body.pub_key.len())?;
    pub_key_dma.copy_from_slice(body.pub_key);

    let digest_dma = pal.dma_alloc(io, body.digest.len())?;
    digest_dma.copy_from_slice(body.digest);

    let signature_dma = pal.dma_alloc(io, body.signature.len())?;
    signature_dma.copy_from_slice(body.signature);

    let valid = pal
        .ecc_verify(io, curve, &*pub_key_dma, &*digest_dma, &*signature_dma)
        .await?;
    let resp_data = DdiEccVerifyTestResp {
        valid: u8::from(valid),
    };

    let resp = pal.dma_alloc_var(io, |buf| {
        ddi::encode_resp(&ddi::success_hdr(hdr, DdiOp::EccVerifyTest), &resp_data, buf)
    })?;
    Ok(resp)
}
