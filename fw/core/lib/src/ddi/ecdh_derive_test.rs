// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_types::ecdh_derive_test::{DdiEcdhDeriveTestReq, DdiEcdhDeriveTestResp};

use super::*;

fn to_hsm_ecc_curve(ddi: DdiEccCurve) -> HsmResult<HsmEccCurve> {
    match ddi {
        DdiEccCurve::P256 => Ok(HsmEccCurve::P256),
        DdiEccCurve::P384 => Ok(HsmEccCurve::P384),
        DdiEccCurve::P521 => Ok(HsmEccCurve::P521),
        _ => Err(HsmError::InvalidArg),
    }
}

pub(crate) async fn ecdh_derive_test<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiEcdhDeriveTestReq<'_> = decoder.decode_data()?;
    let curve = to_hsm_ecc_curve(body.curve)?;

    let priv_key_dma = pal.dma_alloc(io, body.priv_key.len())?;
    priv_key_dma.copy_from_slice(body.priv_key);

    let pub_key_dma = pal.dma_alloc(io, body.peer_pub_key.len())?;
    pub_key_dma.copy_from_slice(body.peer_pub_key);

    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = ddi::encode_resp_hdr(&ddi::success_hdr(hdr, DdiOp::EcdhDeriveTest), buf)?;
        let layout = DdiEcdhDeriveTestResp::reserve(&mut encoder, curve.secret_len())?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiEcdhDeriveTestResp::from_layout(resp, &layout);

    pal.ecdh_derive(io, curve, &*priv_key_dma, &*pub_key_dma, frame.secret)
        .await?;

    Ok(resp)
}
