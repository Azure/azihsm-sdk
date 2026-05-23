// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI EccSign command handler.

use azihsm_fw_ddi_mbor_types::ecc_sign::{DdiEccSignReq, DdiEccSignResp};

use super::*;

pub(crate) async fn ecc_sign<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiEccSignReq<'_> = decoder.decode_data()?;
    let curve = match body.digest_algo {
        DdiHashAlgorithm::Sha256 => HsmEccCurve::P256,
        DdiHashAlgorithm::Sha384 => HsmEccCurve::P384,
        DdiHashAlgorithm::Sha512 => HsmEccCurve::P521,
        _ => return Err(HsmError::InvalidArg),
    };

    let digest_dma = pal.dma_alloc(io, body.digest.len())?;
    digest_dma.copy_from_slice(body.digest);

    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = ddi::encode_resp_hdr(&ddi::success_hdr(hdr, DdiOp::EccSign), buf)?;
        let layout = DdiEccSignResp::reserve(&mut encoder, curve.sig_len())?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiEccSignResp::from_layout(resp, &layout);

    pal.ecc_sign(
        io,
        curve,
        pal.vault_key(io, body.key_id.into())?,
        &*digest_dma,
        frame.signature,
    )
    .await?;

    Ok(resp)
}
