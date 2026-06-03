// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI ShaDigest command handler.
//!
//! Computes a cryptographic hash of the input message using the
//! specified algorithm. This is a NoSession command.
//!
//! Uses the encode-frame-then-fill pattern: encodes the response
//! frame first, then computes the hash directly into the reserved
//! digest slot — zero intermediate copies.
//!
//! TODO: Move to InSession when session support is fully wired.

use azihsm_fw_ddi_mbor_types::sha_digest::DdiShaDigestReq;
use azihsm_fw_ddi_mbor_types::sha_digest::DdiShaDigestResp;

use super::*;

/// Handle DdiShaDigestCmd.
pub(crate) async fn sha_digest<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiShaDigestReq<'_> = decoder.decode_data()?;

    let algo = super::from_ddi::hash(body.sha_mode)?;
    let digest_len = algo.digest_len();

    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let resp_hdr = super::success_hdr(hdr, DdiOp::ShaDigest);
        let mut encoder = super::encode_resp_hdr(&resp_hdr, buf)?;
        let layout = DdiShaDigestResp::reserve(&mut encoder, digest_len)?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiShaDigestResp::from_layout(resp, &layout);
    pal.hash(io, algo, body.msg, frame.digest, true).await?;
    Ok(resp)
}
