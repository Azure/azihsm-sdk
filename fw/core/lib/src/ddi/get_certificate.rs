// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI GetCertificate command handler.
//!
//! Returns a single certificate from a partition's slot chain.
//! This is a NoSession command. The handler is `async` because
//! the underlying `HsmCertStore::get_cert` is async.
//!
//! Uses encode-frame-then-fill pattern: queries the cert size first,
//! encodes the response frame (header + byte-array framing), then
//! writes the cert DER directly into the reserved slice.

use azihsm_fw_ddi_types::get_certificate::DdiGetCertificateReq;
use azihsm_fw_ddi_types::get_certificate::DdiGetCertificateResp;

use super::*;

/// Handle DdiGetCertificateCmd.
pub(crate) async fn get_certificate<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    _fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiGetCertificateReq = decoder.decode_data()?;

    // Query cert size (no copy).
    let len = pal
        .get_cert(part_id, body.slot_id, body.cert_id, None)
        .await?;

    // Encode header + frame, reserving space for cert data.
    let resp_hdr = ddi::success_hdr(hdr, DdiOp::GetCertificate);
    let mut encoder = ddi::encode_resp_hdr(&resp_hdr, smem)?;
    let frame = DdiGetCertificateResp::frame(&mut encoder, len)?;
    let total = encoder.position();

    // Fill the reserved slice in-place.
    pal.get_cert(part_id, body.slot_id, body.cert_id, Some(frame.certificate))
        .await?;

    Ok(&smem[..total])
}
