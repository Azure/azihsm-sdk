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

use azihsm_fw_ddi_mbor_types::get_certificate::DdiGetCertificateReq;
use azihsm_fw_ddi_mbor_types::get_certificate::DdiGetCertificateResp;

use super::*;

/// Handle DdiGetCertificateCmd.
pub(crate) async fn get_certificate<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiGetCertificateReq = decoder.decode_data()?;

    // Query cert size (no copy).
    let len = pal
        .get_cert(io, io.pid(), body.slot_id, body.cert_id, None)
        .await?;

    // Reserve the response inside a closure (encoder borrow ends with the
    // closure), recording where the cert slot landed in a layout returned
    // as the closure's owned out-value. After the closure, rebind the
    // layout against the populated buffer to fill the slot.
    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder =
            super::encode_resp_hdr(&super::success_hdr(hdr, DdiOp::GetCertificate), buf)?;
        let layout = DdiGetCertificateResp::reserve(&mut encoder, len)?;
        Ok((encoder.position(), layout))
    })?;

    let frame = DdiGetCertificateResp::from_layout(resp, &layout);

    pal.get_cert(
        io,
        io.pid(),
        body.slot_id,
        body.cert_id,
        Some(frame.certificate),
    )
    .await?;

    Ok(resp)
}
