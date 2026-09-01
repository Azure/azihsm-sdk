// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `GetCertificate` command handler.
//!
//! Out-of-session command — the TBOR analogue of MBOR `GetCertificate`.
//! Returns a single DER-encoded X.509 certificate from the caller's
//! partition at the requested `(slot_id, cert_id)`.  No session is
//! required; the chain is read for the caller's own bound partition
//! (`io.pid()`), mirroring the MBOR handler.
//!
//! Uses the reserve-then-fill pattern: query the certificate size first,
//! reserve the response `certificate` slot sized to it, then have the PAL
//! copy the DER bytes straight into the reserved slice — no scratch buffer
//! and no copy.  The handler is `async` because the underlying
//! [`HsmCertStore::get_cert`](azihsm_fw_hsm_pal_traits::HsmCertStore::get_cert)
//! is async.

use azihsm_fw_ddi_tbor_types::TborGetCertReq;
use azihsm_fw_ddi_tbor_types::TborGetCertResp;
use azihsm_fw_ddi_tbor_types::CERT_MAX_LEN;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;

/// Handle a TBOR `GetCertificate` request.
///
/// No partition lock or undo log is required: the command only reads a
/// certificate and makes no observable state change.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborGetCertReq::decode(req_buf)?;
    let slot_id = req.slot_id();
    let cert_id = req.cert_id();

    // Query the certificate size (no copy).
    let len = pal.get_cert(io, io.pid(), slot_id, cert_id, None).await?;

    // A provisioned certificate that overflows the wire bound is an
    // internal provisioning invariant violation, not a caller-input error.
    if len > CERT_MAX_LEN {
        return Err(HsmError::InternalError);
    }

    // Build the response with the `certificate` slot reserved (sized but
    // unwritten), then have the PAL copy the DER bytes straight into the
    // reserved slot — no scratch buffer and no copy.
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborGetCertResp::encode(buf, 0, false)?
            .certificate_reserve(len)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;

    // `decode_mut` hands out a `&mut` view into the reserved slot; the view
    // is scoped so its borrow of `resp` ends before `resp` is returned.
    {
        let out = TborGetCertResp::decode_mut(resp)?;
        let actual = pal
            .get_cert(io, io.pid(), slot_id, cert_id, Some(out.certificate))
            .await?;
        if actual != len {
            return Err(HsmError::InternalError);
        }
    }

    Ok(resp)
}
