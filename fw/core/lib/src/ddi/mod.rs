// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub(crate) mod get_api_rev;
pub(crate) mod get_cert_chain_info;
pub(crate) mod get_certificate;
pub(crate) mod get_device_info;
pub(crate) mod get_establish_cred_encryption_key;
pub(crate) mod sha_digest;

use azihsm_fw_ddi::DdiDecoder;
use azihsm_fw_ddi::DdiEncoder;
use azihsm_fw_ddi_mbor::*;
use azihsm_fw_ddi_types::error::DdiErrResp;
use azihsm_fw_ddi_types::*;
pub(crate) use get_api_rev::*;
pub(crate) use get_cert_chain_info::*;
pub(crate) use get_certificate::*;
pub(crate) use get_device_info::*;
pub(crate) use get_establish_cred_encryption_key::*;
pub(crate) use sha_digest::*;

use super::*;

/// Dispatch a DDI command to its handler.
///
/// Returns the response length on success, or a [`HsmError`] on
/// failure. The caller wraps failures in a DDI error response.
///
/// This function is `async` because `GetCertificate` calls into
/// `HsmCertStore::get_cert` which is async.
pub(crate) async fn dispatch<P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &mut [u8],
) -> HsmResult<usize> {
    let resp = match hdr.op {
        DdiOp::GetApiRev => get_api_rev(hdr, decoder, fmem, smem)?,
        DdiOp::GetDeviceInfo => get_device_info(hdr, decoder, part_id, pal, fmem, smem)?,
        DdiOp::GetCertChainInfo => {
            get_cert_chain_info(hdr, decoder, part_id, pal, fmem, smem).await?
        }
        DdiOp::GetCertificate => get_certificate(hdr, decoder, part_id, pal, fmem, smem).await?,
        DdiOp::ShaDigest => sha_digest(hdr, decoder, part_id, pal, fmem, smem).await?,
        DdiOp::GetEstablishCredEncryptionKey => {
            get_establish_cred_encryption_key(hdr, decoder, part_id, pal, fmem, smem).await?
        }
        _ => return Err(HsmError::UnsupportedCmd),
    };
    Ok(resp.len())
}

/// Encode a DDI response (header + data) with a single upfront bounds check.
///
/// Computes the total encoded length via [`MborLen`], checks it fits in
/// `smem`, then encodes with no per-field bounds checks. Returns the
/// encoded length, or [`HsmError::DdiEncodeFailed`] if the buffer is
/// too small.
pub(crate) fn encode_resp<H, D>(hdr: &H, data: &D, smem: &mut [u8]) -> HsmResult<usize>
where
    H: MborEncode + MborLen,
    D: MborEncode + MborLen,
{
    // Pre-compute total length
    let mut acc = MborLenAccumulator::default();
    MborMap(2).mbor_len(&mut acc); // outer Map(2)
    0u8.mbor_len(&mut acc); // key=0
    hdr.mbor_len(&mut acc); // header map
    1u8.mbor_len(&mut acc); // key=1
    data.mbor_len(&mut acc); // data map
    let total = acc.len();

    // Single bounds check
    if total > smem.len() {
        return Err(HsmError::DdiEncodeFailed);
    }

    // Encode — trusted mode: single upfront bounds check means
    // per-field checks are redundant.
    let mut encoder = MborEncoder::new_trusted(smem);
    MborMap(2).mbor_encode(&mut encoder)?;
    0u8.mbor_encode(&mut encoder)?;
    hdr.mbor_encode(&mut encoder)?;
    1u8.mbor_encode(&mut encoder)?;
    data.mbor_encode(&mut encoder)?;

    Ok(total)
}

/// Encode the DDI response header and outer framing, returning the encoder
/// positioned just before the data map.
///
/// Use this with [`DdiGetCertificateResp::frame`] (or similar) to encode the
/// header first, then reserve in-place slots for variable-length fields.
pub(crate) fn encode_resp_hdr<'a>(
    hdr: &DdiRespHdr,
    smem: &'a mut [u8],
) -> HsmResult<MborEncoder<'a>> {
    let mut encoder = MborEncoder::new(smem);
    MborMap(2).mbor_encode(&mut encoder)?;
    0u8.mbor_encode(&mut encoder)?;
    hdr.mbor_encode(&mut encoder)?;
    1u8.mbor_encode(&mut encoder)?;
    Ok(encoder)
}

/// Build a success [`DdiRespHdr`] echoing the request's `rev` field.
pub(crate) fn success_hdr(req: &DdiReqHdr, op: DdiOp) -> DdiRespHdr {
    DdiRespHdr {
        rev: req.rev,
        op,
        sess_id: None,
        status: 0, // DDI Success
        fips_approved: false,
    }
}

/// Encode a DDI error response into `smem`.
///
/// Writes `DdiRespHdr { op, status } + DdiErrResp {}` and returns the
/// encoded length. Used for post-decode errors where the host expects
/// a DDI response body (not just a CQE status code).
///
/// Returns [`HsmError::DdiEncodeFailed`] if the buffer is too small.
pub(crate) fn encode_ddi_err(op: DdiOp, status: HsmError, smem: &mut [u8]) -> HsmResult<usize> {
    let hdr = DdiRespHdr {
        rev: None,
        op,
        sess_id: None,
        status: status.0,
        fips_approved: false,
    };
    let data = DdiErrResp {};
    DdiEncoder::encode_parts(hdr, data, smem)
}
