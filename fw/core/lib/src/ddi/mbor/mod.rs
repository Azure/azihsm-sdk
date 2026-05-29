// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub(crate) mod establish_credential;
pub(crate) mod get_api_rev;
pub(crate) mod get_cert_chain_info;
pub(crate) mod get_certificate;
pub(crate) mod get_device_info;
pub(crate) mod get_establish_cred_encryption_key;
pub(crate) mod get_sealed_bk3;
pub(crate) mod get_session_encryption_key;
pub(crate) mod init_bk3;
pub(crate) mod set_sealed_bk3;
pub(crate) mod sha_digest;

use azihsm_fw_ddi_mbor::*;
use azihsm_fw_ddi_mbor_api::DdiDecoder;
use azihsm_fw_ddi_mbor_api::DdiEncoder;
use azihsm_fw_ddi_mbor_types::error::DdiErrResp;
use azihsm_fw_ddi_mbor_types::*;
pub(crate) use establish_credential::*;
pub(crate) use get_api_rev::*;
pub(crate) use get_cert_chain_info::*;
pub(crate) use get_certificate::*;
pub(crate) use get_device_info::*;
pub(crate) use get_establish_cred_encryption_key::*;
pub(crate) use get_sealed_bk3::*;
pub(crate) use get_session_encryption_key::*;
pub(crate) use init_bk3::*;
pub(crate) use set_sealed_bk3::*;
pub(crate) use sha_digest::*;

use super::*;

/// Minimum DDI API revision accepted by this firmware.
pub(crate) const DDI_API_REV_MIN: DdiApiRev = DdiApiRev { major: 1, minor: 0 };

/// Maximum DDI API revision accepted by this firmware.
pub(crate) const DDI_API_REV_MAX: DdiApiRev = DdiApiRev { major: 1, minor: 0 };

/// Central DDI API revision check.
///
/// All commands except [`DdiOp::GetApiRev`] must carry `hdr.rev` set to a
/// supported revision. `GetApiRev` is the bootstrap command — the host
/// does not yet know the supported revision, so its `hdr.rev` must be
/// `None` (enforced inside its handler).
///
/// Returns [`HsmError::UnsupportedRevision`] if `hdr.rev` is missing or
/// outside the supported range.
#[inline]
fn check_api_rev(hdr: &DdiReqHdr) -> HsmResult<()> {
    if hdr.op == DdiOp::GetApiRev {
        return Ok(());
    }
    let rev = hdr.rev.ok_or(HsmError::UnsupportedRevision)?;
    if rev < DDI_API_REV_MIN || rev > DDI_API_REV_MAX {
        return Err(HsmError::UnsupportedRevision);
    }
    Ok(())
}

/// Dispatch a DDI command to its handler.
///
/// Returns the encoded response slice on success, or a [`HsmError`] on
/// failure. The slice borrows from `pal`'s per-IO allocator and is
/// valid until the IO completes.
///
/// This function is `async` because `GetCertificate` calls into
/// `HsmCertStore::get_cert` which is async.
pub(crate) async fn dispatch<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    check_api_rev(hdr)?;

    match hdr.op {
        DdiOp::GetApiRev => get_api_rev(pal, io, decoder, hdr),
        DdiOp::GetDeviceInfo => get_device_info(pal, io, decoder, hdr),
        DdiOp::GetCertChainInfo => get_cert_chain_info(pal, io, decoder, hdr).await,
        DdiOp::GetCertificate => get_certificate(pal, io, decoder, hdr).await,
        DdiOp::ShaDigest => sha_digest(pal, io, decoder, hdr).await,
        DdiOp::GetEstablishCredEncryptionKey => {
            get_establish_cred_encryption_key(pal, io, decoder, hdr).await
        }
        DdiOp::GetSessionEncryptionKey => get_session_encryption_key(pal, io, decoder, hdr).await,
        DdiOp::GetSealedBk3 => get_sealed_bk3(pal, io, decoder, hdr),
        DdiOp::SetSealedBk3 => set_sealed_bk3(pal, io, decoder, hdr),
        DdiOp::InitBk3 => init_bk3(pal, io, decoder, hdr).await,
        DdiOp::EstablishCredential => establish_credential(pal, io, decoder, hdr).await,
        _ => Err(HsmError::UnsupportedCmd),
    }
}

/// Encode a DDI response (header + data) in a single pass.
///
/// The caller supplies a destination buffer (typically from
/// [`HsmAlloc::alloc_all`](azihsm_fw_hsm_pal_traits::HsmAlloc::alloc_all));
/// this helper encodes directly into it and returns the number of bytes
/// written.
pub(crate) fn encode_resp<H, D>(hdr: &H, data: &D, smem: &mut [u8]) -> HsmResult<usize>
where
    H: MborEncode,
    D: MborEncode,
{
    let mut encoder = MborEncoder::new(smem);
    MborMap(2).mbor_encode(&mut encoder)?;
    0u8.mbor_encode(&mut encoder)?;
    hdr.mbor_encode(&mut encoder)?;
    1u8.mbor_encode(&mut encoder)?;
    data.mbor_encode(&mut encoder)?;
    Ok(encoder.position())
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
