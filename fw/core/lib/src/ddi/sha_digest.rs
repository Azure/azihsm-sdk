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

use azihsm_fw_ddi_types::sha_digest::DdiShaDigestReq;
use azihsm_fw_ddi_types::sha_digest::DdiShaDigestResp;

use super::*;

/// Map DDI hash algorithm to PAL hash algorithm.
fn to_hsm_hash_algo(ddi: DdiHashAlgorithm) -> HsmResult<HsmHashAlgo> {
    match ddi {
        DdiHashAlgorithm::Sha1 => Ok(HsmHashAlgo::Sha1),
        DdiHashAlgorithm::Sha256 => Ok(HsmHashAlgo::Sha256),
        DdiHashAlgorithm::Sha384 => Ok(HsmHashAlgo::Sha384),
        DdiHashAlgorithm::Sha512 => Ok(HsmHashAlgo::Sha512),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Handle DdiShaDigestCmd.
pub(crate) async fn sha_digest<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    _part_id: u8,
    pal: &P,
    _fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiShaDigestReq<'_> = decoder.decode_data()?;

    let algo = to_hsm_hash_algo(body.sha_mode)?;
    let digest_len = algo.digest_len();

    // Encode header + frame, reserving space for the digest.
    let resp_hdr = ddi::success_hdr(hdr, DdiOp::ShaDigest);
    let mut encoder = ddi::encode_resp_hdr(&resp_hdr, smem)?;
    let frame = DdiShaDigestResp::frame(&mut encoder, digest_len)?;
    let total = encoder.position();

    // Compute hash directly into the reserved slice — zero copy.
    pal.hash(algo, body.msg, frame.digest).await?;

    Ok(&smem[..total])
}
