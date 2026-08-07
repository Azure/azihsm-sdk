// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `Hash` command handler.
//!
//! Within an open session, compute a SHA-256 / 384 / 512 digest of a
//! host-supplied message and return it.  A pure hashing utility — no key,
//! no scope, no partition state — the TBOR analogue of MBOR `ShaDigest`.
//!
//! Uses the reserve-then-fill pattern: the response frame is encoded with
//! the digest slot reserved, then the PAL hashes straight into it — no
//! intermediate buffer, no copy.  Available to both Crypto-Officer and
//! Crypto-User sessions.

use azihsm_fw_ddi_tbor_types::HashAlgo;
use azihsm_fw_ddi_tbor_types::TborHashReq;
use azihsm_fw_ddi_tbor_types::TborHashResp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;

use super::validate_active_session;

/// Map the wire [`HashAlgo`] onto the firmware hash algorithm.
fn hsm_hash_algo(algo: HashAlgo) -> HsmResult<HsmHashAlgo> {
    match algo {
        HashAlgo::Sha256 => Ok(HsmHashAlgo::Sha256),
        HashAlgo::Sha384 => Ok(HsmHashAlgo::Sha384),
        HashAlgo::Sha512 => Ok(HsmHashAlgo::Sha512),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Handle a TBOR `Hash` request.
///
/// No partition lock or undo log is required: the command reads no mutable
/// partition state and persists nothing — it hashes the message and
/// returns the digest.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborHashReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));
    validate_active_session(pal, io, sess_id)?;

    let algo = hsm_hash_algo(req.algo())?;
    let digest_len = algo.digest_len();
    let msg = req.msg();

    // Build the response with the digest slot reserved (sized exactly to the
    // algorithm's digest length), then have the PAL hash straight into it.
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborHashResp::encode(buf, 0, false)?
            .digest_reserve(digest_len)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;

    // `decode_mut` hands out a `&mut` view into the reserved slot; the view
    // is scoped so its borrow of `resp` ends before `resp` is returned.  The
    // digest is emitted in natural big-endian order.
    {
        let out = TborHashResp::decode_mut(resp)?;
        pal.hash(io, algo, msg, out.digest, true).await?;
    }

    Ok(resp)
}
