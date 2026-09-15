// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlDsaSign` command handler.
//!
//! Within an open session, produce an ML-DSA (FIPS 204) signature over a
//! host-supplied message using a host-supplied **encoded signing key**.
//! Nothing is persisted and no partition state is read or written.
//!
//! The signing key arrives **out of band** as OOB SGL descriptor 0, because
//! an ML-DSA-65 key is 4032 B against a 4 KiB inbound limit and would leave
//! no room for a message. Its length is fixed by the parameter set, so the
//! handler allocates exactly that and lets the GDMA length-check the
//! transfer — a descriptor whose length disagrees is rejected there.
//!
//! Unlike [`EccSign`](super::ecc_sign), the key arrives in the clear
//! rather than as a masked blob: ML-DSA key generation does not fit in
//! this part's RAM, so the keypair is generated on the host and imported
//! per call, and the masking layer has no ML-DSA key kind yet.  The key is
//! therefore protected only by the session transport, and is zeroized from
//! the request buffer on **every** exit path below.  This is a
//! proof-of-concept path, not a production key-management design.
//!
//! Available to both Crypto-Officer and Crypto-User sessions.

use azihsm_fw_core_crypto_ml_dsa::MlDsaKeyError;
use azihsm_fw_core_crypto_ml_dsa::MlDsaOpError;
use azihsm_fw_core_crypto_ml_dsa::SIGNATURE_LEN;
use azihsm_fw_core_crypto_ml_dsa::SIGNING_KEY_LEN;
use azihsm_fw_ddi_tbor_types::TborMlDsaSignReq;
use azihsm_fw_ddi_tbor_types::TborMlDsaSignResp;
use azihsm_fw_hsm_oob::copy_oob;
use azihsm_fw_hsm_oob::OobPtr;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;

use super::validate_active_session;

/// Map a crypto-layer error onto the wire status.
fn map_err(e: MlDsaOpError) -> HsmError {
    match e {
        // A correct-length key whose coefficients are out of range is
        // reported distinctly from a wrong-length one: the former is the
        // input class that would otherwise panic the decoder, and saying so
        // tells a caller its key is corrupt rather than merely mis-sized.
        MlDsaOpError::Key(MlDsaKeyError::CoefficientOutOfRange) => HsmError::MlDsaInvalidSigningKey,
        MlDsaOpError::Key(MlDsaKeyError::BadLength) | MlDsaOpError::BadLength => {
            HsmError::InvalidArg
        }
        MlDsaOpError::SignFailed => HsmError::MlDsaSignFailed,
        MlDsaOpError::VerifyFailed => HsmError::MlDsaVerifyFailed,
    }
}

/// Handle a TBOR `MlDsaSign` request.
///
/// No partition lock or undo log is required: the command reads no mutable
/// partition state and persists nothing.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
    oob: Option<OobPtr>,
) -> HsmResult<&'p DmaBuf> {
    let req = TborMlDsaSignReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));
    validate_active_session(pal, io, sess_id)?;

    // Reject a key sized for another parameter set here, so the caller sees
    // `InvalidArg` rather than the GDMA's descriptor-length error.
    if req.signing_key_len() as usize != SIGNING_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }

    let oob = oob.ok_or(HsmError::InvalidArg)?;
    if oob.entry_count() < 1 {
        return Err(HsmError::InvalidArg);
    }

    // Pull the signing key in from OOB descriptor 0. The buffer is exactly
    // the parameter set's key length, which is what the GDMA checks the
    // descriptor against, so a key sized for another parameter set is
    // refused by the transfer rather than misread.
    let key = pal.dma_alloc(io, SIGNING_KEY_LEN)?;
    copy_oob(pal, io, &oob, 0, key).await?;

    // Reserve the signature slot and sign straight into it — the response
    // buffer is the only copy of the signature.
    let outcome: HsmResult<&'p DmaBuf> = (|| {
        let resp = pal.dma_alloc_var(io, |buf| {
            let frame = TborMlDsaSignResp::encode(buf, 0, false)?
                .signature_reserve(SIGNATURE_LEN)?
                .finish();
            Ok(frame.as_bytes().len())
        })?;
        {
            let out = TborMlDsaSignResp::decode_mut(resp)?;
            azihsm_fw_core_crypto_ml_dsa::sign_into(key, req.msg(), out.signature)
                .map_err(map_err)?;
        }
        let resp: &'p DmaBuf = resp;
        Ok(resp)
    })();

    // Scrub the caller's private key on every path.
    key.zeroize();
    outcome
}
