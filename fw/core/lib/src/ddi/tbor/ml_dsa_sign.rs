// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlDsaSign` command handler.
//!
//! Within an open session, produce an ML-DSA (FIPS 204) signature over a
//! host-supplied message using a host-supplied **encoded signing key**.
//! Nothing is persisted and no partition state is read or written.
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
/// partition state and persists nothing.  Takes `req_buf: &mut DmaBuf` so
/// the imported signing key can be zeroized in place (`decode_mut`).
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborMlDsaSignReq::decode_mut(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id));
    validate_active_session(pal, io, sess_id)?;

    // The wire schema admits every parameter set so the format does not
    // change when another is enabled, but a given firmware build links
    // exactly one.  Reject a key sized for a parameter set this build does
    // not implement rather than misreading it as the one it does.
    if req.signing_key.len() != SIGNING_KEY_LEN {
        req.signing_key.zeroize();
        return Err(HsmError::InvalidArg);
    }

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
            azihsm_fw_core_crypto_ml_dsa::sign_into(req.signing_key, req.msg, out.signature)
                .map_err(map_err)?;
        }
        let resp: &'p DmaBuf = resp;
        Ok(resp)
    })();

    // Scrub the caller's private key from the request buffer on every path.
    req.signing_key.zeroize();
    outcome
}
