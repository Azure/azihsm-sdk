// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlDsaVerify` command handler.
//!
//! Within an open session, verify an ML-DSA (FIPS 204) signature over a
//! host-supplied message under a host-supplied **encoded verifying key**.
//! Every input is a public value, so this command handles no secret and
//! needs no scrubbing.  Nothing is persisted and no partition state is read
//! or written.
//!
//! A signature that does not verify is returned as
//! [`HsmError::MlDsaVerifyFailed`] rather than as a flag in a successful
//! response, mirroring [`EccVerifyFailed`](HsmError::EccVerifyFailed): a
//! caller that checks only for transport success cannot mistake a bad
//! signature for a good one.
//!
//! Available to both Crypto-Officer and Crypto-User sessions.

use azihsm_fw_core_crypto_ml_dsa::MlDsaOpError;
use azihsm_fw_core_crypto_ml_dsa::SIGNATURE_LEN;
use azihsm_fw_core_crypto_ml_dsa::VERIFYING_KEY_LEN;
use azihsm_fw_ddi_tbor_types::TborMlDsaVerifyReq;
use azihsm_fw_ddi_tbor_types::TborMlDsaVerifyResp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;

use super::validate_active_session;

/// Handle a TBOR `MlDsaVerify` request.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborMlDsaVerifyReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));
    validate_active_session(pal, io, sess_id)?;

    // The wire schema admits every parameter set; this build links exactly
    // one. Reject inputs sized for another rather than misreading them.
    if req.verifying_key().len() != VERIFYING_KEY_LEN || req.signature().len() != SIGNATURE_LEN {
        return Err(HsmError::InvalidArg);
    }

    azihsm_fw_core_crypto_ml_dsa::verify(req.verifying_key(), req.msg(), req.signature()).map_err(
        |e| match e {
            MlDsaOpError::VerifyFailed => HsmError::MlDsaVerifyFailed,
            _ => HsmError::InvalidArg,
        },
    )?;

    pal.dma_alloc_var(io, |buf| {
        let frame = TborMlDsaVerifyResp::encode(buf, 0, false)?.finish();
        Ok(frame.as_bytes().len())
    })
    .map(|b| &*b)
}
