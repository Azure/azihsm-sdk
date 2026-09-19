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
//! The signature arrives **out of band** as OOB SGL descriptor 0: at
//! ML-DSA-65 the verifying key and signature together are 1952 + 3309 =
//! 5261 B, over the firmware's 4 KiB inbound limit. Its length is fixed by
//! the parameter set, so the handler allocates exactly that and the GDMA
//! length-checks the descriptor.
//!
//! A signature that does not verify is returned as
//! [`HsmError::MlDsaVerifyFailed`] rather than as a flag in a successful
//! response, mirroring [`EccVerifyFailed`](HsmError::EccVerifyFailed): a
//! caller that checks only for transport success cannot mistake a bad
//! signature for a good one.
//!
//! Available to both Crypto-Officer and Crypto-User sessions.

use azihsm_fw_core_crypto_ml_dsa::SIGNATURE_LEN;
use azihsm_fw_core_crypto_ml_dsa::VERIFYING_KEY_LEN;
use azihsm_fw_ddi_tbor_types::TborMlDsaVerifyReq;
use azihsm_fw_ddi_tbor_types::TborMlDsaVerifyResp;
use azihsm_fw_hsm_oob::copy_oob;
use azihsm_fw_hsm_oob::OobPtr;
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
    oob: Option<OobPtr>,
) -> HsmResult<&'p DmaBuf> {
    let req = TborMlDsaVerifyReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));
    validate_active_session(pal, io, sess_id)?;

    // The wire schema admits every parameter set; this build links exactly
    // one. Reject a verifying key sized for another rather than misreading
    // it. The signature is length-checked by the GDMA against the buffer
    // below, so it needs no separate check here.
    if req.verifying_key().len() != VERIFYING_KEY_LEN
        || req.signature_len() as usize != SIGNATURE_LEN
    {
        return Err(HsmError::InvalidArg);
    }

    let oob = oob.ok_or(HsmError::InvalidArg)?;
    if oob.entry_count() < 1 {
        return Err(HsmError::InvalidArg);
    }
    let sig = pal.dma_alloc(io, SIGNATURE_LEN)?;
    copy_oob(pal, io, &oob, 0, sig).await?;

    // A signature that does not verify is reported as its own wire status
    // rather than as a flag inside a successful response, so a negative
    // answer becomes an error here.
    if !pal
        .ml_dsa_verify(io, req.verifying_key(), sig, req.msg())
        .await?
    {
        return Err(HsmError::MlDsaVerifyFailed);
    }

    pal.dma_alloc_var(io, |buf| {
        let frame = TborMlDsaVerifyResp::encode(buf, 0, false)?.finish();
        Ok(frame.as_bytes().len())
    })
    .map(|b| &*b)
}
