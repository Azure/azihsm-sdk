// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlDsaKeyGen` command handler.
//!
//! Within an open session, generate an ML-DSA (FIPS 204) keypair on the
//! device from hardware entropy and return both halves. Nothing is
//! persisted and no partition state is read or written.
//!
//! Unlike [`MlDsaSign`](super::ml_dsa_sign), no private key crosses the
//! wire inbound — the device chooses it. The signing key is still returned
//! in the clear, which a production design would replace with a masked blob
//! once the masking layer has an ML-DSA key kind.
//!
//! Available to both Crypto-Officer and Crypto-User sessions.

use azihsm_fw_core_crypto_ml_dsa::SIGNING_KEY_LEN;
use azihsm_fw_core_crypto_ml_dsa::VERIFYING_KEY_LEN;
use azihsm_fw_ddi_tbor_types::TborMlDsaKeyGenReq;
use azihsm_fw_ddi_tbor_types::TborMlDsaKeyGenResp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;

use super::validate_active_session;

/// Handle a TBOR `MlDsaKeyGen` request.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborMlDsaKeyGenReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));
    validate_active_session(pal, io, sess_id)?;

    // FIPS 204 KeyGen takes a 32-byte seed; take it from the hardware DRBG
    // so the private half is the device's own choice.
    let mut seed = [0u8; 32];
    pal.rng_fill_bytes(io, &mut seed)?;

    // Reserve both output slots and generate straight into them, so the
    // response buffer is the only copy of the private half.
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborMlDsaKeyGenResp::encode(buf, 0, false)?
            .signing_key_reserve(SIGNING_KEY_LEN)?
            .verifying_key_reserve(VERIFYING_KEY_LEN)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;

    let outcome = {
        let out = TborMlDsaKeyGenResp::decode_mut(resp)?;
        azihsm_fw_core_crypto_ml_dsa::keygen_into(&seed, out.signing_key, out.verifying_key)
            .map_err(|_| HsmError::MlDsaKeyGenFailed)
    };

    // The seed reconstructs the private key, so it must not outlive the
    // call — scrubbed on both the success and failure paths.
    seed.fill(0);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    outcome?;
    Ok(resp)
}
