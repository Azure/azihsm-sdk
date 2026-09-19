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

use azihsm_fw_core_crypto_ml_dsa::VERIFYING_KEY_LEN;
use azihsm_fw_ddi_tbor_types::TborMlDsaKeyGenReq;
use azihsm_fw_ddi_tbor_types::TborMlDsaKeyGenResp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
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

    // Reserve both output slots and derive straight into them. The reply
    // carries the seed rather than the expanded signing key: the response
    // path is capped at one 4 KiB page, which 4032 + 1952 B exceeds at
    // ML-DSA-65, and the seed is the same secret in a 32-byte form.
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborMlDsaKeyGenResp::encode(buf, 0, false)?
            .seed_reserve(32)?
            .verifying_key_reserve(VERIFYING_KEY_LEN)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;

    let outcome = {
        let out = TborMlDsaKeyGenResp::decode_mut(resp)?;
        out.seed.copy_from_slice(&seed);
        // Empty second buffer: the reply carries the seed, so the expanded
        // signing key is never wanted here.
        pal.ml_dsa_keygen(io, &seed, out.verifying_key, &mut [])
            .await
    };

    // The local copy of the seed is redundant once it is in the response
    // buffer, so scrub it on both paths. The response itself carries the
    // secret to the caller by design.
    seed.fill(0);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    outcome?;
    Ok(resp)
}
