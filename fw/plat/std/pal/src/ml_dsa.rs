// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-DSA for the std platform, in process.
//!
//! uno offloads these to FP1; here they run locally against the RustCrypto
//! implementation. Keeping the emulator on that implementation is deliberate:
//! it is the independent one, so an emulator run and a silicon run agreeing
//! means two implementations agree, not that one agrees with itself.

use azihsm_fw_core_crypto_ml_dsa::MlDsaKeyError;
use azihsm_fw_core_crypto_ml_dsa::MlDsaOpError;
use azihsm_fw_hsm_pal_traits::*;

use crate::StdHsmPal;

/// Maps a crypto-layer error onto the wire status, matching the mapping the
/// TBOR handler used when it called the crate directly.
fn map_err(e: MlDsaOpError) -> HsmError {
    match e {
        MlDsaOpError::Key(MlDsaKeyError::CoefficientOutOfRange) => HsmError::MlDsaInvalidSigningKey,
        MlDsaOpError::Key(MlDsaKeyError::BadLength) | MlDsaOpError::BadLength => {
            HsmError::InvalidArg
        }
        MlDsaOpError::SignFailed => HsmError::MlDsaSignFailed,
        MlDsaOpError::VerifyFailed => HsmError::MlDsaVerifyFailed,
    }
}

impl HsmMlDsa for StdHsmPal {
    async fn ml_dsa_keygen(
        &self,
        _io: &impl HsmIo,
        seed: &[u8; 32],
        vk: &mut [u8],
        sk: &mut [u8],
    ) -> HsmResult<()> {
        if !vk.is_empty() {
            azihsm_fw_core_crypto_ml_dsa::keygen_into(seed, vk)
                .map_err(|_| HsmError::MlDsaKeyGenFailed)?;
        }

        // The signing key is only ever asked for by callers that want the
        // expanded form; the DDI does not, and the crate's keygen entry point
        // deliberately returns the verifying key alone.
        if !sk.is_empty() {
            return Err(HsmError::MlDsaKeyGenFailed);
        }

        Ok(())
    }

    async fn ml_dsa_sign(
        &self,
        _io: &impl HsmIo,
        sk: &[u8],
        msg: &[u8],
        sig: &mut [u8],
    ) -> HsmResult<()> {
        azihsm_fw_core_crypto_ml_dsa::sign_into(sk, msg, sig).map_err(map_err)
    }

    async fn ml_dsa_verify(
        &self,
        _io: &impl HsmIo,
        vk: &[u8],
        sig: &[u8],
        msg: &[u8],
    ) -> HsmResult<bool> {
        match azihsm_fw_core_crypto_ml_dsa::verify(vk, msg, sig) {
            Ok(()) => Ok(true),
            // A well-formed but wrong signature is a negative answer.
            Err(MlDsaOpError::VerifyFailed) => Ok(false),
            Err(e) => Err(map_err(e)),
        }
    }
}
