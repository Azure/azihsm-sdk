// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-engine PKA cryptographic algorithm self-tests (CAST).
//!
//! Unlike the algorithm-level KATs (AES / HKDF / KBKDF), the PKA tests validate
//! **each hardware PKA engine individually**: they pin a specific engine via
//! [`UpkaDriver::acquire_engine`] and run the operation on that engine, so the
//! caller can cover all [`PKA_ENGINES`] engines.
//!
//! The initial test is the RSA-2048 modular-exponentiation (private-key)
//! known-answer test, ported from the reference firmware's
//! `rsa_mod_exp_self_test`: it computes `plaintext = c^d mod n` on the pinned
//! engine and compares against the expected plaintext `k`. Operands are staged
//! into the self-test IO slot's DMA buffer via the bump allocator (see
//! [`crate::self_test`]).

use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_drivers_upka::UpkaRsaKeyType;
use azihsm_fw_uno_reg_soc::io_gsram::UPKA_ENGINE_CMD_COUNT;
use azihsm_fw_uno_trace::tracing::error;

use super::vectors::RSA_2K_MOD_EXP_KAT;
use crate::UnoHsmIo;
use crate::UnoHsmPal;

/// Number of hardware PKA engines to validate (one self-test run each).
pub(super) const PKA_ENGINES: u8 = UPKA_ENGINE_CMD_COUNT as u8;

/// RSA-2048 modulus size in bytes.
const RSA_2K_LEN: usize = 256;

/// Runs the RSA-2048 mod-exp (private-key) known-answer test on PKA engine
/// `engine`.
///
/// Computes `c^d mod n` on the pinned engine and compares the result against
/// the expected plaintext. Returns [`HsmError::SelfTestKatMismatch`] on a
/// mismatch, or any error surfaced by the PKA engine / allocator.
pub(super) async fn run_rsa_mod_exp_on_engine(
    pal: &UnoHsmPal,
    io: &UnoHsmIo,
    engine: u8,
) -> HsmResult<()> {
    let v = &RSA_2K_MOD_EXP_KAT;

    pal.alloc_scoped_async(io, async |scope| {
        // Private key is laid out as `d ‖ n` (exponent then modulus).
        let key = scope.dma_alloc(RSA_2K_LEN * 2)?;
        key[..RSA_2K_LEN].copy_from_slice(v.d);
        key[RSA_2K_LEN..].copy_from_slice(v.n);
        // Input ciphertext `c` and output plaintext buffer.
        let input = scope.dma_alloc(RSA_2K_LEN)?;
        input.copy_from_slice(v.c);
        let output = scope.dma_alloc_zeroed(RSA_2K_LEN)?;

        // Pin the requested engine for the operation, release afterwards.
        let mut eng = pal.pka.acquire_engine(engine).await?;
        let outcome = eng
            .rsa_mod_exp_priv(UpkaRsaKeyType::Rsa2048, &*key, &*input, &mut *output)
            .await;
        let release = eng.release().await;
        outcome?;
        release?;

        // KAT vectors are public, fixed test data — a plain slice comparison is
        // correct; no constant-time compare is needed.
        if &output[..] != v.k {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "RSA-2K mod-exp KAT mismatch on engine"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }

        Ok::<(), HsmError>(())
    })
    .await
}
