// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-256-ECB cryptographic algorithm self-test (CAST).
//!
//! Runs a fixed NIST SP 800-38A known-answer vector through the HSM AES
//! engine's ECB-decrypt path and compares the recovered plaintext against the
//! expected value. Operands are staged into the self-test IO slot's DMA buffer
//! via the bump allocator (see [`crate::self_test`]).

use azihsm_fw_hsm_pal_traits::AesOp;
use azihsm_fw_hsm_pal_traits::HsmAes;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_trace::tracing::error;

use super::vectors::AES_ECB_256_KAT;
use crate::UnoHsmIo;
use crate::UnoHsmPal;

/// Runs the AES-256-ECB known-answer test (decrypt direction) against the HSM
/// AES engine.
///
/// Decrypts the KAT ciphertext and verifies the recovered plaintext. Returns
/// [`HsmError::SelfTestKatMismatch`] on any mismatch (or any error surfaced by
/// the AES engine / allocator).
pub(super) async fn run_aes_ecb(pal: &UnoHsmPal, io: &UnoHsmIo) -> HsmResult<()> {
    let v = &AES_ECB_256_KAT;

    pal.alloc_scoped_async(io, async |scope| {
        // Stage the key and ciphertext into DMA-visible memory.
        let key = scope.dma_alloc(v.key.len())?;
        key.copy_from_slice(v.key);
        let ct = scope.dma_alloc(v.ciphertext.len())?;
        ct.copy_from_slice(v.ciphertext);
        let pt_out = scope.dma_alloc_zeroed(v.plaintext.len())?;

        pal.aes_ecb_enc_dec(io, AesOp::Decrypt, &*key, &*ct, &mut *pt_out)
            .await?;

        // KAT vectors are public, fixed test data — a plain slice comparison is
        // correct; no constant-time compare is needed.
        if &pt_out[..] != v.plaintext {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "AES-ECB decrypt KAT mismatch"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }

        Ok::<(), HsmError>(())
    })
    .await
}
