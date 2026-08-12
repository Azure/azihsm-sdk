// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-256-CBC cryptographic algorithm self-test (CAST).
//!
//! Runs a fixed known-answer vector through the HSM AES engine in **both**
//! directions — encrypt the plaintext and compare against the expected
//! ciphertext, then decrypt that ciphertext and compare back to the plaintext —
//! matching the reference firmware's `aes_cbc_self_test`. Operands are staged
//! into the self-test IO slot's DMA buffer via the bump allocator (see
//! [`crate::self_test`]).

use azihsm_fw_hsm_pal_traits::AesOp;
use azihsm_fw_hsm_pal_traits::HsmAes;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_trace::tracing::error;
use azihsm_fw_uno_trace::tracing::info;

use super::vectors::AES_CBC_256_KAT;
use crate::UnoHsmIo;
use crate::UnoHsmPal;

/// Runs the AES-256-CBC known-answer test against the HSM AES engine.
///
/// Encrypts the KAT plaintext and verifies the ciphertext, then decrypts the
/// ciphertext and verifies the plaintext (round trip), matching the reference
/// firmware. Returns [`HsmError::SelfTestKatMismatch`] on any mismatch (or any
/// error surfaced by the AES engine / allocator).
pub(super) async fn run_aes_cbc(pal: &UnoHsmPal, io: &UnoHsmIo) -> HsmResult<()> {
    let v = &AES_CBC_256_KAT;

    pal.alloc_scoped_async(io, async |scope| {
        // Stage the shared key/IV into DMA-visible memory (the self-test slot).
        // The IV buffer is not mutated by the CBC path (it copies into internal
        // scratch), so the same `iv` is reused for both directions.
        let key = scope.dma_alloc(v.key.len())?;
        key.copy_from_slice(v.key);
        let iv = scope.dma_alloc(v.iv.len())?;
        iv.copy_from_slice(v.iv);

        // ── Encrypt: plaintext → ciphertext, verify against the vector ──
        let pt = scope.dma_alloc(v.plaintext.len())?;
        pt.copy_from_slice(v.plaintext);
        let ct_out = scope.dma_alloc_zeroed(v.ciphertext.len())?;
        info!("selftest", "AES-CBC encrypt 64B: submit");
        pal.aes_cbc_enc_dec(io, AesOp::Encrypt, &*key, &*pt, &*iv, &mut *ct_out, None)
            .await?;
        info!("selftest", "AES-CBC encrypt: engine ok");
        // KAT vectors are public, fixed test data — a plain slice comparison is
        // correct; no constant-time compare is needed.
        if &ct_out[..] != v.ciphertext {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "AES-CBC encrypt KAT mismatch"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }
        info!("selftest", "AES-CBC encrypt: verified");

        // ── Decrypt: ciphertext → plaintext, verify against the vector ──
        let ct = scope.dma_alloc(v.ciphertext.len())?;
        ct.copy_from_slice(v.ciphertext);
        let pt_out = scope.dma_alloc_zeroed(v.plaintext.len())?;
        info!("selftest", "AES-CBC decrypt 64B: submit");
        pal.aes_cbc_enc_dec(io, AesOp::Decrypt, &*key, &*ct, &*iv, &mut *pt_out, None)
            .await?;
        info!("selftest", "AES-CBC decrypt: engine ok");
        if &pt_out[..] != v.plaintext {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "AES-CBC decrypt KAT mismatch"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }
        info!("selftest", "AES-CBC decrypt: verified");

        Ok::<(), HsmError>(())
    })
    .await
}
