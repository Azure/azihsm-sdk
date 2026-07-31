// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES Key Wrap with Padding (RFC 5649) cryptographic algorithm self-test
//! (CAST).
//!
//! Runs a fixed NIST CAVP known-answer vector through the HSM AES engine's
//! KWP-AD (authenticated decryption / unwrap) path and compares the recovered
//! plaintext against the expected value. This validates the same engine path
//! the production RSA-unwrap flow depends on. Operands are staged into the
//! self-test IO slot's DMA buffer via the bump allocator (see
//! [`crate::self_test`]).

use azihsm_fw_hsm_pal_traits::HsmAes;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_trace::tracing::error;

use super::vectors::AES_KWP_256_KAT;
use crate::UnoHsmIo;
use crate::UnoHsmPal;

/// Runs the AES-256 KWP (RFC 5649) known-answer test against the HSM AES
/// engine.
///
/// Unwraps the KAT `wrapped` blob under the KAT `key` and verifies both the
/// recovered length (the Message Length Indicator) and the recovered plaintext
/// bytes. Returns [`HsmError::SelfTestKatMismatch`] on any mismatch (or any
/// error surfaced by the AES engine / allocator).
pub(super) async fn run_aes_kwp(pal: &UnoHsmPal, io: &UnoHsmIo) -> HsmResult<()> {
    let v = &AES_KWP_256_KAT;

    pal.alloc_scoped_async(io, async |scope| {
        // Stage the KEK and wrapped blob into DMA-visible memory.
        let key = scope.dma_alloc(v.key.len())?;
        key.copy_from_slice(v.key);
        let input = scope.dma_alloc(v.wrapped.len())?;
        input.copy_from_slice(v.wrapped);

        // Output must be at least `wrapped.len() - 8` (the AIV semiblock is
        // stripped). For this vector that equals the plaintext length.
        let out = scope.dma_alloc_zeroed(v.wrapped.len() - 8)?;
        let mli = pal.aes_kwp_unwrap(io, &*key, &*input, &mut *out).await?;

        // KAT vectors are public, fixed test data — a plain slice comparison is
        // correct; no constant-time compare is needed.
        if mli != v.plaintext.len() || &out[..mli] != v.plaintext {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "AES-KWP unwrap KAT mismatch"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }

        Ok::<(), HsmError>(())
    })
    .await
}
