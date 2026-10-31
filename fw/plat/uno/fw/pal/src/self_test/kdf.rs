// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key-derivation-function cryptographic algorithm self-tests (CAST).
//!
//! Runs fixed known-answer vectors through the HSM KDF path and compares the
//! derived key material against the expected output, matching the reference
//! firmware's `hkdf_self_test_256` (and, later, `kbkdf_self_test_512`).
//! Operands are staged into the self-test IO slot's DMA buffer via the bump
//! allocator (see [`crate::self_test`]).

use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmKdf;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_trace::tracing::error;

use super::vectors::HKDF_SHA256_KAT;
use super::vectors::KBKDF_SHA512_KAT;
use crate::UnoHsmIo;
use crate::UnoHsmPal;

/// Runs the HKDF (HMAC-SHA-256) known-answer test.
///
/// Performs HKDF-Extract (`salt` + `ikm` → PRK) then HKDF-Expand
/// (PRK + `info` → OKM) and compares the derived OKM against the expected
/// vector. Returns [`HsmError::SelfTestKatMismatch`] on a mismatch (or any
/// error surfaced by the KDF path / allocator).
pub(super) async fn run_hkdf(pal: &UnoHsmPal, io: &UnoHsmIo) -> HsmResult<()> {
    let v = &HKDF_SHA256_KAT;
    let algo = HsmHashAlgo::Sha256;

    pal.alloc_scoped_async(io, async |scope| {
        // Stage the KAT operands into DMA-visible memory (the self-test slot).
        let salt = scope.dma_alloc(v.salt.len())?;
        salt.copy_from_slice(v.salt);
        let ikm = scope.dma_alloc(v.ikm.len())?;
        ikm.copy_from_slice(v.ikm);
        let prk = scope.dma_alloc_zeroed(algo.digest_len())?;

        // HKDF-Extract: PRK = HMAC-Hash(salt, IKM).
        pal.hkdf_extract(io, algo, Some(&*salt), &*ikm, &mut *prk)
            .await?;

        // HKDF-Expand: OKM = Expand(PRK, info, L).
        let info = scope.dma_alloc(v.info.len())?;
        info.copy_from_slice(v.info);
        let okm = scope.dma_alloc_zeroed(v.okm.len())?;
        pal.hkdf_expand(io, algo, &*prk, Some(&*info), &mut *okm)
            .await?;

        // KAT vectors are public, fixed test data — a plain slice comparison is
        // correct; no constant-time compare is needed.
        if &okm[..] != v.okm {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "HKDF KAT mismatch"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }

        Ok::<(), HsmError>(())
    })
    .await
}

/// Runs the KBKDF (SP 800-108 counter mode, HMAC-SHA-512) known-answer test.
///
/// Derives output via [`sp800_108_kdf`](HsmKdf::sp800_108_kdf) — the same
/// production path used by the `KbkdfCounterHmacDerive` DDI op — and compares
/// against the expected vector. Returns [`HsmError::SelfTestKatMismatch`] on a
/// mismatch (or any error surfaced by the KDF path / allocator).
pub(super) async fn run_kbkdf(pal: &UnoHsmPal, io: &UnoHsmIo) -> HsmResult<()> {
    let v = &KBKDF_SHA512_KAT;

    pal.alloc_scoped_async(io, async |scope| {
        // Stage the KAT operands into DMA-visible memory (the self-test slot).
        let key = scope.dma_alloc(v.key.len())?;
        key.copy_from_slice(v.key);
        let label = scope.dma_alloc(v.label.len())?;
        label.copy_from_slice(v.label);
        let context = scope.dma_alloc(v.context.len())?;
        context.copy_from_slice(v.context);
        let okm = scope.dma_alloc_zeroed(v.okm.len())?;

        pal.sp800_108_kdf(
            io,
            HsmHashAlgo::Sha512,
            &*key,
            Some(&*label),
            Some(&*context),
            &mut *okm,
        )
        .await?;

        if &okm[..] != v.okm {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "KBKDF KAT mismatch"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }

        Ok::<(), HsmError>(())
    })
    .await
}
