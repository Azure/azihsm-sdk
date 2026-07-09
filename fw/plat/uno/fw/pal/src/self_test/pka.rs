// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-engine PKA cryptographic algorithm self-tests (CAST).
//!
//! Unlike the algorithm-level KATs (AES / HKDF / KBKDF), the PKA tests validate
//! **each hardware PKA engine individually**: they pin a specific engine via
//! [`UpkaDriver::acquire_engine`] and run the operation on that engine, so the
//! caller can cover all [`PKA_ENGINES`] engines.
//!
//! The RSA tests are ported from the reference firmware's
//! `rsa_mod_exp_self_test` / `rsa_mod_exp_crt_self_test`: they compute
//! `plaintext = c^d mod n` on the pinned engine — using either a standard
//! `d ‖ n` key or a CRT `param1 ‖ param2` key — and compare against the expected
//! plaintext `k`. Operands are staged into the self-test IO slot's DMA buffer
//! via the bump allocator (see [`crate::self_test`]).

use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHash;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmKdf;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_drivers_upka::UpkaEccCurve;
use azihsm_fw_uno_drivers_upka::UpkaRsaKeyType;
use azihsm_fw_uno_reg_soc::io_gsram::UPKA_ENGINE_CMD_COUNT;
use azihsm_fw_uno_trace::tracing::error;

use super::vectors::ECDH_384_KAT;
use super::vectors::ECDH_P384_PRIME_LE;
use super::vectors::OAEP_KEK_SELF_TEST;
use super::vectors::RSA_2K_CRT_KAT;
use super::vectors::RSA_2K_MOD_EXP_KAT;
use crate::UnoHsmIo;
use crate::UnoHsmPal;

/// Number of hardware PKA engines to validate (one self-test run each).
pub(super) const PKA_ENGINES: u8 = UPKA_ENGINE_CMD_COUNT as u8;

/// RSA-2048 modulus size in bytes.
const RSA_2K_LEN: usize = 256;

/// NIST P-384 field element / shared-secret size in bytes.
const ECDH_384_LEN: usize = 48;

/// Runs the RSA-2048 mod-exp (private-key) known-answer test on PKA engine
/// `engine`, followed by the OAEP-decode (SHA-256) KEK check.
///
/// Computes `c^d mod n` on the pinned engine and compares the result against
/// the expected plaintext, then OAEP-decodes that plaintext block and compares
/// the recovered KEK against the expected value (mirroring the reference
/// firmware's `rsa_mod_exp_self_test` + `decode_oaep_kek_self_test`). Returns
/// [`HsmError::SelfTestKatMismatch`] on a mismatch, or any error surfaced by
/// the PKA / SHA engine or the allocator.
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

        if &output[..] != v.k {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "RSA-2K mod-exp KAT mismatch on engine"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }

        // ── OAEP-decode tail (SHA-256, empty label) ──────────────────────────
        // Ported from the reference `decode_oaep_kek_self_test`: the mod-exp
        // output block is little-endian, so it is reversed into the big-endian
        // OAEP-encoded message `EM = 0x00 ‖ maskedSeed ‖ maskedDB`, then
        // OAEP-decoded with the SHA/MGF1 primitives (identical steps to the
        // production `rsa_oaep_decrypt`) and the recovered 16-byte KEK is
        // compared against the expected value. This also exercises SHA-256 and
        // MGF1 on the HSM SHA engine.
        const H_LEN: usize = 32; // SHA-256 digest length.
        let em = scope.dma_alloc(RSA_2K_LEN)?;
        for (i, &b) in output[..RSA_2K_LEN].iter().enumerate() {
            em[RSA_2K_LEN - 1 - i] = b;
        }

        if em[0] != 0x00 {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "RSA-2K OAEP leading byte nonzero on engine"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }

        // Recover seed: seed = maskedSeed XOR MGF(maskedDB, hLen).
        {
            let (seed, db) = em[1..RSA_2K_LEN].split_at_mut(H_LEN);
            pal.mgf1_xor(io, HsmHashAlgo::Sha256, db, seed).await?;
        }
        // Recover DB: DB = maskedDB XOR MGF(seed, dbLen).
        {
            let (seed, db) = em[1..RSA_2K_LEN].split_at_mut(H_LEN);
            pal.mgf1_xor(io, HsmHashAlgo::Sha256, seed, db).await?;
        }

        // Verify lHash' == SHA-256(empty label).
        let label_hash = scope.dma_alloc(H_LEN)?;
        let empty = &input[..0];
        pal.hash(io, HsmHashAlgo::Sha256, empty, label_hash, true)
            .await?;
        let db = &em[1 + H_LEN..RSA_2K_LEN];
        let db_hash: &[u8] = &db[..H_LEN];
        let label_hash_slice: &[u8] = &label_hash[..H_LEN];
        if db_hash != label_hash_slice {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "RSA-2K OAEP lHash mismatch on engine"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }

        // DB = lHash' ‖ PS(0x00…) ‖ 0x01 ‖ M — locate the 0x01 separator, then
        // recover and check the message M against the expected KEK.
        let ps_and_m = &db[H_LEN..];
        let sep = match ps_and_m.iter().position(|&x| x == 0x01) {
            Some(s) if ps_and_m[..s].iter().all(|&x| x == 0x00) => s,
            _ => {
                error!(
                    "selftest",
                    HsmError::SelfTestKatMismatch,
                    "RSA-2K OAEP separator invalid on engine"
                );
                return Err(HsmError::SelfTestKatMismatch);
            }
        };
        let kek: &[u8] = &db[H_LEN + sep + 1..];
        if kek != OAEP_KEK_SELF_TEST {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "RSA-2K OAEP KEK mismatch on engine"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }

        Ok::<(), HsmError>(())
    })
    .await
}

/// Runs the RSA-2048 CRT mod-exp (private-key) known-answer test on PKA engine
/// `engine`.
///
/// Ported from the reference firmware's `rsa_mod_exp_crt_self_test`. The CRT
/// private key is staged as a contiguous `param1 ‖ param2` blob: `param1`
/// (`p ‖ q ‖ dp ‖ dq`, `2 * RSA_2K_LEN`) is read from the key pointer and
/// `param2` (`n ‖ n1q ‖ n2p`, `3 * RSA_2K_LEN`) is read by the hardware from the
/// arg3 pointer that [`rsa_mod_exp_priv`](azihsm_fw_uno_drivers_upka::UpkaEngine::rsa_mod_exp_priv)
/// derives for CRT key types. Computes `c^d mod n` on the pinned engine and
/// compares against the expected plaintext. Returns
/// [`HsmError::SelfTestKatMismatch`] on a mismatch, or any error surfaced by the
/// PKA engine / allocator.
pub(super) async fn run_rsa_mod_exp_crt_on_engine(
    pal: &UnoHsmPal,
    io: &UnoHsmIo,
    engine: u8,
) -> HsmResult<()> {
    let v = &RSA_2K_CRT_KAT;

    pal.alloc_scoped_async(io, async |scope| {
        // CRT private key blob: `param1` (p‖q‖dp‖dq) followed by `param2`
        // (n‖n1q‖n2p). The driver passes the blob base as arg2 (param1) and
        // `base + param1.len()` as arg3 (param2) for CRT key types.
        let key = scope.dma_alloc(v.param1.len() + v.param2.len())?;
        key[..v.param1.len()].copy_from_slice(v.param1);
        key[v.param1.len()..].copy_from_slice(v.param2);
        // Input ciphertext `c` and output plaintext buffer.
        let input = scope.dma_alloc(RSA_2K_LEN)?;
        input.copy_from_slice(v.c);
        let output = scope.dma_alloc_zeroed(RSA_2K_LEN)?;

        // Pin the requested engine for the operation, release afterwards.
        let mut eng = pal.pka.acquire_engine(engine).await?;
        let outcome = eng
            .rsa_mod_exp_priv(UpkaRsaKeyType::Rsa2048Crt, &*key, &*input, &mut *output)
            .await;
        let release = eng.release().await;
        outcome?;
        release?;

        if &output[..] != v.k {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "RSA-2K CRT mod-exp KAT mismatch on engine"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }

        Ok::<(), HsmError>(())
    })
    .await
}

/// Runs the ECDH P-384 (ECC CDH primitive) known-answer test on PKA engine
/// `engine`.
///
/// Ported from the reference firmware's `ecdh_self_test`. Derives the shared
/// secret `z = d_iut * Q_cavs` via a single point multiplication on the pinned
/// engine (the driver performs the required per-call Montgomery-constant setup
/// from the curve prime) and compares against the expected `z_iut`.
///
/// # Endianness
///
/// The peer public key (`qcavs_x ‖ qcavs_y`), private scalar (`d_iut`), and
/// curve prime are little-endian, matching the PKA operand order, and are fed
/// verbatim. The engine emits the shared secret little-endian; the expected
/// `z_iut` is big-endian, so the little-endian engine output is reversed before
/// comparison (mirroring the production `ecdh_derive`).
///
/// Returns [`HsmError::SelfTestKatMismatch`] on a mismatch, or any error
/// surfaced by the PKA engine / allocator.
pub(super) async fn run_ecdh_on_engine(
    pal: &UnoHsmPal,
    io: &UnoHsmIo,
    engine: u8,
) -> HsmResult<()> {
    let v = &ECDH_384_KAT;

    pal.alloc_scoped_async(io, async |scope| {
        // Peer public key as a contiguous `X ‖ Y` block (little-endian).
        let pub_key = scope.dma_alloc(ECDH_384_LEN * 2)?;
        pub_key[..ECDH_384_LEN].copy_from_slice(v.qcavs_x);
        pub_key[ECDH_384_LEN..].copy_from_slice(v.qcavs_y);
        // Private scalar (little-endian).
        let priv_key = scope.dma_alloc(ECDH_384_LEN)?;
        priv_key.copy_from_slice(v.d_iut);
        // Curve prime and Montgomery-constant scratch for the point-multiply.
        let prime = scope.dma_alloc(ECDH_384_LEN)?;
        prime.copy_from_slice(ECDH_P384_PRIME_LE);
        let mont_result = scope.dma_alloc(ECDH_384_LEN)?;
        // Derived shared-secret output (little-endian).
        let secret = scope.dma_alloc_zeroed(ECDH_384_LEN)?;
        // Status word for the hardware on-curve validation the driver runs
        // between the Montgomery-constant setup and the ECDH compute.
        let point_valid = scope.dma_alloc(4)?;

        // Pin the requested engine for the operation, release afterwards.
        let mut eng = pal.pka.acquire_engine(engine).await?;
        let outcome = eng
            .ecdh_derive(
                UpkaEccCurve::P384,
                &*priv_key,
                &*pub_key,
                &mut *secret,
                &*prime,
                &mut *mont_result,
                &mut *point_valid,
            )
            .await;
        let release = eng.release().await;
        outcome?;
        release?;

        // The engine writes the secret little-endian; `z_iut` is big-endian.
        // Compare the reversed output against the expected big-endian value.
        let matches = secret[..ECDH_384_LEN].iter().rev().eq(v.z_iut.iter());
        if !matches {
            error!(
                "selftest",
                HsmError::SelfTestKatMismatch,
                "ECDH P-384 KAT mismatch on engine"
            );
            return Err(HsmError::SelfTestKatMismatch);
        }

        Ok::<(), HsmError>(())
    })
    .await
}
