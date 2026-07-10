// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic Algorithm Self-Tests (CAST) for the Uno HSM core.
//!
//! Implements the FIPS pre-operational and (future) periodic self-tests for
//! the HSM-core cryptographic algorithms. Each test runs a fixed known-answer
//! vector through the PAL crypto path and compares the result against the
//! expected output.
//!
//! # Memory
//!
//! All tests run on a dedicated, reserved IO slot
//! ([`crate::alloc::SELF_TEST_IO_INDEX`]) obtained via
//! [`UnoHsmPal::self_test_io`]. KAT operands are bump-allocated from that
//! slot's `SRAM_IO_BUF`, so the self-tests never contend with host IO or
//! partition-provisioning crypto (which uses the separate admin slot).
//!
//! # Status
//!
//! AES-256-CBC, HKDF, KBKDF, per-engine RSA-2048 mod-exp (standard and CRT),
//! ECDH-P384, ECDSA-P384, and the RNG/DRBG FW-mode KAT are implemented. Further
//! tests are appended to [`run_pre_op`] as they are added — each is a direct
//! call, with per-PKA-engine tests wrapped in a
//! `for engine in 0..PKA_ENGINES` loop.

mod aes_cbc;
mod kdf;
mod pka;
mod vectors;

use azihsm_fw_hsm_pal_traits::HsmResult;

use crate::UnoHsmIo;
use crate::UnoHsmPal;

/// Runs the full pre-operational self-test suite.
///
/// Returns `Err` on the first failing test, leaving it to the caller (the boot
/// gate) to withhold the transition to the running state on failure. Mirrors
/// the reference firmware's `preops_cast` — positive known-answer tests only.
pub(crate) async fn run_pre_op(pal: &UnoHsmPal, io: &UnoHsmIo) -> HsmResult<()> {
    aes_cbc::run_aes_cbc(pal, io).await?;
    kdf::run_hkdf(pal, io).await?;
    kdf::run_kbkdf(pal, io).await?;
    for engine in 0..pka::PKA_ENGINES {
        pka::run_rsa_mod_exp_on_engine(pal, io, engine).await?;
    }
    for engine in 0..pka::PKA_ENGINES {
        pka::run_rsa_mod_exp_crt_on_engine(pal, io, engine).await?;
    }
    for engine in 0..pka::PKA_ENGINES {
        pka::run_ecdh_on_engine(pal, io, engine).await?;
    }
    for engine in 0..pka::PKA_ENGINES {
        pka::run_ecdsa_on_engine(pal, io, engine).await?;
    }
    // The DRBG FW-mode KAT is state-destructive; it saves and restores the
    // production DRBG registers internally. Run it last (matching the reference
    // `preops_cast` ordering) and before any live RNG consumer exists.
    pal.rng.self_test()?;
    Ok(())
}
