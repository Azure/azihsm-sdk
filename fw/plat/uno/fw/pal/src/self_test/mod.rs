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
//! AES-256-CBC is implemented as the initial test. Further tests (HKDF, KBKDF,
//! per-engine ECDSA / ECDH / RSA, and the RNG/DRBG FW-mode KAT) extend the
//! [`SelfTest`] enum and the [`run_one`] dispatch.

mod aes_cbc;
mod kdf;
mod vectors;

use azihsm_fw_hsm_pal_traits::HsmResult;

use crate::UnoHsmIo;
use crate::UnoHsmPal;

/// Identifies a single cryptographic algorithm self-test.
// Variants beyond `AesCbc` (and their constructors) land with the boot gate
// and per-engine tests in a later milestone.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum SelfTest {
    /// AES-256-CBC known-answer test (HSM AES engine).
    AesCbc,
}

/// One scheduled self-test unit: a [`SelfTest`] optionally pinned to a specific
/// hardware engine instance.
///
/// `engine` is `None` for tests that are not engine-scoped (such as
/// [`SelfTest::AesCbc`]); per-PKA-engine tests (added later) carry
/// `Some(index)` to validate each engine individually.
//
// `engine` is read once per-engine tests are wired (later milestone).
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct SelfTestItem {
    /// Which self-test to run.
    pub test: SelfTest,
    /// Target PKA engine instance, if the test is engine-scoped.
    pub engine: Option<u8>,
}

/// Runs a single self-test item to completion.
///
/// The caller decides which items to run; `run_one` itself is
/// context-agnostic.
//
// Wired into the boot gate and the periodic self-test task in a later
// milestone; retained here as the dispatch entry point.
#[allow(dead_code)]
pub(crate) async fn run_one(pal: &UnoHsmPal, io: &UnoHsmIo, item: SelfTestItem) -> HsmResult<()> {
    match item.test {
        SelfTest::AesCbc => aes_cbc::run_aes_cbc(pal, io).await,
    }
}

/// Runs the full pre-operational self-test suite.
///
/// Returns `Err` on the first failing test, leaving it to the caller (the boot
/// gate) to withhold the transition to the running state on failure. Mirrors
/// the reference firmware's `preops_cast` — positive known-answer tests only.
pub(crate) async fn run_pre_op(pal: &UnoHsmPal, io: &UnoHsmIo) -> HsmResult<()> {
    aes_cbc::run_aes_cbc(pal, io).await?;
    kdf::run_hkdf(pal, io).await?;
    Ok(())
}
