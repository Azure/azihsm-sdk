// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic Algorithm Self-Tests (CAST) for the Uno HSM core.
//!
//! Implements the FIPS pre-operational and periodic self-tests for
//! the HSM-core cryptographic algorithms. Each test runs a fixed known-answer
//! vector through the PAL crypto path and compares the result against the
//! expected output.
//!
//! # Memory
//!
//! All tests run on a dedicated, reserved IO slot
//! ([`crate::alloc::SELF_TEST_IO_INDEX`]) obtained via
//! [`UnoHsmIo::self_test`]. KAT operands are bump-allocated from that
//! slot's `SRAM_IO_BUF`, so the self-tests never contend with host IO or
//! partition-provisioning crypto (which uses the separate admin slot).
//!
//! # Status
//!
//! AES-256-CBC, AES-256-ECB, AES-256-KWP, HKDF, KBKDF, per-engine RSA-2048
//! mod-exp (standard and CRT), ECDH-P384, ECDSA-P384, and the RNG/DRBG FW-mode
//! KAT are implemented, pre-operationally and periodically (the periodic RNG
//! KAT is gated by an Admin quiesce handshake over IPC). Further tests are
//! appended to [`run_pre_op`] as they are added — each is a direct call, with
//! per-PKA-engine tests wrapped in a `for engine in 0..PKA_ENGINES` loop.

mod aes_cbc;
mod aes_ecb;
mod aes_kwp;
mod kdf;
mod pka;
mod vectors;

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use embassy_time::Duration;
use embassy_time::Timer;
use embassy_time::with_timeout;

use crate::IpcChannel;
use crate::UnoHsmIo;
use crate::UnoHsmPal;
use crate::ipc::*;

/// Sends one RNG self-test request to Admin and validates the response.
///
/// A timeout must lead directly to fail-stop: the IPC send future cannot be
/// cancelled and then reused while its request remains in flight.
async fn admin_rng_request(pal: &UnoHsmPal, op: IpcMessageOpCode, drained: bool) -> HsmResult<u32> {
    let req = if op == IpcMessageOpCode::RngSelfTestStatus {
        encode_rng_self_test_status(drained)
    } else {
        encode_rng_self_test(op)
    };
    let mut resp = [0u32; IPC_MESSAGE_LENGTH];
    with_timeout(
        Duration::from_secs(1),
        pal.ipc
            .send(IpcChannel::AdminRequest as u8, &req, &mut resp),
    )
    .await
    .map_err(|_| HsmError::CryptoTimeout)?;
    response_status(&resp, op, drained).map_err(|_| HsmError::IpcResponseDecodeError)
}

/// Runs the DRBG KAT under the Admin quiesce handshake.
///
/// The KAT overwrites the shared DRBG, so Admin must stop its RNG users first:
/// `Prepare`, wait for Admin's UCD pause acknowledgement and all accepted
/// host IOs to complete, run the KAT, and send `Done` only on success.
/// On this single-core executor the KAT is synchronous. Any failure leaves
/// Admin quiesced and stops the HSM via [`notify_self_test_failure`].
async fn run_rng_periodic(pal: &UnoHsmPal) -> HsmResult<()> {
    let ok = u32::from(IpcMessageStatusCode::Success);
    let pending = u32::from(IpcMessageStatusCode::Pending);

    let prepare = admin_rng_request(pal, IpcMessageOpCode::RngSelfTestPrepare, false).await?;
    if prepare != ok {
        return Err(HsmError::IpcResponseFailure);
    }

    with_timeout(Duration::from_millis(RNG_DRAIN_TIMEOUT_MS), async {
        let mut pause_acknowledged = false;
        loop {
            let drained = pause_acknowledged && pal.host_io_drained();
            let status =
                admin_rng_request(pal, IpcMessageOpCode::RngSelfTestStatus, drained).await?;
            if status == ok && drained {
                return Ok(());
            }
            if status == ok {
                pause_acknowledged = true;
            }
            if status != pending && status != ok {
                return Err(HsmError::IpcResponseFailure);
            }
            Timer::after(Duration::from_millis(RNG_STATUS_POLL_MS)).await;
        }
    })
    .await
    .map_err(|_| HsmError::CryptoTimeout)??;

    pal.rng.self_test()?;
    let done = admin_rng_request(pal, IpcMessageOpCode::RngSelfTestDone, false).await?;
    if done != ok {
        return Err(HsmError::IpcResponseFailure);
    }
    Ok(())
}

/// One schedulable HSM-core self-test.
///
/// Every PKA engine instance is its own test, as in the reference firmware's
/// `SelfTest` list (`EcdhEngineInstanceN`, `Rsa2KModExpEngineInstanceN`, ...).
/// Pre-operational and periodic execution share [`SelfTest::run`].
#[derive(Clone, Copy)]
enum SelfTest {
    AesCbc,
    AesEcb,
    AesKwp,
    Hkdf,
    Kbkdf,
    RsaModExp(u8),
    RsaModExpCrt(u8),
    Ecdh(u8),
    Ecdsa(u8),
    /// DRBG FW-mode KAT. State-destructive: pre-operationally it runs before
    /// any RNG consumer exists; periodically it runs only after Admin has
    /// quiesced its own RNG use ([`run_rng_periodic`]).
    Rng,
}

/// Tests without a per-engine instance, in execution order.
const FIXED_TESTS: [SelfTest; 5] = [
    SelfTest::AesCbc,
    SelfTest::AesEcb,
    SelfTest::AesKwp,
    SelfTest::Hkdf,
    SelfTest::Kbkdf,
];

/// PKA tests per engine.
const PKA_TESTS_PER_ENGINE: usize = 4;

/// Number of tests in one periodic cycle: the fixed tests, the per-engine PKA
/// tests, and the RNG test last. The RNG test is state-destructive and runs
/// through the Admin quiesce handshake ([`run_rng_periodic`]).
const PERIODIC_TEST_COUNT: usize =
    FIXED_TESTS.len() + PKA_TESTS_PER_ENGINE * pka::PKA_ENGINES as usize + 1;

/// Maximum time to acknowledge the UCD pause and drain accepted host IOs.
const RNG_DRAIN_TIMEOUT_MS: u64 = 1_500;

/// Delay between Admin `Status` polls.
const RNG_STATUS_POLL_MS: u64 = 20;

/// Time between two periodic tests.
const PERIODIC_INTERVAL_SECS: u64 = 60;

impl SelfTest {
    /// Returns `(test kind, engine)` for periodic failure attribution.
    fn id(self) -> (u32, u32) {
        match self {
            Self::AesCbc => (1, 0),
            Self::AesEcb => (2, 0),
            Self::AesKwp => (3, 0),
            Self::Hkdf => (4, 0),
            Self::Kbkdf => (5, 0),
            Self::RsaModExp(e) => (6, e as u32),
            Self::RsaModExpCrt(e) => (7, e as u32),
            Self::Ecdh(e) => (8, e as u32),
            Self::Ecdsa(e) => (9, e as u32),
            Self::Rng => (10, 0),
        }
    }

    /// Executes the known-answer test on the self-test IO slot.
    async fn run(self, pal: &UnoHsmPal, io: &UnoHsmIo) -> HsmResult<()> {
        match self {
            Self::AesCbc => aes_cbc::run_aes_cbc(pal, io).await,
            Self::AesEcb => aes_ecb::run_aes_ecb(pal, io).await,
            Self::AesKwp => aes_kwp::run_aes_kwp(pal, io).await,
            Self::Hkdf => kdf::run_hkdf(pal, io).await,
            Self::Kbkdf => kdf::run_kbkdf(pal, io).await,
            Self::RsaModExp(e) => pka::run_rsa_mod_exp_on_engine(pal, io, e).await,
            Self::RsaModExpCrt(e) => pka::run_rsa_mod_exp_crt_on_engine(pal, io, e).await,
            Self::Ecdh(e) => pka::run_ecdh_on_engine(pal, io, e).await,
            Self::Ecdsa(e) => pka::run_ecdsa_on_engine(pal, io, e).await,
            Self::Rng => pal.rng.self_test(),
        }
    }
}

/// Returns the `index`-th test of the periodic cycle.
///
/// Fixed tests come first, then each engine in turn runs ECDH, ECDSA,
/// RSA mod-exp and RSA mod-exp CRT (the reference firmware's order).
fn periodic_test(index: usize) -> SelfTest {
    if let Some(test) = FIXED_TESTS.get(index) {
        return *test;
    }

    let n = index - FIXED_TESTS.len();
    if n == PKA_TESTS_PER_ENGINE * pka::PKA_ENGINES as usize {
        return SelfTest::Rng;
    }
    let engine = (n / PKA_TESTS_PER_ENGINE) as u8;
    match n % PKA_TESTS_PER_ENGINE {
        0 => SelfTest::Ecdh(engine),
        1 => SelfTest::Ecdsa(engine),
        2 => SelfTest::RsaModExp(engine),
        _ => SelfTest::RsaModExpCrt(engine),
    }
}

/// Reports a failed periodic self-test, like the reference firmware's
/// `notify_self_test_failure` (periodic failures only; a pre-operational
/// failure is propagated as `Err` and the boot gate panics, as in the
/// reference `HsmEnv::new`).
///
/// Saves an attributed crash dump, notifies the peer and enters the FIPS
/// error state through Mailbox0.
fn notify_self_test_failure(test: SelfTest, err: HsmError) -> ! {
    let (kind, engine) = test.id();
    azihsm_fw_uno_fault::enter_self_test_error_state(kind, engine, err)
}

/// Runs the full pre-operational self-test suite.
///
/// Returns `Err` on the first failing test; the caller (the boot gate) panics,
/// as the reference firmware does when `preops_cast` fails. Mirrors
/// the reference firmware's `preops_cast` — positive known-answer tests only.
pub(crate) async fn run_pre_op(pal: &UnoHsmPal, io: &UnoHsmIo) -> HsmResult<()> {
    for test in FIXED_TESTS {
        test.run(pal, io).await?;
    }
    for engine in 0..pka::PKA_ENGINES {
        SelfTest::RsaModExp(engine).run(pal, io).await?;
    }
    for engine in 0..pka::PKA_ENGINES {
        SelfTest::RsaModExpCrt(engine).run(pal, io).await?;
    }
    for engine in 0..pka::PKA_ENGINES {
        SelfTest::Ecdh(engine).run(pal, io).await?;
    }
    for engine in 0..pka::PKA_ENGINES {
        SelfTest::Ecdsa(engine).run(pal, io).await?;
    }
    // The DRBG FW-mode KAT is state-destructive; it saves and restores the
    // production DRBG registers internally. Run it last (matching the reference
    // `preops_cast` ordering) and before any live RNG consumer exists.
    SelfTest::Rng.run(pal, io).await?;
    Ok(())
}

/// Runs one test per [`PERIODIC_INTERVAL_SECS`], cycling through the list forever.
///
/// Tests run one at a time on the dedicated self-test slot, so two periodic
/// tests can never overlap; PKA engines are shared with live IO through
/// `acquire_engine`, which waits for a busy engine. A failure or timeout
/// stops the HSM.
pub(crate) async fn run_periodic(pal: &UnoHsmPal) -> ! {
    let io = UnoHsmIo::self_test();
    let mut index = 0;

    loop {
        Timer::after(Duration::from_secs(PERIODIC_INTERVAL_SECS)).await;

        let test = periodic_test(index);
        let result = match test {
            SelfTest::Rng => run_rng_periodic(pal).await,
            _ => match with_timeout(Duration::from_secs(1), test.run(pal, &io)).await {
                Ok(result) => result,
                Err(_) => Err(HsmError::CryptoTimeout),
            },
        };
        if let Err(e) = result {
            notify_self_test_failure(test, e);
        }

        index += 1;
        if index == PERIODIC_TEST_COUNT {
            index = 0;
        }
    }
}
