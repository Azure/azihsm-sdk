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
//! KAT runs only while Admin holds host IO quiesced; see
//! [`run_rng_periodic`]). Further tests are appended to [`run_pre_op`] as they
//! are added — each is a direct call, with per-PKA-engine tests wrapped in a
//! `for engine in 0..PKA_ENGINES` loop.

mod aes_cbc;
mod aes_ecb;
mod aes_kwp;
mod kdf;
mod pka;
mod vectors;

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_uno_drivers_aes::AesError;
use azihsm_fw_uno_drivers_sha::ShaError;
use azihsm_fw_uno_drivers_upka::UpkaError;
use embassy_time::Duration;
use embassy_time::Instant;
use embassy_time::Timer;
use embassy_time::with_timeout;

use crate::IpcChannel;
use crate::UnoHsmIo;
use crate::UnoHsmPal;
use crate::ipc::*;

/// Sends one RNG self-test request to Admin and returns its validated status.
///
/// Admin answers `Prepare` only once it has quiesced or declined (about 2 s
/// at most), but its event loop can be busy for up to 25 s in the iDFU Ready
/// wait, hence [`RNG_ADMIN_IPC_TIMEOUT_SECS`]. A missing answer stops the HSM
/// while the send future is still alive: an in-flight IPC send cannot be
/// cancelled and the channel reused.
async fn admin_rng_request(
    pal: &UnoHsmPal,
    op: IpcMessageOpCode,
) -> HsmResult<IpcMessageStatusCode> {
    let req = encode_rng_self_test(op);
    let mut resp = [0u32; IPC_MESSAGE_LENGTH];
    {
        let send = core::pin::pin!(
            pal.ipc
                .send(IpcChannel::AdminRequest as u8, &req, &mut resp)
        );
        if with_timeout(Duration::from_secs(RNG_ADMIN_IPC_TIMEOUT_SECS), send)
            .await
            .is_err()
        {
            notify_self_test_failure(SelfTest::Rng, HsmError::RngSelfTestAdminTimeout);
        }
    }
    response_status(&resp, op).map_err(|_| HsmError::IpcResponseDecodeError)
}

/// Outcome of one periodic RNG self-test attempt.
enum RngAttempt {
    Passed,
    /// Admin could not quiesce host IO now; nothing was run. Retry later.
    Deferred,
}

/// Runs the DRBG KAT while Admin holds host IO quiesced.
///
/// The KAT overwrites the DRBG shared with Admin, so Admin must first stop
/// its DRBG reads and pause HSM host IO. `Prepare` is answered `Success` only
/// when HSM UCD is paused and every HSM SQ credit is back (so no host command
/// is queued or in progress), or `Deferred` when Admin cannot quiesce now. On
/// this cooperative executor nothing runs between the reply and the
/// synchronous KAT; the HSM still checks its own IO state once, and treats a
/// mismatch (an SQ set changed during the drain) as "not now". `Done` resumes
/// host IO. A KAT failure stops the HSM without `Done`, leaving host IO
/// paused.
async fn run_rng_periodic(pal: &UnoHsmPal) -> HsmResult<RngAttempt> {
    match admin_rng_request(pal, IpcMessageOpCode::RngSelfTestPrepare).await? {
        IpcMessageStatusCode::Success => {}
        IpcMessageStatusCode::Deferred => return Ok(RngAttempt::Deferred),
        _ => return Err(HsmError::IpcResponseFailure),
    }

    let drained = pal.host_io_drained();
    if drained {
        pal.rng.self_test()?;
    }

    if admin_rng_request(pal, IpcMessageOpCode::RngSelfTestDone).await?
        != IpcMessageStatusCode::Success
    {
        return Err(HsmError::IpcResponseFailure);
    }
    Ok(if drained {
        RngAttempt::Passed
    } else {
        RngAttempt::Deferred
    })
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
    /// any RNG consumer exists; periodically it runs only while Admin holds
    /// host IO quiesced ([`run_rng_periodic`]).
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
/// under the Admin quiesce ([`run_rng_periodic`]).
const PERIODIC_TEST_COUNT: usize =
    FIXED_TESTS.len() + PKA_TESTS_PER_ENGINE * pka::PKA_ENGINES as usize + 1;

/// Bound on one Admin RNG request: Admin's iDFU Ready wait may occupy its
/// event loop for up to 25 seconds (drain time clamped by Admin).
const RNG_ADMIN_IPC_TIMEOUT_SECS: u64 = 30;

/// Delay between attempts of a deferred RNG test.
const RNG_RETRY_INTERVAL_SECS: u64 = 6;

/// Retry a deferred RNG test nine times after its first attempt.
const RNG_MAX_RETRIES: u8 = 9;

/// Time between two periodic tests.
const PERIODIC_INTERVAL_SECS: u64 = 60;

/// Delay between attempts to acquire a busy crypto queue.
const QUEUE_RETRY_INTERVAL_SECS: u64 = 1;

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

/// Runs one scheduled non-RNG test on the self-test slot.
///
/// A full crypto queue is retried for at most one interval; a test that does
/// not finish within one second, or any other failure, stops the HSM.
async fn run_scheduled_test(pal: &UnoHsmPal, io: &UnoHsmIo, test: SelfTest) {
    let admission_deadline = Instant::now() + Duration::from_secs(PERIODIC_INTERVAL_SECS);
    loop {
        let result = {
            let future = test.run(pal, io);
            let mut future = core::pin::pin!(future);
            match with_timeout(Duration::from_secs(1), future.as_mut()).await {
                Ok(result) => result,
                Err(_) => notify_self_test_failure(test, HsmError::CryptoTimeout),
            }
        };
        match result {
            Ok(()) => return,
            Err(e)
                if e == AesError::QUEUE_FULL
                    || e == ShaError::QUEUE_FULL
                    || e == UpkaError::QUEUE_FULL =>
            {
                let retry_at = (Instant::now() + Duration::from_secs(QUEUE_RETRY_INTERVAL_SECS))
                    .min(admission_deadline);
                Timer::at(retry_at).await;
                if Instant::now() >= admission_deadline {
                    notify_self_test_failure(test, e);
                }
            }
            Err(e) => notify_self_test_failure(test, e),
        }
    }
}

/// Retries recoverable quiesce deferrals without delaying scheduled tests.
async fn attempt_rng(
    pal: &UnoHsmPal,
    retry_at: &mut Option<Instant>,
    deferred_count: &mut u8,
) -> bool {
    match run_rng_periodic(pal).await {
        Ok(RngAttempt::Passed) => {
            *retry_at = None;
            *deferred_count = 0;
            true
        }
        Ok(RngAttempt::Deferred) => {
            if *deferred_count >= RNG_MAX_RETRIES {
                notify_self_test_failure(SelfTest::Rng, HsmError::RngSelfTestRetriesExhausted);
            }
            *deferred_count += 1;
            *retry_at = Some(Instant::now() + Duration::from_secs(RNG_RETRY_INTERVAL_SECS));
            false
        }
        Err(e) => notify_self_test_failure(SelfTest::Rng, e),
    }
}

/// Runs one scheduled test per interval and retries a deferred RNG test.
///
/// Tests run one at a time on the dedicated self-test slot, so two periodic
/// tests can never overlap; PKA engines are shared with live IO through
/// `acquire_engine`, which waits for a busy engine. A deferred RNG test does
/// not prevent the remaining scheduled tests from running.
pub(crate) async fn run_periodic(pal: &UnoHsmPal) -> ! {
    let io = UnoHsmIo::self_test();
    let mut index = 0;
    let mut next_test_at = Instant::now() + Duration::from_secs(PERIODIC_INTERVAL_SECS);
    let mut rng_retry_at: Option<Instant> = None;
    let mut rng_deferred_count = 0;

    loop {
        Timer::at(rng_retry_at.map_or(next_test_at, |retry| retry.min(next_test_at))).await;

        let rng_ran_this_turn = if rng_retry_at.is_some_and(|retry| Instant::now() >= retry) {
            attempt_rng(pal, &mut rng_retry_at, &mut rng_deferred_count).await
        } else {
            false
        };
        if Instant::now() < next_test_at {
            continue;
        }

        let test = periodic_test(index);
        match test {
            SelfTest::Rng => {
                if rng_retry_at.is_none() && !rng_ran_this_turn {
                    attempt_rng(pal, &mut rng_retry_at, &mut rng_deferred_count).await;
                }
            }
            _ => run_scheduled_test(pal, &io, test).await,
        }

        index += 1;
        if index == PERIODIC_TEST_COUNT {
            index = 0;
        }
        next_test_at = Instant::now() + Duration::from_secs(PERIODIC_INTERVAL_SECS);
    }
}
