// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency interfaces for transparent recovery from Live Migration,
//! IO aborts, and firmware crash recovery.
//!

use std::time::Duration;

use rand::Rng;
use tracing::*;

use crate::HsmError;
use crate::HsmOwnerBackupKeyConfig;
use crate::HsmPotaEndorsement;
use crate::HsmPotaEndorsementData;
use crate::HsmResult;
use crate::partition::HsmCredentials;
use crate::shared_types::HsmPotaEndorsementSource;

cfg_if::cfg_if! {
    if #[cfg(feature = "res-test")] {
        /// Concrete DDI type used by the API layer with resiliency fault injection.
        pub(crate) type HsmDdi = azihsm_res_test_dev::DdiResTest<azihsm_ddi::AzihsmDdi>;
    } else {
        /// Concrete DDI type used by the API layer.
        pub(crate) type HsmDdi = azihsm_ddi::AzihsmDdi;
    }
}

/// Well-known storage key for the backup masking key.
pub(crate) const AZIHSM_STORAGE_BMK: &str = "azihsm_bmk";

/// Well-known storage key for the masked unwrapping key.
///
/// [TODO] Not yet written during `init_part`. MUK is persisted when the
/// unwrapping key is fetched during a session operation.
/// This constant is reserved for that future implementation.
#[allow(dead_code)]
pub(crate) const AZIHSM_STORAGE_MUK: &str = "azihsm_muk";

/// Persistent key-value storage for resiliency data.
///
/// Implementer is responsible for atomicity of individual operations.
/// Keys are UTF-8 strings: well-known `AZIHSM_STORAGE_*` constants for
/// SDK-internal data, and key labels (UTF-8, <128 bytes) for token keys.
pub trait ResiliencyStorage: Send + Sync {
    /// Read data for the given key.
    ///
    /// Returns `Err(HsmError::NotFound)` when key does not exist.
    fn read(&self, key: &str) -> HsmResult<Vec<u8>>;

    /// Write data for the given key (create or overwrite).
    fn write(&self, key: &str, data: &[u8]) -> HsmResult<()>;

    /// Delete data for the given key. No error if key doesn't exist.
    fn clear(&self, key: &str) -> HsmResult<()>;
}

/// Cross-process and cross-thread lock for coordinating `restore_partition`.
///
/// Non-reentrant: caller must not call `lock()` while already holding the lock.
/// This is a separate coordination mechanism preventing two threads/processes
/// from restoring simultaneously — it is NOT tied to storage.
pub trait ResiliencyLock: Send + Sync {
    /// Acquire the lock. Blocks until available.
    fn lock(&self) -> HsmResult<()>;

    /// Release the lock.
    fn unlock(&self) -> HsmResult<()>;
}

/// Callback for re-signing POTA endorsement during retry and restore.
///
/// Required when POTA endorsement source is `Caller` AND resiliency is
/// enabled. Called during `init_part` (to re-endorse after a
/// resiliency event).
///
/// The callback is responsible for retrieving the current device's PID
/// certificate public key, signing it, and returning the result.
pub trait PotaEndorsementCallback: Send + Sync {
    /// Generate a fresh POTA endorsement for the current device.
    ///
    /// The `pub_key` parameter is the caller's original endorsement public
    /// key, passed for identification.
    ///
    /// The implementation must:
    /// 1. Retrieve the current device's PID certificate public key
    /// 2. Sign it with the caller's private key
    /// 3. Return the signature and the signer's public key
    fn endorse(&self, pub_key: &[u8]) -> HsmResult<HsmPotaEndorsementData>;
}

/// RAII guard for [`ResiliencyLock`].
///
/// Acquires the lock on construction and releases it on drop, ensuring the
/// lock is always released even when the caller returns early due to an error.
///
/// When constructed with `None` (resiliency disabled), the guard is a no-op.
pub(crate) struct ResiliencyLockGuard<'a> {
    lock: Option<&'a dyn ResiliencyLock>,
}

impl<'a> ResiliencyLockGuard<'a> {
    /// Acquire the resiliency lock and return a guard that releases it on drop.
    ///
    /// When `config` is `None`, returns a no-op guard.
    pub(crate) fn acquire(config: Option<&'a HsmResiliencyConfig>) -> HsmResult<Self> {
        if let Some(cfg) = config {
            cfg.lock.lock()?;
            Ok(Self {
                lock: Some(cfg.lock.as_ref()),
            })
        } else {
            Ok(Self { lock: None })
        }
    }
}

impl Drop for ResiliencyLockGuard<'_> {
    fn drop(&mut self) {
        if let Some(lock) = self.lock {
            if let Err(e) = lock.unlock() {
                warn!("Failed to release resiliency lock on drop: {e:?}");
            }
        }
    }
}

/// Resiliency configuration bundle.
///
/// Passed to [`HsmPartition::init()`] to enable resiliency. When `None` is
/// passed, no resiliency behavior is added.
///
/// # Validation rules
///
/// - If POTA endorsement source is `Caller`, `pota_callback` must be
///   `Some`. Otherwise `init()` returns `HsmError::InvalidArgument`.
/// - If POTA endorsement source is `Tpm`, `pota_callback` must be
///   `None`. Otherwise `init()` returns `HsmError::InvalidArgument`.
pub struct HsmResiliencyConfig {
    /// Persistent storage for BMK, MUK, and masked app keys.
    pub storage: Box<dyn ResiliencyStorage>,

    /// Cross-process/thread lock for restore coordination.
    pub lock: Box<dyn ResiliencyLock>,

    /// POTA re-endorsement callback (required when source is Caller).
    pub pota_callback: Option<Box<dyn PotaEndorsementCallback>>,
}

/// Internal resiliency state cached during partition init.
///
/// Stored inside `HsmPartitionInner` when resiliency is enabled.
#[allow(dead_code)]
pub(crate) struct ResiliencyState {
    /// Resiliency configuration (storage, lock, POTA callback).
    pub(crate) config: HsmResiliencyConfig,

    /// Cached credentials for re-establishing during restore.
    pub(crate) cached_credentials: HsmCredentials,

    /// Cached OBK configuration for re-establishing during restore.
    pub(crate) cached_obk_config: HsmOwnerBackupKeyConfig,

    /// Cached POTA endorsement for restore.
    pub(crate) cached_pota_endorsement: HsmPotaEndorsement,

    /// Restore epoch — incremented on each restore_partition.
    /// Keys check this to detect staleness before DDI calls.
    pub(crate) restore_epoch: u64,

    /// Cached session state for reopening after restore.
    /// Populated by `HsmPartition::open_session`, cleared by session drop.
    pub(crate) cached_session: Option<CachedSessionState>,
}

/// Session material needed to reopen a session after resiliency event.
#[allow(dead_code)]
pub(crate) struct CachedSessionState {
    /// Device-assigned session ID.
    pub(crate) sess_id: u16,
    /// API revision used to open the session.
    pub(crate) rev: crate::partition::HsmApiRev,
    /// The 48-byte random seed used for credential encryption.
    pub(crate) seed: [u8; 48],
    /// Backed-up session masking key from the device.
    pub(crate) bmk_session: Vec<u8>,
}

impl std::fmt::Debug for ResiliencyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResiliencyState")
            .field("has_pota_callback", &self.config.pota_callback.is_some())
            .field("cached_obk_config", &self.cached_obk_config)
            .field("cached_pota_endorsement", &self.cached_pota_endorsement)
            .field("restore_epoch", &self.restore_epoch)
            .field("has_cached_session", &self.cached_session.is_some())
            .finish_non_exhaustive()
    }
}

impl ResiliencyState {
    /// Validates the resiliency config against the POTA endorsement.
    ///
    /// Returns `InvalidArgument` if:
    /// - Caller-sourced POTA is missing a callback, or
    /// - TPM-sourced POTA has a callback.
    pub(crate) fn validate_config(
        config: &HsmResiliencyConfig,
        pota_endorsement: &HsmPotaEndorsement,
    ) -> HsmResult<()> {
        let is_caller = pota_endorsement.source() == HsmPotaEndorsementSource::Caller;
        if is_caller != config.pota_callback.is_some() {
            Err(HsmError::InvalidArgument)?;
        }
        Ok(())
    }

    /// Creates a new resiliency state from the config and init parameters.
    ///
    /// The caller must have already called [`Self::validate_config`]
    /// before invoking DDI operations. This constructor trusts that the
    /// config has been validated.
    pub(crate) fn new(
        config: HsmResiliencyConfig,
        credentials: HsmCredentials,
        obk_config: HsmOwnerBackupKeyConfig,
        pota_endorsement: HsmPotaEndorsement,
    ) -> Self {
        Self {
            config,
            cached_credentials: credentials,
            cached_obk_config: obk_config,
            cached_pota_endorsement: pota_endorsement,
            restore_epoch: 0,
            cached_session: None,
        }
    }

    /// Saves session state so [`restore_partition`] can reopen it.
    pub(crate) fn cache_session(&mut self, state: CachedSessionState) {
        self.cached_session = Some(state);
    }

    /// Clears cached session state (e.g. after session close).
    pub(crate) fn clear_session(&mut self) {
        self.cached_session = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HsmOwnerBackupKeySource;

    // Minimal mock implementations for testing ResiliencyState construction and validation logic.
    struct MockStorage;
    impl ResiliencyStorage for MockStorage {
        fn read(&self, _key: &str) -> HsmResult<Vec<u8>> {
            Err(HsmError::NotFound)
        }
        fn write(&self, _key: &str, _data: &[u8]) -> HsmResult<()> {
            Ok(())
        }
        fn clear(&self, _key: &str) -> HsmResult<()> {
            Ok(())
        }
    }

    struct MockLock;
    impl ResiliencyLock for MockLock {
        fn lock(&self) -> HsmResult<()> {
            Ok(())
        }
        fn unlock(&self) -> HsmResult<()> {
            Ok(())
        }
    }

    struct MockPotaCallback;
    impl PotaEndorsementCallback for MockPotaCallback {
        fn endorse(&self, _pub_key: &[u8]) -> HsmResult<HsmPotaEndorsementData> {
            Ok(HsmPotaEndorsementData::new(&[0u8; 96], &[0u8; 120]))
        }
    }

    fn mock_config(with_callback: bool) -> HsmResiliencyConfig {
        HsmResiliencyConfig {
            storage: Box::new(MockStorage),
            lock: Box::new(MockLock),
            pota_callback: if with_callback {
                Some(Box::new(MockPotaCallback))
            } else {
                None
            },
        }
    }

    fn test_creds() -> HsmCredentials {
        HsmCredentials::new(&[1u8; 16], &[2u8; 16])
    }

    fn caller_obk() -> HsmOwnerBackupKeyConfig {
        HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, Some(&[3u8; 32]))
    }

    fn caller_pota() -> HsmPotaEndorsement {
        HsmPotaEndorsement::new(
            HsmPotaEndorsementSource::Caller,
            Some(HsmPotaEndorsementData::new(&[4u8; 96], &[5u8; 120])),
        )
    }

    fn tpm_pota() -> HsmPotaEndorsement {
        HsmPotaEndorsement::new(HsmPotaEndorsementSource::Tpm, None)
    }

    #[test]
    fn resiliency_state_caller_pota_with_callback_succeeds() {
        let config = mock_config(true);
        let pota = caller_pota();
        ResiliencyState::validate_config(&config, &pota)
            .expect("caller POTA with callback should be valid");
        let _state = ResiliencyState::new(config, test_creds(), caller_obk(), pota);
    }

    #[test]
    fn resiliency_state_caller_pota_without_callback_fails() {
        let config = mock_config(false);
        let pota = caller_pota();
        let err = ResiliencyState::validate_config(&config, &pota)
            .expect_err("caller POTA without callback should fail");
        assert_eq!(err, HsmError::InvalidArgument);
    }

    #[test]
    fn resiliency_state_tpm_pota_without_callback_succeeds() {
        let config = mock_config(false);
        let pota = tpm_pota();
        ResiliencyState::validate_config(&config, &pota)
            .expect("TPM POTA without callback should be valid");
        let _state = ResiliencyState::new(config, test_creds(), caller_obk(), pota);
    }

    #[test]
    fn resiliency_state_tpm_pota_with_callback_fails() {
        // TPM handles POTA endorsement itself; providing a callback is a config error.
        let config = mock_config(true);
        let pota = tpm_pota();
        let err = ResiliencyState::validate_config(&config, &pota)
            .expect_err("TPM POTA with callback should fail");
        assert_eq!(err, HsmError::InvalidArgument);
    }

    #[test]
    fn resiliency_state_initial_epoch_is_zero() {
        let state =
            ResiliencyState::new(mock_config(true), test_creds(), caller_obk(), caller_pota());
        assert_eq!(state.restore_epoch, 0);
    }

    #[test]
    fn resiliency_state_caches_credentials() {
        let creds = test_creds();
        let state = ResiliencyState::new(mock_config(true), creds, caller_obk(), caller_pota());
        assert_eq!(state.cached_credentials, creds);
    }

    #[test]
    fn resiliency_state_caches_obk_config() {
        let obk = caller_obk();
        let state =
            ResiliencyState::new(mock_config(true), test_creds(), obk.clone(), caller_pota());
        assert_eq!(
            state.cached_obk_config.key_source(),
            HsmOwnerBackupKeySource::Caller
        );
        assert_eq!(state.cached_obk_config.key(), obk.key());
    }

    #[test]
    fn resiliency_state_caches_pota_endorsement() {
        let pota = caller_pota();
        let state =
            ResiliencyState::new(mock_config(true), test_creds(), caller_obk(), pota.clone());
        assert_eq!(
            state.cached_pota_endorsement.source(),
            HsmPotaEndorsementSource::Caller
        );
        let cached = state
            .cached_pota_endorsement
            .endorsement()
            .expect("cached POTA endorsement should be present");
        let orig = pota
            .endorsement()
            .expect("original POTA endorsement should be present");
        assert_eq!(cached.signature(), orig.signature());
        assert_eq!(cached.pub_key(), orig.pub_key());
    }
}

// ---------------------------------------------------------------------------
// Retry-with-backoff runtime support
// ---------------------------------------------------------------------------

/// Default maximum number of retry attempts.
pub const MAX_RETRIES: u32 = 5;

/// Default base delay in milliseconds for exponential backoff.
/// Each iteration doubles: 400 → 800 → 1600 → 3200 → 6400 ms, plus
/// random jitter of 0–[`BACKOFF_JITTER_MS`] to avoid thundering-herd retries.
///
/// When compiled with `mock` (test builds only) the base is
/// reduced to 8 ms so that retry tests complete quickly while
/// still exercising realistic backoff behavior.
#[cfg(not(feature = "mock"))]
pub(crate) const BACKOFF_BASE_MS: u64 = 400;

#[cfg(feature = "mock")]
pub(crate) const BACKOFF_BASE_MS: u64 = 8;

/// Maximum random jitter added to each backoff delay (in milliseconds).
///
/// A uniform random value in `0..=BACKOFF_JITTER_MS` is added on top of
/// the exponential delay so that concurrent callers don't all retry at
/// exactly the same instant.
///
/// When compiled with `mock` (test builds only) jitter is reduced
/// to 2 ms, preserving the 4:1 base-to-jitter ratio while keeping
/// tests fast.
#[cfg(not(feature = "mock"))]
pub(crate) const BACKOFF_JITTER_MS: u64 = 100;

#[cfg(feature = "mock")]
pub(crate) const BACKOFF_JITTER_MS: u64 = 2;

/// Executes `operation` with exponential-backoff retry.
///
/// The operation is called once.  If it fails and `predicate` returns `true`
/// for the error, the call is retried up to `max_retries` additional times
/// with exponentially increasing delays (`backoff_base_ms * 2^iter`), plus
/// random jitter in `0..=backoff_jitter_ms`.
///
/// Emits [`tracing::warn!`] on each retry and [`tracing::error!`] when all
/// attempts are exhausted.
///
/// # Arguments
///
/// * `operation`        – Closure that performs the fallible work. Receives
///   `None` on the initial call and `Some(&HsmError)` on retries, where
///   the error is the one that triggered the retry.
/// * `predicate`        – Returns `true` for errors that are worth retrying.
/// * `max_retries`      – Maximum number of additional attempts after the first failure.
/// * `backoff_base_ms`  – Base delay in milliseconds; doubled each iteration.
/// * `backoff_jitter_ms`– Maximum random jitter added to each delay (ms).
pub(crate) fn execute_with_backoff<T>(
    mut operation: impl FnMut(Option<&HsmError>) -> HsmResult<T>,
    predicate: fn(&HsmResult<T>) -> bool,
    max_retries: u32,
    backoff_base_ms: u64,
    backoff_jitter_ms: u64,
) -> HsmResult<T> {
    let mut attempt = 0u32;
    let mut result = operation(None);

    while predicate(&result) && attempt < max_retries {
        let backoff_ms = backoff_base_ms * (1 << attempt);
        let jitter_ms = rand::thread_rng().gen_range(0..=backoff_jitter_ms);
        let total_ms = backoff_ms + jitter_ms;
        if let Err(ref err) = result {
            warn!(
                ?err,
                attempt,
                backoff_ms,
                jitter_ms,
                total_ms,
                "Transient error, backing off before retry.",
            );
        }
        std::thread::sleep(Duration::from_millis(total_ms));
        let prev_err = result.err();
        attempt += 1;
        result = operation(prev_err.as_ref());
    }

    if let Err(ref err) = result {
        if attempt > 0 {
            error!(
                ?err,
                retries = attempt,
                "Operation failed after retries, giving up.",
            );
        }
    }

    result
}

/// Returns `true` when the error indicates a transient IO-abort condition
/// that may resolve after a short backoff (e.g., live migration or firmware
/// crash recovery in progress).
pub(crate) fn is_io_abort_error<T>(result: &HsmResult<T>) -> bool {
    matches!(
        result,
        Err(HsmError::IoAborted) | Err(HsmError::IoAbortInProgress)
    )
}

/// Returns `true` when the error is retryable during partition initialization.
///
/// - `IoAborted` / `IoAbortInProgress` — transient driver-level IO-abort
///   conditions (e.g., live migration, firmware crash recovery).
/// - `CredentialsNotEstablished` — credentials were lost (e.g., after migration).
/// - `NonceMismatch` — nonce mismatch during credential negotiation.
/// - `PartitionNotProvisioned` — partition state was lost.
///
/// # Note on POTA re-endorsement
///
/// When POTA source is `Caller` and resiliency is enabled, the
/// `PotaEndorsementCallback` is invoked during `init_part` retries
/// when the previous error was `EccVerifyFailed`, to re-sign the
/// endorsement over the current device's PID public key.
///
/// `EccVerifyFailed` covers the case where a resiliency event
/// occurs between DDI calls during `init_part`. The device
/// regenerates its attestation key, so a POTA signature computed against the
/// old key will fail ECC verification. On retry, `get_pota_endorsement`
/// re-signs over the new PID public key, resolving the mismatch.
pub(crate) fn is_init_retryable_error<T>(result: &HsmResult<T>) -> bool {
    matches!(
        result,
        Err(HsmError::IoAborted)
            | Err(HsmError::IoAbortInProgress)
            | Err(HsmError::CredentialsNotEstablished)
            | Err(HsmError::NonceMismatch)
            | Err(HsmError::PartitionNotProvisioned)
            | Err(HsmError::EccVerifyFailed)
    )
}

/// Returns `true` when the error is retryable during session opening.
///
/// - `IoAborted` / `IoAbortInProgress` — transient driver-level IO-abort
///   conditions (e.g., live migration, firmware crash recovery).
/// - `CredentialsNotEstablished` — credentials were lost (e.g., after migration).
/// - `NonceMismatch` — nonce mismatch during credential negotiation.
/// - `PartitionNotProvisioned` — partition state was lost.
pub(crate) fn is_open_session_retryable_error<T>(result: &HsmResult<T>) -> bool {
    matches!(
        result,
        Err(HsmError::IoAborted)
            | Err(HsmError::IoAbortInProgress)
            | Err(HsmError::CredentialsNotEstablished)
            | Err(HsmError::NonceMismatch)
            | Err(HsmError::PartitionNotProvisioned)
    )
}

#[cfg(test)]
mod retry_tests {
    use std::sync::atomic::AtomicU32;
    use std::sync::atomic::Ordering;

    use super::*;

    /// Helper: always-retryable predicate.
    fn always_retry<T>(result: &HsmResult<T>) -> bool {
        result.is_err()
    }

    /// Helper: never-retryable predicate.
    fn never_retry<T>(_result: &HsmResult<T>) -> bool {
        false
    }

    #[test]
    fn succeeds_on_first_try_no_retry() {
        let call_count = AtomicU32::new(0);
        let result = execute_with_backoff(
            |prev_err| {
                assert!(
                    prev_err.is_none(),
                    "first call should have no previous error"
                );
                call_count.fetch_add(1, Ordering::SeqCst);
                Ok(42)
            },
            always_retry,
            5,
            1, // 1 ms base for fast tests
            0, // no jitter for deterministic tests
        );
        assert_eq!(result, Ok(42));
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn retries_up_to_max_then_returns_error() {
        let call_count = AtomicU32::new(0);
        let max = 3u32;
        let result: HsmResult<()> = execute_with_backoff(
            |_| {
                call_count.fetch_add(1, Ordering::SeqCst);
                Err(HsmError::IoAborted)
            },
            always_retry,
            max,
            1,
            0,
        );
        assert_eq!(result, Err(HsmError::IoAborted));
        // 1 initial + max retries
        assert_eq!(call_count.load(Ordering::SeqCst), 1 + max);
    }

    #[test]
    fn recovers_after_transient_failures() {
        let call_count = AtomicU32::new(0);
        let result = execute_with_backoff(
            |_| {
                let n = call_count.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err(HsmError::IoAbortInProgress)
                } else {
                    Ok(99)
                }
            },
            is_io_abort_error,
            5,
            1,
            0,
        );
        assert_eq!(result, Ok(99));
        assert_eq!(call_count.load(Ordering::SeqCst), 3); // 1 initial + 2 retries
    }

    #[test]
    fn non_retryable_error_returns_immediately() {
        let call_count = AtomicU32::new(0);
        let result: HsmResult<()> = execute_with_backoff(
            |_| {
                call_count.fetch_add(1, Ordering::SeqCst);
                Err(HsmError::InvalidArgument)
            },
            is_io_abort_error,
            5,
            1,
            0,
        );
        assert_eq!(result, Err(HsmError::InvalidArgument));
        assert_eq!(call_count.load(Ordering::SeqCst), 1); // no retries
    }

    #[test]
    fn predicate_never_retry_runs_once() {
        let call_count = AtomicU32::new(0);
        let result: HsmResult<()> = execute_with_backoff(
            |_| {
                call_count.fetch_add(1, Ordering::SeqCst);
                Err(HsmError::IoAborted)
            },
            never_retry,
            5,
            1,
            0,
        );
        assert_eq!(result, Err(HsmError::IoAborted));
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn zero_max_retries_runs_once() {
        let call_count = AtomicU32::new(0);
        let result: HsmResult<()> = execute_with_backoff(
            |_| {
                call_count.fetch_add(1, Ordering::SeqCst);
                Err(HsmError::IoAborted)
            },
            always_retry,
            0,
            1,
            0,
        );
        assert_eq!(result, Err(HsmError::IoAborted));
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn prev_error_is_passed_on_retry() {
        let call_count = AtomicU32::new(0);
        let result = execute_with_backoff(
            |prev_err| {
                let n = call_count.fetch_add(1, Ordering::SeqCst);
                match n {
                    0 => {
                        assert!(
                            prev_err.is_none(),
                            "first call should have no previous error"
                        );
                        Err(HsmError::IoAborted)
                    }
                    1 => {
                        assert_eq!(prev_err, Some(&HsmError::IoAborted));
                        Err(HsmError::IoAbortInProgress)
                    }
                    2 => {
                        assert_eq!(prev_err, Some(&HsmError::IoAbortInProgress));
                        Ok(42)
                    }
                    _ => panic!("unexpected call"),
                }
            },
            always_retry,
            5,
            1,
            0,
        );
        assert_eq!(result, Ok(42));
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }
}
