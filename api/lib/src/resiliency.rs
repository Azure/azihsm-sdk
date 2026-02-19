// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency interfaces for transparent recovery from Live Migration,
//! IO aborts, and firmware crash recovery.
//!
//! The entire resiliency feature is opt-in. When `None` is passed for the
//! resiliency config in `HsmPartition::init()`, behavior is unchanged.

use std::time::Duration;

use tracing::*;

use crate::HsmError;
use crate::HsmOwnerBackupKeyConfig;
use crate::HsmPotaEndorsement;
use crate::HsmPotaEndorsementData;
use crate::HsmResult;
use crate::partition::HsmCredentials;
use crate::shared_types::HsmPotaEndorsementSource;

/// Well-known storage key for the backup masking key.
#[allow(dead_code)]
pub(crate) const AZIHSM_STORAGE_BMK: &str = "azihsm_bmk";

/// Well-known storage key for the masked unwrapping key.
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

/// Callback for re-signing POTA endorsement during restore.
///
/// Only required when POTA endorsement source is `Caller` AND resiliency is
/// enabled. Called during `restore_partition` to re-endorse the partition
/// identity with the caller's OBK private key.
pub trait PotaEndorsementCallback: Send + Sync {
    /// Re-sign the POTA endorsement with the caller's OBK private key.
    ///
    /// Receives the original public key and returns a new signature and
    /// (potentially rotated) public key.
    fn endorse(&self, pub_key: &[u8]) -> HsmResult<HsmPotaEndorsementData>;
}

/// Resiliency configuration bundle.
///
/// Passed to [`HsmPartition::init()`] to enable resiliency. When `None` is
/// passed, no resiliency behavior is added.
///
/// # Validation rules
///
/// - If POTA endorsement source is `Caller`, `pota_callback` **must** be
///   `Some`. Otherwise `init()` returns `HsmError::InvalidArgument`.
/// - If POTA endorsement source is `Tpm`, `pota_callback` is ignored.
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
    /// Persistent storage interface.
    pub(crate) storage: Box<dyn ResiliencyStorage>,

    /// Cross-process/thread lock interface.
    pub(crate) lock: Box<dyn ResiliencyLock>,

    /// Optional POTA callback.
    pub(crate) pota_callback: Option<Box<dyn PotaEndorsementCallback>>,

    /// Cached credentials for re-establishing during restore.
    pub(crate) cached_credentials: HsmCredentials,

    /// Cached OBK configuration for re-establishing during restore.
    pub(crate) cached_obk_config: HsmOwnerBackupKeyConfig,

    /// Cached POTA endorsement for restore.
    pub(crate) cached_pota_endorsement: HsmPotaEndorsement,

    /// Restore epoch — incremented on each restore_partition.
    /// Keys check this to detect staleness before DDI calls.
    pub(crate) restore_epoch: u64,
}

impl std::fmt::Debug for ResiliencyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResiliencyState")
            .field("cached_obk_config", &self.cached_obk_config)
            .field("cached_pota_endorsement", &self.cached_pota_endorsement)
            .field("restore_epoch", &self.restore_epoch)
            .finish_non_exhaustive()
    }
}

impl ResiliencyState {
    /// Creates a new resiliency state from the config and init parameters.
    ///
    /// Validates that the POTA callback is provided when required.
    pub(crate) fn new(
        config: HsmResiliencyConfig,
        credentials: HsmCredentials,
        obk_config: HsmOwnerBackupKeyConfig,
        pota_endorsement: HsmPotaEndorsement,
    ) -> HsmResult<Self> {
        // Validate: Caller-sourced POTA requires a callback
        if pota_endorsement.source() == HsmPotaEndorsementSource::Caller
            && config.pota_callback.is_none()
        {
            Err(HsmError::InvalidArgument)?;
        }

        Ok(Self {
            storage: config.storage,
            lock: config.lock,
            pota_callback: config.pota_callback,
            cached_credentials: credentials,
            cached_obk_config: obk_config,
            cached_pota_endorsement: pota_endorsement,
            restore_epoch: 0,
        })
    }
}

// ---------------------------------------------------------------------------
// Retry-with-backoff runtime support
// ---------------------------------------------------------------------------

/// Default maximum number of retry attempts.
pub(crate) const MAX_RETRIES: u32 = 5;

/// Default base delay in milliseconds for exponential backoff.
/// Each iteration doubles: 400 → 800 → 1600 → 3200 → 6400 ms.
pub(crate) const BACKOFF_BASE_MS: u64 = 400;

/// Executes `operation` with exponential-backoff retry.
///
/// The operation is called once.  If it fails and `predicate` returns `true`
/// for the error, the call is retried up to `max_retries` additional times
/// with exponentially increasing delays (`backoff_base_ms * 2^iter`).
///
/// Emits [`tracing::warn!`] on each retry and [`tracing::error!`] when all
/// attempts are exhausted.
///
/// # Arguments
///
/// * `operation`      – Closure that performs the fallible work.
/// * `predicate`      – Returns `true` for errors that are worth retrying.
/// * `max_retries`    – Maximum number of **additional** attempts after the first failure.
/// * `backoff_base_ms`– Base delay in milliseconds; doubled each iteration.
pub(crate) fn execute_with_backoff<T>(
    mut operation: impl FnMut() -> HsmResult<T>,
    predicate: fn(&HsmResult<T>) -> bool,
    max_retries: u32,
    backoff_base_ms: u64,
) -> HsmResult<T> {
    let mut result = operation();
    let mut iter = 0u32;

    while predicate(&result) && iter < max_retries {
        let backoff_ms = backoff_base_ms * (1 << iter);
        if let Err(ref err) = result {
            warn!(
                ?err,
                iter, backoff_ms, "Transient error, backing off before retry.",
            );
        }
        std::thread::sleep(Duration::from_millis(backoff_ms));
        result = operation();
        iter += 1;
    }

    if let Err(ref err) = result {
        if iter > 0 {
            error!(
                ?err,
                retries = iter,
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
            || {
                call_count.fetch_add(1, Ordering::SeqCst);
                Ok(42)
            },
            always_retry,
            5,
            1, // 1 ms base for fast tests
        );
        assert_eq!(result, Ok(42));
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn retries_up_to_max_then_returns_error() {
        let call_count = AtomicU32::new(0);
        let max = 3u32;
        let result: HsmResult<()> = execute_with_backoff(
            || {
                call_count.fetch_add(1, Ordering::SeqCst);
                Err(HsmError::IoAborted)
            },
            always_retry,
            max,
            1,
        );
        assert_eq!(result, Err(HsmError::IoAborted));
        // 1 initial + max retries
        assert_eq!(call_count.load(Ordering::SeqCst), 1 + max);
    }

    #[test]
    fn recovers_after_transient_failures() {
        let call_count = AtomicU32::new(0);
        let result = execute_with_backoff(
            || {
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
        );
        assert_eq!(result, Ok(99));
        assert_eq!(call_count.load(Ordering::SeqCst), 3); // 1 initial + 2 retries
    }

    #[test]
    fn non_retryable_error_returns_immediately() {
        let call_count = AtomicU32::new(0);
        let result: HsmResult<()> = execute_with_backoff(
            || {
                call_count.fetch_add(1, Ordering::SeqCst);
                Err(HsmError::InvalidArgument)
            },
            is_io_abort_error,
            5,
            1,
        );
        assert_eq!(result, Err(HsmError::InvalidArgument));
        assert_eq!(call_count.load(Ordering::SeqCst), 1); // no retries
    }

    #[test]
    fn predicate_never_retry_runs_once() {
        let call_count = AtomicU32::new(0);
        let result: HsmResult<()> = execute_with_backoff(
            || {
                call_count.fetch_add(1, Ordering::SeqCst);
                Err(HsmError::IoAborted)
            },
            never_retry,
            5,
            1,
        );
        assert_eq!(result, Err(HsmError::IoAborted));
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn zero_max_retries_runs_once() {
        let call_count = AtomicU32::new(0);
        let result: HsmResult<()> = execute_with_backoff(
            || {
                call_count.fetch_add(1, Ordering::SeqCst);
                Err(HsmError::IoAborted)
            },
            always_retry,
            0,
            1,
        );
        assert_eq!(result, Err(HsmError::IoAborted));
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }
}
