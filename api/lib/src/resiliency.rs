// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency interfaces for transparent recovery from Live Migration,
//! IO aborts, and firmware crash recovery.
//!

use std::sync::Arc;
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

/// Well-known storage key for the restore epoch.
///
/// Persisted by [`restore_partition`] each time the epoch is bumped so
/// that other processes can detect a restore even when the BMK does not
/// change (e.g. device crash-and-restart without key rotation).
pub(crate) const AZIHSM_STORAGE_EPOCH: &str = "azihsm_epoch";

/// Well-known storage key for the masked unwrapping key.
///
/// Written by [`generate_key_pair`] (RSA unwrapping key generation) so
/// that `establish_credential` can restore the device's unwrapping key
/// state after a device reset. Read during [`init_part_raw_no_res`] and
/// [`restore_partition`] to provide the MUK to the device. Cleared
/// alongside BMK when `MaskedKeyDecodeFailed` indicates stale keys.
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
///
/// # Deadlock hazard
///
/// The callback is invoked while the partition's internal `RwLock` is
/// held. Implementations must not call methods on the same
/// [`HsmPartition`](crate::HsmPartition) handle that is being
/// initialized or restored — doing so will deadlock.
///
/// Instead, store the device path and open a **separate** partition
/// handle inside the callback:
///
/// ```ignore
/// struct MyPotaCallback {
///     path: String,  // Store the device path, not the HsmPartition
/// }
///
/// impl PotaEndorsementCallback for MyPotaCallback {
///     fn endorse(&self, _pub_key: &[u8]) -> HsmResult<HsmPotaEndorsementData> {
///         // Open a NEW partition handle — do NOT reuse the caller's handle
///         let part = HsmPartitionManager::open_partition(&self.path)?;
///         let pid_pub_key = part.pub_key()?;
///         let (sig, signer_pub_key) = sign_pid_key(&pid_pub_key);
///         Ok(HsmPotaEndorsementData::new(&sig, &signer_pub_key))
///     }
/// }
/// ```
pub trait PotaEndorsementCallback: Send + Sync {
    /// Generate a fresh POTA endorsement for the current device.
    ///
    /// The `pub_key` parameter is the caller's original endorsement public
    /// key, passed for identification.
    ///
    /// The implementation must:
    /// 1. Open a separate partition handle
    /// 2. Retrieve the current device's PID certificate public key
    /// 3. Sign it with the caller's private key
    /// 4. Return the signature and the signer's public key
    fn endorse(&self, pub_key: &[u8]) -> HsmResult<HsmPotaEndorsementData>;
}

/// RAII guard for [`ResiliencyLock`].
///
/// Acquires the lock on construction and releases it on drop, ensuring the
/// lock is always released even when the caller returns early due to an error.
///
/// Owns an `Arc` clone of the lock so it does not borrow the
/// [`HsmResiliencyConfig`], allowing the config to be moved or consumed
/// while the guard is still alive.
pub(crate) struct ResiliencyLockGuard {
    lock: Arc<dyn ResiliencyLock>,
}

impl ResiliencyLockGuard {
    /// Clone the lock `Arc` out of `config`, acquire it, and return a guard
    /// that releases it on drop.
    pub(crate) fn acquire(config: &HsmResiliencyConfig) -> HsmResult<Self> {
        let lock = Arc::clone(&config.lock);
        lock.lock()?;
        Ok(Self { lock })
    }

    /// Try to acquire the resiliency lock from a pre-cloned `Arc`.
    pub(crate) fn acquire_arc(lock: Arc<dyn ResiliencyLock>) -> HsmResult<Self> {
        lock.lock()?;
        Ok(Self { lock })
    }
}

impl Drop for ResiliencyLockGuard {
    fn drop(&mut self) {
        if let Err(e) = self.lock.unlock() {
            warn!("Failed to release resiliency lock on drop: {e:?}");
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
    pub lock: Arc<dyn ResiliencyLock>,

    /// POTA re-endorsement callback (required when source is Caller).
    pub pota_callback: Option<Box<dyn PotaEndorsementCallback>>,
}

/// Internal resiliency state cached during partition init.
///
/// Stored inside `HsmPartitionInner` when resiliency is enabled.
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
}

impl std::fmt::Debug for ResiliencyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResiliencyState")
            .field("has_pota_callback", &self.config.pota_callback.is_some())
            .field("cached_obk_config", &self.cached_obk_config)
            .field("cached_pota_endorsement", &self.cached_pota_endorsement)
            .field("restore_epoch", &self.restore_epoch)
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
    /// Seeds `restore_epoch` from persistent storage so that a newly
    /// initialised process picks up the epoch left by a prior process.
    /// Falls back to `0` when no stored epoch exists.
    ///
    /// Returns an error if persistent storage cannot be read (IO
    /// failure, corruption, etc.) so that initialisation fails fast
    /// rather than silently resetting the epoch to zero.
    ///
    /// The caller must have already called [`Self::validate_config`]
    /// before invoking DDI operations. This constructor trusts that the
    /// config has been validated.
    pub(crate) fn new(
        config: HsmResiliencyConfig,
        credentials: HsmCredentials,
        obk_config: HsmOwnerBackupKeyConfig,
        pota_endorsement: HsmPotaEndorsement,
    ) -> HsmResult<Self> {
        let restore_epoch = Self::read_epoch(&*config.storage)?.unwrap_or(0);

        Ok(Self {
            config,
            cached_credentials: credentials,
            cached_obk_config: obk_config,
            cached_pota_endorsement: pota_endorsement,
            restore_epoch,
        })
    }

    /// Reads the persisted restore epoch from resiliency storage.
    ///
    /// Returns `None` when the key does not exist (first init, or older
    /// storage that predates persisted epochs).
    pub(crate) fn read_epoch(storage: &dyn ResiliencyStorage) -> HsmResult<Option<u64>> {
        match storage.read(AZIHSM_STORAGE_EPOCH) {
            Ok(b) => {
                let bytes: [u8; 8] = b
                    .as_slice()
                    .try_into()
                    .map_err(|_| HsmError::InternalError)?;
                Ok(Some(u64::from_le_bytes(bytes)))
            }
            Err(HsmError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Persists the restore epoch to resiliency storage.
    ///
    /// Called after bumping `restore_epoch` so that other processes can
    /// detect the restore even when the BMK does not change.
    pub(crate) fn write_epoch(storage: &dyn ResiliencyStorage, epoch: u64) -> HsmResult<()> {
        storage.write(AZIHSM_STORAGE_EPOCH, &epoch.to_le_bytes())
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

/// Applies exponential backoff with jitter and sleeps for the computed
/// duration.
pub(crate) fn apply_backoff(attempt: u32, base_ms: u64, jitter_max_ms: u64) {
    let backoff_ms = base_ms.saturating_mul(1u64 << attempt.min(63));
    let jitter_ms = rand::thread_rng().gen_range(0..=jitter_max_ms);
    let total_ms = backoff_ms + jitter_ms;
    std::thread::sleep(Duration::from_millis(total_ms));
}

/// Executes `operation` with exponential-backoff retry.
///
/// The operation is called once.  If it fails and `predicate` returns `true`
/// for the error, the call is retried up to `max_retries` additional times
/// with exponentially increasing delays (`backoff_base_ms * 2^iter`), plus
/// random jitter in `0..=backoff_jitter_ms`.
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
        apply_backoff(attempt, backoff_base_ms, backoff_jitter_ms);
        let prev_err = result.err();
        attempt += 1;
        result = operation(prev_err.as_ref());
    }

    result
}

/// Returns `true` when the error is a transient IO / device-readiness
/// error that may resolve after a short backoff (e.g., live migration,
/// firmware crash recovery in progress, or device submission failure).
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
            | Err(HsmError::DeviceNotReady)
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
            | Err(HsmError::DeviceNotReady)
            | Err(HsmError::CredentialsNotEstablished)
            | Err(HsmError::NonceMismatch)
            | Err(HsmError::PartitionNotProvisioned)
    )
}

/// Returns `true` when the error is retryable during certificate chain
/// retrieval.
///
/// - `IoAborted` / `IoAbortInProgress` — transient driver-level IO-abort
///   conditions (e.g., live migration, firmware crash recovery).
/// - `CredentialsNotEstablished` — credentials were lost (e.g., after migration).
/// - `PartitionNotProvisioned` — partition state was lost.
/// - `CertChainChanged` — a device reset between the two
///   `GetCertChainInfo` calls invalidated the thumbprint check.
pub(crate) fn is_cert_chain_retryable_error<T>(result: &HsmResult<T>) -> bool {
    matches!(
        result,
        Err(HsmError::IoAborted)
            | Err(HsmError::IoAbortInProgress)
            | Err(HsmError::DeviceNotReady)
            | Err(HsmError::CredentialsNotEstablished)
            | Err(HsmError::PartitionNotProvisioned)
            | Err(HsmError::CertChainChanged)
    )
}

/// Returns `true` when the error indicates the key's device handle is
/// stale and the key needs to be restored (unmasked) before it can be
/// used again.
///
/// These errors occur when a resiliency event (live migration, firmware
/// crash recovery) has invalidated the device state, making existing
/// key handles unusable.
///
pub(crate) fn key_needs_restoration(err: &HsmError) -> bool {
    matches!(
        err,
        HsmError::IoAborted
            | HsmError::IoAbortInProgress
            | HsmError::DeviceNotReady
            | HsmError::SessionNeedsRenegotiation
    )
}

/// Returns `true` when the error is retryable during an in-session key
/// operation (e.g., sign, encrypt, decrypt, derive, key generation).
///
/// - `SessionNeedsRenegotiation` — the session was invalidated by a
///   resiliency event. The caller must restore the partition,
///   reopen the session, unmask the key, and retry.
/// - `PendingKeyGeneration` — the device is still regenerating the
///   unwrapping key after live migration. Retrying after a backoff
///   delay allows the operation to succeed once key generation completes.
/// - `IoAborted` / `IoAbortInProgress` — transient driver-level IO-abort
///   conditions (e.g., live migration or firmware crash recovery).
/// - `KeyNotFound` — the key handle may have been invalidated mid-call
///   by a concurrent resiliency event.
///
/// Note: `InvalidPermissions` and `InvalidKeyType` are not retried.
/// The pre-DDI epoch guard prevents the ABA problem where a stale
/// handle index is reused for a different key. If these errors occur
/// they indicate a real bug and must surface immediately.
pub(crate) fn is_key_op_retryable_error(err: &HsmError) -> bool {
    matches!(
        err,
        HsmError::SessionNeedsRenegotiation
            | HsmError::PendingKeyGeneration
            | HsmError::IoAborted
            | HsmError::IoAbortInProgress
            | HsmError::DeviceNotReady
            | HsmError::KeyNotFound
    )
}

/// Returns `true` for errors that indicate credentials are already
/// established on the partition (i.e., a prior `init_part` or another
/// process's restore has already run).
pub(crate) fn is_credentials_already_established(err: &HsmError) -> bool {
    matches!(
        err,
        HsmError::KeyNotFound
            | HsmError::PartitionAlreadyProvisioned
            | HsmError::VaultAppLimitReached
    )
}

/// Executes a key-generation operation with restore-partition and
/// session-reopen recovery on transient errors.
///
/// This is the runtime support function called by the
/// `#[resiliency_key_gen]` proc macro.
///
/// The first attempt runs the DDI operation under the key-ops barrier
/// **read lock** so that a concurrent restore cannot reassign device
/// handles during the DDI call.
///
/// On retry, the function acquires the barrier **write lock** around
/// `restore_partition` + `reopen_session` + the DDI retry.  The write
/// lock prevents the ABA problem where a newly generated key handle
/// could collide with a handle that another thread's
/// `restore_from_masked` just (re)created for a different key.
///
/// On each retry iteration:
/// 1. Applies exponential backoff.
/// 2. Acquires the barrier write lock.
/// 3. Calls `partition.restore_partition()` to re-establish credentials.
/// 4. Calls `partition.reopen_session_if_needed(session)` to reopen the
///    session if its epoch is stale.
/// 5. Retries the operation (still under the write lock).
pub(crate) fn execute_key_gen_with_retry<T>(
    mut operation: impl FnMut() -> HsmResult<T>,
    session: &crate::HsmSession,
    partition: &crate::HsmPartition,
    max_retries: u32,
    backoff_base_ms: u64,
) -> HsmResult<T> {
    let mut result = {
        let _barrier = partition.key_barrier_read();
        operation()
    };
    let mut attempt = 0u32;

    while result.as_ref().is_err_and(is_key_op_retryable_error) && attempt < max_retries {
        apply_backoff(attempt, backoff_base_ms, BACKOFF_JITTER_MS);

        // Acquire write lock for the entire recovery + retry sequence
        // to prevent ABA handle collisions with concurrent
        // restore_from_masked calls.
        let _barrier = partition.key_barrier_write();

        if partition.restore_partition().is_err() {
            attempt += 1;
            continue;
        }
        if partition.reopen_session_if_needed(session).is_err() {
            attempt += 1;
            continue;
        }
        result = operation();
        attempt += 1;
    }

    result
}

/// Executes a key operation with restore-partition, session-reopen, and
/// key-refresh recovery on transient errors.
///
/// This is the runtime support function called by the
/// `#[resiliency_key_op]` proc macro.
///
/// The function uses a restore barrier (partition-level `RwLock`) to
/// prevent the ABA problem where a stale handle index could silently
/// address a different key after a resiliency event:
///
/// - Phase 1 (read lock): checks whether the key's epoch is current.
///   If yes, calls the DDI operation under the read lock so that no
///   concurrent restore can reassign handles mid-call.  If the epoch is
///   stale, skips the DDI and falls through to recovery.
/// - Phase 2 (no lock): evaluates the result — breaks on success,
///   on non-retryable error, or when the retry budget is exhausted.
///   Retryable errors apply backoff and count against the budget.
///   Stale-epoch entry is free (no backoff, no attempt count), but
///   failed recovery in phase 3 still counts against the budget.
/// - Phase 3 (write lock): restores the partition, reopens the
///   session, and refreshes the key.  The write lock blocks until all
///   in-flight operations (read-lock holders) finish, then prevents any
///   new operation from starting until recovery is complete.
pub(crate) fn execute_key_op_with_retry<T>(
    mut operation: impl FnMut() -> HsmResult<T>,
    session: &crate::HsmSession,
    partition: &crate::HsmPartition,
    mut restore_key: impl FnMut() -> HsmResult<()>,
    key_epoch: impl Fn() -> u64,
    max_retries: u32,
    backoff_base_ms: u64,
) -> HsmResult<T> {
    let mut attempt = 0u32;

    loop {
        // Phase 1: read lock — epoch check + operation
        let result = {
            let _barrier = partition.key_barrier_read();
            if key_epoch() < partition.restore_epoch() {
                None // stale handle — skip DDI, go to recovery
            } else if key_epoch() > partition.restore_epoch() {
                // This should never happen — it would indicate a logic bug
                // where the epoch was bumped without proper synchronization.
                break Err(HsmError::InternalError);
            } else {
                Some(operation())
            }
        };

        // Phase 2: evaluate result and decide whether to break, retry, or recover
        match result {
            Some(Ok(value)) => {
                // Key operation succeeded, return the value.
                break Ok(value);
            }
            Some(Err(err)) if is_key_op_retryable_error(&err) && attempt < max_retries => {
                apply_backoff(attempt, backoff_base_ms, BACKOFF_JITTER_MS);
                attempt += 1;
            }
            Some(Err(err)) => {
                // Key operation failed with a non-retryable error. Break and return the error.
                break Err(err);
            }
            None => {
                // Stale epoch — skip to recovery, but respect the retry budget.
                if attempt >= max_retries {
                    break Err(HsmError::RetryExhausted);
                }
            }
        }

        // Phase 3: write lock — key restoration.
        {
            let _barrier = partition.key_barrier_write();
            if partition.restore_partition().is_err() {
                attempt += 1;
                continue;
            }
            if partition.reopen_session_if_needed(session).is_err() {
                // Session reopen failed, continue to retry.
                attempt += 1;
                continue;
            }
            if restore_key().is_err() {
                // Key restoration failed, continue to retry.
                attempt += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::HsmOwnerBackupKeySource;

    // ResiliencyState construction & validation

    // Minimal mock implementations for testing ResiliencyState logic.
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
            lock: Arc::new(MockLock),
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
        let _state = ResiliencyState::new(config, test_creds(), caller_obk(), pota)
            .expect("ResiliencyState::new should succeed");
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
        let _state = ResiliencyState::new(config, test_creds(), caller_obk(), pota)
            .expect("ResiliencyState::new should succeed");
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
            ResiliencyState::new(mock_config(true), test_creds(), caller_obk(), caller_pota())
                .expect("ResiliencyState::new should succeed");
        assert_eq!(state.restore_epoch, 0);
    }

    #[test]
    fn resiliency_state_caches_credentials() {
        let creds = test_creds();
        let state = ResiliencyState::new(mock_config(true), creds, caller_obk(), caller_pota())
            .expect("ResiliencyState::new should succeed");
        assert_eq!(state.cached_credentials, creds);
    }

    #[test]
    fn resiliency_state_caches_obk_config() {
        let obk = caller_obk();
        let state =
            ResiliencyState::new(mock_config(true), test_creds(), obk.clone(), caller_pota())
                .expect("ResiliencyState::new should succeed");
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
            ResiliencyState::new(mock_config(true), test_creds(), caller_obk(), pota.clone())
                .expect("ResiliencyState::new should succeed");
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

    // Retry-with-backoff (execute_with_backoff)

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
