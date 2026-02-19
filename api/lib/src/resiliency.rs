// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency interfaces for transparent recovery from Live Migration,
//! IO aborts, and firmware crash recovery.
//!
//! The entire resiliency feature is opt-in. When `None` is passed for the
//! resiliency config in `HsmPartition::init()`, behavior is unchanged.

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
