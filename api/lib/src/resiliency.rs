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
            storage: config.storage,
            lock: config.lock,
            pota_callback: config.pota_callback,
            cached_credentials: credentials,
            cached_obk_config: obk_config,
            cached_pota_endorsement: pota_endorsement,
            restore_epoch: 0,
        }
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
