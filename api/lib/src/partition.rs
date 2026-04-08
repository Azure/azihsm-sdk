// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM partition management.
//!
//! This module provides structures and operations for managing HSM partitions.
//! Partitions represent logical divisions within an HSM device, each with its
//! own API revision support and configuration.

use std::sync::Arc;

use azihsm_ddi::DdiDev;
use parking_lot::*;
use resiliency_macro::resiliency_open_part;
use tracing::*;

use super::*;
use crate::resiliency::*;

/// HSM API revision.
///
/// Represents a specific API version with major and minor components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HsmApiRev {
    /// Major version number.
    pub major: u32,

    /// Minor version number.
    pub minor: u32,
}

/// HSM API revision range.
///
/// Defines the range of API revisions supported by an HSM partition,
/// from minimum to maximum supported versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HsmApiRevRange {
    /// Minimum supported API revision.
    min: HsmApiRev,

    /// Maximum supported API revision.
    max: HsmApiRev,
}

impl HsmApiRevRange {
    /// Creates a new API revision range.
    ///
    /// # Arguments
    ///
    /// * `min` - Minimum supported API revision
    /// * `max` - Maximum supported API revision
    pub fn new(min: HsmApiRev, max: HsmApiRev) -> Self {
        Self { min, max }
    }

    /// Returns the minimum supported API revision.
    pub fn min(&self) -> HsmApiRev {
        self.min
    }

    /// Returns the maximum supported API revision.
    pub fn max(&self) -> HsmApiRev {
        self.max
    }
}

/// HSM partition information.
///
/// Contains metadata about an HSM partition, including its device path
/// and supported API revision range.
#[derive(Debug, Clone)]
pub struct HsmPartitionInfo {
    /// Device path for accessing the partition.
    pub path: String,

    /// Supported API revision range for this partition.
    pub api_rev_range: Option<HsmApiRevRange>,
}

/// HSM application credentials.
///
/// Contains authentication credentials for accessing HSM partition functionality,
/// including application ID and PIN.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct HsmCredentials {
    /// Application ID
    pub id: [u8; 16],

    /// Application Pin
    pub pin: [u8; 16],
}

impl HsmCredentials {
    /// Creates new application credentials.
    ///
    /// # Arguments
    ///
    /// * `id` - Application ID bytes
    /// * `pin` - Application PIN bytes
    pub fn new(id: &[u8], pin: &[u8]) -> Self {
        let mut app_id = [0u8; 16];
        let mut app_pin = [0u8; 16];
        app_id[..id.len().min(16)].copy_from_slice(&id[..id.len().min(16)]);
        app_pin[..pin.len().min(16)].copy_from_slice(&pin[..pin.len().min(16)]);
        Self {
            id: app_id,
            pin: app_pin,
        }
    }

    /// Returns the application ID.
    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }

    /// Returns the application PIN.
    pub fn pin(&self) -> &[u8; 16] {
        &self.pin
    }
}

/// Owner backup key config (OBK/BK3) containing source and optional OBK.
#[derive(Debug, Clone)]
pub struct HsmOwnerBackupKeyConfig {
    /// Source of the OBK
    key_source: HsmOwnerBackupKeySource,

    /// Optional OBK (required when source is Caller, ignored otherwise)
    key: Option<Vec<u8>>,
}

impl HsmOwnerBackupKeyConfig {
    /// Creates a new owner backup key config instance.
    ///
    /// # Arguments
    ///
    /// * `source` - Source of the OBK
    /// * `obk` - OBK data provided by the caller
    ///
    /// # Returns
    ///
    /// A new `HsmOwnerBackupKeyConfig` instance with the specified source and optional key.
    pub fn new(source: HsmOwnerBackupKeySource, obk: Option<&[u8]>) -> Self {
        Self {
            key_source: source,
            key: obk.map(|b| b.to_vec()),
        }
    }

    /// Returns the owner backup key source.
    ///
    /// # Returns
    ///
    /// The source of the owner backup key.
    pub fn key_source(&self) -> HsmOwnerBackupKeySource {
        self.key_source
    }

    /// Returns the owner backup key.
    ///
    /// # Returns
    ///
    /// Optional reference to the OBK.
    pub fn key(&self) -> Option<&[u8]> {
        self.key.as_deref()
    }
}

/// HSM POTA endorsement data containing signature and public key for verification.
///
/// This structure holds the cryptographic proof for partition owner trust anchor
/// endorsement, including the ECDSA signature over the PID hash and the public
/// key needed to verify the signature.
#[derive(Debug, Clone)]
pub struct HsmPotaEndorsementData {
    /// ECDSA signature over the PID hash
    signature: Vec<u8>,

    /// Public key for signature verification (DER-encoded)
    pub_key: Vec<u8>,
}

/// HSM partition owner trust anchor (aka POTA) endorsement.
#[derive(Debug, Clone)]
pub struct HsmPotaEndorsement {
    /// Source of the POTA endorsement
    source: HsmPotaEndorsementSource,

    /// Optional POTA endorsement data (required when source is Caller, ignored otherwise)
    endorsement: Option<HsmPotaEndorsementData>,
}

impl HsmPotaEndorsementData {
    /// Creates a new POTA endorsement data instance.
    ///
    /// # Arguments
    ///
    /// * `signature` - ECDSA signature over the PID hash
    /// * `public_key` - Public key for signature verification (DER-encoded)
    pub fn new(signature: &[u8], public_key: &[u8]) -> Self {
        Self {
            signature: signature.to_vec(),
            pub_key: public_key.to_vec(),
        }
    }

    /// Returns the ECDSA signature.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the public key for signature verification.
    pub fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }
}

impl HsmPotaEndorsement {
    /// Creates a new POTA endorsement instance.
    ///
    /// # Arguments
    ///
    /// * `source` - Source of the POTA endorsement
    /// * `endorsement` - POTA endorsement data provided by the caller
    ///
    /// # Returns
    ///
    /// A new `HsmPotaEndorsement` instance with the specified source and optional endorsement.
    pub fn new(
        source: HsmPotaEndorsementSource,
        endorsement: Option<HsmPotaEndorsementData>,
    ) -> Self {
        Self {
            source,
            endorsement,
        }
    }

    /// Returns the POTA endorsement source.
    ///
    /// # Returns
    ///
    /// The source of the POTA endorsement.
    pub fn source(&self) -> HsmPotaEndorsementSource {
        self.source
    }

    /// Returns the POTA endorsement data.
    ///
    /// # Returns
    ///
    /// Optional reference to the POTA endorsement data.
    pub fn endorsement(&self) -> Option<&HsmPotaEndorsementData> {
        self.endorsement.as_ref()
    }
}

/// HSM partition manager.
///
/// Provides operations for discovering and opening HSM partitions.
pub struct HsmPartitionManager;

impl HsmPartitionManager {
    /// Retrieves a list of all available HSM partitions.
    ///
    /// Queries the system for available HSM devices and returns information
    /// about each discovered partition, including its device path and
    /// supported API revision range. If the device cannot be opened or
    /// the API revision range cannot be retrieved, `api_rev_range` is
    /// set to `None` for that partition.
    ///
    /// # Returns
    ///
    /// A vector of [`HsmPartitionInfo`] structures.
    #[instrument]
    pub fn partition_info_list() -> Vec<HsmPartitionInfo> {
        let vec = ddi::dev_paths()
            .into_iter()
            .map(|path| {
                let api_rev_range = ddi::open_dev(&path)
                    .and_then(|dev| ddi::get_api_rev(&dev))
                    .ok()
                    .map(|(min, max)| HsmApiRevRange::new(min, max));
                HsmPartitionInfo {
                    path,
                    api_rev_range,
                }
            })
            .collect::<Vec<HsmPartitionInfo>>();
        debug!("Found {} partition(s)", vec.len());
        vec
    }

    /// Opens an HSM partition at the specified path with the given API revision.
    ///
    /// Establishes a connection to the HSM partition, retrieves its
    /// supported API revision range, and validates that the requested
    /// `api_rev` falls within that range. The selected revision is
    /// stored in the partition handle and used by all subsequent
    /// operations (including sessions opened from it).
    ///
    /// If the device returns a transient IO-abort error
    /// ([`HsmError::IoAborted`] or [`HsmError::IoAbortInProgress`]),
    /// the operation is automatically retried with exponential backoff
    /// (up to 5 retries, i.e. 6 attempts in total). This handles transient driver
    /// states during live migration or firmware crash recovery.
    ///
    /// # Arguments
    ///
    /// * `path` - Device path of the partition to open
    /// * `api_rev` - API revision to use for this partition handle
    ///
    /// # Returns
    ///
    /// Returns an `HsmPartition` handle on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The device path is invalid or does not exist
    /// - The device cannot be opened or is already in use
    /// - API revision retrieval fails
    /// - The requested `api_rev` is outside the partition's supported range
    ///   ([`HsmError::UnsupportedApiRevision`])
    /// - The underlying DDI operation fails
    /// - All retry attempts are exhausted for transient IO-abort errors
    #[resiliency_open_part]
    #[instrument()]
    pub fn open_partition(path: &str, api_rev: HsmApiRev) -> HsmResult<HsmPartition> {
        let dev = ddi::open_dev(path)?;
        let dev_info = ddi::dev_info_by_path(path)?;
        let (min, max) = ddi::get_api_rev(&dev)?;
        let part_type = HsmPartType::from(dev.device_kind().ok_or(HsmError::InternalError)?);

        // Validate that the requested API revision is within the partition's supported range.
        if api_rev < min || api_rev > max {
            return Err(HsmError::UnsupportedApiRevision);
        }

        Ok(HsmPartition::new(
            dev,
            HsmApiRevRange::new(min, max),
            api_rev,
            dev_info.path,
            part_type,
            dev_info.driver_ver,
            dev_info.firmware_ver,
            dev_info.hardware_ver,
            dev_info.pci_info,
        ))
    }
}

/// HSM partition handle.
///
/// A thread-safe handle to an open HSM partition. Provides access to partition
/// operations and metadata through an internal `Arc<RwLock<HsmPartitionInner>>`.
///
/// The `key_barrier` is a lightweight RwLock that prevents the ABA problem
/// during resiliency events.  Key operations acquire a read lock around the
/// epoch-check + DDI call, while restore/refresh paths acquire the write
/// lock. This guarantees no handle reassignment can occur while any thread is
/// mid-operation.
#[derive(Debug, Clone)]
pub struct HsmPartition {
    inner: Arc<RwLock<HsmPartitionInner>>,
    key_barrier: Arc<RwLock<()>>,
}

impl HsmPartition {
    /// Creates a new HSM partition handle.
    ///
    /// # Arguments
    ///
    /// * `dev` - HSM device handle
    /// * `api_rev_range` - Supported API revision range
    /// * `api_rev` - API revision selected for this partition handle
    /// * `path` - Device path of the partition
    /// * `part_type` - Type of the partition (Virtual or Physical)
    /// * `driver_ver` - Driver version
    /// * `firmware_ver` - Firmware version
    /// * `hardware_ver` - Hardware version
    /// * `pci_info` - PCI information
    fn new(
        dev: ddi::HsmDev,
        api_rev_range: HsmApiRevRange,
        api_rev: HsmApiRev,
        path: String,
        part_type: HsmPartType,
        driver_ver: String,
        firmware_ver: String,
        hardware_ver: String,
        pci_info: String,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HsmPartitionInner::new(
                dev,
                api_rev_range,
                api_rev,
                path,
                part_type,
                driver_ver,
                firmware_ver,
                hardware_ver,
                pci_info,
            ))),
            key_barrier: Arc::new(RwLock::new(())),
        }
    }

    /// Initializes the HSM partition with application credentials and master keys.
    ///
    /// Configures the partition for use by setting up authentication credentials
    /// and optionally providing master key material.
    ///
    /// # Arguments
    ///
    /// * `creds` - Application credentials (ID and PIN)
    /// * `bmk` - Optional backup masking key
    /// * `muk` - Optional masked unwrapping key
    /// * `obk_config` - Owner backup key (OBK) configuration
    /// * `pota_endorsement` - POTA endorsement data
    /// * `resiliency_config` - Optional resiliency configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Credentials are invalid
    /// - API revision retrieval fails
    /// - Partition initialization fails
    /// - OBK is missing when obk_info source is Caller
    #[instrument(skip_all,  fields(path = self.path().as_str()), err)]
    pub fn init(
        &self,
        creds: HsmCredentials,
        bmk: Option<&[u8]>,
        muk: Option<&[u8]>,
        obk_config: HsmOwnerBackupKeyConfig,
        pota_endorsement: HsmPotaEndorsement,
        resiliency_config: Option<HsmResiliencyConfig>,
    ) -> HsmResult<()> {
        // Validate resiliency config and acquire the resiliency lock
        // for the entire init flow — including the final state write —
        // to fully serialize concurrent init_part / restore_partition
        // calls.  The guard owns an Arc clone, so it does not borrow
        // `resiliency_config` (which we consume below).
        let _lock_guard = if let Some(ref config) = resiliency_config {
            ResiliencyState::validate_config(config, &pota_endorsement)?;
            Some(ResiliencyLockGuard::acquire(config)?)
        } else {
            None
        };

        self.inner().write().init(
            creds,
            bmk,
            muk,
            obk_config,
            pota_endorsement,
            resiliency_config,
        )
    }

    /// Opens a new session on the HSM partition.
    ///
    /// Creates a new cryptographic session with the specified API revision and
    /// application credentials. The session provides a context for performing
    /// cryptographic operations.
    ///
    /// # Arguments
    ///
    /// * `api_rev` - The API revision to use for the session
    /// * `credentials` - Application credentials for authentication
    /// * `seed` - Optional seed value for session initialization
    ///
    /// # Returns
    ///
    /// Returns an `HsmSession` handle on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Credentials are invalid or authentication fails
    /// - The requested API revision is not supported
    /// - Session creation fails
    /// - Maximum number of sessions is reached
    ///
    /// # Resiliency
    ///
    /// When resiliency is enabled and the device returns a transient error,
    /// the operation is retried with `restore_partition` (credential
    /// re-establishment) and exponential backoff.
    ///
    #[instrument(skip_all, err, fields(path = self.path().as_str()))]
    pub fn open_session(
        &self,
        api_rev: HsmApiRev,
        credentials: &HsmCredentials,
        seed: Option<&[u8]>,
    ) -> HsmResult<HsmSession> {
        let result = ddi::open_session(self, api_rev, credentials, seed)?;

        Ok(HsmSession::new(
            result.sess_id,
            result.short_app_id,
            api_rev,
            self.clone(),
            result.seed,
            result.bmk_session,
        ))
    }

    /// Restores partition state after a resiliency event.
    ///
    /// Called from the retry loops (`open_session`, `key_gen`, `key_op`)
    /// when a retryable error is encountered and resiliency is enabled.
    ///
    /// 1. Snapshot the current epoch before acquiring the lock.
    /// 2. Acquire the cross-process resiliency lock.
    /// 3. Double-check the epoch — if it advanced while waiting for the
    ///    lock, another thread/process already restored; skip.
    /// 4. Read BMK and MUK from resiliency storage (the cross-process
    ///    source of truth) rather than from in-memory state.
    /// 5. Re-establish credentials via `ddi::init_part_raw_no_res` — the
    ///    bare DDI call without the retry macro.  `resiliency_config`
    ///    is passed so that `init_part_raw_no_res` can re-endorse POTA
    ///    (via callback) when the source is `Caller`.  Explicit BMK
    ///    and MUK from storage are forwarded so that
    ///    `resolve_cached_bmk/muk` inside `init_part_raw_no_res` use them
    ///    as-is.
    /// 6. On success, persist the new BMK, cache the updated POTA
    ///    endorsement, and bump the epoch so stale keys/sessions
    ///    refresh.  If `init_part_raw_no_res` returns a "credentials
    ///    already established" error, read the epoch from storage
    ///    and adopt it if another process advanced it; otherwise
    ///    our epoch is already current.
    ///    On any other failure, return the error without bumping
    ///    the epoch; the outer retry loop will call us again.
    #[instrument(skip_all)]
    pub(crate) fn restore_partition(&self) -> HsmResult<()> {
        // Snapshot epoch and clone the lock Arc BEFORE acquiring the
        // Cross-process resiliency lock.
        let (pre_lock_epoch, lock_ref) = {
            let inner = self.inner().read();
            let Some(rs) = inner.resiliency_state.as_ref() else {
                return Ok(());
            };
            (rs.restore_epoch, Arc::clone(&rs.config.lock))
        };

        let _lock_guard = ResiliencyLockGuard::acquire_arc(lock_ref)?;

        // Re-acquire READ to double-check epoch, read storage, and
        // call init_part_raw_no_res — all under a single read lock.
        let init_result = {
            let inner = self.inner().read();
            let Some(rs) = inner.resiliency_state.as_ref() else {
                return Ok(());
            };

            // If the epoch advanced while waiting for the lock, another
            // thread/process already restored — skip redundant init_part.
            if rs.restore_epoch != pre_lock_epoch {
                return Ok(());
            }

            // Read BMK and MUK from resiliency storage.
            let bmk_from_storage = Self::read_resiliency_storage(
                &*rs.config.storage,
                crate::resiliency::AZIHSM_STORAGE_BMK,
            )?;
            let muk_from_storage = Self::read_resiliency_storage(
                &*rs.config.storage,
                crate::resiliency::AZIHSM_STORAGE_MUK,
            )?;

            // Single-attempt init_part_raw_no_res — bypasses the retry macro.
            // resiliency_config is passed so init_part_raw_no_res can re-endorse
            // POTA internally when the source is Caller.  Explicit
            // bmk/muk from storage are forwarded so that
            // resolve_cached_bmk/muk inside init_part_raw_no_res use them as-is.
            // BMK persistence is handled manually after the call.
            ddi::init_part_raw_no_res(
                inner.dev(),
                inner.api_rev(),
                rs.cached_credentials,
                bmk_from_storage.as_deref(),
                muk_from_storage.as_deref(),
                &rs.cached_obk_config,
                &rs.cached_pota_endorsement,
                Some(&rs.config),
                true, // let init_part_raw_no_res re-endorse POTA
            )
        };

        // Apply results.
        let mut inner = self.inner().write();
        match init_result {
            // Restore partition success — persist new BMK and MOBK, bump epoch so stale keys/sessions refresh.
            Ok(result) => {
                inner.persist_bmk(&result.bmk)?;
                inner.set_masked_keys(result.bmk, result.mobk);
                inner.update_cached_pota(result.pota_endorsement_data);
                inner.bump_epoch(pre_lock_epoch)?;
                Ok(())
            }
            // Partition is already restored by another thread or process.
            // Update the epoch so session & stale key(s) refresh.
            Err(err) if is_credentials_already_established(&err) => {
                inner.sync_epoch_from_storage()?;
                Ok(())
            }
            Err(err) => {
                // Any other failure is returned to the caller
                // so the outer retry loop can retry again with backoff.
                Err(err)
            }
        }
    }

    /// Resets the HSM partition state.
    ///
    /// including established credentials and active sessions. This is useful for
    /// test cleanup and recovery scenarios.
    ///
    /// # Errors
    ///
    /// Returns an error if the reset operation fails.
    #[instrument(skip_all, err, fields(path = self.path().as_str()))]
    pub fn reset(&self) -> HsmResult<()> {
        self.inner().write().reset()
    }

    /// Returns the API revision range supported by this partition.
    ///
    /// # Returns
    ///
    /// The supported API revision range with minimum and maximum versions.
    pub fn api_rev_range(&self) -> HsmApiRevRange {
        self.inner().read().api_rev_range()
    }

    /// Returns the API revision currently in use by this partition handle.
    ///
    /// This is the revision selected when the partition was opened via
    /// [`HsmPartitionManager::open_partition`].
    ///
    /// # Returns
    ///
    /// The [`HsmApiRev`] bound to this partition handle.
    pub fn api_rev(&self) -> HsmApiRev {
        self.inner().read().api_rev()
    }

    /// Returns the partition type (Virtual or Physical).
    ///
    /// # Returns
    ///
    /// The type of partition - either Virtual (simulator/emulated) or Physical (hardware device).
    pub fn part_type(&self) -> HsmPartType {
        self.inner().read().part_type()
    }

    /// Returns the device path.
    ///
    /// # Returns
    ///
    /// The operating system device path used to access this partition.
    pub fn path(&self) -> String {
        self.inner().read().path().to_string()
    }

    /// Returns the driver version.
    ///
    /// # Returns
    ///
    /// The version string of the device driver.
    pub fn driver_ver(&self) -> String {
        self.inner().read().driver_ver().to_string()
    }

    /// Returns the firmware version.
    ///
    /// # Returns
    ///
    /// The version string of the device firmware.
    pub fn firmware_ver(&self) -> String {
        self.inner().read().firmware_ver().to_string()
    }

    /// Returns the hardware version.
    ///
    /// # Returns
    ///
    /// The version string of the hardware device.
    pub fn hardware_ver(&self) -> String {
        self.inner().read().hardware_ver().to_string()
    }

    /// Returns the PCI hardware information.
    ///
    /// # Returns
    ///
    /// The PCI hardware identifier in bus:device:function format.
    pub fn pci_info(&self) -> String {
        self.inner().read().pci_info().to_string()
    }

    /// Retrieves the certificate chain stored in the partition.
    ///
    /// Returns the certificate chain in PEM format (RFC 7468), with each certificate
    /// encoded in Base64 with `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----`
    /// delimiters and LF line endings. Multiple certificates are separated by a single
    /// newline character (`\n`). The certificates are ordered from leaf/partition certificate
    /// (first) to root certificate (last).
    ///
    /// # Arguments
    ///
    /// * `slot` - The certificate slot number.
    ///
    /// # Returns
    ///
    /// Returns the certificate chain as a PEM string.
    pub fn cert_chain(&self, slot: u8) -> HsmResult<String> {
        ddi::get_cert_chain(self, slot)
    }

    /// Retrieves the public key of the partition identity (PID) certificate.
    ///
    /// # Returns
    ///
    /// Returns the DER-encoded public key of the PID certificate.
    pub fn pub_key(&self) -> HsmResult<Vec<u8>> {
        self.inner().read().pub_key()
    }

    /// Retrieves the backup masking key that was set during partition initialization.
    ///
    /// # Arguments
    ///
    /// * `bmk` - Optional output buffer to receive the BMK.
    ///
    /// # Returns
    ///
    /// Returns the size of the BMK on success.
    pub fn bmk(&self, bmk: Option<&mut [u8]>) -> HsmResult<usize> {
        let inner = self.inner().read();
        let data = inner.bmk();
        if let Some(buf) = bmk {
            if buf.len() < data.len() {
                return Err(HsmError::BufferTooSmall);
            }
            buf[..data.len()].copy_from_slice(data);
        }
        Ok(data.len())
    }

    /// Retrieves the backup masking key that was set during partition initialization.
    ///
    /// # Returns
    ///
    /// A vector containing the BMK bytes.
    pub fn bmk_vec(&self) -> Vec<u8> {
        self.inner().read().bmk().to_vec()
    }

    /// Retrieves the masked owner backup key that was set during partition initialization.
    ///
    /// # Arguments
    /// * `mobk` - Optional output buffer to receive the MOBK.
    ///
    /// # Returns
    ///
    /// Returns the size of the MOBK on success.
    pub fn mobk(&self, mobk: Option<&mut [u8]>) -> HsmResult<usize> {
        let inner = self.inner().read();
        let data = inner.mobk();
        if let Some(buf) = mobk {
            if buf.len() < data.len() {
                return Err(HsmError::BufferTooSmall);
            }
            buf[..data.len()].copy_from_slice(data);
        }
        Ok(data.len())
    }

    /// Returns the masked owner backup key (MOBK).
    ///
    /// Retrieves the masked owner backup key that was set during partition initialization.
    ///
    /// # Returns
    ///
    /// A vector containing the MOBK bytes.
    pub fn mobk_vec(&self) -> Vec<u8> {
        self.inner().read().mobk().to_vec()
    }

    /// Returns a reference to the internal partition state.
    ///
    /// Provides access to the inner `Arc<RwLock<HsmPartitionInner>>` for
    /// internal operations that require direct access to the shared state.
    ///
    /// # Returns
    ///
    /// A reference to the wrapped partition inner state.
    pub(crate) fn inner(&self) -> &Arc<RwLock<HsmPartitionInner>> {
        &self.inner
    }

    /// Returns `true` if resiliency was configured for this partition
    /// (i.e., a non-`None` [`HsmResiliencyConfig`] was passed to [`init`]).
    pub(crate) fn resiliency_enabled(&self) -> bool {
        self.inner().read().resiliency_state.is_some()
    }

    /// Writes a value to the partition's resiliency storage.
    ///
    /// No-op when resiliency is not enabled.
    pub(crate) fn write_resiliency_storage(&self, key: &str, data: &[u8]) -> HsmResult<()> {
        let inner = self.inner().read();
        if let Some(rs) = inner.resiliency_state.as_ref() {
            rs.config.storage.write(key, data)?;
        }
        Ok(())
    }

    /// Reads a value from resiliency storage, returning `None` when the
    /// key does not exist.
    ///
    /// `NotFound` is converted to `Ok(None)` (the key has not been
    /// persisted yet, e.g. first restore). Any other storage error
    /// (IO failure, corruption) is propagated so the caller does not
    /// silently proceed with missing key material.
    fn read_resiliency_storage(
        storage: &dyn ResiliencyStorage,
        key: &str,
    ) -> HsmResult<Option<Vec<u8>>> {
        match storage.read(key) {
            Ok(v) => Ok(Some(v)),
            Err(HsmError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Returns the current partition restore epoch.
    ///
    /// The epoch is incremented each time [`restore_partition`] successfully
    /// re-establishes credentials — or adopts credentials restored by
    /// another process — after a resiliency event (live migration,
    /// firmware crash recovery). Keys and sessions compare their
    /// last-known epoch against this value to detect staleness.
    ///
    /// Returns `0` when resiliency is not enabled.
    pub(crate) fn restore_epoch(&self) -> u64 {
        self.inner()
            .read()
            .resiliency_state
            .as_ref()
            .map_or(0, |rs| rs.restore_epoch)
    }

    /// Acquires a read lock on the key barrier.
    ///
    /// Hold this across the epoch-check + DDI call sequence to prevent
    /// any concurrent restore/refresh from reassigning device handles.
    /// Multiple threads may hold the read lock simultaneously.
    pub(crate) fn key_barrier_read(&self) -> RwLockReadGuard<'_, ()> {
        self.key_barrier.read()
    }

    /// Acquires a write lock on the key barrier.
    ///
    /// Hold this during restore-partition + reopen-session + refresh-key
    /// to ensure no thread is mid-operation while handles are being
    /// reassigned.  Blocks until all read-lock holders finish.
    pub(crate) fn key_barrier_write(&self) -> RwLockWriteGuard<'_, ()> {
        self.key_barrier.write()
    }

    /// Reopens the session if its epoch is behind the partition's
    /// current restore epoch.
    ///
    /// After [`restore_partition`] increments the epoch, any session whose
    /// `last_restore_epoch` is older must be reopened so its device-side
    /// state is re-established.  This method:
    ///
    /// 1. Compares the session's epoch against the partition's epoch.
    /// 2. If stale, reads the cached session material (seed, BMK, etc.).
    /// 3. Calls `ddi::reopen_session` to re-establish the session.
    /// 4. Updates the cached BMK and the session's epoch.
    ///
    /// No-op when resiliency is disabled or the session is already current.
    #[instrument(skip_all, fields(session_id))]
    pub(crate) fn reopen_session_if_needed(&self, session: &HsmSession) -> HsmResult<()> {
        // Fast path: no lock required.
        let current_epoch = self.restore_epoch();
        let session_epoch = session.last_restore_epoch();
        if session_epoch == current_epoch {
            // Session is current, no reopen needed.
            return Ok(());
        } else if session_epoch > current_epoch {
            // This should never happen — session cannot be newer than the partition's epoch.
            return Err(HsmError::InternalError);
        }

        // Read credentials from the resiliency state.
        let creds = {
            let inner = self.inner().read();
            let Some(rs) = inner.resiliency_state.as_ref() else {
                return Ok(());
            };
            rs.cached_credentials
        };

        // Read session material directly from the session itself.
        let sess_id = session.id();
        let rev = session.api_rev();
        let seed = session.seed();
        let bmk_session = session.bmk_session();

        // Hold the session write lock across the DDI call so that only
        // one thread performs the reopen for a given epoch.  Racing
        // threads block here and then observe the updated epoch.
        let reopen_result = session.with_reopen_guard(current_epoch, || {
            self.inner()
                .read()
                .reopen_session(rev, sess_id, &creds, &seed, &bmk_session)
        })?;

        // If we actually performed the reopen, update the BMK on the session.
        if let Some(result) = reopen_result {
            session.set_bmk_session(result.bmk_session);
        }

        Ok(())
    }
}
///
/// Represents an open connection to an HSM partition. This handle provides
/// access to partition information, API revision support, and the underlying
/// device for cryptographic operations.
#[derive(Debug)]
pub(crate) struct HsmPartitionInner {
    dev: ddi::HsmDev,
    api_rev_range: HsmApiRevRange,
    api_rev: HsmApiRev,
    bmk: Vec<u8>,
    mobk: Vec<u8>,
    path: String,
    part_type: HsmPartType,
    driver_ver: String,
    firmware_ver: String,
    hardware_ver: String,
    pci_info: String,
    resiliency_state: Option<ResiliencyState>,
}

impl HsmPartitionInner {
    /// Creates a new partition handle.
    ///
    /// # Arguments
    ///
    /// * `dev` - HSM device handle
    /// * `api_rev_range` - Supported API revision range
    /// * `api_rev_inuse` - API revision selected for this partition handle
    /// * `path` - Device path string
    /// * `part_type` - Type of the partition (Virtual or Physical)
    /// * `driver_ver` - Driver version string
    /// * `firmware_ver` - Firmware version string
    /// * `hardware_ver` - Hardware version string
    /// * `pci_info` - PCI information string
    fn new(
        dev: ddi::HsmDev,
        api_rev_range: HsmApiRevRange,
        api_rev: HsmApiRev,
        path: String,
        part_type: HsmPartType,
        driver_ver: String,
        firmware_ver: String,
        hardware_ver: String,
        pci_info: String,
    ) -> Self {
        Self {
            dev,
            api_rev_range,
            api_rev,
            path,
            part_type,
            driver_ver,
            firmware_ver,
            hardware_ver,
            pci_info,
            bmk: Vec::new(),
            mobk: Vec::new(),
            resiliency_state: None,
        }
    }

    /// Returns the API revision range supported by this partition.
    ///
    /// # Returns
    ///
    /// The supported API revision range with minimum and maximum versions.
    pub fn api_rev_range(&self) -> HsmApiRevRange {
        self.api_rev_range
    }

    /// Returns the API revision in use by this partition.
    pub(crate) fn api_rev(&self) -> HsmApiRev {
        self.api_rev
    }

    /// Returns the partition type (Virtual or Physical).
    pub fn part_type(&self) -> HsmPartType {
        self.part_type
    }

    /// Returns the device path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the driver version.
    pub fn driver_ver(&self) -> &str {
        &self.driver_ver
    }

    /// Returns the firmware version.
    pub fn firmware_ver(&self) -> &str {
        &self.firmware_ver
    }

    /// Returns the hardware version.
    pub fn hardware_ver(&self) -> &str {
        &self.hardware_ver
    }

    /// Returns the PCI hardware information.
    pub fn pci_info(&self) -> &str {
        &self.pci_info
    }

    /// Returns the underlying device handle.
    pub(crate) fn dev(&self) -> &ddi::HsmDev {
        &self.dev
    }

    /// Sets the backup masking key (BMK) and masked owner backup key (MOBK).
    ///
    /// Updates the internal state with the provided key material.
    ///
    /// # Arguments
    ///
    /// * `bmk` - Backup masking key bytes
    /// * `mobk` - Masked owner backup key bytes
    pub(crate) fn set_masked_keys(&mut self, bmk: Vec<u8>, mobk: Vec<u8>) {
        self.bmk = bmk;
        self.mobk = mobk;
    }

    /// Clears the cached masked keys after partition reset.
    pub(crate) fn clear_masked_keys(&mut self) {
        self.bmk.clear();
        self.mobk.clear();
    }

    /// Resets the partition and clears cached masked keys.
    pub(crate) fn reset(&mut self) -> HsmResult<()> {
        self.dev.simulate_nssr_after_lm().map_err(HsmError::from)?;
        self.clear_masked_keys();
        Ok(())
    }

    /// Reopens a session on the partition.
    pub(crate) fn reopen_session(
        &self,
        api_rev: HsmApiRev,
        sess_id: u16,
        credentials: &HsmCredentials,
        seed: &[u8; 48],
        bmk_session: &[u8],
    ) -> HsmResult<ddi::ReopenSessionResult> {
        ddi::reopen_session(&self.dev, api_rev, sess_id, credentials, seed, bmk_session)
    }

    /// Retrieves the public key of the partition identity (PID) certificate.
    pub(crate) fn pub_key(&self) -> HsmResult<Vec<u8>> {
        ddi::get_part_pub_key(&self.dev, self.api_rev)
    }

    /// Initializes the partition with application credentials and master keys.
    ///
    /// Performs the DDI init_part call, resolves BMK/MOBK/POTA results,
    /// caches masked keys, and sets resiliency state.  Called under a
    /// write lock from `HsmPartition::init`.
    pub(crate) fn init(
        &mut self,
        creds: HsmCredentials,
        bmk: Option<&[u8]>,
        muk: Option<&[u8]>,
        obk_config: HsmOwnerBackupKeyConfig,
        pota_endorsement: HsmPotaEndorsement,
        resiliency_config: Option<HsmResiliencyConfig>,
    ) -> HsmResult<()> {
        let result = ddi::init_part(
            &self.dev,
            self.api_rev,
            creds,
            bmk,
            muk,
            &obk_config,
            &pota_endorsement,
            resiliency_config.as_ref(),
        );

        // Resolve the BMK, MOBK, and POTA endorsement to cache.
        //
        // On success: use the values returned by the device.
        //
        // On "credentials already established" (another thread or
        // process already initialized this partition): read the BMK
        // from resiliency storage (persisted by the successful init),
        // use empty MOBK (not returned by the device in this case),
        // and keep the caller's original POTA endorsement (the
        // callback will re-sign on the next restore anyway).
        //
        // On any other error: propagate immediately.
        let (init_bmk, init_mobk, committed_pota) = match result {
            // Init success - cache the BMK, MOBK, and POTA endorsement returned by the device.
            Ok(result) => (
                result.bmk,
                result.mobk,
                HsmPotaEndorsement::new(
                    pota_endorsement.source(),
                    Some(result.pota_endorsement_data),
                ),
            ),
            // Credentials are already established when another thread/process beat us to init — read BMK from storage and proceed with restore flow to sync state and refresh credentials.
            Err(err) if is_credentials_already_established(&err) => {
                let bmk = resiliency_config
                    .as_ref()
                    .map(Self::read_bmk_from_storage)
                    .transpose()?
                    .unwrap_or_default();
                (bmk, Vec::new(), pota_endorsement)
            }
            // Any other error is propagated to the caller.
            Err(err) => return Err(err),
        };

        self.set_masked_keys(init_bmk, init_mobk);

        if let Some(config) = resiliency_config {
            let resiliency_state = ResiliencyState::new(config, creds, obk_config, committed_pota)?;
            self.set_resiliency_state(resiliency_state);
        }

        Ok(())
    }

    /// Reads the BMK from resiliency storage, returning an empty Vec
    /// if the key does not exist.
    ///
    /// Only `NotFound` is treated as "no BMK yet"; other storage
    /// errors (IO failure, corruption) are propagated so that init
    /// fails fast rather than proceeding with an empty BMK.
    fn read_bmk_from_storage(config: &HsmResiliencyConfig) -> HsmResult<Vec<u8>> {
        match config.storage.read(crate::resiliency::AZIHSM_STORAGE_BMK) {
            Ok(v) => Ok(v),
            Err(HsmError::NotFound) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Returns the backup masking key (BMK).
    ///
    /// # Returns
    ///
    /// A byte slice containing the BMK.
    pub fn bmk(&self) -> &[u8] {
        &self.bmk
    }

    /// Returns the masked owner backup key (MOBK).
    ///
    /// # Returns
    ///
    /// A byte slice containing the MOBK.
    pub fn mobk(&self) -> &[u8] {
        &self.mobk
    }

    pub(crate) fn set_resiliency_state(&mut self, resiliency: ResiliencyState) {
        self.resiliency_state = Some(resiliency);
    }

    /// Persists the BMK to resiliency storage so other processes see
    /// the updated key.
    fn persist_bmk(&self, bmk: &[u8]) -> HsmResult<()> {
        if let Some(rs) = self.resiliency_state.as_ref() {
            rs.config
                .storage
                .write(crate::resiliency::AZIHSM_STORAGE_BMK, bmk)?;
        }
        Ok(())
    }

    /// Updates the cached POTA endorsement data with the latest values
    /// returned by `init_part_raw_no_res`.  The callback may return a new
    /// public key (e.g., key rotation); caching it ensures the next
    /// restore passes the updated pub key to `invoke_pota_callback`.
    fn update_cached_pota(&mut self, pota_data: HsmPotaEndorsementData) {
        if let Some(rs) = self.resiliency_state.as_mut() {
            rs.cached_pota_endorsement =
                HsmPotaEndorsement::new(rs.cached_pota_endorsement.source(), Some(pota_data));
        }
    }

    /// Handles the epoch update when credentials are already established.
    ///
    /// Reads the epoch from storage and compares it against the in-memory
    /// `restore_epoch`:
    /// - If storage epoch > restore epoch, another process restored the
    ///   partition — adopt the storage epoch so our keys/sessions detect
    ///   staleness.
    /// - If storage epoch == restore epoch, we already have the current
    ///   epoch — no action needed.  Only the thread that actually
    ///   restores the partition (the `Ok` arm) writes to storage.
    /// - If storage epoch < restore epoch, storage is corrupted or a
    ///   logic bug caused the epoch to go backwards — return
    ///   `InternalError`.
    fn sync_epoch_from_storage(&mut self) -> HsmResult<()> {
        let Some(rs) = self.resiliency_state.as_mut() else {
            return Ok(());
        };
        match ResiliencyState::read_epoch(&*rs.config.storage)? {
            Some(storage_epoch) if storage_epoch > rs.restore_epoch => {
                // Another process restored the partition; adopt stored epoch.
                rs.restore_epoch = storage_epoch;
            }
            Some(storage_epoch) if storage_epoch < rs.restore_epoch => {
                // Epoch went backwards — storage corruption or logic bug.
                return Err(HsmError::InternalError);
            }
            _ => {
                // No stored epoch or storage epoch == restore epoch; keep current epoch.
            }
        }
        Ok(())
    }

    /// Bumps the restore epoch and persists it to storage.
    ///
    /// The caller must hold the cross-process resiliency lock.
    /// Reads the current stored epoch (which may have been advanced by
    /// another process since our `pre_lock_epoch` snapshot) and
    /// increments from that value, ensuring monotonicity.
    fn bump_epoch(&mut self, _pre_lock_epoch: u64) -> HsmResult<()> {
        if let Some(rs) = self.resiliency_state.as_mut() {
            // Read the authoritative epoch from shared storage.
            // Another process may have bumped it between our snapshot and lock acquisition.
            // We must bump from the stored value to ensure we do not go backwards.
            let stored = ResiliencyState::read_epoch(&*rs.config.storage)?.unwrap_or(0);
            let new_epoch = stored.saturating_add(1);
            rs.restore_epoch = new_epoch;
            ResiliencyState::write_epoch(&*rs.config.storage, new_epoch)?;
        }
        Ok(())
    }
}

/// Cleans up resources when the last partition reference is dropped.
///
/// Fires exactly once when the final `Arc` reference is released and the
/// inner state is consumed — no `RwLock` acquisition needed.
impl Drop for HsmPartitionInner {
    #[instrument(skip_all, fields(path = self.path.as_str()))]
    fn drop(&mut self) {}
}
