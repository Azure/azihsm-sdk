// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM partition management.
//!
//! This module provides structures and operations for managing HSM partitions.
//! Partitions represent logical divisions within an HSM device, each with its
//! own API revision support and configuration.

use std::sync::Arc;

use azihsm_ddi::DdiDev;
use parking_lot::RwLock;
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
/// Contains metadata about an HSM partition, including its device path.
#[derive(Debug, Clone)]
pub struct HsmPartitionInfo {
    /// Device path for accessing the partition.
    pub path: String,
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
    /// about each discovered partition.
    ///
    /// # Returns
    ///
    /// A vector of partition information structures.
    #[instrument]
    pub fn partition_info_list() -> Vec<HsmPartitionInfo> {
        let vec = ddi::dev_paths()
            .into_iter()
            .map(|path| HsmPartitionInfo { path })
            .collect::<Vec<HsmPartitionInfo>>();
        debug!("Found {} partition(s)", vec.len());
        vec
    }

    /// Opens an HSM partition at the specified path.
    ///
    /// Establishes a connection to the HSM partition and retrieves its
    /// supported API revision range.
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
    /// - The underlying DDI operation fails
    /// - All retry attempts are exhausted for transient IO-abort errors
    #[resiliency_open_part]
    #[instrument()]
    pub fn open_partition(path: &str) -> HsmResult<HsmPartition> {
        let dev = ddi::open_dev(path)?;
        let dev_info = ddi::dev_info_by_path(path)?;
        let (min, max) = ddi::get_api_rev(&dev)?;
        let part_type = HsmPartType::from(dev.device_kind().ok_or(HsmError::InternalError)?);
        Ok(HsmPartition::new(
            dev,
            HsmApiRevRange::new(min, max),
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
#[derive(Debug, Clone)]
pub struct HsmPartition(Arc<RwLock<HsmPartitionInner>>);

impl HsmPartition {
    /// Creates a new HSM partition handle.
    ///
    /// # Arguments
    ///
    /// * `dev` - HSM device handle
    /// * `api_rev_range` - Supported API revision range
    /// * `path` - Device path of the partition
    /// * `part_type` - Type of the partition (Virtual or Physical)
    /// * `driver_ver` - Driver version
    /// * `firmware_ver` - Firmware version
    /// * `hardware_ver` - Hardware version
    /// * `pci_info` - PCI information
    fn new(
        dev: ddi::HsmDev,
        api_rev_range: HsmApiRevRange,
        path: String,
        part_type: HsmPartType,
        driver_ver: String,
        firmware_ver: String,
        hardware_ver: String,
        pci_info: String,
    ) -> Self {
        Self(Arc::new(RwLock::new(HsmPartitionInner::new(
            dev,
            api_rev_range,
            path,
            part_type,
            driver_ver,
            firmware_ver,
            hardware_ver,
            pci_info,
        ))))
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
        // Validate resiliency config
        if let Some(ref config) = resiliency_config {
            ResiliencyState::validate_config(config, &pota_endorsement)?;
        }

        // Acquire the resiliency lock for the entire init flow to prevent
        // races with concurrent init_part / restore_partition calls.
        // When `resiliency_config` is `None` this returns a no-op guard.
        let _lock_guard = ResiliencyLockGuard::acquire(resiliency_config.as_ref())?;

        let result = self.with_dev(|dev| {
            ddi::init_part(
                dev,
                self.api_rev_range().min(),
                creds,
                bmk,
                muk,
                &obk_config,
                &pota_endorsement,
                resiliency_config.as_ref(),
            )
        })?;
        self.inner()
            .write()
            .set_masked_keys(result.bmk, result.mobk);

        // Release the lock before consuming the config.
        drop(_lock_guard);

        // Set up resiliency state — config already validated above.
        // Use the POTA endorsement data that was actually sent to the device
        // (which may differ from the caller's original when the callback
        // re-signed after a resiliency event).
        if let Some(config) = resiliency_config {
            let committed_pota = HsmPotaEndorsement::new(
                pota_endorsement.source(),
                Some(result.pota_endorsement_data),
            );
            let resiliency_state = ResiliencyState::new(config, creds, obk_config, committed_pota);
            self.inner().write().set_resiliency_state(resiliency_state);
        }
        Ok(())
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
    /// re-establishment) and exponential backoff (up to 5 retries).
    ///
    /// Retryable errors:
    /// - [`HsmError::IoAborted`]
    /// - [`HsmError::IoAbortInProgress`]
    /// - [`HsmError::CredentialsNotEstablished`]
    /// - [`HsmError::NonceMismatch`]
    /// - [`HsmError::PartitionNotProvisioned`]
    #[instrument(skip_all, err, fields(path = self.path().as_str()))]
    pub fn open_session(
        &self,
        api_rev: HsmApiRev,
        credentials: &HsmCredentials,
        seed: Option<&[u8]>,
    ) -> HsmResult<HsmSession> {
        let resiliency = self.resiliency_enabled();
        let result = self.with_dev(|dev| ddi::open_session(dev, api_rev, credentials, seed));

        // Retry with restore when resiliency is enabled and the initial
        // attempt returned a retryable error.
        let result = if resiliency && is_open_session_retryable_error(&result) {
            self.retry_open_session(result, api_rev, credentials, seed)?
        } else {
            result?
        };

        // Cache session state so restore_partition can reopen the session
        // if a later resiliency event occurs.
        if resiliency {
            self.inner().write().cache_session(CachedSessionState {
                sess_id: result.sess_id,
                rev: api_rev,
                seed: result.seed,
                bmk_session: result.bmk_session.clone(),
            });
        }

        Ok(HsmSession::new(
            result.sess_id,
            result.short_app_id,
            api_rev,
            self.clone(),
        ))
    }

    /// Retry loop for `open_session` with restore-partition recovery.
    ///
    /// Called when the initial `ddi::open_session` attempt failed with a
    /// retryable error and resiliency is enabled.  On each iteration:
    /// 1. Apply exponential backoff for IO-abort errors.
    /// 2. Call `restore_partition` to re-establish credentials.
    /// 3. Retry `ddi::open_session`.
    fn retry_open_session(
        &self,
        initial_result: HsmResult<ddi::OpenSessionResult>,
        api_rev: HsmApiRev,
        credentials: &HsmCredentials,
        seed: Option<&[u8]>,
    ) -> HsmResult<ddi::OpenSessionResult> {
        use std::time::Duration;

        let mut result = initial_result;
        let mut iter = 0u32;

        while is_open_session_retryable_error(&result) && iter < MAX_RETRIES {
            // Exponential backoff for IO-abort conditions
            if let Err(ref err) = result {
                if matches!(err, HsmError::IoAborted | HsmError::IoAbortInProgress) {
                    let backoff_ms = BACKOFF_BASE_MS * (1 << iter);
                    std::thread::sleep(Duration::from_millis(backoff_ms));
                }
            }

            let restore_result = self.restore_partition();

            match restore_result {
                Err(HsmError::RestorePartitionFailed) => {
                    // Another LM may have occurred during restore; skip op,
                    // loop again so the next iteration restores again.
                    warn!("RestorePartitionFailed during open_session retry.");
                }
                Err(err) => {
                    error!(?err, "restore_partition failed fatally.");
                    return Err(err);
                }
                Ok(()) => {
                    result =
                        self.with_dev(|dev| ddi::open_session(dev, api_rev, credentials, seed));
                }
            }
            iter += 1;
        }

        if let Err(ref err) = result {
            if iter > 0 {
                error!(?err, retries = iter, "open_session failed after retries.");
            }
        }

        result
    }

    /// Restores partition state after a resiliency event.
    ///
    /// Called from the retry loop when `open_session` (or a future
    /// operation) encounters a retryable error and resiliency is enabled.
    ///
    /// 1. Acquire the cross-process resiliency lock.
    /// 2. Re-endorse POTA via callback (if source is Caller).
    /// 3. Re-establish credentials via a **single** `ddi::init_part`
    ///    call (no resiliency config → no proc-macro retry).  Errors
    ///    are logged and ignored — the outer `retry_open_session` loop
    ///    will call us again.  This keeps worst-case `init_part` calls
    ///    at `MAX_RETRIES` instead of `MAX_RETRIES²`.
    /// 4. Increment `restore_epoch`.
    #[instrument(skip_all)]
    fn restore_partition(&self) -> HsmResult<()> {
        // Snapshot the cached resiliency state under a short-lived read lock.
        let (rev, creds, obk_config, pota_endorsement, bmk_copy) = {
            let inner = self.inner().read();
            let Some(rs) = inner.resiliency_state.as_ref() else {
                return Ok(());
            };

            rs.config.lock.lock()?;

            (
                inner.api_rev_range().min(),
                rs.cached_credentials,
                rs.cached_obk_config.clone(),
                rs.cached_pota_endorsement.clone(),
                if inner.bmk().is_empty() {
                    None
                } else {
                    Some(inner.bmk().to_vec())
                },
            )
        };

        // Re-endorse POTA so init_part gets a fresh signature.
        let pota_endorsement = self.reendorse_pota(pota_endorsement);

        // Single-attempt init_part (no resiliency config disables the
        // proc-macro retry; POTA was already re-endorsed above).
        let init_result = self.with_dev(|dev| {
            ddi::init_part(
                dev,
                rev,
                creds,
                bmk_copy.as_deref(),
                None,
                &obk_config,
                &pota_endorsement,
                None,
            )
        });

        // Apply results and release the cross-process lock.
        let mut inner = self.inner().write();
        match init_result {
            Ok(result) => inner.set_masked_keys(result.bmk, result.mobk),
            Err(ref err) => info!(?err, "init_part during restore failed, ignoring."),
        }

        if let Some(rs) = inner.resiliency_state.as_mut() {
            rs.restore_epoch += 1;
            rs.config.lock.unlock().ok();
        }

        Ok(())
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
        self.with_dev(|dev| {
            dev.simulate_nssr_after_lm()
                .map_err(|_| HsmError::DdiCmdFailure)
        })?;
        // Clear cached masked keys after reset
        self.inner().write().clear_masked_keys();
        Ok(())
    }

    /// Returns the API revision range supported by this partition.
    ///
    /// # Returns
    ///
    /// The supported API revision range with minimum and maximum versions.
    pub fn api_rev_range(&self) -> HsmApiRevRange {
        self.inner().read().api_rev_range()
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
        self.with_dev(|dev| ddi::get_cert_chain(dev, self.api_rev_range().min(), slot))
    }

    /// Retrieves the public key of the partition identity (PID) certificate.
    ///
    /// # Returns
    ///
    /// Returns the DER-encoded public key of the PID certificate.
    pub fn pub_key(&self) -> HsmResult<Vec<u8>> {
        self.with_dev(|dev| ddi::get_part_pub_key(dev, self.api_rev_range().min()))
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
        let len = self.inner().read().bmk().len();
        if let Some(buf) = bmk {
            if buf.len() < len {
                return Err(HsmError::BufferTooSmall);
            }
            buf[..len].copy_from_slice(self.inner().read().bmk());
        }
        Ok(len)
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
        let len = self.inner().read().mobk().len();
        if let Some(buf) = mobk {
            if buf.len() < len {
                return Err(HsmError::BufferTooSmall);
            }
            buf[..len].copy_from_slice(self.inner().read().mobk());
        }
        Ok(len)
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

    /// Executes a closure with access to the underlying device handle.
    ///
    /// Provides thread-safe access to the HSM device for internal operations.
    /// Acquires a read lock on the partition and passes the device handle
    /// to the provided closure.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure that receives the device handle and returns a value
    ///
    /// # Returns
    ///
    /// Returns the value produced by the closure.
    pub(crate) fn with_dev<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&ddi::HsmDev) -> T,
    {
        let part = self.inner().read();
        let dev = part.dev();
        f(dev)
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
        &self.0
    }

    /// Returns `true` if resiliency was configured for this partition
    /// (i.e., a non-`None` [`HsmResiliencyConfig`] was passed to [`init`]).
    pub(crate) fn resiliency_enabled(&self) -> bool {
        self.inner().read().resiliency_state.is_some()
    }

    /// Invokes the POTA endorsement callback to produce a fresh endorsement.
    ///
    /// After NSSR / live migration the device may have regenerated its
    /// attestation key, making the cached endorsement stale. This helper
    /// invokes the caller-supplied [`PotaEndorsementCallback`] (if present
    /// and source is `Caller`) and returns a new [`HsmPotaEndorsement`]
    /// with the fresh signature and public key.
    ///
    /// If the source is not `Caller`, no callback is configured, or the
    /// callback fails, the original `pota_endorsement` is returned
    /// unchanged.
    fn reendorse_pota(&self, pota_endorsement: HsmPotaEndorsement) -> HsmPotaEndorsement {
        if pota_endorsement.source() != HsmPotaEndorsementSource::Caller {
            return pota_endorsement;
        }

        let fresh = {
            let inner = self.inner().read();
            inner
                .resiliency_state
                .as_ref()
                .and_then(|rs| rs.config.pota_callback.as_ref())
                .map(|cb| ddi::invoke_pota_callback(cb.as_ref(), &pota_endorsement))
        };

        match fresh {
            Some(Ok(data)) => {
                info!("Re-endorsed POTA via callback.");
                HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(data))
            }
            Some(Err(err)) => {
                warn!(?err, "POTA re-endorsement callback failed, using cached.");
                pota_endorsement
            }
            None => pota_endorsement,
        }
    }
}

/// HSM partition handle.
///
/// Represents an open connection to an HSM partition. This handle provides
/// access to partition information, API revision support, and the underlying
/// device for cryptographic operations.
#[derive(Debug)]
pub(crate) struct HsmPartitionInner {
    dev: ddi::HsmDev,
    api_rev_range: HsmApiRevRange,
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
    /// * `path` - Device path string
    /// * `part_type` - Type of the partition (Virtual or Physical)
    /// * `driver_ver` - Driver version string
    /// * `firmware_ver` - Firmware version string
    /// * `hardware_ver` - Hardware version string
    /// * `pci_info` - PCI information string
    fn new(
        dev: ddi::HsmDev,
        api_rev_range: HsmApiRevRange,
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

    /// Caches session state for `restore_partition`.
    pub(crate) fn cache_session(&mut self, state: CachedSessionState) {
        if let Some(ref mut rs) = self.resiliency_state {
            rs.cache_session(state);
        }
    }

    /// Clears cached session state.
    #[allow(dead_code)]
    pub(crate) fn clear_session_cache(&mut self) {
        if let Some(ref mut rs) = self.resiliency_state {
            rs.clear_session();
        }
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
