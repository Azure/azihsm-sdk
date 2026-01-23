// Copyright (C) Microsoft Corporation. All rights reserved.

//! HSM partition management.
//!
//! This module provides structures and operations for managing HSM partitions.
//! Partitions represent logical divisions within an HSM device, each with its
//! own API revision support and configuration.

use std::sync::*;

use azihsm_ddi::DevInfo;
use azihsm_ddi_types::DdiDeviceKind;
use tracing::*;

use super::*;

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
    /// Partition type (Virtual or Physical).
    pub part_type: Option<HsmPartType>,

    /// Device path for accessing the partition.
    pub path: String,

    /// Driver version string.
    pub driver_ver: String,

    /// Firmware version string.
    pub firmware_ver: String,

    /// Hardware version string.
    pub hardware_ver: String,

    /// PCI BDF (Bus:Device:Function) information.
    pub pci_info: String,
}

impl HsmPartitionInfo {
    /// Creates new partition information from DevInfo.
    ///
    /// # Arguments
    ///
    /// * `dev_info` - Device information from the DDI layer
    /// * `part_type` - Optional partition type (Virtual or Physical)
    fn new(dev_info: DevInfo, part_type: Option<HsmPartType>) -> Self {
        Self {
            part_type,
            path: dev_info.path,
            driver_ver: dev_info.driver_ver,
            firmware_ver: dev_info.firmware_ver,
            hardware_ver: dev_info.hardware_ver,
            pci_info: dev_info.pci_info,
        }
    }
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

impl From<DdiDeviceKind> for HsmPartType {
    fn from(kind: DdiDeviceKind) -> Self {
        match kind {
            DdiDeviceKind::Virtual => HsmPartType::Virtual,
            DdiDeviceKind::Physical => HsmPartType::Physical,
            _ => unreachable!(),
        }
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
        let vec: Vec<HsmPartitionInfo> = ddi::dev_paths()
            .into_iter()
            .filter_map(|path| {
                let dev_info = ddi::dev_info_by_path(&path).ok()?;
                Some(HsmPartitionInfo::new(dev_info, None))
            })
            .collect();
        debug!("Found {} partition(s)", vec.len());
        vec
    }

    /// Opens an HSM partition at the specified path.
    ///
    /// Establishes a connection to the HSM partition and retrieves its
    /// supported API revision range.
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
    #[instrument()]
    pub fn open_partition(path: &str) -> HsmResult<HsmPartition> {
        let dev_info = ddi::dev_info_by_path(path)?;
        let dev = ddi::open_dev(path)?;
        let (min, max) = ddi::get_api_rev(&dev)?;
        let part_type = dev.device_kind().map(HsmPartType::from);
        Ok(HsmPartition::new(
            dev,
            HsmApiRevRange::new(min, max),
            HsmPartitionInfo::new(dev_info, part_type),
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
    /// * `part_info` - Partition metadata
    fn new(dev: ddi::HsmDev, api_rev_range: HsmApiRevRange, part_info: HsmPartitionInfo) -> Self {
        Self(Arc::new(RwLock::new(HsmPartitionInner::new(
            dev,
            api_rev_range,
            part_info,
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
    /// * `mobk` - Optional masked owner backup key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Credentials are invalid
    /// - API revision retrieval fails
    /// - Partition initialization fails
    #[instrument(skip_all,  fields(path = self.info().path.as_str()), err)]
    pub fn init(
        &self,
        creds: HsmCredentials,
        bmk: Option<&[u8]>,
        muk: Option<&[u8]>,
        mobk: Option<&[u8]>,
    ) -> HsmResult<()> {
        let (bmk, mobk) = self.with_dev(|dev| {
            let (bmk, mobk) =
                ddi::init_part(dev, self.api_rev_range().min(), creds, bmk, muk, mobk)?;
            Ok((bmk, mobk))
        })?;
        self.inner().write().unwrap().set_masked_keys(bmk, mobk);
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
    #[instrument(skip_all, err, fields(path = &self.info().path))]
    pub fn open_session(
        &self,
        api_rev: HsmApiRev,
        credentials: &HsmCredentials,
        seed: Option<&[u8]>,
    ) -> HsmResult<HsmSession> {
        let (id, app_id) =
            self.with_dev(|dev| ddi::open_session(dev, api_rev, credentials, seed))?;
        Ok(HsmSession::new(id, app_id, api_rev, self.clone()))
    }

    /// Returns the API revision range supported by this partition.
    ///
    /// # Returns
    ///
    /// The supported API revision range with minimum and maximum versions.
    pub fn api_rev_range(&self) -> HsmApiRevRange {
        self.inner().read().unwrap().api_rev_range()
    }

    /// Returns partition information.
    ///
    /// # Returns
    ///
    /// A clone of the partition information structure containing metadata
    /// such as the device path.
    pub fn info(&self) -> HsmPartitionInfo {
        self.inner().read().unwrap().info().clone()
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
    /// * `cert_chain` - Optional output buffer to receive the certificate chain.
    ///   If `None`, returns the exact size needed to hold the chain.
    ///
    /// # Returns
    ///
    /// Returns the size of the certificate chain on success. When `cert_chain` is `None`,
    /// this is the exact number of bytes needed. When `cert_chain` is provided, this is
    /// the actual number of bytes written to the buffer.
    pub fn cert_chain(&self, slot: u8, cert_chain: Option<&mut [u8]>) -> HsmResult<usize> {
        self.with_dev(|dev| ddi::get_cert_chain(dev, self.api_rev_range().min(), slot, cert_chain))
    }

    /// Retrieves the certificate chain stored in the partition as a vector.
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
    /// Returns a vector containing the certificate chain bytes.
    pub fn cert_chain_vec(&self, slot: u8) -> HsmResult<Vec<u8>> {
        let cert_size = self.cert_chain(slot, None)?;
        let mut cert_buffer = vec![0u8; cert_size];
        let actual_size = self.cert_chain(slot, Some(&mut cert_buffer[..]))?;
        cert_buffer.truncate(actual_size);
        Ok(cert_buffer)
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
        let len = self.inner().read().unwrap().bmk().len();
        if let Some(buf) = bmk {
            if buf.len() < len {
                return Err(HsmError::BufferTooSmall);
            }
            buf[..len].copy_from_slice(self.inner().read().unwrap().bmk());
        }
        Ok(len)
    }

    /// Retrieves the backup masking key that was set during partition initialization.
    ///
    /// # Returns
    ///
    /// A vector containing the BMK bytes.
    pub fn bmk_vec(&self) -> Vec<u8> {
        self.inner().read().unwrap().bmk().to_vec()
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
        let len = self.inner().read().unwrap().mobk().len();
        if let Some(buf) = mobk {
            if buf.len() < len {
                return Err(HsmError::BufferTooSmall);
            }
            buf[..len].copy_from_slice(self.inner().read().unwrap().mobk());
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
        self.inner().read().unwrap().mobk().to_vec()
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
        let part = self.inner().read().unwrap();
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
}

/// Cleans up resources when the partition is dropped.
///
/// Ensures proper cleanup and logging when the partition handle goes out of scope.
impl Drop for HsmPartition {
    #[instrument(skip_all, fields(path = self.info().path.as_str()) )]
    fn drop(&mut self) {}
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
    part_info: HsmPartitionInfo,
    bmk: Vec<u8>,
    mobk: Vec<u8>,
}

impl HsmPartitionInner {
    /// Creates a new partition handle.
    ///
    /// # Arguments
    ///
    /// * `dev` - HSM device handle
    /// * `api_rev_range` - Supported API revision range
    /// * `part_info` - Partition metadata
    fn new(dev: ddi::HsmDev, api_rev_range: HsmApiRevRange, part_info: HsmPartitionInfo) -> Self {
        Self {
            dev,
            api_rev_range,
            part_info,
            bmk: Vec::new(),
            mobk: Vec::new(),
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

    /// Returns partition information.
    ///
    /// # Returns
    ///
    /// A reference to the partition information structure containing metadata
    /// such as the device path.
    pub fn info(&self) -> &HsmPartitionInfo {
        &self.part_info
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
}
