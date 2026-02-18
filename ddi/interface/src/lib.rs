// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! Device Driver Interface (DDI) interface library

mod error;

use std::cmp::Ordering;

use azihsm_ddi_types::DdiAesOp;
use azihsm_ddi_types::DdiDeviceKind;
use azihsm_ddi_types::DdiOpReq;
pub use error::DdiError;

/// DDI Result
pub type DdiResult<T> = Result<T, DdiError>;

/// DDI Cookie
pub type DdiCookie = u64;

/// Device Info
#[derive(Clone, Debug)]
pub struct DevInfo {
    /// Device path
    pub path: String,

    /// Driver Version
    pub driver_ver: String,

    /// Firmware Version
    pub firmware_ver: String,

    /// Hardware Version
    pub hardware_ver: String,

    /// PCI BDF information
    pub pci_info: String,

    /// entropy data 32-bytes
    pub entropy_data: Vec<u8>,
}

impl Ord for DevInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path.cmp(&other.path)
    }
}

impl PartialOrd for DevInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for DevInfo {
    fn eq(&self, other: &Self) -> bool {
        self.path.eq(&other.path)
    }
}

impl Eq for DevInfo {}

/// Device Driver Interface trait
pub trait Ddi: Default {
    /// Device
    type Dev: DdiDev;

    /// Returns the HSM device information list
    ///
    /// # Returns
    /// * `Vec<DevInfo>` - HSM device information list
    fn dev_info_list(&self) -> Vec<DevInfo>;

    /// Open HSM device
    ///
    /// # Arguments
    /// `path` - Device path
    ///
    /// # Returns
    /// `Self::Dev` - HSM Device
    ///
    /// # Error
    /// * `DdiError` - Error encountered while opening the device
    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev>;
}

#[derive(Default, Clone)]
/// AES GCM input parameter
pub struct DdiAesGcmParams {
    /// key id
    pub key_id: u32,

    /// initial vector
    pub iv: [u8; 12usize],

    /// Optional
    /// *`aad`. Optional input to encryption operation
    pub aad: Option<Vec<u8>>,

    /// tag
    pub tag: Option<[u8; 16usize]>,

    /// session id
    pub session_id: u16,

    /// short app id
    pub short_app_id: u8,
}

#[derive(Default, Clone, Debug)]
/// AES GCM output
pub struct DdiAesGcmResult {
    /// Tag
    pub tag: Option<[u8; 16usize]>,

    /// IV returned from the device
    pub iv: Option<[u8; 12usize]>,

    /// FIPS approved indication
    pub fips_approved: bool,

    /// output data
    pub data: Vec<u8>,
}

#[derive(Default, Clone)]
/// Aes Xts input parameter
pub struct DdiAesXtsParams {
    /// dataUnitLen
    pub data_unit_len: usize,

    /// keyid1
    pub key_id1: u32,

    /// keyid2
    pub key_id2: u32,

    /// tweak vector
    pub tweak: [u8; 16usize],

    /// session id
    pub session_id: u16,

    /// short app id
    pub short_app_id: u8,
}

#[derive(Default, Clone, Debug)]
///DdiAesXtsResult
pub struct DdiAesXtsResult {
    /// output data
    pub data: Vec<u8>,

    /// FIPS approved indication
    pub fips_approved: bool,
}

/// Driver Error Status
#[derive(Clone, Copy, Debug)]
pub enum DriverError {
    /// Io abort is in progress
    IoAbortInProgress = 0x04000001,

    /// Io aborted
    IoAborted = 0x04000002,
}

/// Device Trait
pub trait DdiDev {
    /// Set Device Kind, to determine encode/decode behavior
    ///
    /// # Arguments
    /// * `type`        - Type of device
    ///
    /// # Error
    /// * `DdiError` - Error encountered?
    fn set_device_kind(&mut self, kind: DdiDeviceKind);

    /// Execute Operation
    ///
    /// # Arguments
    /// * `req`         - Operation Request
    /// * `cookie`      - Cookie
    ///
    /// # Returns
    /// * `OpReq::Resp` - Operation response
    ///
    /// # Error
    /// * `DdiError` - Error encountered while executing the command
    fn exec_op<T: DdiOpReq>(&self, req: &T, cookie: &mut Option<DdiCookie>)
        -> DdiResult<T::OpResp>;

    /// Execute GCM operation (encryption / decryption) with slice buffers
    ///
    /// # Arguments
    ///
    /// * `mode`        -- Encryption / decryption
    /// * `gcm_params` -- required. GCM parameters
    /// * `src_buf` --- source buffer slice to encrypt or decrypt
    /// * `dst_buf` --- destination buffer slice to write encrypted or decrypted data
    /// * `fips_approved` -- output parameter to indicate if operation was FIPS approved
    ///
    /// # Returns
    /// * `usize` - Number of bytes written to destination buffer
    /// # Error
    /// * `DdiError` - Error encountered while executing the command
    fn exec_op_fp_gcm_slice(
        &self,
        mode: DdiAesOp,
        gcm_params: DdiAesGcmParams,
        src_buf: &[u8],
        dst_buf: &mut [u8],
        tag: &mut Option<[u8; 16]>,
        iv: &mut Option<[u8; 12]>,
        fips_approved: &mut bool,
    ) -> Result<usize, DdiError>;

    /// Execute GCM operation (encryption / decryption)
    ///
    /// # Arguments
    ///
    /// * `mode`        -- Encryption / decryption
    /// * `gcm_params` -- required. GCM parameters
    /// * `src_buf` --- source buffer to encrypt or decrypt
    ///
    /// # Returns
    /// * `DdiAesGcmResult` - Operation response
    ///
    /// # Error
    /// * `DdiError` - Error encountered while executing the command
    fn exec_op_fp_gcm(
        &self,
        mode: DdiAesOp,
        gcm_params: DdiAesGcmParams,
        src_buf: Vec<u8>,
    ) -> Result<DdiAesGcmResult, DdiError>;

    /// Execute Xts operation (encryption / decryption)
    ///
    /// # Arguments
    ///
    /// * `mode`        -- Encryption / decryption
    /// * `xts_params` -- required. Xts parameters
    /// * `src_buf` --- source buffer to encrypt or decrypt
    ///
    /// # Returns
    /// * `DdiAesXtsResult` - Operation response
    ///
    /// # Error
    /// * `DdiError` - Error encountered while executing the command
    fn exec_op_fp_xts(
        &self,
        mode: DdiAesOp,
        xts_params: DdiAesXtsParams,
        src_buf: Vec<u8>,
    ) -> Result<DdiAesXtsResult, DdiError>;

    /// Execute Xts operation (encryption / decryption) with slice buffers
    ///
    /// # Arguments
    ///
    /// * `mode`        -- Encryption / decryption
    /// * `xts_params` -- required. Xts parameters
    /// * `src_buf` --- source buffer slice to encrypt or decrypt
    /// * `dst_buf` --- destination buffer slice to write encrypted or decrypted data
    /// * `fips_approved` -- output parameter to indicate if operation was FIPS approved
    ///
    /// # Returns
    /// * `usize` - Number of bytes written to destination buffer
    /// # Error
    /// * `DdiError` - Error encountered while executing the command
    fn exec_op_fp_xts_slice(
        &self,
        mode: DdiAesOp,
        xts_params: DdiAesXtsParams,
        src_buf: &[u8],
        dst_buf: &mut [u8],
        fips_approved: &mut bool,
    ) -> Result<usize, DdiError>;

    /// Execute NVMe subsystem reset to help emulate Live Migration
    ///
    /// # Returns
    /// * `Ok(())` - Successfully sent NSSR Reset Device command
    /// * `Err(DdiError)` - Error occurred while executing the command
    fn simulate_nssr_after_lm(&self) -> Result<(), DdiError>;
}
