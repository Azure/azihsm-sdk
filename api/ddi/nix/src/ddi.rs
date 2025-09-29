// Copyright (C) Microsoft Corporation. All rights reserved.

//! DDI Implementation - MCR Linux Device - DDI Module

#![allow(unsafe_code)]

use std::fs::OpenOptions;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use glob::glob;
use mcr_ddi::Ddi;
use mcr_ddi::DdiError;
use mcr_ddi::DdiResult;
use mcr_ddi::DevInfo;
use nix::ioctl_readwrite;

use crate::dev::DdiNixDev;

/// DDI Implementation - MCR Linux Device Interface
#[derive(Default)]
pub struct DdiNix {}

#[repr(C)]
struct McrCpGetDeviceInfoIoctlOutData {
    argsz: u32,
    ctrl_id: u16,
    pci_info: [u8; 33],
    serial_number: [u8; 33],
    model_num: [u8; 5],
    fw_rev: [u8; 33],
    driver_rev: [u8; 16],
    reserved: [u8; 17],
    entropy_data: [u8; 32],
}

impl Default for McrCpGetDeviceInfoIoctlOutData {
    fn default() -> Self {
        McrCpGetDeviceInfoIoctlOutData {
            argsz: mem::size_of::<McrCpGetDeviceInfoIoctlOutData>() as u32,
            ctrl_id: 0,
            pci_info: [0u8; 33],
            serial_number: [0u8; 33],
            model_num: [0u8; 5],
            fw_rev: [0u8; 33],
            driver_rev: [0u8; 16],
            reserved: [0u8; 17],
            entropy_data: [0u8; 32],
        }
    }
}

const MCR_HSM_IOC_MAGIC: u8 = b'B';
const MCR_HSM_IOC_SEQ: u8 = 0x04;

ioctl_readwrite!(
    mcr_ctrl_cmd_get_device_info,
    MCR_HSM_IOC_MAGIC,
    MCR_HSM_IOC_SEQ,
    McrCpGetDeviceInfoIoctlOutData
);

///
/// query_device_info
/// Returns a DevInfo structure that should have
/// the following information about the device
///     Driver version
///     Firmware version
///     hardware version
/// If the ioctl to get the device info fails
/// or any of the properties returned by device info ioctl
/// has an error, return None
fn query_device_info(path: &str) -> DdiResult<DevInfo> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(Path::new(path))
        .map_err(DdiError::IoError)?;

    let mut cmd = McrCpGetDeviceInfoIoctlOutData::default();
    // SAFETY: IOCTL call requires unsafe call. The pointers to the buffers are valid and have been checked via
    // debugging as well as code reviews.
    let resp = unsafe { mcr_ctrl_cmd_get_device_info(file.as_raw_fd(), &mut cmd) };
    if resp.is_err() {
        Err(DdiError::InvalidParameter)?
    } else {
        // Ioctl passed and we have valid data
        // convert the byte array for each of the relevant fields to
        // String
        // DevInfo only contains driver version, firmware version and
        // hardware version( serial number)

        let byte_vec = cmd.driver_rev.to_vec();
        let driver_ver =
            String::from_utf8(byte_vec).map_err(|_| DdiError::DeviceInfoIoctlInvalidData)?;

        let byte_vec = cmd.fw_rev.to_vec();
        let firmware_ver =
            String::from_utf8(byte_vec).map_err(|_| DdiError::DeviceInfoIoctlInvalidData)?;

        let byte_vec = cmd.serial_number.to_vec();
        let hardware_ver =
            String::from_utf8(byte_vec).map_err(|_| DdiError::DeviceInfoIoctlInvalidData)?;

        let byte_vec = cmd.pci_info.to_vec();
        let pci_info =
            String::from_utf8(byte_vec).map_err(|_| DdiError::DeviceInfoIoctlInvalidData)?;

        let entropy_data = cmd.entropy_data.to_vec();

        Ok(DevInfo {
            path: path.to_owned(),
            driver_ver,
            firmware_ver,
            hardware_ver,
            pci_info,
            entropy_data,
        })
    }
}

impl Ddi for DdiNix {
    type Dev = DdiNixDev;

    /// Returns the HSM device information list
    ///
    /// # Returns
    /// * `Vec<DevInfo>` - HSM device information list
    fn dev_info_list(&self) -> Vec<DevInfo> {
        let mut devs = Vec::new();

        if let Ok(devices) = glob("/dev/azihsm*") {
            for device in devices.flatten() {
                if let Some(path) = device.to_str() {
                    let path = String::from(path);
                    let dev_info = query_device_info(path.as_str());
                    match dev_info {
                        Ok(v) => devs.push(v),
                        // If querying a specific device's info fails, show a
                        // warning, but do not return an error. The device info
                        // will not be added to the returned vector (`devs`)
                        Err(e) => tracing::warn!("Device Info error: {:?}", e),
                    }
                }
            }
        }

        // Log a success message and a list of all devices
        tracing::debug!(size = devs.len(), "Got DdiNix device info list");
        for (i, dev) in devs.iter().enumerate() {
            tracing::debug!(index = i, path = ?dev.path);
        }
        tracing::trace!(devs = ?devs);

        devs
    }

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
    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev> {
        DdiNixDev::open(path)
    }
}
