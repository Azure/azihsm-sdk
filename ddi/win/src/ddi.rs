// Copyright (C) Microsoft Corporation. All rights reserved.

//! DDI Implementation - MCR Windows Device - DDI Module

#![allow(unsafe_code)]

#[cfg(windows)]
extern crate winapi;

use std::ffi::CStr;
use std::fs::OpenOptions;
use std::mem;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;
use std::ptr::null_mut;

use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_interface::DdiResult;
use azihsm_ddi_interface::DevInfo;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::DWORD;
use winapi::shared::winerror::ERROR_NO_MORE_ITEMS;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::minwinbase::OVERLAPPED;
use winapi::um::setupapi::SetupDiEnumDeviceInterfaces;
use winapi::um::setupapi::SetupDiGetClassDevsW;
use winapi::um::setupapi::SetupDiGetDeviceInterfaceDetailA;
use winapi::um::setupapi::DIGCF_DEVICEINTERFACE;
use winapi::um::setupapi::DIGCF_PRESENT;
use winapi::um::setupapi::SP_DEVICE_INTERFACE_DATA;
use winapi::um::setupapi::SP_DEVICE_INTERFACE_DETAIL_DATA_A;
use winapi::um::setupapi::SP_DEVINFO_DATA;
use winapi::um::winioctl::CTL_CODE;
use winapi::um::winioctl::FILE_READ_ACCESS;
use winapi::um::winioctl::FILE_WRITE_ACCESS;
use winapi::um::winioctl::METHOD_BUFFERED;
use winapi::um::winnt::HANDLE;
use winapi::DEFINE_GUID;

use crate::dev::DdiWinDev;

const MAX_MC_DEVICES_SUPPORTED: u32 = 10;

/// DDI Implementation - MCR Windows Device Interface
#[derive(Default)]
pub struct DdiWin {}

/// discover_manticore_dev
///
/// Function to discover all Manticore devices in the system
/// Each Manticore device is a PCIe function (PF or VF) and a
/// FDO (Function Device Object) is installed by the Manticore
/// device driver against each such PCIe function.
///
/// Each such PCIe function's FDO exposes an interface using
/// a GUID. The GUID is referred to as GUID_MSFTMC_IFACE below
///
/// #Arguments
///    None
///
/// #Returns
/// Returns a vector of String.
/// Each entry in the vector represents an abstract link to
/// a Manticore device. This string can be passed in
/// native WIndows functions or equivalent to obtain a handle
/// to the device. Once such a handle is obtained, ioctl()
/// functions can be used to send requests and receive responses
/// from the device. Each path is discovered using SetupAPIs exposed
/// by winapi crate.
///
/// Each entry in this vector is unique and represents an instance
/// of a Manticore device
///
/// This vector can be zero in length. Zero implies there are no manticore
/// devices in the system (It is possible there are manticore devices
/// plugged in but no device driver is installed or the device has been
/// disabled or the device is in some error state
/// )
fn discover_manticore_dev() -> Vec<String> {
    DEFINE_GUID! {GUID_MSFTMC_IFACE,
    0x44a8ec43, 0x14be, 0x4fae, 0x88, 0xc4, 0xd7, 0x2b, 0x4d, 0xb0, 0xf4, 0xa0};

    let u1 = mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
    let u2 = mem::size_of::<SP_DEVINFO_DATA>() as u32;
    let mut dev_vec = Vec::new();

    let mut did = SP_DEVICE_INTERFACE_DATA {
        cbSize: u1,
        InterfaceClassGuid: GUID_MSFTMC_IFACE,
        Flags: 0,
        Reserved: 0,
    };

    let mut dd = SP_DEVINFO_DATA {
        cbSize: u2,
        ClassGuid: GUID_MSFTMC_IFACE,
        DevInst: 0,
        Reserved: 0,
    };

    let num_mc_devices: u32 = MAX_MC_DEVICES_SUPPORTED;

    // SAFETY: WINAPI call requires unsafe call. The pointers to the buffers are valid and have been checked via
    // debugging as well as code reviews.
    let h_di = unsafe {
        SetupDiGetClassDevsW(
            &GUID_MSFTMC_IFACE,
            null_mut(),
            null_mut(),
            DIGCF_DEVICEINTERFACE | DIGCF_PRESENT,
        )
    };

    if h_di != INVALID_HANDLE_VALUE {
        for mc_index in 0..num_mc_devices {
            // SAFETY: WINAPI call requires unsafe call. The pointers to the buffers are valid and have been checked via
            // debugging as well as code reviews.
            let b_ret = unsafe {
                SetupDiEnumDeviceInterfaces(
                    h_di,
                    null_mut(),
                    &GUID_MSFTMC_IFACE,
                    mc_index,
                    &mut did,
                )
            };

            if b_ret == 0 {
                break;
            }

            let mut size: u32 = 0;
            let u3 = mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_A>() as u32;
            let _dev_intf_detail_data = SP_DEVICE_INTERFACE_DETAIL_DATA_A {
                cbSize: u3,
                DevicePath: [0],
            };

            // SAFETY: WINAPI call requires unsafe call. The pointers to the buffers are valid and have been checked via
            // debugging as well as code reviews.
            let mut b_ret = unsafe {
                SetupDiGetDeviceInterfaceDetailA(
                    h_di,
                    &mut did,
                    null_mut(),
                    0,
                    &mut size,
                    null_mut(),
                )
            };

            if b_ret == 0 {
                // SAFETY: WINAPI call requires unsafe call. The pointers to the buffers are valid and have been checked via
                // debugging as well as code reviews.
                let win_error = unsafe { GetLastError() };
                if win_error == ERROR_NO_MORE_ITEMS {
                    break;
                }

                let di_arr = vec![0i8; size as usize];

                let p = di_arr.as_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_A;
                // SAFETY: WINAPI call requires unsafe call. The pointers to the buffers are valid and have been checked via
                // debugging as well as code reviews.
                unsafe {
                    (*p).cbSize = u3;
                    b_ret = SetupDiGetDeviceInterfaceDetailA(
                        h_di, &mut did, p, size, &mut size, &mut dd,
                    );
                }

                if b_ret == 0 {
                    break;
                }

                // SAFETY: WINAPI call requires unsafe call. The pointers to the buffers are valid and have been checked via
                // debugging as well as code reviews.
                let c_str: &CStr = unsafe { CStr::from_ptr(&(*p).DevicePath[0]) };

                if let Ok(dev_str) = c_str.to_str() {
                    dev_vec.push(String::from(dev_str));
                }
            }
        }
    }
    dev_vec
}

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
    hot_patch_reserved: [usize; 16],
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
            hot_patch_reserved: [0usize; 16],
        }
    }
}

///
/// query_device_info
/// Returns a DevInfo structure that has the following
/// information about the device
/// # Returns
/// * Option<DevInfo> Information about the device
fn query_device_info(path: &str) -> DdiResult<DevInfo> {
    let ioctl_code: DWORD = CTL_CODE(
        0x3F,
        0x400,
        METHOD_BUFFERED,
        FILE_READ_ACCESS | FILE_WRITE_ACCESS,
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(Path::new(path))
        .map_err(DdiError::IoError)?;

    let h_device: HANDLE = file.as_raw_handle() as HANDLE;
    let null_ptr: *mut c_void = ptr::null_mut();
    let ioctl_out_buffer = McrCpGetDeviceInfoIoctlOutData::default();
    let out_ptr = ptr::addr_of!(ioctl_out_buffer);
    let mut bytes_returned: DWORD = 0;
    let overlapped_ptr: *const u8 = std::ptr::null();
    // SAFETY: WINAPI call requires unsafe call. The pointers to the buffers are valid and have been checked via
    // debugging as well as code reviews.
    // This ioctl takes no input buffer and must provide an output
    // buffer
    let ioctl_ret = unsafe {
        DeviceIoControl(
            h_device,
            ioctl_code,
            null_ptr,
            0,
            out_ptr as *mut c_void,
            mem::size_of::<McrCpGetDeviceInfoIoctlOutData>() as DWORD,
            &mut bytes_returned as *mut u32,
            overlapped_ptr as *mut OVERLAPPED,
        )
    };

    if ioctl_ret == 0 {
        // Safety: This is unsafe because of the call to
        // system routine DeviceIoControl
        let win_error = unsafe { GetLastError() };
        Err(DdiError::WinError(win_error))?
    } else {
        // Ioctl passed and we have valid data
        // convert the byte array for each of the relevant fields to
        // String
        // DevInfo only contains driver version, firmware version and
        // hardware version( serial number)
        // Meaningful to do validation on driver version

        let byte_vec = ioctl_out_buffer.driver_rev.to_vec();

        let driver_ver =
            String::from_utf8(byte_vec).map_err(|_| DdiError::DeviceInfoIoctlInvalidData)?;

        let byte_vec = ioctl_out_buffer.fw_rev.to_vec();

        let firmware_ver =
            String::from_utf8(byte_vec).map_err(|_| DdiError::DeviceInfoIoctlInvalidData)?;

        let byte_vec = ioctl_out_buffer.serial_number.to_vec();

        let hardware_ver =
            String::from_utf8(byte_vec).map_err(|_| DdiError::DeviceInfoIoctlInvalidData)?;

        let byte_vec = ioctl_out_buffer.pci_info.to_vec();

        let pci_info =
            String::from_utf8(byte_vec).map_err(|_| DdiError::DeviceInfoIoctlInvalidData)?;

        let entropy_data = ioctl_out_buffer.entropy_data.to_vec();

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

impl Ddi for DdiWin {
    type Dev = DdiWinDev;

    /// Returns the HSM device information list
    ///
    /// # Returns
    /// * `Vec<DevInfo>` - HSM device information list
    fn dev_info_list(&self) -> Vec<DevInfo> {
        let dev_path_list = discover_manticore_dev();
        let mut devs = Vec::new();

        for dev in dev_path_list.iter() {
            let path = String::from(dev);
            let dev_info = query_device_info(path.as_str());
            match dev_info {
                Ok(v) => devs.push(v),
                // If querying a specific device's info fails, show a warning,
                // but do not return an error. The device info will not be added
                // to the returned vector (`devs`)
                Err(e) => tracing::warn!("Device Info error: {:?}", e),
            }
        }

        // Log a success message and a list of all devices
        tracing::debug!(size = devs.len(), "Got DdiWin device info list");
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
        DdiWinDev::open(path)
    }
}
