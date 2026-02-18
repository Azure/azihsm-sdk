// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::c_void;

use azihsm_api::*;
use open_enum::open_enum;
use zerocopy::IntoBytes;

use super::*;

/// Partition property identifier enumeration.
///
/// This enum defines the various properties that can be queried from an HSM partition.
/// Each property has a unique identifier that is used to retrieve specific attributes
/// of a partition.
///
/// The enum is represented as a u32 to ensure compatibility with C APIs and consistent
/// memory layout across different platforms.
#[open_enum]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AzihsmPartPropId {
    /// Device type property (Virtual or Physical).
    // Corresponds to AZIHSM_PART_PROP_ID_TYPE
    Type = 1,

    /// OS device path.
    // Corresponds to AZIHSM_PART_PROP_ID_PATH
    Path = 2,

    /// Driver version string.
    // Corresponds to AZIHSM_PART_PROP_ID_DRIVER_VERSION
    DriverVersion = 3,

    /// Firmware version string.
    // Corresponds to AZIHSM_PART_PROP_ID_FIRMWARE_VERSION
    FirmwareVersion = 4,

    /// Hardware version string.
    // Corresponds to AZIHSM_PART_PROP_ID_HARDWARE_VERSION
    HardwareVersion = 5,

    /// PCI hardware ID (bus:device:function).
    // Corresponds to AZIHSM_PART_PROP_ID_PCI_HW_ID
    PciHwId = 6,

    /// Minimum API revision supported by the device.
    // Corresponds to AZIHSM_PART_PROP_ID_MIN_API_REV
    MinApiRev = 7,

    /// Maximum API revision supported by the device.
    // Corresponds to AZIHSM_PART_PROP_ID_MAX_API_REV
    MaxApiRev = 8,

    /// Manufacturer certificate chain in PEM format.
    // Corresponds to AZIHSM_PART_PROP_ID_MANUFACTURER_CERT_CHAIN
    ManufacturerCertChain = 9,

    /// Backup masking key (BMK).
    // Corresponds to AZIHSM_PART_PROP_ID_BACKUP_MASKING_KEY
    BackupMaskingKey = 10,

    /// Masked owner backup key (MOBK).
    // Corresponds to AZIHSM_PART_PROP_ID_MASKED_OWNER_BACKUP_KEY
    MaskedOwnerBackupKey = 11,

    /// Partition identity (PID) public key in DER format.
    // Corresponds to AZIHSM_PART_PROP_ID_PART_PUB_KEY
    PartPubKey = 12,
}

/// UUID structure.
///
/// Contains a 16-byte universally unique identifier.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(unused)]
pub struct AzihsmUuid {
    /// 16-byte UUID value.
    pub bytes: [u8; 16],
}

/// Partition property structure for querying partition attributes.
///
/// # Safety
/// When using this struct from C code:
/// - `val` must point to valid memory for `len` bytes
/// - `val` lifetime must exceed the lifetime of this struct
/// - Caller is responsible for proper memory management
#[repr(C)]
pub struct AzihsmPartProp {
    /// Property identifier.
    pub id: AzihsmPartPropId,

    /// Pointer to the property value.
    pub val: *mut c_void,

    /// Length of the property value in bytes.
    pub len: u32,
}

/// Get a property of a partition
///
/// @param[in] handle Handle to the partition
/// @param[in/out] part_prop Pointer to partition property structure. On input, specifies which property to get. On output, contains the property value.
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_get_prop(
    handle: AzihsmHandle,
    part_prop: *mut AzihsmPartProp,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(part_prop)?;

        let prop = deref_mut_ptr(part_prop)?;
        let partition = HsmPartition::try_from(handle)?;

        get_partition_prop(&partition, prop)
    })
}

/// Helper function to get a partition property.
fn get_partition_prop(
    partition: &HsmPartition,
    part_prop: &mut AzihsmPartProp,
) -> Result<(), AzihsmStatus> {
    match part_prop.id {
        AzihsmPartPropId::Type => {
            let part_type = partition.part_type();
            copy_to_part_prop(part_prop, part_type.as_bytes())
        }
        AzihsmPartPropId::Path => {
            let path = AzihsmStr::from_string(&partition.path());
            copy_to_part_prop(part_prop, path.as_bytes())
        }
        AzihsmPartPropId::DriverVersion => {
            let driver_version = AzihsmStr::from_string(&partition.driver_ver());
            copy_to_part_prop(part_prop, driver_version.as_bytes())
        }
        AzihsmPartPropId::FirmwareVersion => {
            let firmware_version = AzihsmStr::from_string(&partition.firmware_ver());
            copy_to_part_prop(part_prop, firmware_version.as_bytes())
        }
        AzihsmPartPropId::HardwareVersion => {
            let hardware_version = AzihsmStr::from_string(&partition.hardware_ver());
            copy_to_part_prop(part_prop, hardware_version.as_bytes())
        }
        AzihsmPartPropId::PciHwId => {
            let pci_info = AzihsmStr::from_string(&partition.pci_info());
            copy_to_part_prop(part_prop, pci_info.as_bytes())
        }
        AzihsmPartPropId::MinApiRev => {
            let api_rev = partition.api_rev_range().min();
            let api_rev_ffi = AzihsmApiRev {
                major: api_rev.major,
                minor: api_rev.minor,
            };
            copy_to_part_prop(part_prop, api_rev_ffi.as_bytes())
        }
        AzihsmPartPropId::MaxApiRev => {
            let api_rev = partition.api_rev_range().max();
            let api_rev_ffi = AzihsmApiRev {
                major: api_rev.major,
                minor: api_rev.minor,
            };
            copy_to_part_prop(part_prop, api_rev_ffi.as_bytes())
        }
        AzihsmPartPropId::BackupMaskingKey => {
            get_property_with_buffer(part_prop, |buf| partition.bmk(buf))
        }
        AzihsmPartPropId::MaskedOwnerBackupKey => {
            get_property_with_buffer(part_prop, |buf| partition.mobk(buf))
        }
        AzihsmPartPropId::ManufacturerCertChain => {
            let cert_chain = AzihsmStr::from_string(&partition.cert_chain(0)?);
            copy_to_part_prop(part_prop, cert_chain.as_bytes())
        }
        AzihsmPartPropId::PartPubKey => {
            let pub_key = partition.pub_key()?;
            copy_to_part_prop(part_prop, &pub_key)
        }
        _ => Err(AzihsmStatus::UnsupportedProperty),
    }
}

/// Extract a mutable byte slice from a partition property
impl<'a> TryFrom<&'a mut AzihsmPartProp> for &'a mut [u8] {
    type Error = AzihsmStatus;

    /// Converts a partition property to a mutable byte slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `prop.val` points to valid memory
    /// containing at least `prop.len` bytes.
    #[allow(unsafe_code)]
    fn try_from(prop: &'a mut AzihsmPartProp) -> Result<Self, Self::Error> {
        validate_ptr(prop.val)?;

        // SAFETY: Pointer has been validated as non-null above
        let slice =
            unsafe { std::slice::from_raw_parts_mut(prop.val as *mut u8, prop.len as usize) };
        Ok(slice)
    }
}

/// Copy a byte slice into a partition property buffer.
///
/// # Arguments
///
/// * `part_prop` - The partition property to copy into
/// * `bytes` - The byte slice to copy from
///
/// # Returns
///
/// * `Ok(())` - On success
/// * `Err(AzihsmStatus::BufferTooSmall)` - If the partition property buffer is too small
fn copy_to_part_prop(part_prop: &mut AzihsmPartProp, bytes: &[u8]) -> Result<(), AzihsmStatus> {
    let required_len = bytes.len() as u32;
    if part_prop.len < required_len {
        part_prop.len = required_len;
        Err(AzihsmStatus::BufferTooSmall)?;
    }

    let buf: &mut [u8] = part_prop.try_into()?;
    buf[..bytes.len()].copy_from_slice(bytes);
    part_prop.len = required_len;
    Ok(())
}

/// Helper function to retrieve a property that requires a buffer.
///
/// This function handles the common pattern of:
/// 1. Getting the required size by calling the getter with None
/// 2. Validating the user's buffer
/// 3. Writing directly to the user's buffer
///
/// # Arguments
///
/// * `part_prop` - The partition property structure
/// * `getter` - A closure that takes an Option<&mut [u8]> and returns Result<usize, HsmError>
///
/// # Returns
///
/// * `Ok(())` - On success
/// * `Err(AzihsmStatus)` - On failure
fn get_property_with_buffer<F>(
    part_prop: &mut AzihsmPartProp,
    getter: F,
) -> Result<(), AzihsmStatus>
where
    F: Fn(Option<&mut [u8]>) -> HsmResult<usize>,
{
    // Get required size first
    let required_size = getter(None)?;

    // If the required size is zero, the property is not present
    if required_size == 0 {
        return Err(AzihsmStatus::PropertyNotPresent);
    }

    // Check if user provided a buffer or if buffer is too small
    if part_prop.val.is_null() || (part_prop.len as usize) < required_size {
        part_prop.len = required_size as u32;
        return Err(AzihsmStatus::BufferTooSmall);
    }

    // Get the mutable slice from the user's buffer
    let buffer: &mut [u8] = part_prop.try_into()?;
    let buffer_slice = &mut buffer[..required_size];

    // Write directly to user's buffer
    let actual_size = getter(Some(buffer_slice))?;
    part_prop.len = actual_size as u32;
    Ok(())
}
