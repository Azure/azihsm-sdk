// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM partition operations for the native C API.
//!
//! This module provides the FFI (Foreign Function Interface) bindings for
//! HSM partition management operations, exposing them to C callers through
//! the ABI-compatible interface.

use azihsm_api::HsmPartition;

use super::*;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AzihsmOwnerBackupKeyConfig {
    /// Source of the owner backup key
    pub source: AzihsmOwnerBackupKeySource,

    /// Pointer to the owner backup key buffer (if source is Caller)
    pub owner_backup_key: *const AzihsmBuffer,
}

/// Convert AzihsmOwnerBackupKeyConfig to HsmOwnerBackupKeyConfig
impl<'a> TryFrom<&'a AzihsmOwnerBackupKeyConfig> for api::HsmOwnerBackupKeyConfig<'a> {
    type Error = AzihsmStatus;

    fn try_from(config: &'a AzihsmOwnerBackupKeyConfig) -> Result<Self, Self::Error> {
        let source: api::HsmOwnerBackupKeySource = config.source.into();

        match source {
            api::HsmOwnerBackupKeySource::Caller => {
                let slice = buffer_to_optional_slice(config.owner_backup_key)?;
                let obk = slice.ok_or(AzihsmStatus::InvalidArgument)?;
                if obk.is_empty() {
                    Err(AzihsmStatus::InvalidArgument)?;
                }
                Ok(api::HsmOwnerBackupKeyConfig::new(source, Some(obk)))
            }
            api::HsmOwnerBackupKeySource::Tpm => {
                if !config.owner_backup_key.is_null() {
                    Err(AzihsmStatus::InvalidArgument)?;
                }
                Ok(api::HsmOwnerBackupKeyConfig::new(source, None))
            }
            _ => Err(AzihsmStatus::InvalidArgument),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AzihsmPotaEndorsementData {
    /// Pointer to the signature buffer
    pub signature: *const AzihsmBuffer,

    /// Pointer to the public key buffer
    pub public_key: *const AzihsmBuffer,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AzihsmPotaEndorsement {
    /// Source of the POTA endorsement
    pub source: AzihsmPotaEndorsementSource,

    /// Pointer to the POTA endorsement data (if source is Caller)
    pub endorsement: *const AzihsmPotaEndorsementData,
}

/// Convert AzihsmPotaEndorsement to HsmPotaEndorsement
///
/// The returned HsmPotaEndorsement borrows from the original C buffers,
/// which must remain valid for the lifetime of the returned value.
impl<'a> TryFrom<&'a AzihsmPotaEndorsement> for api::HsmPotaEndorsement<'a> {
    type Error = AzihsmStatus;

    fn try_from(config: &'a AzihsmPotaEndorsement) -> Result<Self, Self::Error> {
        let source: api::HsmPotaEndorsementSource = config.source.into();

        match source {
            api::HsmPotaEndorsementSource::Caller => {
                let endorsement_data = deref_ptr(config.endorsement)?;

                let signature = buffer_to_optional_slice(endorsement_data.signature)?
                    .ok_or(AzihsmStatus::InvalidArgument)?;
                if signature.is_empty() {
                    return Err(AzihsmStatus::InvalidArgument);
                }

                let public_key = buffer_to_optional_slice(endorsement_data.public_key)?
                    .ok_or(AzihsmStatus::InvalidArgument)?;
                if public_key.is_empty() {
                    return Err(AzihsmStatus::InvalidArgument);
                }

                let data = api::HsmPotaEndorsementData::new(signature, public_key);
                Ok(api::HsmPotaEndorsement::new(source, Some(data)))
            }
            api::HsmPotaEndorsementSource::Tpm | api::HsmPotaEndorsementSource::Random => {
                // Endorsement data must be null for TPM and Random sources
                if !config.endorsement.is_null() {
                    return Err(AzihsmStatus::InvalidArgument);
                }
                Ok(api::HsmPotaEndorsement::new(source, None))
            }
            _ => Err(AzihsmStatus::InvalidArgument),
        }
    }
}

/// Get the list of HSM partitions
///
/// @param[out] handle Handle to the HSM partition list
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences a raw pointer.
/// The caller must ensure that the pointer is valid and points to a valid `AzihsmHandle`.
///
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_get_list(handle: *mut AzihsmHandle) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(handle)?;

        let part_list = Box::new(api::HsmPartitionManager::partition_info_list());

        // SAFETY: the function ensures that the pointer is valid
        unsafe { *handle = HANDLE_TABLE.alloc_handle(HandleType::PartitionList, part_list) }

        Ok(())
    })
}

/// Free the HSM partition list
///
/// @param[in] handle Handle to the HSM partition list
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is marked unsafe due to unsafe(no_mangle).
///
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub extern "C" fn azihsm_part_free_list(handle: AzihsmHandle) -> AzihsmStatus {
    abi_boundary(|| {
        let _: Box<Vec<api::HsmPartitionInfo>> =
            HANDLE_TABLE.free_handle(handle, HandleType::PartitionList)?;

        Ok(())
    })
}

/// Get partition count
///
/// @param[in] handle Handle to the HSM partition list
/// @param[out] count Number of partitions
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences a raw pointer.
/// The caller must ensure that handle is a valid `AzihsmHandle`.
/// The caller must also ensure that the pointer is valid and points to a valid `AzihsmU32`.
///
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_get_count(
    handle: AzihsmHandle,
    count: *mut u32,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(count)?;

        let part_list: &Vec<api::HsmPartitionInfo> =
            HANDLE_TABLE.as_ref(handle, HandleType::PartitionList)?;

        // SAFETY: the function ensures that the pointer is valid
        unsafe { *count = part_list.len() as u32 }

        Ok(())
    })
}

/// Get the partition path
/// @param[in] handle Handle to the HSM partition list
/// @param[in] index Index of the partition
/// @param[in/out] On input, the length of the buffer pointed to by `path` in bytes.
///                On output, the number of bytes written to the buffer.
/// @param[out] path Buffer to receive the null-terminated partition path in UTF-8 format on Linux and UTF-16 format on Windows.
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_get_path(
    handle: AzihsmHandle,
    index: u32,
    path: *mut AzihsmStr,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(path)?;

        // SAFETY: the function ensures that the pointers are valid
        let path = unsafe { &mut *path };
        if path.len != 0 && path.str.is_null() {
            Err(AzihsmStatus::InvalidArgument)?
        }

        let part_list: &Vec<api::HsmPartitionInfo> =
            HANDLE_TABLE.as_ref(handle, HandleType::PartitionList)?;

        // Get the path for the partition at the given index
        let part = match part_list.get(index as usize) {
            Some(part) => part,
            None => Err(AzihsmStatus::IndexOutOfRange)?,
        };

        let path_str = AzihsmStr::from_string(&part.path);

        if path.len < path_str.len {
            // If the provided buffer is too small, return the required size
            path.len = path_str.len;
            Err(AzihsmStatus::BufferTooSmall)?
        }

        // SAFETY: the function ensures that the pointer is valid
        unsafe {
            std::ptr::copy_nonoverlapping(path_str.str, path.str, path_str.len as usize);
        }

        path.len = path_str.len;

        Ok(())
    })
}

/// Open an HSM partition
///
/// @param[in] path Pointer to the partition path (null-terminated UTF-8 string on Linux and UTF-16 string on Windows)
/// @param[out] handle Handle to the opened HSM partition
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
/// The caller must ensure that the `path` pointer is valid and points to a valid `c_void`
/// that can be interpreted as a null-terminated UTF-8 string on Linux and UTF-16 string on Windows.
/// The caller must also ensure that the `handle` argument is a valid  `AzihsmHandle` pointer.
///
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_open(
    path: *const AzihsmStr,
    handle: *mut AzihsmHandle,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(handle)?;
        validate_ptr(path)?;

        // SAFETY: the function ensures that the pointer is valid
        let path = unsafe { &*path };
        if path.is_null() || path.len == 0 {
            Err(AzihsmStatus::InvalidArgument)?
        }

        // Convert the AzihsmStr to a Rust String
        let path_str = AzihsmStr::to_string(path);

        let partition = Box::new(api::HsmPartitionManager::open_partition(&path_str)?);

        // SAFETY: the function ensures that the pointer is valid
        unsafe { *handle = HANDLE_TABLE.alloc_handle(HandleType::Partition, partition) }

        Ok(())
    })
}

/// Initialize an HSM partition
///
/// @param[in] part_handle Handle to the HSM partition
/// @param[in] creds Pointer to application credentials (ID and PIN)
/// @param[in] bmk Optional backup masking key buffer (can be null)
/// @param[in] muk Optional masked unwrapping key buffer (can be null)
/// @param[in] backup_key_config Configuration for owner backup key
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_init(
    part_handle: AzihsmHandle,
    creds: *const AzihsmCredentials,
    bmk: *const AzihsmBuffer,
    muk: *const AzihsmBuffer,
    backup_key_config: *const AzihsmOwnerBackupKeyConfig,
    pota_endorsement: *const AzihsmPotaEndorsement,
) -> AzihsmStatus {
    abi_boundary(|| {
        let creds = deref_ptr(creds)?;
        let obk_config = deref_ptr(backup_key_config)?;
        let pota_endorsement = deref_ptr(pota_endorsement)?;

        // Get the partition from the handle
        let partition = &HsmPartition::try_from(part_handle)?;

        // Convert optional buffers to Option<&[u8]>
        let bmk_slice = buffer_to_optional_slice(bmk)?;
        let muk_slice = buffer_to_optional_slice(muk)?;

        // Convert config to HsmOwnerBackupKeyConfig
        let obk_info = api::HsmOwnerBackupKeyConfig::try_from(obk_config)?;

        // Convert to HsmPotaEndorsement
        let pota_endorsement = api::HsmPotaEndorsement::try_from(pota_endorsement)?;

        partition.init(
            creds.into(),
            bmk_slice,
            muk_slice,
            obk_info,
            pota_endorsement,
        )?;

        Ok(())
    })
}

/// Close an HSM partition
///
/// @param[in] handle Handle to the HSM partition
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences a raw pointer.
/// This function is marked unsafe due to unsafe(no_mangle).
///
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_close(handle: AzihsmHandle) -> AzihsmStatus {
    abi_boundary(|| {
        let _: Box<HsmPartition> = HANDLE_TABLE.free_handle(handle, HandleType::Partition)?;
        Ok(())
    })
}

/// Reset the HSM partition state
///
/// including established credentials and active sessions. This is useful for
/// test cleanup and recovery scenarios.
///
/// @param[in] part_handle Handle to the HSM partition
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences a raw pointer.
/// This function is marked unsafe due to unsafe(no_mangle).
///
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_reset(part_handle: AzihsmHandle) -> AzihsmStatus {
    abi_boundary(|| {
        // Get the partition from the handle
        let partition = &HsmPartition::try_from(part_handle)?;

        partition.reset()?;

        Ok(())
    })
}
