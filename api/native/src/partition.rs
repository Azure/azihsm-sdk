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

    /// Pointer to the plaintext owner backup key buffer (OBK).
    /// Required when `source` is `Caller` and `masked_owner_backup_key`
    /// is NULL. The device's `init_bk3` operation is one-shot per
    /// power cycle, so callers should provide OBK only on the first
    /// init and cache the resulting MOBK (read via the
    /// `MaskedOwnerBackupKey` property) for subsequent inits.
    pub owner_backup_key: *const AzihsmBuffer,

    /// Pointer to the masked owner backup key buffer (MOBK).
    /// When non-NULL on a `Caller` source, the SDK skips the OBK→MOBK
    /// derivation and uses this MOBK directly. Exactly one of
    /// `owner_backup_key` or `masked_owner_backup_key` must be non-NULL
    /// for the `Caller` source.
    pub masked_owner_backup_key: *const AzihsmBuffer,
}

/// Convert AzihsmOwnerBackupKeyConfig to HsmOwnerBackupKeyConfig
impl<'a> TryFrom<&'a AzihsmOwnerBackupKeyConfig> for api::HsmOwnerBackupKeyConfig {
    type Error = AzihsmStatus;

    fn try_from(config: &'a AzihsmOwnerBackupKeyConfig) -> Result<Self, Self::Error> {
        let source: api::HsmOwnerBackupKeySource = config.source.into();

        match source {
            api::HsmOwnerBackupKeySource::Caller => {
                let obk = buffer_to_optional_slice(config.owner_backup_key)?;
                let mobk = buffer_to_optional_slice(config.masked_owner_backup_key)?;
                let key = match (obk, mobk) {
                    (Some(obk), None) if !obk.is_empty() => api::HsmOwnerBackupKey::from_obk(obk),
                    (None, Some(mobk)) if !mobk.is_empty() => {
                        api::HsmOwnerBackupKey::from_masked_key(mobk)
                    }
                    _ => return Err(AzihsmStatus::InvalidArgument),
                };
                Ok(api::HsmOwnerBackupKeyConfig::new(source, key))
            }
            api::HsmOwnerBackupKeySource::Tpm => {
                if !config.owner_backup_key.is_null() || !config.masked_owner_backup_key.is_null() {
                    Err(AzihsmStatus::InvalidArgument)?;
                }
                Ok(api::HsmOwnerBackupKeyConfig::new(
                    source,
                    api::HsmOwnerBackupKey::default(),
                ))
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
/// The conversion copies data from the C buffers into the returned
/// owned `HsmPotaEndorsement`. The C buffers only need to remain
/// valid for the duration of the `azihsm_part_init` call.
impl<'a> TryFrom<&'a AzihsmPotaEndorsement> for api::HsmPotaEndorsement {
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
            api::HsmPotaEndorsementSource::Tpm => {
                // Endorsement data must be null for TPM source
                if !config.endorsement.is_null() {
                    return Err(AzihsmStatus::InvalidArgument);
                }
                Ok(api::HsmPotaEndorsement::new(source, None))
            }
            _ => Err(AzihsmStatus::InvalidArgument),
        }
    }
}

/// FFI-safe partition info structure.
///
/// C-compatible representation of `HsmPartitionInfo` with the path
/// expressed as an `AzihsmStr` (pointer + length) instead of a Rust `String`,
/// and the supported API revision range as min/max fields.
#[repr(C)]
pub struct AzihsmPartInfo {
    /// Device path (caller-owned buffer, filled by the API)
    pub path: AzihsmStr,

    /// Minimum supported API revision
    pub api_rev_min: AzihsmApiRev,

    /// Maximum supported API revision
    pub api_rev_max: AzihsmApiRev,
}

impl AzihsmPartInfo {
    /// Copies data from `HsmPartitionInfo` into this caller-owned struct.
    ///
    /// The caller must pre-allocate `self.path.str` with at least enough
    /// space. On entry, `self.path.len` is the buffer capacity in
    /// `azihsm_char` elements (including the null terminator).
    /// On return, `self.path.len` is set to the required/written count
    /// of `azihsm_char` elements.
    ///
    /// Returns `BufferTooSmall` if the path buffer is too small
    /// (with `self.path.len` updated to the required size in elements).
    #[allow(unsafe_code)]
    fn copy_from(&mut self, src: &api::HsmPartitionInfo) -> Result<(), AzihsmStatus> {
        let path_str = AzihsmStr::from_string(&src.path);

        //return error if the provided buffer is too small, with required size in path.len
        if self.path.len < path_str.len {
            self.path.len = path_str.len;
            return Err(AzihsmStatus::BufferTooSmall);
        }

        // SAFETY: caller guarantees self.path.str points to a buffer
        // of at least self.path.len azihsm_char elements, and we checked it is large enough.
        unsafe {
            std::ptr::copy_nonoverlapping(path_str.str, self.path.str, path_str.len as usize);
        }
        self.path.len = path_str.len;

        let range = src.api_rev_range.ok_or(AzihsmStatus::DeviceNotAccessible)?;
        self.api_rev_min = AzihsmApiRev::from(range.min());
        self.api_rev_max = AzihsmApiRev::from(range.max());

        Ok(())
    }
}
/// Convert a nullable C resiliency config pointer to an optional Rust config.
///
/// Returns `Ok(None)` when `ptr` is null, `Ok(Some(...))` when valid,
/// or `Err(...)` if the config is malformed.
#[allow(unsafe_code)]
pub(crate) fn resiliency_config_from_ptr(
    ptr: *const AzihsmResiliencyConfig,
) -> Result<Option<api::HsmResiliencyConfig>, AzihsmStatus> {
    if ptr.is_null() {
        return Ok(None);
    }

    let config = deref_ptr(ptr)?;

    Ok(Some(api::HsmResiliencyConfig::try_from(config)?))
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

/// Get partition info at the given index
///
/// @param[in] handle Handle to the HSM partition list
/// @param[in] index Index of the partition
/// @param[in/out] part_info Pointer to an `AzihsmPartInfo` structure.
///                On input, `part_info.path.len` is the size of the buffer pointed to by `part_info.path.str`.
///                On output, `part_info.path.len` is set to the required/written size.
///                `part_info.api_rev_min` / `part_info.api_rev_max` are only valid on
///                `AZIHSM_STATUS_SUCCESS`.
///
/// @return 0 on success, AZIHSM_STATUS_BUFFER_TOO_SMALL if the path buffer is too small
///         (part_info.path.len is updated to the required size), or a negative error code on failure.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_get_info(
    handle: AzihsmHandle,
    index: u32,
    part_info: *mut AzihsmPartInfo,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(part_info)?;

        // SAFETY: the function ensures that the pointer is valid
        let part_info = unsafe { &mut *part_info };
        if part_info.path.len != 0 && part_info.path.str.is_null() {
            Err(AzihsmStatus::InvalidArgument)?
        }

        let part_list: &Vec<api::HsmPartitionInfo> =
            HANDLE_TABLE.as_ref(handle, HandleType::PartitionList)?;

        let part = match part_list.get(index as usize) {
            Some(part) => part,
            None => Err(AzihsmStatus::IndexOutOfRange)?,
        };

        part_info.copy_from(part)?;

        Ok(())
    })
}

/// Open an HSM partition with a specified API revision
///
/// The caller selects an API revision within the range reported by
/// `azihsm_part_get_info`. All subsequent operations on this handle
/// (including sessions opened from it) will use the selected revision.
///
/// @param[in] path Pointer to an `azihsm_str` containing the partition
///            device path. The `str` field must point to a valid
///            null-terminated buffer and `len` must include the null
///            terminator (i.e. `str[len-1] == 0`).
/// @param[out] handle Handle to the opened HSM partition
/// @param[in] api_rev API revision to use for this partition handle
/// @return 0 on success, AZIHSM_STATUS_UNSUPPORTED_API_REVISION if api_rev is
///         outside the partition's supported range, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
/// The caller must ensure that `path` is a valid pointer to an `AzihsmStr`
/// whose `str` field points to a null-terminated buffer of `len`
/// `azihsm_char` elements (including the terminator).
/// The caller must also ensure that the `handle` argument is a valid `AzihsmHandle` pointer.
///
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_open(
    path: *const AzihsmStr,
    handle: *mut AzihsmHandle,
    api_rev: AzihsmApiRev,
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

        let partition = Box::new(api::HsmPartitionManager::open_partition(
            &path_str,
            api_rev.into(),
        )?);

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
/// @param[in] pota_endorsement POTA endorsement configuration
/// @param[in] resiliency_config Optional resiliency configuration (can be null).
///            When non-null, enables automatic retry/recovery for transient
///            hardware resets. If POTA source is Caller, `pota_callback_ops`
///            must be non-null. If POTA source is TPM, `pota_callback_ops`
///            must be null.
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
    resiliency_config: *const AzihsmResiliencyConfig,
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

        // Convert resiliency config
        let resiliency_config = resiliency_config_from_ptr(resiliency_config)?;

        partition.init(
            creds.into(),
            bmk_slice,
            muk_slice,
            obk_info,
            pota_endorsement,
            resiliency_config,
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
