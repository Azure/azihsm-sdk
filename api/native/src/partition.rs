// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM partition operations for the native C API.
//!
//! This module provides the FFI (Foreign Function Interface) bindings for
//! HSM partition management operations, exposing them to C callers through
//! the ABI-compatible interface.

use azihsm_api::HsmPartition;

use super::*;

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
/// This function is makred unsafe due to unsafe(no_mangle).
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
/// @param[in] mobk Optional masked owner backup key buffer (can be null)
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
    mobk: *const AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let creds = deref_ptr(creds)?;

        // Get the partition from the handle
        let partition = &HsmPartition::try_from(part_handle)?;

        // Convert optional buffers to Option<&[u8]>
        let bmk_slice = buffer_to_optional_slice(bmk)?;
        let muk_slice = buffer_to_optional_slice(muk)?;
        let mobk_slice = buffer_to_optional_slice(mobk)?;

        partition.init(creds.into(), bmk_slice, muk_slice, mobk_slice)?;

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
