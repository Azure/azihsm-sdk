// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
use crate::*;

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
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_get_list(handle: *mut AzihsmHandle) -> AzihsmError {
    abi_boundary(|| {
        if handle.is_null() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?
        }

        let part_list = Box::new(partition_info_list());

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
/// This function is makred unsafe due to no_mangle.
///
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn azihsm_part_free_list(handle: AzihsmHandle) -> AzihsmError {
    abi_boundary(|| {
        // SAFETY: the function ensures that the pointer is valid
        let _: Box<Vec<PartitionInfo>> =
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
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_get_count(
    handle: AzihsmHandle,
    count: *mut u32,
) -> AzihsmError {
    abi_boundary(|| {
        if count.is_null() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?
        }

        let part_list: &Vec<PartitionInfo> =
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
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_get_path(
    handle: AzihsmHandle,
    index: u32,
    path: *mut AzihsmStr,
) -> AzihsmError {
    abi_boundary(|| {
        if path.is_null() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?
        }

        // SAFETY: the function ensures that the pointers are valid
        let path = unsafe { &mut *path };
        if path.len != 0 && path.str.is_null() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?
        }

        let part_list: &Vec<PartitionInfo> =
            HANDLE_TABLE.as_ref(handle, HandleType::PartitionList)?;

        // Get the path for the partition at the given index
        let part = match part_list.get(index as usize) {
            Some(part) => part,
            None => Err(AZIHSM_ERROR_INDEX_OUT_OF_RANGE)?,
        };

        let path_str = AzihsmStr::from_string(&part.path);

        if path.len < path_str.len {
            // If the provided buffer is too small, return the required size
            path.len = path_str.len;
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
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
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_open(
    path: *const AzihsmStr,
    handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        if handle.is_null() || path.is_null() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?
        }

        // SAFETY: the function ensures that the pointer is valid
        let path = unsafe { &*path };
        if path.is_null() || path.len == 0 {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?
        }

        // Convert the AzihsmStr to a Rust String
        let path_str = AzihsmStr::to_string(path);

        let partition =
            Box::new(partition_open(&path_str).map_err(|_| AZIHSM_ERROR_INVALID_ARGUMENT)?);

        // SAFETY: the function ensures that the pointer is valid
        unsafe { *handle = HANDLE_TABLE.alloc_handle(HandleType::Partition, partition) }

        Ok(())
    })
}

/// Temporary function to initialize the partition with BK3 and credentials
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_init(
    part_handle: AzihsmHandle,
    creds: *const AppCreds,
) -> AzihsmError {
    abi_boundary(|| {
        if creds.is_null() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?
        }

        // Safety: `creds` is not null
        let credentials = unsafe { *creds };

        // Get the partition from the handle
        let partition: &Partition = HANDLE_TABLE.as_ref(part_handle, HandleType::Partition)?;

        partition
            .init(credentials)
            .map_err(|_| AZIHSM_ERROR_INVALID_ARGUMENT)?;

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
/// This function is marked unsafe due to no_mangle.
///
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_part_close(handle: AzihsmHandle) -> AzihsmError {
    abi_boundary(|| {
        // SAFETY: the function ensures that the handle is valid
        let _: Box<Partition> = HANDLE_TABLE.free_handle(handle, HandleType::Partition)?;

        Ok(())
    })
}
