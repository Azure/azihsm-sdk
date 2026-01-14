// Copyright (C) Microsoft Corporation. All rights reserved.

//! HSM session operations for the native C API.
//!
//! This module provides the FFI (Foreign Function Interface) bindings for
//! HSM session management operations, exposing them to C callers through
//! the ABI-compatible interface.

use super::*;

/// @brief Open an HSM partition
///
/// @param[in] dev_handle Handle to the HSM partition
/// @param[in] api_rev Pointer to the API revision structure
/// @param[in] creds Pointer to the application credentials
/// @param[out] sess_handle Pointer to the session handle to be allocated
///
/// @return `AzihsmError` indicating the result of the operation
///
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sess_open(
    dev_handle: AzihsmHandle,
    api_rev: *const AzihsmApiRev,
    creds: *const AzihsmCredentials,
    sess_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        if sess_handle.is_null() {
            Err(AzihsmError::InvalidArgument)?
        }

        let api_rev = deref_ptr(api_rev)?;
        let credentials = deref_ptr(creds)?;

        // Get the partition from the handle
        let partition: &api::HsmPartition =
            HANDLE_TABLE.as_ref(dev_handle, HandleType::Partition)?;

        let session =
            Box::new(partition.open_session(api_rev.into(), &credentials.into(), None)?);

        let handle = HANDLE_TABLE.alloc_handle(HandleType::Session, session);

        // Return the generated session handle
        assign_ptr(sess_handle, handle)?;

        Ok(())
    })
}

/// @brief Close an HSM session
///
/// @param[in] handle Handle to the HSM session
///
/// @return `AzihsmError` indicating the result of the operation
///
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sess_close(handle: AzihsmHandle) -> AzihsmError {
    abi_boundary(|| {
        let _: Box<api::HsmSession> = HANDLE_TABLE.free_handle(handle, HandleType::Session)?;

        Ok(())
    })
}
