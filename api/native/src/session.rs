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
/// @param[in] seed Pointer to the optional seed buffer
/// @param[out] sess_handle Pointer to the session handle to be allocated
///
/// @return `AzihsmError` indicating the result of the operation
///
/// # Safety
///
/// - `dev_handle` must be a valid partition handle.
/// - `api_rev` must be a valid pointer to an `AzihsmApiRev` structure.
/// - `creds` must be a valid pointer to an `AzihsmCredentials` structure.
/// - `sess_handle` must be a valid pointer to memory where the session handle
///   will be written.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sess_open(
    dev_handle: AzihsmHandle,
    api_rev: *const AzihsmApiRev,
    creds: *const AzihsmCredentials,
    seed: *const AzihsmBuffer,
    sess_handle: *mut AzihsmHandle,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(sess_handle)?;

        let api_rev = deref_ptr(api_rev)?;
        let credentials = deref_ptr(creds)?;
        let seed_slice = buffer_to_optional_slice(seed)?;

        // Get the partition from the handle
        let partition = &api::HsmPartition::try_from(dev_handle)?;

        let session =
            Box::new(partition.open_session(api_rev.into(), &credentials.into(), seed_slice)?);

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
/// # Safety
///
/// - `handle` must be a valid session handle previously returned by
///   `azihsm_sess_open`.
/// - The handle must not have been previously closed.
/// - After this call, the handle becomes invalid and must not be used.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sess_close(handle: AzihsmHandle) -> AzihsmStatus {
    abi_boundary(|| {
        let _: Box<api::HsmSession> = HANDLE_TABLE.free_handle(handle, HandleType::Session)?;

        Ok(())
    })
}
