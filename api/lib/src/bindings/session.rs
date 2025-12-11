// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
use crate::*;

/// @brief Open an HSM partition
///
/// @param[in] dev_handle Handle to the HSM partition
/// @param[in] kind Type of session to open
/// @param[in] api_rev Pointer to the API revision structure
/// @param[in] creds Pointer to the application credentials
/// @param[out] sess_handle Pointer to the session handle to be allocated
///
/// @return `AzihsmError` indicating the result of the operation
///
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sess_open(
    dev_handle: AzihsmHandle,
    kind: SessionType,
    api_rev: *const ApiRev,
    creds: *const AppCreds,
    sess_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        if api_rev.is_null() || creds.is_null() || sess_handle.is_null() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?
        }

        // Get the partition from the handle
        let partition: &Partition = HANDLE_TABLE.as_ref(dev_handle, HandleType::Partition)?;

        // Safety: `api_rev` is not null
        let api_rev = unsafe { *api_rev };

        // Safety: `creds` is not null
        let credentials = unsafe { *creds };

        let session = Box::new(partition.open_session(kind, api_rev, credentials)?);

        // SAFETY: the function ensures that the pointer is valid
        unsafe { *sess_handle = HANDLE_TABLE.alloc_handle(HandleType::Session, session) }

        Ok(())
    })
}

#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_sess_close(handle: AzihsmHandle) -> AzihsmError {
    abi_boundary(|| {
        let mut session: Box<Session> = HANDLE_TABLE.free_handle(handle, HandleType::Session)?;

        if !session.is_closed() {
            session.close()?;
        }
        Ok(())
    })
}
