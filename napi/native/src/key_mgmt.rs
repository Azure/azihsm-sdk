// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;

use super::*;

/// Generate a symmetric key
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_props Pointer to key properties list
/// @param[out] key_handle Pointer to store the generated key handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_gen(
    sess_handle: AzihsmHandle,
    algo: *const AzihsmAlgo,
    key_props: *const AzihsmKeyPropList,
    key_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        validate_ptr(key_handle)?;

        let algo = deref_ptr(algo)?;
        let props = deref_ptr(key_props)?;
        let key_props = HsmKeyProps::try_from(props)?;
        let session: HsmSession = sess_handle.try_into()?;

        // Generate key based on algorithm ID
        let handle = match algo.id {
            // AES family algorithms
            AzihsmAlgoId::AesKeyGen => {
                let mut aes_algo = HsmAesKeyGenAlgo::try_from(algo)?;
                let key = HsmKeyManager::generate_key(&session, &mut aes_algo, key_props)?;
                HANDLE_TABLE.alloc_handle(HandleType::AesKey, Box::new(key))
            }

            // Unknown or unsupported algorithms
            _ => Err(AzihsmError::InvalidArgument)?,
        };

        // Return the generated key handle
        assign_ptr(key_handle, handle)?;

        Ok(())
    })
}

/// Delete a key from the HSM
///
/// @param[in] key_handle Handle to the key to delete
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is marked unsafe due to no_mangle.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_delete(key_handle: AzihsmHandle) -> AzihsmError {
    abi_boundary(|| {
        let key_type = HANDLE_TABLE.get_handle_type(key_handle)?;

        match key_type {
            HandleType::AesKey => {
                let _key: Box<HsmAesKey> = HANDLE_TABLE.free_handle(key_handle, key_type)?;
                // [TODO] Delete the key via HsmKeyManager when supported
            }
            _ => Err(AzihsmError::UnsupportedKeyKind)?,
        }

        Ok(())
    })
}
