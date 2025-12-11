// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(unsafe_code)]

use crate::bindings::ffi_types::AzihsmKeyProp;
use crate::bindings::HANDLE_TABLE;
use crate::crypto::aes::AesCbcKey;
use crate::crypto::aes::AesXtsKey;
use crate::crypto::ec::EcdsaKeyPair;
use crate::crypto::rsa::RsaPkcsKeyPair;
use crate::types::key_props::KeyPropValue;
use crate::*;

/// Get a property of a key
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] key Handle to the key
/// @param[in/out] key_prop Pointer to key property structure. On input, specifies which property to get. On output, contains the property value.
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_get_prop(
    sess_handle: AzihsmHandle,
    key_handle: AzihsmHandle,
    key_prop: *mut AzihsmKeyProp,
) -> AzihsmError {
    abi_boundary(|| {
        // Validate pointers
        validate_pointers!(key_prop);

        // Extract session and key handle type
        let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;
        let key_handle_type = HANDLE_TABLE.get_handle_type(key_handle)?;

        let prop_ref = deref_mut_ptr!(key_prop);

        // Property ID is already AzihsmKeyPropId, no conversion needed
        let prop_id = prop_ref.id;

        // Get property value - handle type determines which key (public/private)
        let value = match key_handle_type {
            HandleType::RsaPublicKey => {
                let rsa_key_pair: &RsaPkcsKeyPair =
                    HANDLE_TABLE.as_ref(key_handle, key_handle_type)?;
                session.get_pub_property(rsa_key_pair, prop_id)?
            }
            HandleType::RsaPrivateKey => {
                let rsa_key_pair: &RsaPkcsKeyPair =
                    HANDLE_TABLE.as_ref(key_handle, key_handle_type)?;
                session.get_priv_property(rsa_key_pair, prop_id)?
            }
            HandleType::EcdsaPublicKey => {
                let ec_key_pair: &EcdsaKeyPair =
                    HANDLE_TABLE.as_ref(key_handle, key_handle_type)?;
                session.get_pub_property(ec_key_pair, prop_id)?
            }
            HandleType::EcdsaPrivateKey => {
                let ec_key_pair: &EcdsaKeyPair =
                    HANDLE_TABLE.as_ref(key_handle, key_handle_type)?;
                session.get_priv_property(ec_key_pair, prop_id)?
            }
            HandleType::AesCbcKey => {
                let aes_cbc_key: &AesCbcKey = HANDLE_TABLE.as_ref(key_handle, key_handle_type)?;
                session.get_property(aes_cbc_key, prop_id)?
            }
            HandleType::AesXtsKey => {
                let aes_xts_key: &AesXtsKey = HANDLE_TABLE.as_ref(key_handle, key_handle_type)?;
                session.get_property(aes_xts_key, prop_id)?
            }
            _ => Err(AZIHSM_OPERATION_NOT_SUPPORTED)?,
        };

        // Write property value to C buffer using helper method
        let buffer = prop_ref.as_mut_slice()?;
        let bytes_written = value.to_bytes(buffer)?;
        // Overflow condition should never occur as we check buffer size when we push data
        prop_ref.len = bytes_written.try_into().map_err(|_| AZIHSM_ERROR_PANIC)?;

        Ok(())
    })
}

/// Set a property of a key
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] key Handle to the key
/// @param[in] key_prop Pointer to key property structure containing the property to set
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_set_prop(
    sess_handle: AzihsmHandle,
    key_handle: AzihsmHandle,
    key_prop: *const AzihsmKeyProp,
) -> AzihsmError {
    abi_boundary(|| {
        // Validate pointers
        validate_pointers!(key_prop);

        // Extract session and key handle type
        let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;
        let key_handle_type = HANDLE_TABLE.get_handle_type(key_handle)?;

        let prop_ref = deref_const_ptr!(key_prop);

        // Property ID is already AzihsmKeyPropId, no conversion needed
        let prop_id = prop_ref.id;

        // Read property value from C buffer using helper method
        let buffer = prop_ref.as_slice()?;
        let value = KeyPropValue::from_bytes(prop_id, buffer)?;

        // Set property value - handle type determines which key (public/private)
        match key_handle_type {
            HandleType::RsaPublicKey => {
                let rsa_key_pair =
                    HANDLE_TABLE.as_mut::<RsaPkcsKeyPair>(key_handle, key_handle_type)?;
                session.set_pub_property(rsa_key_pair, prop_id, value)?;
            }
            HandleType::RsaPrivateKey => {
                let rsa_key_pair =
                    HANDLE_TABLE.as_mut::<RsaPkcsKeyPair>(key_handle, key_handle_type)?;
                session.set_priv_property(rsa_key_pair, prop_id, value)?;
            }
            HandleType::EcdsaPublicKey => {
                let ec_key_pair =
                    HANDLE_TABLE.as_mut::<EcdsaKeyPair>(key_handle, key_handle_type)?;
                session.set_pub_property(ec_key_pair, prop_id, value)?;
            }
            HandleType::EcdsaPrivateKey => {
                let ec_key_pair =
                    HANDLE_TABLE.as_mut::<EcdsaKeyPair>(key_handle, key_handle_type)?;
                session.set_priv_property(ec_key_pair, prop_id, value)?;
            }
            HandleType::AesCbcKey => {
                let aes_cbc_key: &mut AesCbcKey =
                    HANDLE_TABLE.as_mut::<AesCbcKey>(key_handle, key_handle_type)?;
                session.set_property(aes_cbc_key, prop_id, value)?;
            }
            HandleType::AesXtsKey => {
                let aes_xts_key: &mut AesXtsKey =
                    HANDLE_TABLE.as_mut::<AesXtsKey>(key_handle, key_handle_type)?;
                session.set_property(aes_xts_key, prop_id, value)?;
            }
            _ => Err(AZIHSM_OPERATION_NOT_SUPPORTED)?,
        }

        Ok(())
    })
}
