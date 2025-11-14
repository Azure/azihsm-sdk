// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(unsafe_code)]

use crate::bindings::ffi_types::AzihsmAlgo;
use crate::bindings::ffi_types::AzihsmKeyProp;
use crate::bindings::ffi_types::AzihsmKeyPropList;
use crate::bindings::HANDLE_TABLE;
use crate::crypto::aes::AesCbcKey;
use crate::crypto::ec::EcdsaKeyPair;
use crate::crypto::rsa::RsaPkcsKeyPair;
use crate::types::key_props::*;
use crate::types::AlgoId;
use crate::*;

/// Generic helper to delete a key and free its handle
fn delete_key_with_method<K, F>(
    session: &Session,
    key_handle: AzihsmHandle,
    handle_type: HandleType,
    delete_fn: F,
) -> Result<(), AzihsmError>
where
    K: 'static,
    F: FnOnce(&Session, &mut K) -> Result<(), AzihsmError>,
{
    let key: &mut K = HANDLE_TABLE.as_mut(key_handle, handle_type)?;

    // Delete the key from the HSM
    delete_fn(session, key)?;

    // Free the key handle
    let _: Box<K> = HANDLE_TABLE.free_handle(key_handle, handle_type)?;

    Ok(())
}

/// Generate a symmetric key
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_props Pointer to key properties list (can be null)
/// @param[out] key_handle Pointer to store the generated key handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_gen(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    key_props: *const AzihsmKeyPropList,
    key_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(algo, key_handle);

        // Get the session from the handle (mutable reference needed)
        let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;

        let algo = deref_mut_ptr!(algo);

        // Convert C key properties to Rust KeyProps if provided
        let key_props = convert_key_props!(key_props);

        // Generate key based on algorithm ID
        match algo.id {
            // AES family algorithms
            AlgoId::AesKeyGen => {
                let mut aes_key = AesCbcKey::new(key_props);

                session.generate_key(&mut aes_key)?;

                let key_box = Box::new(aes_key);

                // SAFETY: key_handle pointer is validated above
                unsafe {
                    *key_handle = HANDLE_TABLE.alloc_handle(HandleType::AesCbcKey, key_box);
                }
            }

            // Unknown or unsupported algorithms
            _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
        }

        Ok(())
    })
}

/// Generate an asymmetric key pair
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] pub_key_props Pointer to public key properties list (can be null)
/// @param[in] priv_key_props Pointer to private key properties list (can be null)
/// @param[out] pub_key_handle Pointer to store the generated public key handle
/// @param[out] priv_key_handle Pointer to store the generated private key handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_gen_pair(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    pub_key_props: *const AzihsmKeyPropList,
    priv_key_props: *const AzihsmKeyPropList,
    pub_key_handle: *mut AzihsmHandle,
    priv_key_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(algo, pub_key_handle, priv_key_handle);

        let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;

        let algo = deref_mut_ptr!(algo);

        // Convert public key properties
        let pub_key_props = convert_key_props!(pub_key_props);

        // Convert private key properties
        let priv_key_props = convert_key_props!(priv_key_props);

        // Generate key pair based on algorithm ID
        match algo.id {
            // ECC Key Pair Generation
            AlgoId::EcKeyPairGen => {
                // Create EcdsaKeyPair object with separate properties for public and private keys
                let mut ec_key_pair = EcdsaKeyPair::new(pub_key_props, priv_key_props);

                session.generate_key_pair(&mut ec_key_pair)?;

                // Both handles point to the same key pair object
                // The caller is responsible for using them appropriately
                let pub_key_box = Box::new(ec_key_pair.clone());
                let priv_key_box = Box::new(ec_key_pair);

                // SAFETY: handle pointers are validated above
                unsafe {
                    *pub_key_handle =
                        HANDLE_TABLE.alloc_handle(HandleType::EcdsaPublicKey, pub_key_box);
                    *priv_key_handle =
                        HANDLE_TABLE.alloc_handle(HandleType::EcdsaPrivateKey, priv_key_box);
                }
            }
            // RSA Key Pair generation
            AlgoId::RsaPkcsKeyPairGen => {
                // create RSA key pair
                let mut rsa_key_pair = RsaPkcsKeyPair::new(pub_key_props, priv_key_props);
                session.generate_key_pair(&mut rsa_key_pair)?;

                // Both handles point to the same key pair object
                // The caller is responsible for using them appropriately
                let pub_key_box = Box::new(rsa_key_pair.clone());
                let priv_key_box = Box::new(rsa_key_pair);

                // SAFETY: handle pointers are validated above
                unsafe {
                    *pub_key_handle =
                        HANDLE_TABLE.alloc_handle(HandleType::RsaPublicKey, pub_key_box);
                    *priv_key_handle =
                        HANDLE_TABLE.alloc_handle(HandleType::RsaPrivateKey, priv_key_box);
                }
            }

            // Unknown or unsupported algorithms
            _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
        }

        Ok(())
    })
}

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
    _sess_handle: AzihsmHandle,
    _key: AzihsmHandle,
    _key_prop: *mut AzihsmKeyProp,
) -> AzihsmError {
    abi_boundary(|| Err(AZIHSM_OPERATION_NOT_SUPPORTED))
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
    _sess_handle: AzihsmHandle,
    _key: AzihsmHandle,
    _key_prop: *const AzihsmKeyProp,
) -> AzihsmError {
    abi_boundary(|| Err(AZIHSM_OPERATION_NOT_SUPPORTED))
}

/// Delete a key from the HSM
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] key_handle Handle to the key to delete
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is marked unsafe due to no_mangle.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_delete(
    sess_handle: AzihsmHandle,
    key_handle: AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;
        let handle_type = HANDLE_TABLE.get_handle_type(key_handle)?;

        match handle_type {
            HandleType::AesCbcKey => {
                delete_key_with_method::<AesCbcKey, _>(
                    session,
                    key_handle,
                    HandleType::AesCbcKey,
                    |sess, key| sess.delete_key(key),
                )?;
            }

            HandleType::EcdsaPublicKey => {
                delete_key_with_method::<EcdsaKeyPair, _>(
                    session,
                    key_handle,
                    HandleType::EcdsaPublicKey,
                    |sess, key| sess.delete_pub_key(key),
                )?;
            }

            HandleType::EcdsaPrivateKey => {
                delete_key_with_method::<EcdsaKeyPair, _>(
                    session,
                    key_handle,
                    HandleType::EcdsaPrivateKey,
                    |sess, key| sess.delete_priv_key(key),
                )?;
            }
            HandleType::RsaPublicKey => {
                delete_key_with_method::<RsaPkcsKeyPair, _>(
                    session,
                    key_handle,
                    HandleType::RsaPublicKey,
                    |sess, key| sess.delete_pub_key(key),
                )?;
            }
            HandleType::RsaPrivateKey => {
                delete_key_with_method::<RsaPkcsKeyPair, _>(
                    session,
                    key_handle,
                    HandleType::RsaPrivateKey,
                    |sess, key| sess.delete_priv_key(key),
                )?;
            }

            _ => Err(AZIHSM_ERROR_INVALID_HANDLE)?,
        }
        Ok(())
    })
}
