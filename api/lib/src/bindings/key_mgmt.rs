// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(unsafe_code)]

use crate::bindings::ffi_types::AzihsmAlgo;
use crate::bindings::ffi_types::AzihsmBuffer;
use crate::bindings::ffi_types::AzihsmKeyPropList;
use crate::bindings::utils::prepare_output_buffer;
use crate::bindings::HANDLE_TABLE;
use crate::crypto::aes::AesCbcKey;
use crate::crypto::aes::AesXtsKey;
use crate::crypto::ec::EcdsaKeyPair;
use crate::crypto::ecdh::EcdhAlgo;
use crate::crypto::ecdh::SecretKey;
use crate::crypto::hkdf::HkdfAlgo;
use crate::crypto::hmac::HmacKey;
use crate::crypto::rsa::AlgoRsaAesKeyWrap;
use crate::crypto::rsa::RsaPkcsKeyPair;
use crate::crypto::Key;
use crate::crypto::KeyGenOp;
use crate::types::key_props::*;
use crate::types::AlgoId;
use crate::*;

/// Generic helper to generate a key and allocate its handle
fn generate_key_with_method<K, F>(
    session: &Session,
    key_props: KeyProps,
    handle_type: HandleType,
    key_handle: *mut AzihsmHandle,
    new_fn: F,
) -> Result<(), AzihsmError>
where
    K: Key + KeyGenOp + 'static,
    F: FnOnce(KeyProps) -> K,
{
    let mut key = new_fn(key_props);

    session.generate_key(&mut key)?;

    let key_box = Box::new(key);

    // SAFETY: key_handle pointer is validated by caller
    unsafe {
        *key_handle = HANDLE_TABLE.alloc_handle(handle_type, key_box);
    }

    Ok(())
}

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
                generate_key_with_method(
                    session,
                    key_props,
                    HandleType::AesCbcKey,
                    key_handle,
                    AesCbcKey::new,
                )?;
            }

            // AES XTS Key Generation
            AlgoId::AesXtsKeyGen => {
                generate_key_with_method(
                    session,
                    key_props,
                    HandleType::AesXtsKey,
                    key_handle,
                    AesXtsKey::new,
                )?;
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
                // Validate properties before creating key pair
                let mut validated_pub_props = KeyProps::new();
                let mut validated_priv_props = KeyProps::new();

                validated_pub_props.apply_user_properties(&pub_key_props)?;
                validated_priv_props.apply_user_properties(&priv_key_props)?;

                // Synchronize bit_len between public and private keys
                // Spec requires BIT_LEN for public key, but we accept it on either side for compatibility
                // Both keys in a pair must have the same bit length
                match (
                    validated_pub_props.bit_len(),
                    validated_priv_props.bit_len(),
                ) {
                    (Some(pub_len), Some(priv_len)) if pub_len != priv_len => {
                        // Error: mismatched bit lengths
                        Err(AZIHSM_ERROR_INVALID_ARGUMENT)?
                    }
                    (None, Some(priv_len)) => {
                        // Accept bit_len from private key for compatibility, copy to public
                        validated_pub_props.set_bit_len(priv_len);
                    }
                    (Some(pub_len), None) => {
                        // Spec-compliant: bit_len provided on public key, copy to private
                        validated_priv_props.set_bit_len(pub_len);
                    }
                    (None, None) => {
                        // Error: bit_len is required (spec says on public key)
                        Err(AZIHSM_KEY_PROPERTY_NOT_PRESENT)?
                    }
                    _ => {
                        // Both set and equal - OK
                    }
                }

                // Create RSA key pair with validated properties
                let mut rsa_key_pair =
                    RsaPkcsKeyPair::new(validated_pub_props, validated_priv_props)?;
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

            HandleType::AesXtsKey => {
                delete_key_with_method::<AesXtsKey, _>(
                    session,
                    key_handle,
                    HandleType::AesXtsKey,
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

#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_unwrap(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    unwrapping_key: AzihsmHandle,
    wrapped_key: *mut AzihsmBuffer,
    key_props: *const AzihsmKeyPropList,
    key_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(algo, wrapped_key, key_handle);

        let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;

        let algo = deref_mut_ptr!(algo);

        // Convert C key properties to Rust KeyProps if provided
        let unwrapped_key_props = convert_key_props!(key_props);

        let wrapped_key = deref_mut_ptr!(wrapped_key);
        validate_buffer!(wrapped_key);
        let wrapped_data = wrapped_key.as_slice()?;
        // Get KeyHandle for unwrapped key
        let key_handle_type = HANDLE_TABLE.get_handle_type(unwrapping_key)?;
        match key_handle_type {
            HandleType::RsaPrivateKey => {
                // Generate key based on algorithm ID
                match algo.id {
                    AlgoId::RsaAesKeywrap => {
                        // SAFETY: algo pointer was validated above and from_algo safely deserializes the algorithm parameters
                        let rsa_wrap_algo = unsafe { algo.from_algo::<AlgoRsaAesKeyWrap>()? };
                        // check if hash algo is supported
                        let oaep_params = &rsa_wrap_algo.params.oaep_params;
                        // check if hash algo and mgf1 hash algo are the same
                        if oaep_params.hash_algo_id != oaep_params.mgf1_hash_algo_id.to_algo_id() {
                            Err(AZIHSM_RSA_INVALID_PADDING)?;
                        }
                        let rsa_unwrapping_key: &RsaPkcsKeyPair =
                            HANDLE_TABLE.as_ref(unwrapping_key, HandleType::RsaPrivateKey)?;

                        // call unwrap function
                        let new_key_id = session.unwrap(
                            rsa_unwrapping_key,
                            &rsa_wrap_algo,
                            wrapped_data,
                            &unwrapped_key_props,
                        )?;
                        if new_key_id.0 == 0 {
                            Err(AZIHSM_RSA_UNWRAP_INVALID_KEY_ID)?;
                        }
                        match rsa_wrap_algo.params.key_type {
                            KeyKind::Aes => {
                                // get aes key instance
                                let aes_key: AesCbcKey =
                                    AesCbcKey::new_with_id(unwrapped_key_props, new_key_id);

                                let key_box = Box::new(aes_key);

                                // SAFETY: key_handle pointer is validated above
                                unsafe {
                                    *key_handle =
                                        HANDLE_TABLE.alloc_handle(HandleType::AesCbcKey, key_box);
                                }
                            }
                            KeyKind::Rsa => {
                                // Create KeyProps for the unwrapped RSA key with appropriate properties

                                let rsa_pub_props = KeyProps::builder().build();
                                // get rsa key instance
                                let rsa_key: RsaPkcsKeyPair = RsaPkcsKeyPair::new_with_id(
                                    new_key_id,
                                    None,
                                    unwrapped_key_props,
                                    rsa_pub_props,
                                )?;

                                let key_box = Box::new(rsa_key);

                                // SAFETY: key_handle pointer is validated above
                                unsafe {
                                    *key_handle = HANDLE_TABLE
                                        .alloc_handle(HandleType::RsaPrivateKey, key_box);
                                }
                            }
                            KeyKind::Ec => {
                                // create empty pub key properties
                                let ec_pub_props = KeyProps::builder().build();
                                // get ec key instance
                                let ec_key: EcdsaKeyPair = EcdsaKeyPair::new_with_id(
                                    new_key_id,
                                    ec_pub_props,
                                    unwrapped_key_props,
                                );

                                let key_box = Box::new(ec_key);

                                // SAFETY: key_handle pointer is validated above
                                unsafe {
                                    *key_handle = HANDLE_TABLE
                                        .alloc_handle(HandleType::EcdsaPrivateKey, key_box);
                                }
                            }
                            _ => Err(AZIHSM_KEY_KIND_NOT_SUPPORTED)?,
                        }
                    }
                    // Unknown or unsupported algorithms
                    _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
                }
            }
            _ => Err(AZIHSM_ERROR_INVALID_HANDLE)?,
        }

        Ok(())
    })
}

#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_derive(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    base_key: AzihsmHandle,
    key_props: *const AzihsmKeyPropList,
    key_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(algo, key_handle);

        let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;

        let algo = deref_mut_ptr!(algo);

        // Convert C key properties to Rust KeyProps if provided
        let derived_key_props = convert_key_props!(key_props);
        // Get KeyHandle type for base key
        let key_handle_type = HANDLE_TABLE.get_handle_type(base_key)?;

        match key_handle_type {
            HandleType::EcdsaPrivateKey => {
                // Generate key based on algorithm ID
                match algo.id {
                    AlgoId::Ecdh => {
                        // SAFETY: algo pointer was validated above and from_algo safely deserializes the algorithm parameters
                        let ecdh_algo = unsafe { algo.from_algo::<EcdhAlgo>()? };

                        let ecdh_base_key: &EcdsaKeyPair =
                            HANDLE_TABLE.as_ref(base_key, HandleType::EcdsaPrivateKey)?;

                        // call derive function
                        let derived_key_id =
                            session.key_derive(&ecdh_algo, ecdh_base_key, &derived_key_props)?;

                        // create a secret key object with received id
                        let secret_key: SecretKey =
                            SecretKey::new_with_id(derived_key_props, derived_key_id);

                        let derived_key_box = Box::new(secret_key);

                        // SAFETY: key_handle pointer is validated above
                        unsafe {
                            *key_handle =
                                HANDLE_TABLE.alloc_handle(HandleType::SecretKey, derived_key_box);
                        }
                    }
                    // Unknown or unsupported algorithms
                    _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
                }
            }
            HandleType::SecretKey => {
                // Generate key based on algorithm ID
                match algo.id {
                    AlgoId::HkdfDerive => {
                        // SAFETY: algo pointer was validated above and from_algo safely deserializes the algorithm parameters
                        let hkdf_algo = unsafe { algo.from_algo::<HkdfAlgo>()? };

                        let hkdf_base_key: &SecretKey =
                            HANDLE_TABLE.as_ref(base_key, HandleType::SecretKey)?;

                        // call derive function
                        let derived_key_id =
                            session.key_derive(&hkdf_algo, hkdf_base_key, &derived_key_props)?;
                        // check if target key type to create correct key
                        match derived_key_props
                            .kind()
                            .ok_or(AZIHSM_KEY_PROPERTY_NOT_PRESENT)?
                        {
                            KeyKind::Aes => {
                                // Create a secret key object with received id
                                let aes_key: AesCbcKey =
                                    AesCbcKey::new_with_id(derived_key_props, derived_key_id);

                                let derived_key_box = Box::new(aes_key);

                                // SAFETY: key_handle pointer is validated above
                                unsafe {
                                    *key_handle = HANDLE_TABLE
                                        .alloc_handle(HandleType::AesCbcKey, derived_key_box);
                                }
                            }
                            KeyKind::HmacSha1
                            | KeyKind::HmacSha256
                            | KeyKind::HmacSha384
                            | KeyKind::HmacSha512 => {
                                // Create a HMAC key object with received id
                                let hmac_key: HmacKey =
                                    HmacKey::new_with_id(derived_key_props, derived_key_id);

                                let derived_key_box = Box::new(hmac_key);

                                // SAFETY: key_handle pointer is validated above
                                unsafe {
                                    *key_handle = HANDLE_TABLE
                                        .alloc_handle(HandleType::HmacKey, derived_key_box);
                                }
                            }
                            _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
                        }
                    }
                    // Unknown or unsupported algorithms
                    _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
                }
            }
            // Unknown or unsupported algorithms
            _ => Err(AZIHSM_ERROR_INVALID_HANDLE)?,
        }

        Ok(())
    })
}

/// Wrap user data using RSA key wrapping.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification (RSA AES KeyWrap)
/// @param[in] wrapping_key Handle to the RSA public key used for wrapping
/// @param[in] user_data Pointer to data buffer to be wrapped
/// @param[out] wrapped_data Pointer to wrapped data output buffer
///
/// @return 0 on success, or a negative error code on failure.
/// If output buffer is insufficient, required length is updated in the output buffer and
/// the function returns the AZIHSM_ERROR_INSUFFICIENT_BUFFER error.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_wrap(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    wrapping_key: AzihsmHandle,
    user_data: *const AzihsmBuffer,
    wrapped_data: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(algo, user_data, wrapped_data);

        let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;
        let algo_spec = deref_mut_ptr!(algo);
        let user_data_buf = deref_const_ptr!(user_data);
        let wrapped_buf = deref_mut_ptr!(wrapped_data);

        validate_buffer!(user_data_buf);
        let data_to_wrap = user_data_buf.as_slice()?;

        // Get the key handle type and perform operation based on key type and algorithm
        let key_handle_type = HANDLE_TABLE.get_handle_type(wrapping_key)?;

        match key_handle_type {
            HandleType::RsaPublicKey => {
                let key: &RsaPkcsKeyPair =
                    HANDLE_TABLE.as_ref(wrapping_key, HandleType::RsaPublicKey)?;

                match algo_spec.id {
                    AlgoId::RsaAesKeywrap => {
                        // SAFETY: algo_spec points to a valid AzihsmAlgo, checked by caller
                        let rsa_wrap_algo = unsafe { algo_spec.from_algo::<AlgoRsaAesKeyWrap>()? };

                        // Validate OAEP parameters
                        let oaep_params = &rsa_wrap_algo.params.oaep_params;
                        if oaep_params.hash_algo_id != oaep_params.mgf1_hash_algo_id.to_algo_id() {
                            Err(AZIHSM_RSA_INVALID_PADDING)?;
                        }

                        // Get the wrapped key length first
                        let wrapped_len =
                            session.wrap_len(key, &rsa_wrap_algo, data_to_wrap.len())?;

                        // Prepare output buffer using the common helper
                        let output_slice = prepare_output_buffer(wrapped_buf, wrapped_len as u32)?;

                        // Perform wrapping operation through session
                        let bytes_written =
                            session.wrap(key, &rsa_wrap_algo, data_to_wrap, output_slice)?;

                        // Update output buffer length to actual bytes written
                        wrapped_buf.len = bytes_written as u32;
                    }
                    _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
                }
            }
            _ => Err(AZIHSM_ERROR_INVALID_HANDLE)?,
        }

        Ok(())
    })
}
