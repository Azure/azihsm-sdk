// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(unsafe_code)]

use crate::bindings::ffi_types::AlgoConverter;
use crate::bindings::ffi_types::AzihsmAlgo;
use crate::bindings::ffi_types::AzihsmBuffer;
use crate::bindings::HANDLE_TABLE;
use crate::crypto::ec::EcdsaAlgo;
use crate::crypto::ec::EcdsaKeyPair;
use crate::crypto::ec::EcdsaSignStream;
use crate::crypto::ec::EcdsaVerifyStream;
use crate::crypto::hmac::HmacAlgo;
use crate::crypto::hmac::HmacKey;
use crate::crypto::hmac::HmacSignStream;
use crate::crypto::hmac::HmacVerifyStream;
use crate::crypto::rsa::RsaPkcs15Algo;
use crate::crypto::rsa::RsaPkcsKeyPair;
use crate::crypto::rsa::RsaPkcsPssAlgo;
use crate::crypto::Algo;
use crate::crypto::Key;
use crate::crypto::SignOp;
use crate::crypto::StreamingSignOp;
use crate::crypto::StreamingSignVerifyAlgo;
use crate::crypto::StreamingVerifyOp;
use crate::crypto::VerifyOp;
use crate::types::AlgoId;
use crate::*;

/// Generic helper function for signing operations.
fn perform_sign_operation<A, K>(
    session: &Session,
    algo_spec: &mut AzihsmAlgo,
    key: &K,
    input_data: &[u8],
    sig_buf: &mut AzihsmBuffer,
) -> Result<(), AzihsmError>
where
    A: Algo + SignOp<K> + AlgoConverter,
    K: Key,
{
    // Extract algorithm using the AlgoConverter trait
    // SAFETY: algo_spec points to a valid AzihsmAlgo, checked by caller
    let algo = unsafe { algo_spec.from_algo::<A>()? };

    // Get required signature length
    let required_len = algo.signature_len(key)?;
    let sig_data = prepare_output_buffer(sig_buf, required_len)?;

    // Perform signing operation
    session.sign(&algo, key, input_data, sig_data)?;

    // Update output buffer length to actual signature length
    sig_buf.len = required_len;

    Ok(())
}

/// Sign data using a cryptographic key and algorithm.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_handle Handle to the signing key
/// @param[in] data Pointer to data buffer to be signed
/// @param[out] sig Pointer to signature output buffer
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
pub unsafe extern "C" fn azihsm_crypt_sign(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    data: *const AzihsmBuffer,
    sig: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(algo, data, sig);

        let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;
        let algo_spec = deref_mut_ptr!(algo);
        let data_buf = deref_const_ptr!(data);
        let sig_buf = deref_mut_ptr!(sig);

        validate_buffer!(data_buf);
        let input_data = data_buf.as_slice()?;

        // Get the key handle type and perform operation based on key type and algorithm
        let key_handle_type = HANDLE_TABLE.get_handle_type(key_handle)?;

        match key_handle_type {
            HandleType::EcdsaPrivateKey => {
                let key: &EcdsaKeyPair =
                    HANDLE_TABLE.as_ref(key_handle, HandleType::EcdsaPrivateKey)?;
                perform_sign_operation::<EcdsaAlgo, EcdsaKeyPair>(
                    session, algo_spec, key, input_data, sig_buf,
                )?;
            }

            HandleType::RsaPrivateKey => {
                let key: &RsaPkcsKeyPair =
                    HANDLE_TABLE.as_ref(key_handle, HandleType::RsaPrivateKey)?;

                match algo_spec.id {
                    // PKCS#1 v1.5 algorithms
                    AlgoId::RsaPkcs
                    | AlgoId::RsaPkcsSha1
                    | AlgoId::RsaPkcsSha256
                    | AlgoId::RsaPkcsSha384
                    | AlgoId::RsaPkcsSha512 => {
                        perform_sign_operation::<RsaPkcs15Algo, RsaPkcsKeyPair>(
                            session, algo_spec, key, input_data, sig_buf,
                        )?;
                    }
                    // PSS algorithms
                    AlgoId::RsaPkcsPss
                    | AlgoId::RsaPkcsPssSha1
                    | AlgoId::RsaPkcsPssSha256
                    | AlgoId::RsaPkcsPssSha384
                    | AlgoId::RsaPkcsPssSha512 => {
                        perform_sign_operation::<RsaPkcsPssAlgo, RsaPkcsKeyPair>(
                            session, algo_spec, key, input_data, sig_buf,
                        )?;
                    }
                    _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
                }
            }
            HandleType::HmacKey => {
                let key: &HmacKey = HANDLE_TABLE.as_ref(key_handle, HandleType::HmacKey)?;

                perform_sign_operation::<HmacAlgo, HmacKey>(
                    session, algo_spec, key, input_data, sig_buf,
                )?;
            }
            // Add support for other key types here as needed (RSA, etc.)
            _ => {
                Err(AZIHSM_ERROR_INVALID_HANDLE)?;
            }
        }

        Ok(())
    })
}

/// Generic helper function for verification operations.
fn perform_verify_operation<A, K>(
    session: &Session,
    algo_spec: &mut AzihsmAlgo,
    key: &K,
    input_data: &[u8],
    signature_data: &[u8],
) -> Result<(), AzihsmError>
where
    A: Algo + VerifyOp<K> + AlgoConverter,
    K: Key,
{
    // Extract algorithm using the AlgoConverter trait
    // SAFETY: algo_spec points to a valid AzihsmAlgo, checked by caller
    let algo = unsafe { algo_spec.from_algo::<A>()? };

    // Perform verification operation
    session.verify(&algo, key, input_data, signature_data)?;

    Ok(())
}

/// Verify signature using a cryptographic key and algorithm.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_handle Handle to the verification key
/// @param[in] data Pointer to data buffer that was signed
/// @param[in] sig Pointer to signature buffer to verify
///
/// @return 0 on success, or a negative error code on failure.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_verify(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    data: *const AzihsmBuffer,
    sig: *const AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(algo, data, sig);

        let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;
        let algo_spec = deref_mut_ptr!(algo);
        let data_buf = deref_const_ptr!(data);
        let sig_buf = deref_const_ptr!(sig);

        validate_buffer!(data_buf);
        validate_buffer!(sig_buf);

        let input_data = data_buf.as_slice()?;
        let signature_data = sig_buf.as_slice()?;

        let key_handle_type = HANDLE_TABLE.get_handle_type(key_handle)?;

        match key_handle_type {
            HandleType::EcdsaPublicKey => {
                let key: &EcdsaKeyPair =
                    HANDLE_TABLE.as_ref(key_handle, HandleType::EcdsaPublicKey)?;
                perform_verify_operation::<EcdsaAlgo, EcdsaKeyPair>(
                    session,
                    algo_spec,
                    key,
                    input_data,
                    signature_data,
                )?;
            }

            HandleType::RsaPublicKey => {
                let key: &RsaPkcsKeyPair =
                    HANDLE_TABLE.as_ref(key_handle, HandleType::RsaPublicKey)?;

                match algo_spec.id {
                    // PKCS#1 v1.5 algorithms
                    AlgoId::RsaPkcs
                    | AlgoId::RsaPkcsSha1
                    | AlgoId::RsaPkcsSha256
                    | AlgoId::RsaPkcsSha384
                    | AlgoId::RsaPkcsSha512 => {
                        perform_verify_operation::<RsaPkcs15Algo, RsaPkcsKeyPair>(
                            session,
                            algo_spec,
                            key,
                            input_data,
                            signature_data,
                        )?;
                    }
                    // PSS algorithms
                    AlgoId::RsaPkcsPss
                    | AlgoId::RsaPkcsPssSha1
                    | AlgoId::RsaPkcsPssSha256
                    | AlgoId::RsaPkcsPssSha384
                    | AlgoId::RsaPkcsPssSha512 => {
                        perform_verify_operation::<RsaPkcsPssAlgo, RsaPkcsKeyPair>(
                            session,
                            algo_spec,
                            key,
                            input_data,
                            signature_data,
                        )?;
                    }
                    _ => {
                        Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?;
                    }
                }
            }
            HandleType::HmacKey => {
                let key: &HmacKey = HANDLE_TABLE.as_ref(key_handle, HandleType::HmacKey)?;

                perform_verify_operation::<HmacAlgo, HmacKey>(
                    session,
                    algo_spec,
                    key,
                    input_data,
                    signature_data,
                )?;
            }
            _ => {
                Err(AZIHSM_ERROR_INVALID_HANDLE)?;
            }
        }

        Ok(())
    })
}

/// Generic helper function for streaming sign initialization
unsafe fn perform_sign_init<'a, A, K>(
    session: &'a Session,
    algo: &A,
    key: &K,
    ctx_handle_type: HandleType,
    ctx_handle: *mut AzihsmHandle,
) -> Result<(), AzihsmError>
where
    A: Algo + StreamingSignVerifyAlgo<'a, K>,
    K: Key,
{
    let sign_stream = session.sign_init(algo, key)?;

    let ctx = HANDLE_TABLE.alloc_handle(ctx_handle_type, Box::new(sign_stream));

    // SAFETY: ctx_handle is validated by caller
    unsafe {
        *ctx_handle = ctx;
    }
    Ok(())
}

/// Initialize streaming sign operation.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_handle Handle to the signing key
/// @param[out] ctx_handle Pointer to receive the streaming context handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_sign_init(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    ctx_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(algo, ctx_handle);

        let algo_spec = deref_mut_ptr!(algo);
        let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;
        let key_handle_type = HANDLE_TABLE.get_handle_type(key_handle)?;

        match key_handle_type {
            HandleType::EcdsaPrivateKey => {
                // Validate algorithm
                match algo_spec.id {
                    AlgoId::Ecdsa
                    | AlgoId::EcdsaSha1
                    | AlgoId::EcdsaSha256
                    | AlgoId::EcdsaSha384
                    | AlgoId::EcdsaSha512 => {}
                    _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
                }

                let ecdsa_algo = EcdsaAlgo::new(algo_spec.id);
                let key: &EcdsaKeyPair =
                    HANDLE_TABLE.as_ref(key_handle, HandleType::EcdsaPrivateKey)?;

                // SAFETY: ctx_handle is validated by caller
                unsafe {
                    perform_sign_init::<EcdsaAlgo, EcdsaKeyPair>(
                        session,
                        &ecdsa_algo,
                        key,
                        HandleType::EcSignStreamingContext,
                        ctx_handle,
                    )?;
                }

                Ok(())
            }
            HandleType::HmacKey => {
                // Validate algorithm
                match algo_spec.id {
                    AlgoId::HmacSha1
                    | AlgoId::HmacSha256
                    | AlgoId::HmacSha384
                    | AlgoId::HmacSha512 => {}
                    _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
                }

                let hmac_algo = HmacAlgo { id: algo_spec.id };
                let key: &HmacKey = HANDLE_TABLE.as_ref(key_handle, HandleType::HmacKey)?;

                // SAFETY: ctx_handle is validated by caller
                unsafe {
                    perform_sign_init::<HmacAlgo, HmacKey>(
                        session,
                        &hmac_algo,
                        key,
                        HandleType::HmacSignStreamingContext,
                        ctx_handle,
                    )?;
                }
                Ok(())
            }
            // Future: Add RSA support
            _ => Err(AZIHSM_ERROR_INVALID_HANDLE),
        }
    })
}

/// Generic helper for streaming update operations
fn perform_streaming_update<S>(
    ctx_handle: AzihsmHandle,
    ctx_handle_type: HandleType,
    input_data: &[u8],
) -> Result<(), AzihsmError>
where
    S: StreamingSignOp,
{
    let stream: &mut S = HANDLE_TABLE.as_mut(ctx_handle, ctx_handle_type)?;
    stream.update(input_data)
}

/// Update streaming sign operation with additional data.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] ctx_handle Handle to the streaming sign context
/// @param[in] data Pointer to data buffer to be signed
///
/// @return 0 on success, or a negative error code on failure.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_sign_update(
    sess_handle: AzihsmHandle,
    ctx_handle: AzihsmHandle,
    data: *const AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(data);

        let _session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;
        let data_buf = deref_const_ptr!(data);
        validate_buffer!(data_buf);
        let input_data = data_buf.as_slice()?;

        let ctx_handle_type = HANDLE_TABLE.get_handle_type(ctx_handle)?;

        match ctx_handle_type {
            HandleType::EcSignStreamingContext => {
                perform_streaming_update::<EcdsaSignStream<'_>>(
                    ctx_handle,
                    ctx_handle_type,
                    input_data,
                )?;
            }
            HandleType::HmacSignStreamingContext => {
                perform_streaming_update::<HmacSignStream<'_>>(
                    ctx_handle,
                    ctx_handle_type,
                    input_data,
                )?;
            }
            _ => Err(AZIHSM_ERROR_INVALID_HANDLE)?,
        }

        Ok(())
    })
}

/// Generic helper for streaming sign finalization
fn perform_streaming_sign_final<S>(
    ctx_handle: AzihsmHandle,
    ctx_handle_type: HandleType,
    sig_buf: &mut AzihsmBuffer,
) -> Result<(), AzihsmError>
where
    S: StreamingSignOp,
{
    // Get signature length first
    let sign_stream_ref: &S = HANDLE_TABLE.as_ref(ctx_handle, ctx_handle_type)?;
    let required_len = sign_stream_ref.signature_len()?;

    let sig_data = prepare_output_buffer(sig_buf, required_len)?;

    // Take ownership and finalize
    let sign_stream: S = *HANDLE_TABLE.free_handle(ctx_handle, ctx_handle_type)?;

    let bytes_written = sign_stream.finalize(sig_data)?;
    sig_buf.len = bytes_written as u32;

    Ok(())
}

/// Finalize streaming sign operation and retrieve signature.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] ctx_handle Handle to the streaming sign context (consumed by this call)
/// @param[out] sig Pointer to signature output buffer
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
pub unsafe extern "C" fn azihsm_crypt_sign_final(
    sess_handle: AzihsmHandle,
    ctx_handle: AzihsmHandle,
    sig: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(sig);

        let _session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;
        let sig_buf = deref_mut_ptr!(sig);

        let ctx_handle_type = HANDLE_TABLE.get_handle_type(ctx_handle)?;

        match ctx_handle_type {
            HandleType::EcSignStreamingContext => {
                perform_streaming_sign_final::<EcdsaSignStream<'_>>(
                    ctx_handle,
                    ctx_handle_type,
                    sig_buf,
                )?;
            }
            HandleType::HmacSignStreamingContext => {
                perform_streaming_sign_final::<HmacSignStream<'_>>(
                    ctx_handle,
                    ctx_handle_type,
                    sig_buf,
                )?;
            }
            _ => Err(AZIHSM_ERROR_INVALID_HANDLE)?,
        }

        Ok(())
    })
}

/// Generic helper function for streaming verify initialization
unsafe fn perform_verify_init<'a, A, K>(
    session: &'a Session,
    algo: &A,
    key: &K,
    ctx_handle_type: HandleType,
    ctx_handle: *mut AzihsmHandle,
) -> Result<(), AzihsmError>
where
    A: crate::crypto::Algo + crate::crypto::StreamingSignVerifyAlgo<'a, K>,
    K: Key,
{
    let verify_stream = session.verify_init(algo, key)?;

    let ctx = HANDLE_TABLE.alloc_handle(ctx_handle_type, Box::new(verify_stream));

    // SAFETY: ctx_handle is validated by caller
    unsafe {
        *ctx_handle = ctx;
    }
    Ok(())
}

/// Initialize streaming verify operation.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_handle Handle to the verification key
/// @param[out] ctx_handle Pointer to receive the streaming context handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_verify_init(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    ctx_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(algo, ctx_handle);

        let algo_spec = deref_mut_ptr!(algo);
        let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;
        let key_handle_type = HANDLE_TABLE.get_handle_type(key_handle)?;

        match key_handle_type {
            HandleType::EcdsaPublicKey => {
                // Validate algorithm
                match algo_spec.id {
                    AlgoId::Ecdsa
                    | AlgoId::EcdsaSha1
                    | AlgoId::EcdsaSha256
                    | AlgoId::EcdsaSha384
                    | AlgoId::EcdsaSha512 => {}
                    _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
                }

                let ecdsa_algo = EcdsaAlgo::new(algo_spec.id);
                let key: &EcdsaKeyPair =
                    HANDLE_TABLE.as_ref(key_handle, HandleType::EcdsaPublicKey)?;

                // SAFETY: ctx_handle is validated by caller
                unsafe {
                    perform_verify_init::<EcdsaAlgo, EcdsaKeyPair>(
                        session,
                        &ecdsa_algo,
                        key,
                        HandleType::EcVerifyStreamingContext,
                        ctx_handle,
                    )?;
                }
                Ok(())
            }
            HandleType::HmacKey => {
                // Validate algorithm
                match algo_spec.id {
                    AlgoId::HmacSha1
                    | AlgoId::HmacSha256
                    | AlgoId::HmacSha384
                    | AlgoId::HmacSha512 => {}
                    _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
                }

                let hmac_algo = HmacAlgo { id: algo_spec.id };
                let key: &HmacKey = HANDLE_TABLE.as_ref(key_handle, HandleType::HmacKey)?;

                // SAFETY: ctx_handle is validated by caller
                unsafe {
                    perform_verify_init::<HmacAlgo, HmacKey>(
                        session,
                        &hmac_algo,
                        key,
                        HandleType::HmacVerifyStreamingContext,
                        ctx_handle,
                    )?;
                }
                Ok(())
            }
            // Future: Add RSA support
            _ => Err(AZIHSM_ERROR_INVALID_HANDLE),
        }
    })
}

/// Update streaming verify operation with additional data.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] ctx_handle Handle to the streaming verify context
/// @param[in] data Pointer to data buffer that was signed
///
/// @return 0 on success, or a negative error code on failure.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_verify_update(
    sess_handle: AzihsmHandle,
    ctx_handle: AzihsmHandle,
    data: *const AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(data);

        let _session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;
        let data_buf = deref_const_ptr!(data);
        validate_buffer!(data_buf);
        let input_data = data_buf.as_slice()?;

        let ctx_handle_type = HANDLE_TABLE.get_handle_type(ctx_handle)?;

        match ctx_handle_type {
            HandleType::EcVerifyStreamingContext => {
                let verify_stream: &mut EcdsaVerifyStream =
                    HANDLE_TABLE.as_mut(ctx_handle, HandleType::EcVerifyStreamingContext)?;
                verify_stream.update(input_data)?;
            }
            _ => Err(AZIHSM_ERROR_INVALID_HANDLE)?,
        }

        Ok(())
    })
}

/// Generic helper for streaming verify finalization
fn perform_streaming_verify_final<V>(
    ctx_handle: AzihsmHandle,
    ctx_handle_type: HandleType,
    signature_data: &[u8],
) -> Result<(), AzihsmError>
where
    V: StreamingVerifyOp,
{
    let verify_stream: V = *HANDLE_TABLE.free_handle(ctx_handle, ctx_handle_type)?;
    verify_stream.finalize(signature_data)
}

/// Finalize streaming verify operation and verify signature.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] ctx_handle Handle to the streaming verify context (consumed by this call)
/// @param[in] sig Pointer to signature buffer to verify
///
/// @return 0 on success, or a negative error code on failure.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_verify_final(
    sess_handle: AzihsmHandle,
    ctx_handle: AzihsmHandle,
    sig: *const AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(sig);

        let _session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;
        let sig_buf = deref_const_ptr!(sig);
        validate_buffer!(sig_buf);
        let signature_data = sig_buf.as_slice()?;

        let ctx_handle_type = HANDLE_TABLE.get_handle_type(ctx_handle)?;

        match ctx_handle_type {
            HandleType::EcVerifyStreamingContext => {
                perform_streaming_verify_final::<EcdsaVerifyStream>(
                    ctx_handle,
                    ctx_handle_type,
                    signature_data,
                )?;
            }
            HandleType::HmacVerifyStreamingContext => {
                perform_streaming_verify_final::<HmacVerifyStream<'_>>(
                    ctx_handle,
                    ctx_handle_type,
                    signature_data,
                )?;
            }
            _ => Err(AZIHSM_ERROR_INVALID_HANDLE)?,
        }

        Ok(())
    })
}
