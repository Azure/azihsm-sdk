// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(unsafe_code)]

use crate::bindings::ffi_types::AlgoConverter;
use crate::bindings::ffi_types::AzihsmAlgo;
use crate::bindings::ffi_types::AzihsmBuffer;
use crate::bindings::HANDLE_TABLE;
use crate::crypto::aes::AesCbcAlgo;
use crate::crypto::aes::AesCbcDecryptStreamOp;
use crate::crypto::aes::AesCbcEncryptStreamOp;
use crate::crypto::aes::AesCbcKey;
use crate::crypto::aes::AesXtsAlgo;
use crate::crypto::aes::AesXtsKey;
use crate::crypto::rsa::RsaPkcsKeyPair;
use crate::crypto::rsa::RsaPkcsOaepAlgo;
use crate::crypto::Algo;
use crate::crypto::DecryptOp;
use crate::crypto::EncryptOp;
use crate::crypto::Key;
use crate::crypto::Stage;
use crate::crypto::StreamingDecryptOp;
use crate::crypto::StreamingEncDecAlgo;
use crate::crypto::StreamingEncryptOp;
use crate::types::AlgoId;
use crate::*;

/// Common cryptographic operation types
enum CryptoOp {
    Encrypt,
    Decrypt,
}

/// Generic helper function for crypto operations.
fn perform_crypto_operation<TAlgo, TKey>(
    session: &Session,
    algo_spec: &mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    key_handle_type: HandleType,
    input_data: &[u8],
    output_buf: &mut AzihsmBuffer,
    operation: CryptoOp,
) -> Result<TAlgo, AzihsmError>
where
    TAlgo: Algo + EncryptOp<TKey> + DecryptOp<TKey> + AlgoConverter,
    TKey: Key,
{
    // Get key from handle table
    let key: &TKey = HANDLE_TABLE.as_ref(key_handle, key_handle_type)?;

    // Extract algorithm using the AlgoConverter trait
    // SAFETY: algo_spec points to a valid AzihsmAlgo, checked by caller
    let mut algo = unsafe { algo_spec.from_algo::<TAlgo>()? };

    // Check buffer size and perform operation based on type
    let bytes_written = match operation {
        CryptoOp::Encrypt => {
            let required_len = algo.ciphertext_len(input_data.len());
            let output_data = prepare_output_buffer(output_buf, required_len as u32)?;
            session.encrypt(&mut algo, key, input_data, output_data)?
        }
        CryptoOp::Decrypt => {
            let required_len = algo.plaintext_len(input_data.len());
            let output_data = prepare_output_buffer(output_buf, required_len as u32)?;
            session.decrypt(&mut algo, key, input_data, output_data)?
        }
    };

    output_buf.len = bytes_written as u32;

    // Return the algorithm so caller can decide whether to update
    Ok(algo)
}

/// Internal helper function for common encryption/decryption logic
#[allow(unsafe_code)]
unsafe fn azihsm_crypt_common(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    input_buffer: *const AzihsmBuffer,
    output_buffer: *mut AzihsmBuffer,
    operation: CryptoOp,
) -> Result<(), AzihsmError> {
    validate_pointers!(algo, input_buffer, output_buffer);

    let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;

    let algo_spec = deref_mut_ptr!(algo);

    let input_buf = deref_const_ptr!(input_buffer);

    let output_buf = deref_mut_ptr!(output_buffer);

    validate_buffer!(input_buf);

    let input_data = input_buf.as_slice()?;

    let key_handle_type = HANDLE_TABLE.get_handle_type(key_handle)?;

    match key_handle_type {
        HandleType::AesCbcKey => {
            if algo_spec.id != AlgoId::AesCbc && algo_spec.id != AlgoId::AesCbcPad {
                Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?;
            }

            let aes_cbc = perform_crypto_operation::<AesCbcAlgo, AesCbcKey>(
                session,
                algo_spec,
                key_handle,
                HandleType::AesCbcKey,
                input_data,
                output_buf,
                operation,
            )?;

            // Copy the modified IV back to the algorithm parameters
            // SAFETY: algo_spec points to a valid AzihsmAlgo, checked above
            unsafe { aes_cbc.update_algo(algo_spec)? };
        }
        HandleType::AesXtsKey => {
            if algo_spec.id != AlgoId::AesXts {
                Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?;
            }

            perform_crypto_operation::<AesXtsAlgo, AesXtsKey>(
                session,
                algo_spec,
                key_handle,
                HandleType::AesXtsKey,
                input_data,
                output_buf,
                operation,
            )?;
        }
        HandleType::RsaPrivateKey => {
            // check if keyhandle type and operation is compatible
            match operation {
                CryptoOp::Encrypt => {
                    Err(AZIHSM_OPERATION_NOT_SUPPORTED)?;
                }
                CryptoOp::Decrypt => {
                    match algo_spec.id {
                        // PKCS#1 v1.5 algorithms
                        AlgoId::RsaPkcsOaep => {
                            perform_crypto_operation::<RsaPkcsOaepAlgo, RsaPkcsKeyPair>(
                                session,
                                algo_spec,
                                key_handle,
                                key_handle_type,
                                input_data,
                                output_buf,
                                operation,
                            )?;
                        }

                        _ => {
                            Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?;
                        }
                    }
                }
            }
        }
        HandleType::RsaPublicKey => {
            match operation {
                CryptoOp::Encrypt => {
                    match algo_spec.id {
                        // PKCS#1 v1.5 algorithms
                        AlgoId::RsaPkcsOaep => {
                            perform_crypto_operation::<RsaPkcsOaepAlgo, RsaPkcsKeyPair>(
                                session,
                                algo_spec,
                                key_handle,
                                key_handle_type,
                                input_data,
                                output_buf,
                                operation,
                            )?;
                        }

                        _ => {
                            Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?;
                        }
                    }
                }
                CryptoOp::Decrypt => {
                    Err(AZIHSM_OPERATION_NOT_SUPPORTED)?;
                }
            }
        }

        // Add support for other key types here as needed
        _ => {
            Err(AZIHSM_ERROR_INVALID_HANDLE)?;
        }
    }

    Ok(())
}

/// Encrypt data using a cryptographic key and algorithm.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_handle Handle to the encryption key
/// @param[in] plain_text Pointer to plaintext data buffer
/// @param[out] cipher_text Pointer to ciphertext output buffer
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
pub unsafe extern "C" fn azihsm_crypt_encrypt(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    plain_text: *const AzihsmBuffer,
    cipher_text: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(||
        // SAFETY: The caller must ensure that the pointers are valid.
        unsafe {
        azihsm_crypt_common(
            sess_handle,
            algo,
            key_handle,
            plain_text,
            cipher_text,
            CryptoOp::Encrypt,
        )
    })
}

/// Decrypt data using a cryptographic key and algorithm.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_handle Handle to the decryption key
/// @param[in] cipher_text Pointer to ciphertext data buffer
/// @param[out] plain_text Pointer to plaintext output buffer
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_decrypt(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    cipher_text: *const AzihsmBuffer,
    plain_text: *mut AzihsmBuffer,
) -> AzihsmError {
    // SAFETY: The caller must ensure that the pointers are valid and point to properly initialized buffers and algorithm structures.
    abi_boundary(|| unsafe {
        azihsm_crypt_common(
            sess_handle,
            algo,
            key_handle,
            cipher_text,
            plain_text,
            CryptoOp::Decrypt,
        )
    })
}

/// Generic helper for streaming initialization
unsafe fn perform_streaming_init<'a, TAlgo, TKey, TStreamOp>(
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    ctx_handle: *mut AzihsmHandle,
    supported_algos: &[AlgoId],
    init_fn: impl FnOnce(&TAlgo, &TKey) -> Result<TStreamOp, AzihsmError>,
) -> Result<(), AzihsmError>
where
    TAlgo: AlgoConverter + StreamingEncDecAlgo<'a, TKey>,
    TKey: Key,
    TStreamOp: 'a,
{
    validate_pointers!(algo, ctx_handle);

    let algo_spec = deref_mut_ptr!(algo);
    let key_handle_type = HANDLE_TABLE.get_handle_type(key_handle)?;

    let (stream_op, ctx_handle_type) = match key_handle_type {
        HandleType::AesCbcKey => {
            if !supported_algos.contains(&algo_spec.id) {
                Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?;
            }

            let key: &TKey = HANDLE_TABLE.as_ref(key_handle, key_handle_type)?;
            // SAFETY: algo_spec points to a valid AzihsmAlgo, checked by validate_pointers! macro
            let algo = unsafe { algo_spec.from_algo::<TAlgo>()? };
            let stream = init_fn(&algo, key)?;
            (Box::new(stream), HandleType::AesCbcStreamingContext)
        }
        _ => Err(AZIHSM_ERROR_INVALID_HANDLE)?,
    };

    // SAFETY: ctx_handle pointer is validated by validate_pointers! macro
    unsafe {
        *ctx_handle = HANDLE_TABLE.alloc_handle(ctx_handle_type, stream_op);
    }
    Ok(())
}

/// Initialize streaming encryption operation.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_handle Handle to the encryption key
/// @param[out] ctx_handle Pointer to receive the streaming context handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_encrypt_init(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    ctx_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(||
        // SAFETY: The caller must ensure that the pointers are valid.
        unsafe {
            let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;
            let key_handle_type = HANDLE_TABLE.get_handle_type(key_handle)?;

            match key_handle_type {
                HandleType::AesCbcKey => {
                    perform_streaming_init::<AesCbcAlgo, AesCbcKey, AesCbcEncryptStreamOp<'_>>(
                        algo,
                        key_handle,
                        ctx_handle,
                        &[AlgoId::AesCbc, AlgoId::AesCbcPad],
                        |algo, key| session.encrypt_init(algo, key),
                    )
                }
                // Future: Add HandleType::AesXtsKey, etc.
                _ => Err(AZIHSM_ERROR_INVALID_HANDLE),
            }
    })
}

/// Update streaming encryption operation with additional plaintext data.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] ctx_handle Handle to the streaming encryption context
/// @param[in] plain_text Pointer to plaintext data buffer to encrypt
/// @param[out] cipher_text Pointer to ciphertext output buffer
///
/// @return 0 on success, or a negative error code on failure.
/// If output buffer is insufficient, required length is updated in the output buffer and
/// the function returns the AZIHSM_ERROR_INSUFFICIENT_BUFFER error.
/// Note: Output may be less than input size if buffering occurs (e.g., for block alignment).
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_encrypt_update(
    _sess_handle: AzihsmHandle,
    ctx_handle: AzihsmHandle,
    plain_text: *const AzihsmBuffer,
    cipher_text: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(plain_text, cipher_text);

        let input_buf = deref_const_ptr!(plain_text);
        let output_buf = deref_mut_ptr!(cipher_text);
        let input_data = input_buf.as_slice()?;

        let ctx_handle_type = HANDLE_TABLE.get_handle_type(ctx_handle)?;

        match ctx_handle_type {
            HandleType::AesCbcStreamingContext => {
                let encrypt_stream: &mut AesCbcEncryptStreamOp<'_> =
                    HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesCbcStreamingContext)?;

                // Calculate required output size based on buffered data + new input
                let required_len =
                    encrypt_stream.required_output_len(input_data.len(), Stage::Update);

                let output_data = prepare_output_buffer(output_buf, required_len as u32)?;
                let bytes_written = encrypt_stream.update(input_data, output_data)?;
                output_buf.len = bytes_written as u32;
            }
            // Future: Add HandleType::AesXtsStreamingContext, etc.
            _ => Err(AZIHSM_ERROR_INVALID_HANDLE)?,
        }

        Ok(())
    })
}

/// Finalize streaming encryption operation and retrieve any remaining ciphertext.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] ctx_handle Handle to the streaming encryption context (consumed by this call)
/// @param[out] cipher_text Pointer to ciphertext output buffer
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
pub unsafe extern "C" fn azihsm_crypt_encrypt_final(
    _sess_handle: AzihsmHandle,
    ctx_handle: AzihsmHandle,
    cipher_text: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(cipher_text);

        let output_buf = deref_mut_ptr!(cipher_text);

        let ctx_handle_type = HANDLE_TABLE.get_handle_type(ctx_handle)?;

        match ctx_handle_type {
            HandleType::AesCbcStreamingContext => {
                // First, check what output size we need
                let encrypt_stream_ref: &AesCbcEncryptStreamOp<'_> =
                    HANDLE_TABLE.as_ref(ctx_handle, HandleType::AesCbcStreamingContext)?;

                // Calculate required output size based on buffered data + new input
                let required_len = encrypt_stream_ref.required_output_len(0, Stage::Finalize);

                let output_data = prepare_output_buffer(output_buf, required_len as u32)?;

                // Now that buffer is validated, take ownership and finalize
                let encrypt_stream: AesCbcEncryptStreamOp<'_> =
                    *HANDLE_TABLE.free_handle(ctx_handle, HandleType::AesCbcStreamingContext)?;

                let bytes_written = encrypt_stream.finalize(output_data)?;
                output_buf.len = bytes_written as u32;
            }
            // Future: Add HandleType::AesXtsStreamingContext, etc.
            _ => Err(AZIHSM_ERROR_INVALID_HANDLE)?,
        }

        Ok(())
    })
}

/// Initialize streaming decryption operation.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_handle Handle to the decryption key
/// @param[out] ctx_handle Pointer to receive the streaming context handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_decrypt_init(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    ctx_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(||
        // SAFETY: The caller must ensure that the pointers are valid.
        unsafe {
            let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;
            let key_handle_type = HANDLE_TABLE.get_handle_type(key_handle)?;

            match key_handle_type {
                HandleType::AesCbcKey => {
                    perform_streaming_init::<AesCbcAlgo, AesCbcKey, AesCbcDecryptStreamOp<'_>>(
                        algo,
                        key_handle,
                        ctx_handle,
                        &[AlgoId::AesCbc, AlgoId::AesCbcPad],
                        |algo, key| session.decrypt_init(algo, key),
                    )
                }
                // Future: Add HandleType::AesXtsKey, etc.
                _ => Err(AZIHSM_ERROR_INVALID_HANDLE),
            }
    })
}

/// Update streaming decryption operation with additional ciphertext data.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] ctx_handle Handle to the streaming decryption context
/// @param[in] cipher_text Pointer to ciphertext data buffer to decrypt
/// @param[out] plain_text Pointer to plaintext output buffer
///
/// @return 0 on success, or a negative error code on failure.
/// If output buffer is insufficient, required length is updated in the output buffer and
/// the function returns the AZIHSM_ERROR_INSUFFICIENT_BUFFER error.
/// Note: Output may be less than input size if buffering occurs (e.g., for block alignment).
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_decrypt_update(
    _sess_handle: AzihsmHandle,
    ctx_handle: AzihsmHandle,
    cipher_text: *const AzihsmBuffer,
    plain_text: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(cipher_text, plain_text);

        let input_buf = deref_const_ptr!(cipher_text);
        let output_buf = deref_mut_ptr!(plain_text);
        let input_data = input_buf.as_slice()?;

        let ctx_handle_type = HANDLE_TABLE.get_handle_type(ctx_handle)?;

        match ctx_handle_type {
            HandleType::AesCbcStreamingContext => {
                let decrypt_stream: &mut AesCbcDecryptStreamOp<'_> =
                    HANDLE_TABLE.as_mut(ctx_handle, HandleType::AesCbcStreamingContext)?;

                // Calculate required output size based on buffered data + new input
                let required_len =
                    decrypt_stream.required_output_len(input_data.len(), Stage::Update);

                let output_data = prepare_output_buffer(output_buf, required_len as u32)?;
                let bytes_written = decrypt_stream.update(input_data, output_data)?;
                output_buf.len = bytes_written as u32;
            }
            // Future: Add HandleType::AesXtsStreamingContext, etc.
            _ => Err(AZIHSM_ERROR_INVALID_HANDLE)?,
        }

        Ok(())
    })
}

/// Finalize streaming decryption operation and retrieve any remaining plaintext.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] ctx_handle Handle to the streaming decryption context (consumed by this call)
/// @param[out] plain_text Pointer to plaintext output buffer
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
pub unsafe extern "C" fn azihsm_crypt_decrypt_final(
    _sess_handle: AzihsmHandle,
    ctx_handle: AzihsmHandle,
    plain_text: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(plain_text);

        let output_buf = deref_mut_ptr!(plain_text);

        let ctx_handle_type = HANDLE_TABLE.get_handle_type(ctx_handle)?;

        match ctx_handle_type {
            HandleType::AesCbcStreamingContext => {
                // First, check what output size we need
                let decrypt_stream_ref: &AesCbcDecryptStreamOp<'_> =
                    HANDLE_TABLE.as_ref(ctx_handle, HandleType::AesCbcStreamingContext)?;

                // Calculate required output size based on buffered data + new input
                let required_len = decrypt_stream_ref.required_output_len(0, Stage::Finalize);

                let output_data = prepare_output_buffer(output_buf, required_len as u32)?;

                // Now that buffer is validated, take ownership and finalize
                let decrypt_stream: AesCbcDecryptStreamOp<'_> =
                    *HANDLE_TABLE.free_handle(ctx_handle, HandleType::AesCbcStreamingContext)?;

                let bytes_written = decrypt_stream.finalize(output_data)?;
                output_buf.len = bytes_written as u32;
            }
            // Future: Add HandleType::AesXtsStreamingContext, etc.
            _ => Err(AZIHSM_ERROR_INVALID_HANDLE)?,
        }

        Ok(())
    })
}
