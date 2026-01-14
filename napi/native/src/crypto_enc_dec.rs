// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
use crate::algo::aes::*;

/// Common cryptographic operation types
#[derive(PartialEq)]
pub(crate) enum CryptoOp {
    Encrypt,
    Decrypt,
}

/// Encrypt data using a cryptographic key and algorithm.
///
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
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_encrypt(
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    plain_text: *const AzihsmBuffer,
    cipher_text: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        let algo = deref_mut_ptr(algo)?;
        let key_type: HandleType = key_handle.try_into()?;
        let input_buf = deref_ptr(plain_text)?;
        let output_buf = deref_mut_ptr(cipher_text)?;

        match key_type {
            HandleType::AesKey => {
                aes_cbc_crypt(algo, key_handle, input_buf, output_buf, CryptoOp::Encrypt)?;
            }
            _ => Err(AzihsmError::UnsupportedKeyKind)?,
        }

        Ok(())
    })
}

/// Decrypt data using a cryptographic key and algorithm.
///
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_handle Handle to the decryption key
/// @param[in] cipher_text Pointer to ciphertext data buffer
/// @param[out] plain_text Pointer to plaintext output buffer
///
/// @return 0 on success, or a negative error code on failure.
/// If output buffer is insufficient, required length is updated in the output buffer and
/// the function returns the AZIHSM_ERROR_INSUFFICIENT_BUFFER error.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_decrypt(
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    cipher_text: *const AzihsmBuffer,
    plain_text: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        let algo = deref_mut_ptr(algo)?;
        let key_type: HandleType = key_handle.try_into()?;
        let input_buf = deref_ptr(cipher_text)?;
        let output_buf = deref_mut_ptr(plain_text)?;

        match key_type {
            HandleType::AesKey => {
                aes_cbc_crypt(algo, key_handle, input_buf, output_buf, CryptoOp::Decrypt)?
            }
            _ => Err(AzihsmError::UnsupportedKeyKind)?,
        }

        Ok(())
    })
}

/// Initialize streaming encryption operation.
///
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_handle Handle to the encryption key
/// @param[out] ctx_handle Pointer to receive the streaming context handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_encrypt_init(
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    ctx_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        let algo = deref_mut_ptr(algo)?;
        let key_type: HandleType = key_handle.try_into()?;

        let handle = match key_type {
            HandleType::AesKey => aes_cbc_streaming_init(algo, key_handle, CryptoOp::Encrypt)?,
            _ => Err(AzihsmError::UnsupportedKeyKind)?,
        };

        // Return the context handle
        assign_ptr(ctx_handle, handle)?;

        Ok(())
    })
}

/// Update streaming encryption operation with additional plaintext data.
///
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
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_encrypt_update(
    ctx_handle: AzihsmHandle,
    plain_text: *const AzihsmBuffer,
    cipher_text: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        let ctx_type: HandleType = ctx_handle.try_into()?;
        let input_buf = deref_ptr(plain_text)?;
        let output_buf = deref_mut_ptr(cipher_text)?;

        match ctx_type {
            HandleType::AesCbcStreamingCtx => {
                aes_cbc_streaming_update(ctx_handle, input_buf, output_buf)?
            }
            _ => Err(AzihsmError::InvalidHandle)?,
        }

        Ok(())
    })
}

/// Finalize streaming encryption operation and retrieve any remaining ciphertext.
///
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
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_encrypt_final(
    ctx_handle: AzihsmHandle,
    cipher_text: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        let ctx_type: HandleType = ctx_handle.try_into()?;
        let output_buf = deref_mut_ptr(cipher_text)?;

        match ctx_type {
            HandleType::AesCbcStreamingCtx => aes_cbc_streaming_final(ctx_handle, output_buf)?,
            _ => Err(AzihsmError::InvalidHandle)?,
        }
        Ok(())
    })
}

/// Initialize streaming decryption operation.
///
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_handle Handle to the decryption key
/// @param[out] ctx_handle Pointer to receive the streaming context handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_decrypt_init(
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    ctx_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        let algo = deref_mut_ptr(algo)?;
        let key_type: HandleType = key_handle.try_into()?;

        let handle = match key_type {
            HandleType::AesKey => aes_cbc_streaming_init(algo, key_handle, CryptoOp::Decrypt)?,
            _ => Err(AzihsmError::UnsupportedKeyKind)?,
        };

        // Return the context handle
        assign_ptr(ctx_handle, handle)?;

        Ok(())
    })
}

/// Update streaming decryption operation with additional ciphertext data.
///
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
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_decrypt_update(
    ctx_handle: AzihsmHandle,
    cipher_text: *const AzihsmBuffer,
    plain_text: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        let ctx_type: HandleType = ctx_handle.try_into()?;
        let input_buf = deref_ptr(cipher_text)?;
        let output_buf = deref_mut_ptr(plain_text)?;

        match ctx_type {
            HandleType::AesCbcStreamingCtx => {
                aes_cbc_streaming_update(ctx_handle, input_buf, output_buf)?
            }
            _ => Err(AzihsmError::InvalidHandle)?,
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
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_decrypt_final(
    ctx_handle: AzihsmHandle,
    plain_text: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        let ctx_type: HandleType = ctx_handle.try_into()?;
        let output_buf = deref_mut_ptr(plain_text)?;

        match ctx_type {
            HandleType::AesCbcStreamingCtx => aes_cbc_streaming_final(ctx_handle, output_buf)?,
            _ => Err(AzihsmError::InvalidHandle)?,
        }
        Ok(())
    })
}
