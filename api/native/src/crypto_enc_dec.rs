// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::algo::aes::*;
use crate::algo::rsa::*;

/// Encrypt data using a cryptographic key and algorithm.
///
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_handle Handle to the encryption key
/// @param[in] plain_text Pointer to plaintext data buffer
/// @param[out] cipher_text Pointer to ciphertext output buffer
///
/// @return 0 on success, or a negative error code on failure.
/// If output buffer is insufficient, required length is updated in the output buffer and
/// the function returns the AZIHSM_STATUS_INSUFFICIENT_BUFFER error.
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
) -> AzihsmStatus {
    abi_boundary(|| {
        let algo = deref_mut_ptr(algo)?;
        let plain_text = deref_ptr(plain_text)?;
        let input_buf: &[u8] = plain_text.try_into()?;
        let output_buf = deref_mut_ptr(cipher_text)?;

        match algo.id {
            AzihsmAlgoId::AesCbc | AzihsmAlgoId::AesCbcPad => {
                aes_cbc_encrypt(algo, key_handle, input_buf, output_buf)?;
            }

            AzihsmAlgoId::AesGcm => {
                aes_gcm_encrypt(algo, key_handle, input_buf, output_buf)?;
            }

            AzihsmAlgoId::AesXts => {
                aes_xts_encrypt(algo, key_handle, input_buf, output_buf)?;
            }
            AzihsmAlgoId::RsaPkcs | AzihsmAlgoId::RsaPkcsOaep | AzihsmAlgoId::RsaAesWrap => {
                rsa_encrypt(algo, key_handle, input_buf, output_buf)?;
            }
            _ => Err(AzihsmStatus::UnsupportedAlgorithm)?,
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
/// the function returns the AZIHSM_STATUS_INSUFFICIENT_BUFFER error.
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
) -> AzihsmStatus {
    abi_boundary(|| {
        let algo = deref_mut_ptr(algo)?;
        let cipher_text = deref_ptr(cipher_text)?;
        let input_buf: &[u8] = cipher_text.try_into()?;
        let output_buf = deref_mut_ptr(plain_text)?;

        match algo.id {
            AzihsmAlgoId::AesCbc | AzihsmAlgoId::AesCbcPad => {
                aes_cbc_decrypt(algo, key_handle, input_buf, output_buf)?
            }
            AzihsmAlgoId::AesGcm => aes_gcm_decrypt(algo, key_handle, input_buf, output_buf)?,
            AzihsmAlgoId::AesXts => {
                aes_xts_decrypt(algo, key_handle, input_buf, output_buf)?;
            }
            AzihsmAlgoId::RsaPkcs | AzihsmAlgoId::RsaPkcsOaep => {
                rsa_decrypt(algo, key_handle, input_buf, output_buf)?;
            }
            _ => Err(AzihsmStatus::UnsupportedAlgorithm)?,
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
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(ctx_handle)?;

        let algo = deref_mut_ptr(algo)?;

        let handle = match algo.id {
            AzihsmAlgoId::AesCbc | AzihsmAlgoId::AesCbcPad => {
                aes_cbc_encrypt_init(algo, key_handle)?
            }
            AzihsmAlgoId::AesGcm => aes_gcm_encrypt_init(algo, key_handle)?,
            AzihsmAlgoId::AesXts => aes_xts_encrypt_init(algo, key_handle)?,
            _ => Err(AzihsmStatus::UnsupportedAlgorithm)?,
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
/// the function returns the AZIHSM_STATUS_INSUFFICIENT_BUFFER error.
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
) -> AzihsmStatus {
    abi_boundary(|| {
        let ctx_type: HandleType = HandleType::try_from(ctx_handle)?;
        let input_buf = deref_ptr(plain_text)?;
        let output_buf = deref_mut_ptr(cipher_text)?;

        match ctx_type {
            HandleType::AesCbcEncryptCtx => {
                aes_cbc_encrypt_update(ctx_handle, input_buf, output_buf)?
            }
            HandleType::AesGcmEncryptCtx => {
                aes_gcm_encrypt_update(ctx_handle, input_buf, output_buf)?
            }
            HandleType::AesXtsEncryptCtx => {
                aes_xts_encrypt_update(ctx_handle, input_buf, output_buf)?
            }
            _ => Err(AzihsmStatus::InvalidHandle)?,
        }

        Ok(())
    })
}

/// Finish streaming encryption operation and retrieve any remaining ciphertext.
///
/// @param[in] ctx_handle Handle to the streaming encryption context
/// @param[out] cipher_text Pointer to ciphertext output buffer
///
/// @return 0 on success, or a negative error code on failure.
/// If output buffer is insufficient, required length is updated in the output buffer and
/// the function returns the AZIHSM_STATUS_INSUFFICIENT_BUFFER error.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_encrypt_finish(
    ctx_handle: AzihsmHandle,
    cipher_text: *mut AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let ctx_type = HandleType::try_from(ctx_handle)?;
        let output_buf = deref_mut_ptr(cipher_text)?;

        match ctx_type {
            HandleType::AesCbcEncryptCtx => aes_cbc_encrypt_finish(ctx_handle, output_buf)?,
            HandleType::AesGcmEncryptCtx => aes_gcm_encrypt_finish(ctx_handle, output_buf)?,
            HandleType::AesXtsEncryptCtx => aes_xts_encrypt_finish(ctx_handle, output_buf)?,
            _ => Err(AzihsmStatus::InvalidHandle)?,
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
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(ctx_handle)?;

        let algo = deref_mut_ptr(algo)?;

        let handle = match algo.id {
            AzihsmAlgoId::AesCbc | AzihsmAlgoId::AesCbcPad => {
                aes_cbc_decrypt_init(algo, key_handle)?
            }
            AzihsmAlgoId::AesGcm => aes_gcm_decrypt_init(algo, key_handle)?,
            AzihsmAlgoId::AesXts => aes_xts_decrypt_init(algo, key_handle)?,
            _ => Err(AzihsmStatus::UnsupportedAlgorithm)?,
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
/// the function returns the AZIHSM_STATUS_INSUFFICIENT_BUFFER error.
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
) -> AzihsmStatus {
    abi_boundary(|| {
        let ctx_type: HandleType = HandleType::try_from(ctx_handle)?;
        let input_buf = deref_ptr(cipher_text)?;
        let output_buf = deref_mut_ptr(plain_text)?;

        match ctx_type {
            HandleType::AesCbcDecryptCtx => {
                aes_cbc_decrypt_update(ctx_handle, input_buf, output_buf)?
            }
            HandleType::AesGcmDecryptCtx => {
                aes_gcm_decrypt_update(ctx_handle, input_buf, output_buf)?
            }
            HandleType::AesXtsDecryptCtx => {
                aes_xts_decrypt_update(ctx_handle, input_buf, output_buf)?
            }
            _ => Err(AzihsmStatus::InvalidHandle)?,
        }

        Ok(())
    })
}

/// Finish streaming decryption operation and retrieve any remaining plaintext.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] ctx_handle Handle to the streaming decryption context
/// @param[out] plain_text Pointer to plaintext output buffer
///
/// @return 0 on success, or a negative error code on failure.
/// If output buffer is insufficient, required length is updated in the output buffer and
/// the function returns the AZIHSM_STATUS_INSUFFICIENT_BUFFER error.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_decrypt_finish(
    ctx_handle: AzihsmHandle,
    plain_text: *mut AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        let ctx_type: HandleType = HandleType::try_from(ctx_handle)?;
        let output_buf = deref_mut_ptr(plain_text)?;

        match ctx_type {
            HandleType::AesCbcDecryptCtx => aes_cbc_decrypt_finish(ctx_handle, output_buf)?,
            HandleType::AesGcmDecryptCtx => aes_gcm_decrypt_finish(ctx_handle, output_buf)?,
            HandleType::AesXtsDecryptCtx => aes_xts_decrypt_finish(ctx_handle, output_buf)?,
            _ => Err(AzihsmStatus::InvalidHandle)?,
        }
        Ok(())
    })
}
