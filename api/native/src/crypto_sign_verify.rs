// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
use crate::algo::ecc::*;
use crate::algo::hmac::*;
use crate::algo::rsa::*;

/// Sign data using a cryptographic key and algorithm.
///
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
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_sign(
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    data: *const AzihsmBuffer,
    sig: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        let algo = deref_mut_ptr(algo)?;
        let data_buf = deref_ptr(data)?;
        let sig_buf = deref_mut_ptr(sig)?;

        // Convert input buffer to slice
        let input_data: &[u8] = data_buf.try_into()?;

        // Dispatch based on algorithm ID
        match algo.id {
            AzihsmAlgoId::Ecdsa => {
                ecc_sign(key_handle, input_data, sig_buf)?;
            }
            AzihsmAlgoId::EcdsaSha1
            | AzihsmAlgoId::EcdsaSha256
            | AzihsmAlgoId::EcdsaSha384
            | AzihsmAlgoId::EcdsaSha512 => {
                ecc_hash_sign(algo.id, key_handle, input_data, sig_buf)?;
            }

            AzihsmAlgoId::HmacSha1
            | AzihsmAlgoId::HmacSha256
            | AzihsmAlgoId::HmacSha384
            | AzihsmAlgoId::HmacSha512 => {
                hmac_sign(key_handle, input_data, sig_buf)?;
            }

            AzihsmAlgoId::RsaPkcsSha1
            | AzihsmAlgoId::RsaPkcsSha256
            | AzihsmAlgoId::RsaPkcsSha384
            | AzihsmAlgoId::RsaPkcsSha512 => {
                rsa_hash_sign(algo.id, key_handle, input_data, sig_buf)?;
            }
            AzihsmAlgoId::RsaPkcsPss => {
                rsa_pss_sign(algo, key_handle, input_data, sig_buf)?;
            }
            AzihsmAlgoId::RsaPkcsPssSha1
            | AzihsmAlgoId::RsaPkcsPssSha256
            | AzihsmAlgoId::RsaPkcsPssSha384
            | AzihsmAlgoId::RsaPkcsPssSha512 => {
                rsa_pss_hash_sign(algo.id, algo, key_handle, input_data, sig_buf)?;
            }
            _ => Err(AzihsmError::UnsupportedAlgorithm)?,
        }

        Ok(())
    })
}

/// Verify signature using a cryptographic key and algorithm.
///
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
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_verify(
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    data: *const AzihsmBuffer,
    sig: *const AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        let algo = deref_mut_ptr(algo)?;
        let data_buf = deref_ptr(data)?;
        let sig_buf = deref_ptr(sig)?;

        // Convert buffers to slices
        let input_data: &[u8] = data_buf.try_into()?;
        let sig_data: &[u8] = sig_buf.try_into()?;

        // Dispatch based on algorithm ID and perform verification
        let is_valid = match algo.id {
            AzihsmAlgoId::Ecdsa => ecc_verify(key_handle, input_data, sig_data)?,
            AzihsmAlgoId::EcdsaSha1
            | AzihsmAlgoId::EcdsaSha256
            | AzihsmAlgoId::EcdsaSha384
            | AzihsmAlgoId::EcdsaSha512 => {
                ecc_hash_verify(algo.id, key_handle, input_data, sig_data)?
            }

            AzihsmAlgoId::HmacSha1
            | AzihsmAlgoId::HmacSha256
            | AzihsmAlgoId::HmacSha384
            | AzihsmAlgoId::HmacSha512 => hmac_verify(key_handle, input_data, sig_data)?,

            AzihsmAlgoId::RsaPkcsSha1
            | AzihsmAlgoId::RsaPkcsSha256
            | AzihsmAlgoId::RsaPkcsSha384
            | AzihsmAlgoId::RsaPkcsSha512 => {
                rsa_hash_verify(algo.id, key_handle, input_data, sig_data)?
            }

            AzihsmAlgoId::RsaPkcsPss => rsa_pss_verify(algo, key_handle, input_data, sig_data)?,

            AzihsmAlgoId::RsaPkcsPssSha1
            | AzihsmAlgoId::RsaPkcsPssSha256
            | AzihsmAlgoId::RsaPkcsPssSha384
            | AzihsmAlgoId::RsaPkcsPssSha512 => {
                rsa_pss_hash_verify(algo.id, algo, key_handle, input_data, sig_data)?
            }
            _ => Err(AzihsmError::UnsupportedAlgorithm)?,
        };

        if !is_valid {
            Err(AzihsmError::InvalidSignature)?;
        }

        Ok(())
    })
}

/// Initialize streaming sign operation.
///
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_handle Handle to the signing key
/// @param[out] ctx_handle Pointer to receive the streaming context handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_sign_init(
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    ctx_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        validate_ptr(ctx_handle)?;

        let algo = deref_mut_ptr(algo)?;

        // Dispatch based on algorithm ID
        let handle = match algo.id {
            AzihsmAlgoId::Ecdsa => {
                // Streaming pre-computed hash input is not supported
                Err(AzihsmError::UnsupportedAlgorithm)?
            }

            AzihsmAlgoId::EcdsaSha1
            | AzihsmAlgoId::EcdsaSha256
            | AzihsmAlgoId::EcdsaSha384
            | AzihsmAlgoId::EcdsaSha512 => ecc_sign_init(algo.id, key_handle)?,

            AzihsmAlgoId::HmacSha1
            | AzihsmAlgoId::HmacSha256
            | AzihsmAlgoId::HmacSha384
            | AzihsmAlgoId::HmacSha512 => hmac_sign_init(key_handle)?,
            _ => Err(AzihsmError::UnsupportedAlgorithm)?,
        };

        assign_ptr(ctx_handle, handle)?;
        Ok(())
    })
}

/// Update streaming sign operation with additional data.
///
/// @param[in] ctx_handle Handle to the streaming sign context
/// @param[in] data Pointer to data buffer to be signed
///
/// @return 0 on success, or a negative error code on failure.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_sign_update(
    ctx_handle: AzihsmHandle,
    data: *const AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        let data_buf = deref_ptr(data)?;
        let input_data: &[u8] = data_buf.try_into()?;
        let ctx_type = HandleType::try_from(ctx_handle)?;

        match ctx_type {
            HandleType::EccSignStreamingCtx => {
                ecc_sign_update(ctx_handle, input_data)?;
            }
            HandleType::HmacSignStreamingCtx => {
                hmac_sign_update(ctx_handle, input_data)?;
            }
            _ => Err(AzihsmError::InvalidHandle)?,
        }

        Ok(())
    })
}

/// Finalize streaming sign operation and retrieve signature.
///
/// @param[in] ctx_handle Handle to the streaming sign context
/// @param[out] sig Pointer to signature output buffer
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
pub unsafe extern "C" fn azihsm_crypt_sign_final(
    ctx_handle: AzihsmHandle,
    sig: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        let sig_buf = deref_mut_ptr(sig)?;
        let ctx_type = HandleType::try_from(ctx_handle)?;

        match ctx_type {
            HandleType::EccSignStreamingCtx => {
                ecc_sign_final(ctx_handle, sig_buf)?;
            }
            HandleType::HmacSignStreamingCtx => {
                hmac_sign_final(ctx_handle, sig_buf)?;
            }
            _ => Err(AzihsmError::InvalidHandle)?,
        }

        Ok(())
    })
}

/// Initialize streaming verify operation.
///
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_handle Handle to the verification key
/// @param[out] ctx_handle Pointer to receive the streaming context handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_verify_init(
    algo: *mut AzihsmAlgo,
    key_handle: AzihsmHandle,
    ctx_handle: *mut AzihsmHandle,
) -> AzihsmError {
    abi_boundary(|| {
        validate_ptr(ctx_handle)?;

        let algo = deref_mut_ptr(algo)?;

        // Dispatch based on algorithm ID
        let handle = match algo.id {
            AzihsmAlgoId::Ecdsa => {
                // Streaming pre-computed hash input is not supported
                Err(AzihsmError::UnsupportedAlgorithm)?
            }

            AzihsmAlgoId::EcdsaSha1 => ecc_verify_init(algo.id, key_handle)?,
            AzihsmAlgoId::EcdsaSha256 | AzihsmAlgoId::EcdsaSha384 | AzihsmAlgoId::EcdsaSha512 => {
                ecc_verify_init(algo.id, key_handle)?
            }

            AzihsmAlgoId::HmacSha1
            | AzihsmAlgoId::HmacSha256
            | AzihsmAlgoId::HmacSha384
            | AzihsmAlgoId::HmacSha512 => hmac_verify_init(key_handle)?,
            _ => Err(AzihsmError::UnsupportedAlgorithm)?,
        };

        assign_ptr(ctx_handle, handle)?;
        Ok(())
    })
}

/// Update streaming verify operation with additional data.
///
/// @param[in] ctx_handle Handle to the streaming verify context
/// @param[in] data Pointer to data buffer that was signed
///
/// @return 0 on success, or a negative error code on failure.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_verify_update(
    ctx_handle: AzihsmHandle,
    data: *const AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        let data_buf = deref_ptr(data)?;
        let input_data: &[u8] = data_buf.try_into()?;
        let ctx_type: HandleType = HandleType::try_from(ctx_handle)?;

        match ctx_type {
            HandleType::EccVerifyStreamingCtx => {
                ecc_verify_update(ctx_handle, input_data)?;
            }
            HandleType::HmacVerifyStreamingCtx => {
                hmac_verify_update(ctx_handle, input_data)?;
            }
            _ => Err(AzihsmError::InvalidHandle)?,
        }

        Ok(())
    })
}

/// Finalize streaming verify operation and verify signature.
///
/// @param[in] ctx_handle Handle to the streaming verify context
/// @param[in] sig Pointer to signature buffer to verify
///
/// @return 0 on success, or a negative error code on failure.
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_crypt_verify_final(
    ctx_handle: AzihsmHandle,
    sig: *const AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        let sig_buf = deref_ptr(sig)?;
        let signature: &[u8] = sig_buf.try_into()?;
        let ctx_type: HandleType = HandleType::try_from(ctx_handle)?;

        let is_valid = match ctx_type {
            HandleType::EccVerifyStreamingCtx => ecc_verify_final(ctx_handle, signature)?,
            HandleType::HmacVerifyStreamingCtx => hmac_verify_final(ctx_handle, signature)?,
            _ => Err(AzihsmError::InvalidHandle)?,
        };

        if !is_valid {
            Err(AzihsmError::InvalidSignature)?;
        }

        Ok(())
    })
}
