// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
use crate::algo::ecc::ecc_sign;
use crate::algo::ecc::ecc_verify;

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

        // Get the key handle type and perform operation based on key type and algorithm
        let key_type: HandleType = key_handle.try_into()?;

        match key_type {
            HandleType::EccPrivKey => {
                ecc_sign(algo, key_handle, input_data, sig_buf)?;
            }

            // Add support for other key types here as needed (RSA, etc.)
            _ => {
                Err(AzihsmError::UnsupportedKeyKind)?;
            }
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

        let key_type: HandleType = key_handle.try_into()?;

        let is_valid = match key_type {
            HandleType::EccPubKey => ecc_verify(algo, key_handle, input_data, sig_data)?,

            // Add support for other key types here as needed (RSA, etc.)
            _ => Err(AzihsmError::UnsupportedKeyKind)?,
        };

        if !is_valid {
            Err(AzihsmError::InvalidSignature)?;
        }

        Ok(())
    })
}
