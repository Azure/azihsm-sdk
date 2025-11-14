// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(unsafe_code)]

use crate::bindings::ffi_types::AlgoConverter;
use crate::bindings::ffi_types::AzihsmAlgo;
use crate::bindings::ffi_types::AzihsmBuffer;
use crate::bindings::HANDLE_TABLE;
use crate::crypto::aes::AesCbcKey;
use crate::crypto::ec::EcdsaAlgo;
use crate::crypto::ec::EcdsaKeyPair;
use crate::crypto::sha::ShaAlgo;
use crate::crypto::DecryptOp;
use crate::crypto::DigestOp;
use crate::crypto::EncryptOp;
use crate::crypto::SignOp;
use crate::types::AlgoId;
use crate::*;
/// Common cryptographic operation types
enum CryptoOp {
    Encrypt,
    Decrypt,
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
            let key: &AesCbcKey = HANDLE_TABLE.as_ref(key_handle, HandleType::AesCbcKey)?;
            let key_id = key.id().ok_or(AZIHSM_INTERNAL_ERROR)?;

            match algo_spec.id {
                AlgoId::AesCbc | AlgoId::AesCbcPad => {
                    // Extract AES-CBC algorithm using the AlgoExtractor trait
                    // SAFETY: algo_spec points to a valid AzihsmAlgo, checked above
                    let mut aes_cbc =
                        unsafe { algo_spec.from_algo::<crate::crypto::aes::AesCbcAlgo>()? };

                    // Check buffer size and perform operation based on type
                    let bytes_written = match operation {
                        CryptoOp::Encrypt => {
                            let required_len = aes_cbc.ciphertext_len(input_data.len());
                            let output_data =
                                prepare_output_buffer(output_buf, required_len as u32)?;
                            session.encrypt(&mut aes_cbc, key_id, input_data, output_data)?
                        }
                        CryptoOp::Decrypt => {
                            let required_len = aes_cbc.plaintext_len(input_data.len());
                            let output_data =
                                prepare_output_buffer(output_buf, required_len as u32)?;
                            session.decrypt(&mut aes_cbc, key_id, input_data, output_data)?
                        }
                    };
                    output_buf.len = bytes_written as u32;

                    // Copy the modified IV back to the algorithm parameters
                    // SAFETY: algo_spec points to a valid AzihsmAlgo, checked above
                    unsafe { aes_cbc.update_algo(algo_spec)? };
                }
                _ => {
                    Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?;
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
                let priv_key_id = key.priv_key_id().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;

                // SAFETY: algo_spec points to a valid AzihsmAlgo, checked above
                let ecdsa_algo = unsafe { algo_spec.from_algo::<EcdsaAlgo>()? };

                // Get required signature length
                let required_len = ecdsa_algo.signature_len(key)?;
                let sig_data = prepare_output_buffer(sig_buf, required_len)?;

                session.sign(&ecdsa_algo, priv_key_id, input_data, sig_data)?;

                // Update output buffer length to actual signature length
                sig_buf.len = required_len;
            }
            // Add support for other key types here as needed (RSA, etc.)
            _ => {
                Err(AZIHSM_ERROR_INVALID_HANDLE)?;
            }
        }

        Ok(())
    })
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

                // SAFETY: algo_spec points to a valid AzihsmAlgo, checked above
                let ecdsa_algo = unsafe { algo_spec.from_algo::<EcdsaAlgo>()? };

                session.verify(&ecdsa_algo, key, input_data, signature_data)?;
            }
            // Add support for other key types here as needed (RSA, etc.)
            _ => {
                Err(AZIHSM_ERROR_INVALID_HANDLE)?;
            }
        }

        Ok(())
    })
}

/// Compute cryptographic digest (hash) of data using the specified algorithm.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] data Pointer to data buffer to be hashed
/// @param[out] digest Pointer to digest output buffer
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
pub unsafe extern "C" fn azihsm_crypt_digest(
    sess_handle: AzihsmHandle,
    algo: *const AzihsmAlgo,
    data: *const AzihsmBuffer,
    digest: *mut AzihsmBuffer,
) -> AzihsmError {
    abi_boundary(|| {
        validate_pointers!(algo, data, digest);

        let session: &Session = HANDLE_TABLE.as_ref(sess_handle, HandleType::Session)?;

        let algo_spec: &AzihsmAlgo = deref_const_ptr!(algo);

        let data_buf = deref_const_ptr!(data);

        let digest_buf = deref_mut_ptr!(digest);

        validate_buffer!(data_buf);

        let input_data = data_buf.as_slice()?;

        // Get Support hash function and required output length
        let mut sha_algo = ShaAlgo { algo: algo_spec.id };
        let required_len = sha_algo.digest_len()?;

        // Check if output buffer is sufficient, update length if needed
        let digest_data = prepare_output_buffer(digest_buf, required_len)?;

        // Perform the digest operation
        sha_algo.digest(session, input_data, digest_data)
    })
}
