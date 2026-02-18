// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;

use super::*;
use crate::algo::aes::*;
use crate::algo::ecc::*;
use crate::algo::hmac::*;
use crate::algo::kdf::*;
use crate::algo::rsa::*;
use crate::algo::secret::*;

/// Generate a symmetric key
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] key_props Pointer to key properties list
/// @param[out] key_handle Pointer to store the generated key handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_gen(
    sess_handle: AzihsmHandle,
    algo: *const AzihsmAlgo,
    key_props: *const AzihsmKeyPropList,
    key_handle: *mut AzihsmHandle,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(key_handle)?;

        let algo = deref_ptr(algo)?;
        let props = deref_ptr(key_props)?;
        let key_props = HsmKeyProps::try_from(props)?;
        let session: HsmSession = HsmSession::try_from(sess_handle)?;

        // Generate key based on algorithm ID
        let handle = match algo.id {
            // AES family algorithms
            AzihsmAlgoId::AesKeyGen | AzihsmAlgoId::AesGcmKeyGen | AzihsmAlgoId::AesXtsKeyGen => {
                aes_generate_key(&session, algo, key_props)?
            }
            // Unknown or unsupported algorithms
            _ => Err(AzihsmStatus::InvalidArgument)?,
        };

        // Return the generated key handle
        assign_ptr(key_handle, handle)?;

        Ok(())
    })
}

/// Generate an asymmetric key pair
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] priv_key_props Pointer to private key properties list
/// @param[in] pub_key_props Pointer to public key properties list
/// @param[out] priv_key_handle Pointer to store the generated private key handle
/// @param[out] pub_key_handle Pointer to store the generated public key handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_gen_pair(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    priv_key_props: *const AzihsmKeyPropList,
    pub_key_props: *const AzihsmKeyPropList,
    priv_key_handle: *mut AzihsmHandle,
    pub_key_handle: *mut AzihsmHandle,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(pub_key_handle)?;
        validate_ptr(priv_key_handle)?;

        let algo = deref_ptr(algo)?;
        let props = deref_ptr(pub_key_props)?;
        let pub_key_props = HsmKeyProps::try_from(props)?;
        let props = deref_ptr(priv_key_props)?;
        let priv_key_props = HsmKeyProps::try_from(props)?;
        let session: HsmSession = HsmSession::try_from(sess_handle)?;

        // Generate key based on algorithm ID
        let (priv_key, pub_key) = match algo.id {
            AzihsmAlgoId::EcKeyPairGen => {
                ecc_generate_key_pair(&session, algo, priv_key_props, pub_key_props)?
            }
            AzihsmAlgoId::RsaKeyUnwrappingKeyPairGen => {
                rsa_generate_key_pair(&session, algo, priv_key_props, pub_key_props)?
            }

            // Unknown or unsupported algorithms
            _ => Err(AzihsmStatus::InvalidArgument)?,
        };

        assign_ptr(priv_key_handle, priv_key)?;
        assign_ptr(pub_key_handle, pub_key)?;

        Ok(())
    })
}

/// Delete a key from the HSM
///
/// @param[in] key_handle Handle to the key to delete
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is marked unsafe due to no_mangle.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_delete(key_handle: AzihsmHandle) -> AzihsmStatus {
    abi_boundary(|| {
        let key_type = HandleType::try_from(key_handle)?;

        match key_type {
            HandleType::AesKey => {
                let key: Box<HsmAesKey> = HANDLE_TABLE.free_handle(key_handle, key_type)?;
                key.delete_key()?;
            }
            HandleType::AesGcmKey => {
                let key: Box<HsmAesGcmKey> = HANDLE_TABLE.free_handle(key_handle, key_type)?;
                key.delete_key()?;
            }
            HandleType::AesXtsKey => {
                let key: Box<HsmAesXtsKey> = HANDLE_TABLE.free_handle(key_handle, key_type)?;
                key.delete_key()?;
            }
            HandleType::EccPrivKey => {
                let key: Box<HsmEccPrivateKey> = HANDLE_TABLE.free_handle(key_handle, key_type)?;
                key.delete_key()?;
            }
            HandleType::EccPubKey => {
                let key: Box<HsmEccPublicKey> = HANDLE_TABLE.free_handle(key_handle, key_type)?;
                key.delete_key()?;
            }
            HandleType::RsaPrivKey => {
                let _key: Box<HsmRsaPrivateKey> = HANDLE_TABLE.free_handle(key_handle, key_type)?;
                // [FIXME] Delete for HSM internal RSA private key should be no-op.
                //key.delete_key()?;
            }
            HandleType::RsaPubKey => {
                let key: Box<HsmRsaPublicKey> = HANDLE_TABLE.free_handle(key_handle, key_type)?;
                key.delete_key()?;
            }
            HandleType::GenericSecretKey => {
                let key: Box<HsmGenericSecretKey> =
                    HANDLE_TABLE.free_handle(key_handle, key_type)?;
                key.delete_key()?;
            }
            HandleType::HmacKey => {
                let key: Box<HsmHmacKey> = HANDLE_TABLE.free_handle(key_handle, key_type)?;
                key.delete_key()?;
            }
            _ => Err(AzihsmStatus::UnsupportedKeyKind)?,
        }

        Ok(())
    })
}

/// Derive a key from a base key
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] algo Pointer to algorithm specification
/// @param[in] base_key Handle to the base key
/// @param[in] key_props Pointer to key properties list for the derived key
/// @param[out] key_handle Pointer to store the derived key handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_derive(
    sess_handle: AzihsmHandle,
    algo: *mut AzihsmAlgo,
    base_key: AzihsmHandle,
    key_props: *const AzihsmKeyPropList,
    key_handle: *mut AzihsmHandle,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(key_handle)?;

        let algo = deref_ptr(algo)?;
        let props = deref_ptr(key_props)?;
        let derived_key_props = HsmKeyProps::try_from(props)?;
        let session = HsmSession::try_from(sess_handle)?;

        // Dispatch based on algorithm ID
        let handle = match algo.id {
            // ECDH derivation
            AzihsmAlgoId::Ecdh => ecdh_derive_key(&session, algo, base_key, derived_key_props)?,

            // HKDF derivation
            AzihsmAlgoId::HkdfDerive => {
                hkdf_derive_key(&session, algo, base_key, derived_key_props)?
            }

            _ => Err(AzihsmStatus::UnsupportedAlgorithm)?,
        };

        assign_ptr(key_handle, handle)?;
        Ok(())
    })
}

/// Unwrap a wrapped key using an unwrapping key
///
/// This function unwraps (decrypts) a previously wrapped key using the specified
/// unwrapping key and algorithm. The unwrapped key is imported into the HSM with
/// the provided key properties.
///
/// @param[in] algo Pointer to algorithm specification for unwrapping
/// @param[in] unwrapping_key Handle to the key used to unwrap (decrypt) the wrapped key
/// @param[in] wrapped_key Pointer to buffer containing the wrapped key data
/// @param[in] key_props Pointer to key properties list for the unwrapped key
/// @param[out] key_handle Pointer to store the unwrapped key handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_unwrap(
    algo: *mut AzihsmAlgo,
    unwrapping_key: AzihsmHandle,
    wrapped_key: *mut AzihsmBuffer,
    key_props: *const AzihsmKeyPropList,
    key_handle: *mut AzihsmHandle,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(key_handle)?;

        let algo = deref_mut_ptr(algo)?;
        let wrapped_key = deref_ptr(wrapped_key)?;
        let wrapped_key_buf: &[u8] = wrapped_key.try_into()?;

        let props = deref_ptr(key_props)?;
        let key_props = HsmKeyProps::try_from(props)?;

        // Dispatch based on algorithm ID
        let handle = match algo.id {
            AzihsmAlgoId::RsaAesKeyWrap => {
                rsa_unwrap_key(algo, unwrapping_key, wrapped_key_buf, key_props)?
            }
            _ => Err(AzihsmStatus::UnsupportedAlgorithm)?,
        };

        assign_ptr(key_handle, handle)?;

        Ok(())
    })
}

/// Unwrap a wrapped key pair using an unwrapping key
///
/// This function unwraps (decrypts) a previously wrapped key pair using the specified
/// unwrapping key and algorithm. The unwrapped key pair is imported into the HSM with
/// the provided key properties.
///
/// @param[in] algo Pointer to algorithm specification for unwrapping
/// @param[in] unwrapping_key Handle to the key used to unwrap (decrypt) the wrapped key pair
/// @param[in] wrapped_key Pointer to buffer containing the wrapped key pair data
/// @param[in] priv_key_props Pointer to private key properties list for the unwrapped key
/// @param[in] pub_key_props Pointer to public key properties list for the unwrapped key
/// @param[out] priv_key_handle Pointer to store the unwrapped private key handle
/// @param[out] pub_key_handle Pointer to store the unwrapped public key handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_unwrap_pair(
    algo: *mut AzihsmAlgo,
    unwrapping_key: AzihsmHandle,
    wrapped_key: *const AzihsmBuffer,
    priv_key_props: *const AzihsmKeyPropList,
    pub_key_props: *const AzihsmKeyPropList,
    priv_key_handle: *mut AzihsmHandle,
    pub_key_handle: *mut AzihsmHandle,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(priv_key_handle)?;
        validate_ptr(pub_key_handle)?;

        let algo = deref_mut_ptr(algo)?;
        let wrapped_key = deref_ptr(wrapped_key)?;
        let wrapped_key_buf: &[u8] = wrapped_key.try_into()?;

        let priv_props = deref_ptr(priv_key_props)?;
        let priv_key_props = HsmKeyProps::try_from(priv_props)?;

        let pub_props = deref_ptr(pub_key_props)?;
        let pub_key_props = HsmKeyProps::try_from(pub_props)?;

        // Dispatch based on algorithm ID
        let (priv_handle, pub_handle) = match algo.id {
            AzihsmAlgoId::RsaAesKeyWrap => rsa_unwrap_key_pair(
                algo,
                unwrapping_key,
                wrapped_key_buf,
                priv_key_props,
                pub_key_props,
            )?,
            _ => Err(AzihsmStatus::UnsupportedAlgorithm)?,
        };

        assign_ptr(priv_key_handle, priv_handle)?;
        assign_ptr(pub_key_handle, pub_handle)?;

        Ok(())
    })
}

/// Unmask a masked symmetric key
///
/// This function unmasks a previously masked symmetric key. The masked key contains
/// the key material and properties, so no external properties or unwrapping keys
/// are needed. The key is imported into the HSM within the provided session.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] key_kind The kind of key to unmask (e.g., AES)
/// @param[in] masked_key Pointer to buffer containing the masked key data
/// @param[out] key_handle Pointer to store the unmasked key handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_unmask(
    sess_handle: AzihsmHandle,
    key_kind: AzihsmKeyKind,
    masked_key: *const AzihsmBuffer,
    key_handle: *mut AzihsmHandle,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(key_handle)?;

        let session = HsmSession::try_from(sess_handle)?;
        let masked_key = deref_ptr(masked_key)?;
        let masked_key_buf: &[u8] = masked_key.try_into()?;

        // Dispatch based on key kind
        let handle = match key_kind {
            AzihsmKeyKind::Aes => aes_unmask_key(&session, masked_key_buf)?,
            AzihsmKeyKind::AesGcm => aes_gcm_unmask_key(&session, masked_key_buf)?,
            AzihsmKeyKind::AesXts => aes_xts_unmask_key(&session, masked_key_buf)?,
            AzihsmKeyKind::SharedSecret => secret_unmask_key(&session, masked_key_buf)?,
            AzihsmKeyKind::HmacSha256 | AzihsmKeyKind::HmacSha384 | AzihsmKeyKind::HmacSha512 => {
                hmac_unmask_key(&session, masked_key_buf)?
            }
            _ => Err(AzihsmStatus::UnsupportedKeyKind)?,
        };

        assign_ptr(key_handle, handle)?;

        Ok(())
    })
}

/// Unmask a masked key pair
///
/// This function unmasks a previously masked key pair. The masked key contains
/// the key material and properties, so no external properties or unwrapping keys
/// are needed. The key pair is imported into the HSM within the provided session.
///
/// @param[in] sess_handle Handle to the HSM session
/// @param[in] key_kind The kind of key pair to unmask (RSA or ECC)
/// @param[in] masked_key Pointer to buffer containing the masked key pair data
/// @param[out] priv_key_handle Pointer to store the unmasked private key handle
/// @param[out] pub_key_handle Pointer to store the unmasked public key handle
///
/// @return 0 on success, or a negative error code on failure
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_key_unmask_pair(
    sess_handle: AzihsmHandle,
    key_kind: AzihsmKeyKind,
    masked_key: *const AzihsmBuffer,
    priv_key_handle: *mut AzihsmHandle,
    pub_key_handle: *mut AzihsmHandle,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(priv_key_handle)?;
        validate_ptr(pub_key_handle)?;

        let session = HsmSession::try_from(sess_handle)?;
        let masked_key = deref_ptr(masked_key)?;
        let masked_key_buf: &[u8] = masked_key.try_into()?;

        // Dispatch based on key kind
        let (priv_handle, pub_handle) = match key_kind {
            AzihsmKeyKind::Rsa => rsa_unmask_key_pair(&session, masked_key_buf)?,
            AzihsmKeyKind::Ecc => ecc_unmask_key_pair(&session, masked_key_buf)?,
            _ => Err(AzihsmStatus::UnsupportedKeyKind)?,
        };

        assign_ptr(priv_key_handle, priv_handle)?;
        assign_ptr(pub_key_handle, pub_handle)?;

        Ok(())
    })
}

/// Generate a key attestation report
///
/// This function generates an attestation report for a key.
///
/// @param[in] key_handle Handle to the key to attest
/// @param[in] report_data Pointer to buffer containing custom data to include in the report (max 128 bytes)
/// @param[out] report Pointer to buffer to receive the attestation report
///
/// @return 0 on success, or a negative error code on failure
///
/// # Notes
/// - The function performs a two-pass operation: first to determine the required buffer
///   size, then to generate the actual report
/// - The report buffer's length field will be updated with the actual report size
///
/// @internal
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_generate_key_report(
    key_handle: AzihsmHandle,
    report_data: *const AzihsmBuffer,
    report: *mut AzihsmBuffer,
) -> AzihsmStatus {
    abi_boundary(|| {
        validate_ptr(report)?;

        let report_data = deref_ptr(report_data)?;
        let report_data_buf: &[u8] = report_data.try_into()?;
        let report_buf = deref_mut_ptr(report)?;

        let key_type = HandleType::try_from(key_handle)?;

        match key_type {
            HandleType::EccPrivKey => {
                ecc_generate_key_report(key_handle, report_data_buf, report_buf)?;
            }
            HandleType::RsaPrivKey => {
                rsa_generate_key_report(key_handle, report_data_buf, report_buf)?;
            }
            _ => Err(AzihsmStatus::UnsupportedKeyKind)?,
        }

        Ok(())
    })
}
