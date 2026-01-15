// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;

use super::*;
use crate::algo::aes::*;
use crate::algo::ecc::*;
use crate::algo::rsa::*;

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
) -> AzihsmError {
    abi_boundary(|| {
        validate_ptr(key_handle)?;

        let algo = deref_ptr(algo)?;
        let props = deref_ptr(key_props)?;
        let key_props = HsmKeyProps::try_from(props)?;
        let session: HsmSession = sess_handle.try_into()?;

        // Generate key based on algorithm ID
        let handle = match algo.id {
            // AES family algorithms
            AzihsmAlgoId::AesKeyGen => aes_generate_key(&session, algo, key_props)?,

            // Unknown or unsupported algorithms
            _ => Err(AzihsmError::InvalidArgument)?,
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
) -> AzihsmError {
    abi_boundary(|| {
        validate_ptr(pub_key_handle)?;
        validate_ptr(priv_key_handle)?;

        let algo = deref_ptr(algo)?;
        let props = deref_ptr(pub_key_props)?;
        let pub_key_props = HsmKeyProps::try_from(props)?;
        let props = deref_ptr(priv_key_props)?;
        let priv_key_props = HsmKeyProps::try_from(props)?;
        let session: HsmSession = sess_handle.try_into()?;

        // Generate key based on algorithm ID
        let (priv_key, pub_key) = match algo.id {
            AzihsmAlgoId::EcKeyPairGen => {
                ecc_generate_key_pair(&session, algo, priv_key_props, pub_key_props)?
            }
            AzihsmAlgoId::RsaKeyUnwrappingKeyPairGen => {
                rsa_generate_key_pair(&session, algo, priv_key_props, pub_key_props)?
            }

            // Unknown or unsupported algorithms
            _ => Err(AzihsmError::InvalidArgument)?,
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
pub unsafe extern "C" fn azihsm_key_delete(key_handle: AzihsmHandle) -> AzihsmError {
    abi_boundary(|| {
        let key_type: HandleType = key_handle.try_into()?;

        match key_type {
            HandleType::AesKey => {
                let key: Box<HsmAesKey> = HANDLE_TABLE.free_handle(key_handle, key_type)?;
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
            _ => Err(AzihsmError::UnsupportedKeyKind)?,
        }

        Ok(())
    })
}
