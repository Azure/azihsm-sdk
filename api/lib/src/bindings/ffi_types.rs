// Copyright (C) Microsoft Corporation. All rights reserved.
#![allow(unused_imports)]
#![allow(dead_code)]

use std::ffi::c_void;
use std::slice;

use crate::crypto::aes::AesCbcAlgo;
use crate::crypto::aes::AesXtsAlgo;
use crate::crypto::aes::AES_CBC_BLOCK_IV_LENGTH;
use crate::crypto::aes::AES_XTS_SECTOR_NUM_LEN;
use crate::crypto::ec::EcdsaAlgo;
use crate::crypto::ecdh::EcdhAlgo;
use crate::crypto::ecdh::EcdhParams;
use crate::crypto::hkdf::HkdfAlgo;
use crate::crypto::hkdf::HkdfAlgoParams;
use crate::crypto::hmac::HmacAlgo;
use crate::crypto::rsa::AlgoRsaAesKeyWrap;
use crate::crypto::rsa::AzihsmMgf1Id;
use crate::crypto::rsa::RsaAesKeyWrapParams;
use crate::crypto::rsa::RsaPkcs15Algo;
use crate::crypto::rsa::RsaPkcsOaepAlgo;
use crate::crypto::rsa::RsaPkcsOaepParams;
use crate::crypto::rsa::RsaPkcsPssAlgo;
use crate::crypto::rsa::RsaPkcsPssParams;
use crate::deref_const_ptr;
use crate::deref_mut_ptr;
use crate::types::AlgoId;
use crate::types::AzihsmKeyPropId;
use crate::types::KeyKind;
use crate::validate_conditions;
use crate::validate_pointers;
use crate::AzihsmError;
use crate::AZIHSM_ALGORITHM_NOT_SUPPORTED;
use crate::AZIHSM_ERROR_INVALID_ARGUMENT;
use crate::AZIHSM_OPERATION_NOT_SUPPORTED;

/// C FFI structure for a single key property
///
/// # Safety
/// When using this struct from C code:
/// - `val` must point to valid memory for `len` bytes
/// - `val` lifetime must exceed the lifetime of this struct
/// - Caller is responsible for proper memory management
///
#[repr(C)]
pub struct AzihsmKeyProp {
    pub id: AzihsmKeyPropId,
    pub val: *mut c_void,
    pub len: u32,
}

impl AzihsmKeyProp {
    /// Get property value as immutable slice
    #[allow(unsafe_code)]
    pub(crate) fn as_slice(&self) -> Result<&[u8], AzihsmError> {
        if self.val.is_null() {
            // Only allow null pointer if length is 0
            if self.len == 0 {
                Ok(&[])
            } else {
                Err(AZIHSM_ERROR_INVALID_ARGUMENT)
            }
        } else {
            // SAFETY: self.val is guaranteed to be non-null and valid for self.len bytes by the caller.
            Ok(unsafe { slice::from_raw_parts(self.val as *const u8, self.len as usize) })
        }
    }

    /// Get property value as mutable slice
    #[allow(unsafe_code)]
    pub(crate) fn as_mut_slice(&mut self) -> Result<&mut [u8], AzihsmError> {
        if self.val.is_null() {
            // Only allow null pointer if length is 0
            if self.len == 0 {
                Ok(&mut [])
            } else {
                Err(AZIHSM_ERROR_INVALID_ARGUMENT)
            }
        } else {
            // SAFETY: self.val is guaranteed to be non-null and valid for self.len bytes by the caller.
            Ok(unsafe { slice::from_raw_parts_mut(self.val as *mut u8, self.len as usize) })
        }
    }
}

/// C FFI structure for a list of key properties
///
/// # Safety
/// When using this struct from C code:
/// - `props` must point to valid memory for `count` elements
/// - Each element's `val` must point to valid memory for `len` bytes
/// - The lifetimes of `props` and its elements must exceed the lifetime of this struct
/// - Caller is responsible for proper memory management
///
#[repr(C)]
pub struct AzihsmKeyPropList {
    pub props: *mut AzihsmKeyProp,
    pub count: u32,
}

/// C FFI structure for algorithm specification
///
/// # Safety
/// When using this struct from C code:
/// - `params` must point to valid memory for `len` bytes if not null
/// - `params` lifetime must exceed the lifetime of this struct
/// - If `params` is null, `len` should be 0
/// - Caller is responsible for proper memory management of `params`
///
#[repr(C)]
pub struct AzihsmAlgo {
    pub id: AlgoId,
    pub params: *mut c_void,
    pub len: u32,
}

/// Trait for creating Rust algorithm objects from C algorithm FFI structures
pub(crate) trait AlgoConverter {
    /// Create a Rust algorithm object from a C algorithm FFI structure
    #[allow(unsafe_code)]
    unsafe fn from_algo(algo: &mut AzihsmAlgo) -> Result<Self, AzihsmError>
    where
        Self: Sized;

    /// Update the C algorithm FFI structure with the Rust algorithm object
    #[allow(unsafe_code)]
    unsafe fn update_algo(&self, _algo: &mut AzihsmAlgo) -> Result<(), AzihsmError> {
        Err(AZIHSM_OPERATION_NOT_SUPPORTED)
    }
}

impl AlgoConverter for AesCbcAlgo {
    #[allow(unsafe_code)]
    unsafe fn from_algo(algo: &mut AzihsmAlgo) -> Result<Self, AzihsmError> {
        if !matches!(algo.id, AlgoId::AesCbc | AlgoId::AesCbcPad) {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        validate_conditions!(
            algo.params.is_null(),
            algo.len < std::mem::size_of::<AzihsmAlgoAesCbcParams>() as u32
        );

        let params = deref_const_ptr!(algo.params as *const AzihsmAlgoAesCbcParams);

        let pkcs7_pad = matches!(algo.id, AlgoId::AesCbcPad);

        Ok(AesCbcAlgo::new(params.iv, pkcs7_pad))
    }

    // Note: algo params are checked for validity by the caller.
    #[allow(unsafe_code)]
    unsafe fn update_algo(&self, algo: &mut AzihsmAlgo) -> Result<(), AzihsmError> {
        if !matches!(algo.id, AlgoId::AesCbc | AlgoId::AesCbcPad) {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        let params = deref_mut_ptr!(algo.params as *mut AzihsmAlgoAesCbcParams);

        // Copy the modified IV back to the params structure
        params.iv = self.iv;

        Ok(())
    }
}

impl AlgoConverter for AesXtsAlgo {
    #[allow(unsafe_code)]
    unsafe fn from_algo(algo: &mut AzihsmAlgo) -> Result<Self, AzihsmError> {
        if !matches!(algo.id, AlgoId::AesXts) {
            Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?;
        }

        validate_conditions!(
            algo.params.is_null(),
            algo.len < std::mem::size_of::<AzihsmAlgoAesXtsParams>() as u32
        );

        let params = deref_const_ptr!(algo.params as *const AzihsmAlgoAesXtsParams);

        Ok(AesXtsAlgo {
            sector_num: params.sector_num,
            data_unit_len: (params.data_unit_len != 0).then_some(params.data_unit_len),
        })
    }
}

impl AlgoConverter for EcdsaAlgo {
    #[allow(unsafe_code)]
    unsafe fn from_algo(algo: &mut AzihsmAlgo) -> Result<Self, AzihsmError> {
        // Validate that this is an ECDSA algorithm
        if !matches!(
            algo.id,
            AlgoId::Ecdsa
                | AlgoId::EcdsaSha1
                | AlgoId::EcdsaSha256
                | AlgoId::EcdsaSha384
                | AlgoId::EcdsaSha512
        ) {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        // ECDSA algorithms typically don't need additional parameters
        // The algorithm ID contains all the information needed
        Ok(EcdsaAlgo::new(algo.id))
    }
}

impl AzihsmAlgo {
    /// Create a Rust algorithm object from the C algorithm FFI structure.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it dereferences raw pointers.
    /// The caller must ensure the algorithm type matches the expected parameter structure.
    #[allow(clippy::wrong_self_convention)]
    #[allow(unsafe_code)]
    pub(crate) unsafe fn from_algo<T>(&mut self) -> Result<T, AzihsmError>
    where
        T: AlgoConverter,
    {
        // SAFETY: The caller must ensure that `self` contains valid parameters for the expected algorithm type.
        unsafe { T::from_algo(self) }
    }
}

/// C FFI structure for a buffer
///
/// # Safety
/// When using this struct from C code:
/// - `buf` must point to valid memory for `len` bytes
/// - `buf` lifetime must exceed the lifetime of this struct
/// - Caller is responsible for proper memory management
#[repr(C)]
pub struct AzihsmBuffer {
    pub buf: *mut c_void,
    pub len: u32,
}

impl AzihsmBuffer {
    #[allow(unsafe_code)]
    pub(crate) fn as_slice(&self) -> Result<&[u8], AzihsmError> {
        if self.buf.is_null() {
            // Only allow null buffer if length is 0
            if self.len == 0 {
                Ok(&[])
            } else {
                Err(AZIHSM_ERROR_INVALID_ARGUMENT)
            }
        } else {
            // SAFETY: self.buf is guaranteed to be non-null and valid for self.len bytes by the caller.
            Ok(unsafe { slice::from_raw_parts(self.buf as *const u8, self.len as usize) })
        }
    }

    #[allow(unsafe_code)]
    pub(crate) fn as_mut_slice(&mut self) -> Result<&mut [u8], AzihsmError> {
        if self.buf.is_null() {
            // Only allow null buffer if length is 0
            if self.len == 0 {
                Ok(&mut [])
            } else {
                Err(AZIHSM_ERROR_INVALID_ARGUMENT)
            }
        } else {
            // SAFETY: self.buf is guaranteed to be non-null and valid for self.len bytes by the caller.
            Ok(unsafe { slice::from_raw_parts_mut(self.buf as *mut u8, self.len as usize) })
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len as usize
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// AES CBC parameters.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AzihsmAlgoAesCbcParams {
    /// IV
    pub iv: [u8; 16],
}

/// AES XTS parameters.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AzihsmAlgoAesXtsParams {
    /// Sector number
    pub sector_num: [u8; 16],
    /// Data unit length
    pub data_unit_len: u32,
}

/// RSA PKCS OAEP parameters.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AzihsmAlgoRsaPkcsOaepParams {
    /// Hash algorithm ID
    pub hash_algo_id: AlgoId,
    /// MGF1 hash algorithm ID
    pub mgf1_hash_algo_id: AzihsmMgf1Id,
    /// Label
    pub label: *const AzihsmBuffer,
}

/// RSA AES keywrap parameters.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AzihsmAlgoRsaAesKeyWrapParams {
    /// AES key bits
    pub aes_key_bits: u32,
    /// key type
    pub key_type: KeyKind,
    /// OAEP parameters
    pub oaep_params: *const AzihsmAlgoRsaPkcsOaepParams,
}

/// Implement Algo converter for RsaKeyWrap
impl AlgoConverter for AlgoRsaAesKeyWrap {
    #[allow(unsafe_code)]
    unsafe fn from_algo(algo: &mut AzihsmAlgo) -> Result<Self, AzihsmError> {
        if algo.id != AlgoId::RsaAesKeywrap {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        validate_conditions!(
            algo.params.is_null(),
            algo.len < std::mem::size_of::<AzihsmAlgoRsaAesKeyWrapParams>() as u32
        );

        let azihsm_rsa_key_wrap_params =
            deref_const_ptr!(algo.params as *const AzihsmAlgoRsaAesKeyWrapParams);

        // Deref oaep params if present
        validate_conditions!(azihsm_rsa_key_wrap_params.oaep_params.is_null());
        let azihsm_oaep_params = deref_const_ptr!(azihsm_rsa_key_wrap_params.oaep_params);

        // Extract and process the label first
        let label = if !azihsm_oaep_params.label.is_null() {
            let label_buffer = deref_const_ptr!(azihsm_oaep_params.label);
            if label_buffer.len > 0 {
                Some(label_buffer.as_slice()?.to_vec())
            } else {
                None
            }
        } else {
            None
        };

        // Initialize OAEP parameters
        let oaep_params = RsaPkcsOaepParams {
            hash_algo_id: azihsm_oaep_params.hash_algo_id,
            mgf1_hash_algo_id: azihsm_oaep_params.mgf1_hash_algo_id,
            label,
        };

        // Initialize the main key wrap parameters
        let rsa_key_wrap_params = RsaAesKeyWrapParams {
            aes_key_bits: azihsm_rsa_key_wrap_params.aes_key_bits,
            key_type: azihsm_rsa_key_wrap_params.key_type,
            oaep_params,
        };

        Ok(AlgoRsaAesKeyWrap {
            params: rsa_key_wrap_params,
        })
    }
}

// Implement Algo converter for RsaPkcs15Algo
impl AlgoConverter for RsaPkcs15Algo {
    #[allow(unsafe_code)]
    unsafe fn from_algo(algo: &mut AzihsmAlgo) -> Result<Self, AzihsmError> {
        // Validate that this is an RSA algorithm
        if !matches!(
            algo.id,
            AlgoId::RsaPkcs
                | AlgoId::RsaPkcsSha1
                | AlgoId::RsaPkcsSha256
                | AlgoId::RsaPkcsSha384
                | AlgoId::RsaPkcsSha512
        ) {
            Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?;
        }
        // RSA algorithms typically don't need additional parameters
        Ok(RsaPkcs15Algo::new(algo.id))
    }
}

// Implement algo converter for RsaPkcsPssAlgo

/// RSA PKCS OAEP parameters.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AzihsmAlgoRsaPkcsPssParams {
    /// Hash algorithm ID
    pub hash_algo_id: AlgoId,
    /// MGF1 hash algorithm ID
    pub mgf_id: AzihsmMgf1Id,
    /// salt length in bytes
    pub salt_len: u32,
}

impl AlgoConverter for RsaPkcsPssAlgo {
    #[allow(unsafe_code)]
    unsafe fn from_algo(algo: &mut AzihsmAlgo) -> Result<Self, AzihsmError> {
        // Validate that this is an RSA PSS algorithm
        if !matches!(
            algo.id,
            AlgoId::RsaPkcsPssSha1
                | AlgoId::RsaPkcsPssSha256
                | AlgoId::RsaPkcsPssSha384
                | AlgoId::RsaPkcsPssSha512
        ) {
            Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?;
        }
        // Start parsing AzihsmAlgoRsaPkcsPssParams
        validate_conditions!(
            algo.params.is_null(),
            algo.len < std::mem::size_of::<AzihsmAlgoRsaPkcsPssParams>() as u32
        );
        let azihsm_rsa_pkcs_pss_params =
            deref_const_ptr!(algo.params as *const AzihsmAlgoRsaPkcsPssParams);

        Ok(RsaPkcsPssAlgo::new(
            algo.id,
            RsaPkcsPssParams {
                hash_algo_id: azihsm_rsa_pkcs_pss_params.hash_algo_id,
                mgf_id: azihsm_rsa_pkcs_pss_params.mgf_id,
                salt_len: azihsm_rsa_pkcs_pss_params.salt_len,
            },
        ))
    }
}

// Implement Algoconverter for RSA PKCS OAEP Algo
impl AlgoConverter for RsaPkcsOaepAlgo {
    #[allow(unsafe_code)]
    unsafe fn from_algo(algo: &mut AzihsmAlgo) -> Result<Self, AzihsmError> {
        if algo.id != AlgoId::RsaPkcsOaep {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        validate_conditions!(
            algo.params.is_null(),
            algo.len < std::mem::size_of::<AzihsmAlgoRsaPkcsOaepParams>() as u32
        );

        let azihsm_oaep_params =
            deref_const_ptr!(algo.params as *const AzihsmAlgoRsaPkcsOaepParams);

        // Extract and process the label first
        let label = if !azihsm_oaep_params.label.is_null() {
            let label_buffer = deref_const_ptr!(azihsm_oaep_params.label);
            if label_buffer.len > 0 {
                Some(label_buffer.as_slice()?.to_vec())
            } else {
                None
            }
        } else {
            None
        };

        // Initialize OAEP parameters
        let oaep_params = RsaPkcsOaepParams {
            hash_algo_id: azihsm_oaep_params.hash_algo_id,
            mgf1_hash_algo_id: azihsm_oaep_params.mgf1_hash_algo_id,
            label,
        };

        Ok(RsaPkcsOaepAlgo {
            id: algo.id,
            params: oaep_params,
        })
    }

    #[allow(unsafe_code)]
    unsafe fn update_algo(&self, _algo: &mut AzihsmAlgo) -> Result<(), AzihsmError> {
        Err(AZIHSM_OPERATION_NOT_SUPPORTED)
    }
}

pub struct AzihsmAlgoEcdhAParams {
    pub pub_key: *const AzihsmBuffer,
}

impl AlgoConverter for EcdhAlgo {
    #[allow(unsafe_code)]
    unsafe fn from_algo(algo: &mut AzihsmAlgo) -> Result<Self, AzihsmError> {
        // Validate that this is an ECDH algorithm
        if !matches!(algo.id, AlgoId::Ecdh) {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }
        // Extract public key from params
        validate_conditions!(
            algo.params.is_null(),
            algo.len < std::mem::size_of::<AzihsmAlgoEcdhAParams>() as u32
        );

        let ecdh_params = deref_const_ptr!(algo.params as *const AzihsmAlgoEcdhAParams);

        validate_conditions!(ecdh_params.pub_key.is_null());
        let pub_key_buffer = deref_const_ptr!(ecdh_params.pub_key);
        validate_conditions!(pub_key_buffer.is_empty());
        let pub_key_slice = pub_key_buffer.as_slice()?;
        let ecdh_params = EcdhParams {
            pub_key: pub_key_slice.to_vec(),
        };
        Ok(EcdhAlgo {
            params: ecdh_params,
        })
    }
}

/// HKDF parameters.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AzihsmAlgoHkdfParams {
    /// HMAC Algorithm
    pub hmac_algo_id: AlgoId,
    /// Salt value
    pub salt: *const AzihsmBuffer,
    /// Info value
    pub info: *const AzihsmBuffer,
}

impl AlgoConverter for HkdfAlgo {
    #[allow(unsafe_code)]
    unsafe fn from_algo(algo: &mut AzihsmAlgo) -> Result<Self, AzihsmError> {
        if algo.id != AlgoId::HkdfDerive {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        validate_conditions!(
            algo.params.is_null(),
            algo.len < std::mem::size_of::<AzihsmAlgoHkdfParams>() as u32
        );

        let azihsm_hkdf_params = deref_const_ptr!(algo.params as *const AzihsmAlgoHkdfParams);
        // Extract and process the HMAC algorithm ID
        let hmac_algo_id = azihsm_hkdf_params.hmac_algo_id;

        // Extract and process the salt
        let salt = if !azihsm_hkdf_params.salt.is_null() {
            let salt_buffer = deref_const_ptr!(azihsm_hkdf_params.salt);
            if salt_buffer.len > 0 {
                Some(salt_buffer.as_slice()?.to_vec())
            } else {
                None
            }
        } else {
            None
        };

        // Extract and process the info next
        let info = if !azihsm_hkdf_params.info.is_null() {
            let info_buffer = deref_const_ptr!(azihsm_hkdf_params.info);
            if info_buffer.len > 0 {
                Some(info_buffer.as_slice()?.to_vec())
            } else {
                None
            }
        } else {
            None
        };
        // Construct Hkdf Algo Params
        let hkdf_params = HkdfAlgoParams {
            hmac_algo_id,
            salt,
            info,
        };
        Ok(HkdfAlgo {
            params: hkdf_params,
        })
    }
}

impl AlgoConverter for HmacAlgo {
    #[allow(unsafe_code)]
    unsafe fn from_algo(algo: &mut AzihsmAlgo) -> Result<Self, AzihsmError> {
        // Validate that this is an HMAC algorithm
        if !matches!(
            algo.id,
            AlgoId::HmacSha1 | AlgoId::HmacSha256 | AlgoId::HmacSha384 | AlgoId::HmacSha512
        ) {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        // HMAC algorithms typically don't need additional parameters
        // The algorithm ID contains all the information needed
        Ok(HmacAlgo { id: algo.id })
    }
}
