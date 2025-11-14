// Copyright (C) Microsoft Corporation. All rights reserved.
#![allow(unused_imports)]
#![allow(dead_code)]

use std::ffi::c_void;
use std::slice;

use crate::crypto::aes::AesCbcAlgo;
use crate::crypto::aes::AES_CBC_BLOCK_IV_LENGTH;
use crate::crypto::ec::EcdsaAlgo;
use crate::deref_const_ptr;
use crate::deref_mut_ptr;
use crate::types::AlgoId;
use crate::types::AzihsmKeyPropId;
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
            Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?;
        }

        validate_conditions!(
            algo.params.is_null(),
            algo.len < std::mem::size_of::<AzihsmAlgoAesCbcParams>() as u32
        );

        let params = deref_const_ptr!(algo.params as *const AzihsmAlgoAesCbcParams);
        validate_pointers!(params.iv);

        let iv_buffer = deref_mut_ptr!(params.iv);

        validate_conditions!(
            iv_buffer.buf.is_null(),
            iv_buffer.len != AES_CBC_BLOCK_IV_LENGTH as u32
        );

        let iv_slice = iv_buffer.as_slice()?;

        let mut iv = [0u8; AES_CBC_BLOCK_IV_LENGTH];
        iv.copy_from_slice(iv_slice);

        let pkcs7_pad = matches!(algo.id, AlgoId::AesCbcPad);

        Ok(AesCbcAlgo::new(iv, pkcs7_pad))
    }

    // Note: algo params are checked for validity by the caller.
    #[allow(unsafe_code)]
    unsafe fn update_algo(&self, algo: &mut AzihsmAlgo) -> Result<(), AzihsmError> {
        if !matches!(algo.id, AlgoId::AesCbc | AlgoId::AesCbcPad) {
            Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?;
        }

        let params = deref_const_ptr!(algo.params as *const AzihsmAlgoAesCbcParams);

        let iv_buffer = deref_mut_ptr!(params.iv);

        let iv_slice = iv_buffer.as_mut_slice()?;

        // Copy the modified IV back to the original buffer
        iv_slice.copy_from_slice(&self.iv);

        Ok(())
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
            Err(AZIHSM_ALGORITHM_NOT_SUPPORTED)?;
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
        if self.buf.is_null() || self.len == 0 {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)
        } else {
            // SAFETY: self.buf is guaranteed to be non-null and valid for self.len bytes by the caller.
            Ok(unsafe { slice::from_raw_parts(self.buf as *const u8, self.len as usize) })
        }
    }

    #[allow(unsafe_code)]
    pub(crate) fn as_mut_slice(&mut self) -> Result<&mut [u8], AzihsmError> {
        if self.buf.is_null() || self.len == 0 {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)
        } else {
            // SAFETY: self.buf is guaranteed to be non-null and valid for self.len bytes by the caller.
            Ok(unsafe { slice::from_raw_parts_mut(self.buf as *mut u8, self.len as usize) })
        }
    }

    pub(crate) fn is_valid(&self) -> bool {
        !self.buf.is_null() && self.len > 0
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
    pub iv: *mut AzihsmBuffer,
}
