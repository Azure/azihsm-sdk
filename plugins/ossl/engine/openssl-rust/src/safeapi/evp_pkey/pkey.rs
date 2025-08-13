// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ffi::c_long;
use std::ffi::c_uint;
use std::ffi::c_void;
use std::ptr::addr_of_mut;
use std::ptr::null_mut;

use crate::d2i_PrivateKey;
use crate::safeapi::error::*;
use crate::safeapi::evp_pkey::method::EvpPKeyType;
use crate::EVP_PKEY_assign;
#[cfg(feature = "openssl_111")]
use crate::EVP_PKEY_base_id;
use crate::EVP_PKEY_copy_parameters;
use crate::EVP_PKEY_free;
use crate::EVP_PKEY_get0_EC_KEY;
use crate::EVP_PKEY_get0_RSA;
#[cfg(feature = "openssl_3")]
use crate::EVP_PKEY_get_base_id;
use crate::EVP_PKEY_new;
use crate::EC_KEY;
use crate::EVP_PKEY;
use crate::EVP_PKEY_EC;
use crate::EVP_PKEY_RSA;
use crate::RSA;

/// This wraps an EVP_PKEY pointer
pub struct EvpPKey {
    key: *mut EVP_PKEY,
    allocated: bool,
}

impl EvpPKey {
    /// Create a new EvpPKey
    ///
    /// # Returns
    /// Result of the new EvpPKey creation
    pub fn new() -> OpenSSLResult<Self> {
        let key = unsafe { EVP_PKEY_new() };
        if key.is_null() {
            Err(OpenSSLError::AllocationFailed)?;
        }
        Ok(Self {
            key,
            allocated: true,
        })
    }

    /// Create a new EvpPKey that will not be freed on drop
    ///
    /// # Returns
    /// Result of the new EvpPKey creation
    pub fn new_unowned() -> OpenSSLResult<Self> {
        let key = unsafe { EVP_PKEY_new() };
        if key.is_null() {
            Err(OpenSSLError::AllocationFailed)?;
        }
        Ok(Self {
            key,
            allocated: false,
        })
    }

    /// Create a new EvpPKey (private) from DER
    ///
    /// # Argument
    /// * `key_type` - Key type
    /// * `key` - Slice to private key in DER format
    ///
    /// # Returns
    /// Result of the new EvpPkey creation from DER
    /// Caller must free the returned object
    pub fn new_from_private_der(key_type: EvpPKeyType, key: &[u8]) -> OpenSSLResult<Self> {
        let mut key_ptr = key.as_ptr();
        let result = unsafe {
            d2i_PrivateKey(
                key_type.pkey_type() as c_int,
                null_mut(),
                addr_of_mut!(key_ptr),
                key.len() as c_long,
            )
        };
        if result.is_null() {
            Err(OpenSSLError::AllocationFailed)?;
        }
        Ok(Self::new_from_ptr(result))
    }

    /// Free an allocated EvpPKey
    pub fn free(&mut self) {
        if !self.key.is_null() {
            unsafe {
                EVP_PKEY_free(self.key);
            }
            self.key = null_mut();
        }
    }

    /// Create a new EvpPKey from a pointer
    ///
    /// # Argument
    /// * `key` - Raw pointer to EVP_PKEY
    ///
    /// # Returns
    /// New EvpPKey from pointer
    pub fn new_from_ptr(key: *mut EVP_PKEY) -> Self {
        Self {
            key,
            allocated: false,
        }
    }

    /// Get mutable pointer to EVP_PKEY
    pub fn as_mut_ptr(&self) -> *mut EVP_PKEY {
        self.key
    }

    fn get_nid(&self) -> c_int {
        #[cfg(feature = "openssl_3")]
        unsafe {
            EVP_PKEY_get_base_id(self.key)
        }
        #[cfg(feature = "openssl_111")]
        unsafe {
            EVP_PKEY_base_id(self.key)
        }
    }

    /// Get the key type
    ///
    /// # Returns
    /// Result of the key type
    pub fn key_type(&self) -> OpenSSLResult<EvpPKeyType> {
        let nid = self.get_nid();
        EvpPKeyType::from_nid(nid as c_uint)
    }

    /// Get EC_KEY pointer from EvpPKey
    /// Caller must free the returned object
    ///
    /// # Returns
    /// Result of the get EC_KEY ptr from EvpPKey
    pub fn ec_key(&self) -> OpenSSLResult<*mut EC_KEY> {
        let key_ptr = unsafe { EVP_PKEY_get0_EC_KEY(self.key) };
        if key_ptr.is_null() {
            Err(OpenSSLError::InvalidKey)?;
        }
        Ok(key_ptr as *mut EC_KEY)
    }

    /// Assign EC_KEY to EVP_PKEY
    ///
    /// # Argument
    /// * `key_ptr` - Raw pointer to EC_KEY
    ///
    /// # Returns
    /// Result of the EC_KEY key assignment
    pub fn assign_ec_key(&self, key_ptr: *mut EC_KEY) -> OpenSSLResult<()> {
        let result =
            unsafe { EVP_PKEY_assign(self.key, EVP_PKEY_EC as c_int, key_ptr as *mut c_void) };
        if result != 1 {
            Err(OpenSSLError::InvalidKey)?;
        }
        Ok(())
    }

    /// Get RSA pointer from EvpPKey
    /// Caller must free the returned object
    ///
    /// # Returns
    /// Result of the get RSA ptr from EvpPKey
    pub fn rsa(&self) -> OpenSSLResult<*mut RSA> {
        let key_ptr = unsafe { EVP_PKEY_get0_RSA(self.key) };
        if key_ptr.is_null() {
            Err(OpenSSLError::InvalidKey)?;
        }
        Ok(key_ptr as *mut RSA)
    }

    /// Assign RSA to EVP_PKEY
    ///
    /// # Argument
    /// * `key_ptr` - Raw pointer to RSA
    ///
    /// # Returns
    /// Result of the RSA key assignment
    pub fn assign_rsa(&self, key_ptr: *mut RSA) -> OpenSSLResult<()> {
        let result =
            unsafe { EVP_PKEY_assign(self.key, EVP_PKEY_RSA as c_int, key_ptr as *mut c_void) };
        if result != 1 {
            Err(OpenSSLError::InvalidKey)?;
        }
        Ok(())
    }

    /// Copy parameters from source pkey
    ///
    /// # Argument
    /// * `src` - Source pkey
    ///
    /// # Returns
    /// Result of the copy parameters from source pkey
    pub fn copy_parameters(&self, src: &EvpPKey) -> OpenSSLResult<()> {
        let result = unsafe { EVP_PKEY_copy_parameters(self.key, src.key) };
        if result != 1 {
            Err(OpenSSLError::InvalidKey)?;
        }
        Ok(())
    }
}

impl Drop for EvpPKey {
    fn drop(&mut self) {
        if self.allocated {
            self.free();
        }
    }
}
