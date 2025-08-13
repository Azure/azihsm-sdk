// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::addr_of_mut;
use std::ptr::null_mut;
use std::sync::OnceLock;

use crate::d2i_RSA_PUBKEY;
use crate::openssl_log;
use crate::safeapi::error::*;
use crate::BN_new;
use crate::BN_pseudo_rand;
use crate::CRYPTO_get_ex_new_index;
use crate::RSA_free;
use crate::RSA_get_ex_data;
use crate::RSA_new;
use crate::RSA_set0_key;
use crate::RSA_set_ex_data;
use crate::CRYPTO_EX_INDEX_RSA;
use crate::RSA;

static RSA_KEY_DATA_IDX: OnceLock<c_int> = OnceLock::new();

fn get_or_init_rsa_key_data_idx() -> OpenSSLResult<c_int> {
    let data = RSA_KEY_DATA_IDX.get_or_init(|| unsafe {
        CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_RSA as c_int,
            0,
            null_mut(),
            None,
            None,
            None,
        )
    });

    if *data == -1 {
        Err(OpenSSLError::KeyDataIndexError)?;
    }

    Ok(*data)
}

pub struct RsaKey<T> {
    key: *mut RSA,
    _phantom: PhantomData<T>,
}

impl<T: Clone> RsaKey<T> {
    /// Create a new key object
    ///
    /// # Return
    /// Object, or error. Caller must free the key object.
    pub fn new() -> OpenSSLResult<Self> {
        let key = unsafe { RSA_new() };
        if key.is_null() {
            Err(OpenSSLError::AllocationFailed)?;
        }

        Ok(Self::new_from_ptr(key))
    }

    /// Create a new object from an existing pointer
    ///
    /// # Argument
    /// * `key` - a pointer to a key object
    ///
    /// # Return
    /// Key object from allocated pointer. The data will not be freed on drop.
    pub fn new_from_ptr(key: *mut RSA) -> Self {
        Self {
            key,
            _phantom: PhantomData,
        }
    }

    /// Get underlying RSA key pointer
    pub fn as_mut_ptr(&self) -> *mut RSA {
        self.key
    }

    /// Set data on key
    ///
    /// # Argument
    /// * `data` - data to set on key
    ///
    /// # Return
    /// Result of set data
    pub fn set_data(&mut self, data: T) -> OpenSSLResult<()> {
        let data_idx = get_or_init_rsa_key_data_idx()?;

        // Free any existing data
        self.free_data();

        let data_ptr = Box::into_raw(Box::new(data));

        if unsafe { RSA_set_ex_data(self.key, data_idx, data_ptr as *mut c_void) } == -1 {
            // Retake ownership to drop
            let _ = unsafe { Box::from_raw(data_ptr) };
            Err(OpenSSLError::KeyDataIndexError)?;
        }

        Ok(())
    }

    /// Reset the data on the key without freeing the existing data
    /// Use this with caution as it can lead to memory leaks.
    /// This method should only be used to reset the destination RSA key data to default state during key copy.
    /// For other use cases, use only `set_data` method without resetting the data first.
    ///
    /// Explanation: During the key copy operation, the data pointer in the source RSA object is copied to the destination RSA object
    /// by OpenSSL. Freeing this data on the destination RSA object will lead to double free error.
    ///
    /// # Return
    /// Result of reset data
    pub fn reset_data(&mut self) -> OpenSSLResult<()> {
        let data_idx = get_or_init_rsa_key_data_idx()?;
        if unsafe { RSA_set_ex_data(self.key, data_idx, null_mut()) } == -1 {
            Err(OpenSSLError::KeyDataIndexError)?;
        }

        Ok(())
    }

    /// Free the underlying key structure
    pub fn free_key(&mut self) {
        if self.key.is_null() {
            return;
        }

        unsafe {
            RSA_free(self.key);
        }

        self.key = null_mut();
    }

    /// Free the ancillary data attached to this object
    pub fn free_data(&mut self) {
        let data_idx = match get_or_init_rsa_key_data_idx() {
            Ok(idx) => idx,
            Err(_) => return,
        };
        let data_ptr = match self.get_data_ptr() {
            Ok(ptr) => ptr,
            Err(_) => return,
        };
        if data_ptr.is_null() {
            return;
        }

        // Drop the box
        let _: Box<T> = unsafe { Box::from_raw(data_ptr) };

        unsafe {
            RSA_set_ex_data(self.key, data_idx, null_mut());
        }
    }

    /// Completely free this key and all associated data
    pub fn free(&mut self) {
        self.free_data();
        self.free_key();
    }

    /// Get reference to data in the key
    ///
    /// # Return
    /// Pointer to data in key
    pub fn get_data(&self) -> OpenSSLResult<Option<&T>> {
        let data_idx = get_or_init_rsa_key_data_idx()?;

        // SAFETY: data already allocated
        let data = unsafe { RSA_get_ex_data(self.key, data_idx) } as *const T;
        if data.is_null() {
            return Ok(None);
        }

        // SAFETY: data is valid
        Ok(Some(unsafe { &*data }))
    }

    /// Get pointer to data in the key
    ///
    /// # Return
    /// Pointer to data in key
    pub fn get_data_ptr(&self) -> OpenSSLResult<*mut T> {
        let data_idx = get_or_init_rsa_key_data_idx()?;
        Ok(unsafe { RSA_get_ex_data(self.key, data_idx) as *mut T })
    }

    /// Create a new key object from a DER encoded public key
    /// Caller must free the key object.
    pub fn from_der(pub_key: Vec<u8>) -> OpenSSLResult<Self> {
        let der_key_len = pub_key.len() as i64;
        let mut key_ptr = pub_key.as_ptr();

        let raw_rsa_key = unsafe { d2i_RSA_PUBKEY(null_mut(), addr_of_mut!(key_ptr), der_key_len) };
        if raw_rsa_key.is_null() {
            openssl_log!(
                OpenSSLError::KeyGenerationError,
                tracing::Level::ERROR,
                "RsaKey::from_der: error parsing public key",
            );
            Err(OpenSSLError::KeyGenerationError)?;
        }
        let rsa_key: RsaKey<T> = RsaKey::new_from_ptr(raw_rsa_key);
        Ok(rsa_key)
    }

    /// Set an empty n parameter of the given size on the RSA key
    ///
    /// # Warning
    /// This clobbers any existing key n, e, and d parameters.
    pub fn set_n(&self, len: usize) {
        unsafe {
            // Create a random parameter of at least the given bit length.
            // The exact content doesn't matter, it only matters the size is correct.
            let n = BN_new();
            BN_pseudo_rand(n, len as c_int, 1, 1);
            RSA_set0_key(self.key, n, BN_new(), BN_new());
        }
    }
}
