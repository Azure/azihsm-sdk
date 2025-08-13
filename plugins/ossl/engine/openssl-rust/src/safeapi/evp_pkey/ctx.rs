// Copyright (C) Microsoft Corporation. All rights reserved.

use std::clone::Clone;
use std::ffi::c_int;
use std::ffi::c_uint;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::null_mut;

use crate::safeapi::ec::key::EcKey;
use crate::safeapi::engine::Engine;
use crate::safeapi::error::OpenSSLError;
use crate::safeapi::error::OpenSSLResult;
use crate::safeapi::evp_pkey::pkey::EvpPKey;
use crate::safeapi::rsa::key::RsaKey;
use crate::EVP_PKEY_CTX_dup;
use crate::EVP_PKEY_CTX_free;
use crate::EVP_PKEY_CTX_get0_pkey;
use crate::EVP_PKEY_CTX_get_data;
use crate::EVP_PKEY_CTX_new;
use crate::EVP_PKEY_CTX_new_id;
use crate::EVP_PKEY_CTX_set_data;
use crate::EVP_PKEY_CTX;

/// Wrapper for an EVP_PKEY_CTX
/// `cipher_data` member of EVP_PKEY_CTX is used to store the Engine PKey implementation specific data.
pub struct EvpPKeyCtx<T> {
    inner: *mut EVP_PKEY_CTX,
    is_allocated: bool,
    _phantom: PhantomData<T>,
}

impl<T: Clone> EvpPKeyCtx<T> {
    /// Construct a new `EvpPKeyCtx` object with an engine and pkey
    ///
    /// # Argument
    /// * `key` - `EvpPKey` object
    /// * `engine` - `Engine` object
    ///
    /// # Returns
    /// New `EvpPKeyCtx` object
    pub fn new(key: &EvpPKey, e: &Engine) -> OpenSSLResult<Self> {
        let inner = unsafe { EVP_PKEY_CTX_new(key.as_mut_ptr(), e.as_mut_ptr()) };
        if inner.is_null() {
            Err(OpenSSLError::AllocationFailed)?;
        }

        Ok(Self {
            inner,
            is_allocated: true,
            _phantom: PhantomData,
        })
    }

    /// Construct a new `EvpPKeyCtx` object with engine and nid
    ///
    /// # Argument
    /// * `id` - NID of the algorithm
    /// * `e` - `Engine` object
    ///
    /// # Returns
    /// New `EvpPKeyCtx` object
    pub fn new_from_id(id: c_uint, e: &Engine) -> OpenSSLResult<Self> {
        let inner = unsafe { EVP_PKEY_CTX_new_id(id as c_int, e.as_mut_ptr()) };
        if inner.is_null() {
            Err(OpenSSLError::AllocationFailed)?;
        }

        Ok(Self {
            inner,
            is_allocated: true,
            _phantom: PhantomData,
        })
    }

    /// Construct a new `EvpPKeyCtx` object from an existing pointer
    ///
    /// # Argument
    /// * `ctx` - The `EVP_PKEY_CTX` pointer
    ///
    /// # Returns
    /// * New `EvpPKeyCtx` object
    pub fn new_from_ptr(inner: *mut EVP_PKEY_CTX) -> Self {
        Self {
            inner,
            is_allocated: false,
            _phantom: PhantomData,
        }
    }

    /// Get an immutable pointer to the internal EVP_PKEY_CTX
    pub fn as_ptr(&self) -> *const EVP_PKEY_CTX {
        self.inner as *const EVP_PKEY_CTX
    }

    /// Get a mutable pointer to the internal EVP_PKEY_CTX
    pub fn as_mut_ptr(&self) -> *mut EVP_PKEY_CTX {
        self.inner
    }

    /// Set the data with this object, freeing any existing data.
    pub fn set_data(&self, data: T) {
        self.free_data();

        let data_ptr = Box::into_raw(Box::new(data));

        unsafe {
            EVP_PKEY_CTX_set_data(self.inner, data_ptr as *mut c_void);
        }
    }

    /// Get the data attached to this context
    ///
    /// # Return
    /// * `Option<&T>` - Will be none if data is not set
    pub fn get_data(&self) -> Option<&T> {
        let data_ptr = unsafe { EVP_PKEY_CTX_get_data(self.inner) } as *const T;
        if data_ptr.is_null() {
            return None;
        }

        Some(unsafe { &*data_ptr })
    }

    /// Free the internal data attached to this context
    pub fn free_data(&self) {
        let data_ptr = unsafe { EVP_PKEY_CTX_get_data(self.inner) } as *mut T;
        if data_ptr.is_null() {
            return;
        }

        // Drop the box
        let _: Box<T> = unsafe { Box::from_raw(data_ptr) };

        unsafe {
            EVP_PKEY_CTX_set_data(self.inner, null_mut());
        }
    }

    /// Get EVP_PKEY from data
    pub fn get_evp_pkey(&self) -> OpenSSLResult<EvpPKey> {
        let pkey_ptr = unsafe { EVP_PKEY_CTX_get0_pkey(self.inner) };
        if pkey_ptr.is_null() {
            Err(OpenSSLError::InvalidKey)?;
        }

        Ok(EvpPKey::new_from_ptr(pkey_ptr))
    }

    pub fn ec_key_from_pkey(&self) -> Option<EcKey<T>> {
        let pkey = self.get_evp_pkey().ok()?;
        let key_ptr = pkey.ec_key().ok()?;
        let ec_key: EcKey<T> = EcKey::new_from_ptr(key_ptr);
        Some(ec_key)
    }

    pub fn rsa_from_pkey(&self) -> Option<RsaKey<T>> {
        let pkey = self.get_evp_pkey().ok()?;
        let key_ptr = pkey.rsa().ok()?;
        let rsa_key: RsaKey<T> = RsaKey::new_from_ptr(key_ptr);
        Some(rsa_key)
    }

    pub fn dup(&self) -> Option<*mut EVP_PKEY_CTX> {
        let copy_ctx = unsafe { EVP_PKEY_CTX_dup(self.inner) };
        if copy_ctx.is_null() {
            return None;
        }
        Some(copy_ctx)
    }
}

impl<T> Drop for EvpPKeyCtx<T> {
    fn drop(&mut self) {
        if self.is_allocated {
            unsafe {
                EVP_PKEY_CTX_free(self.inner);
            }
        }
    }
}
