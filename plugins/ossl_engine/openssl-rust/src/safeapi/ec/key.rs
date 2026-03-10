// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::addr_of_mut;
use std::ptr::null_mut;
use std::sync::OnceLock;

use crate::d2i_EC_PUBKEY;
use crate::i2d_EC_PUBKEY;
use crate::openssl_log;
use crate::safeapi::error::OpenSSLError;
use crate::safeapi::error::OpenSSLResult;
use crate::BN_free;
use crate::BN_new;
use crate::CRYPTO_get_ex_new_index;
use crate::EC_GROUP_get_curve_name;
use crate::EC_GROUP_new_by_curve_name;
use crate::EC_KEY_free;
use crate::EC_KEY_generate_key;
use crate::EC_KEY_get0_group;
use crate::EC_KEY_get0_public_key;
use crate::EC_KEY_get_ex_data;
use crate::EC_KEY_get_flags;
use crate::EC_KEY_new;
use crate::EC_KEY_set_ex_data;
use crate::EC_KEY_set_flags;
use crate::EC_KEY_set_group;
use crate::EC_KEY_set_public_key;
use crate::EC_POINT_get_affine_coordinates_GFp;
use crate::EC_POINT_new;
use crate::EC_POINT_set_affine_coordinates_GFp;
use crate::BIGNUM;
use crate::CRYPTO_EX_INDEX_EC_KEY;
use crate::EC_GROUP;
use crate::EC_KEY;
use crate::EC_POINT;

static EC_KEY_DATA_IDX: OnceLock<c_int> = OnceLock::new();

fn get_or_init_ec_key_data_idx() -> OpenSSLResult<c_int> {
    let data = EC_KEY_DATA_IDX.get_or_init(|| unsafe {
        CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_EC_KEY as c_int,
            0,
            null_mut(),
            None,
            None,
            None,
        )
    });

    if *data == -1 {
        openssl_log!(
            OpenSSLError::KeyDataIndexError,
            tracing::Level::ERROR,
            "get_or_init_ec_key_data_idx: could not get index",
        );
        Err(OpenSSLError::KeyDataIndexError)?;
    }

    Ok(*data)
}

pub struct EcKey<T> {
    key: *mut EC_KEY,
    _phantom: PhantomData<T>,
}

impl<T: Clone> EcKey<T> {
    /// Create a new key object
    ///
    /// # Return
    /// Object, or error. Caller must free the key object.
    pub fn new() -> OpenSSLResult<Self> {
        let key = unsafe { EC_KEY_new() };
        if key.is_null() {
            openssl_log!(
                OpenSSLError::AllocationFailed,
                tracing::Level::ERROR,
                "EcKey::new: Could not allocate new EC_KEY",
            );
            Err(OpenSSLError::AllocationFailed)?;
        }

        Ok(Self::new_from_ptr(key))
    }

    /// Create a new object from an existing pointer
    ///
    /// # Argument
    /// * key - a pointer to a key object
    ///
    /// # Return
    /// Key object from allocated pointer. The data will not be freed on drop.
    pub fn new_from_ptr(key: *mut EC_KEY) -> Self {
        Self {
            key,
            _phantom: PhantomData,
        }
    }

    /// Create a new key object from an existing public key (EC_POINT)
    ///
    /// # Argument
    /// * ec_point - a pointer to a public key object
    /// * curve_name - the curve name
    ///
    /// # Return
    /// Result of the Key object creation from public key.
    /// Caller must free the key object.
    pub fn new_from_pubkey(ec_point: *const EC_POINT, curve_name: i32) -> OpenSSLResult<Self> {
        let mut ec_key: EcKey<T> = Self::new()?;
        ec_key.set_key_group_by_name(curve_name).inspect_err(|_| {
            ec_key.free();
        })?;
        ec_key.set_public_key(ec_point)?;
        Ok(ec_key)
    }

    /// Set data on key
    ///
    /// # Argument
    /// * data - data to set on key
    ///
    /// # Return
    /// Result of set data
    pub fn set_data(&mut self, data: T) -> OpenSSLResult<()> {
        let data_idx = get_or_init_ec_key_data_idx()?;

        // Free any existing data
        self.free_data();

        let data_ptr = Box::into_raw(Box::new(data));

        if unsafe { EC_KEY_set_ex_data(self.key, data_idx, data_ptr as *mut c_void) } == -1 {
            // Retake ownership to drop
            let _ = unsafe { Box::from_raw(data_ptr) };
            openssl_log!(
                OpenSSLError::KeyDataIndexError,
                tracing::Level::ERROR,
                "EcKey::set_data: could not set data",
            );
            Err(OpenSSLError::KeyDataIndexError)?;
        }

        Ok(())
    }

    /// Reset data to nullptr on key without freeing the existing data.
    /// Use this with caution as it can lead to memory leaks.
    /// This method should only be used to reset the destination EC_KEY data to a default state during key copy callback.
    /// For other use cases, only use `set_data` without resetting the data first.
    ///
    /// Explanation: During the key copy call, the data pointer in the EC_KEY is copied from the source to destination by OpenSSL.
    /// Freeing this data will lead to double free.
    ///
    /// # Return
    /// Result of reset data
    pub fn reset_data(&mut self) -> OpenSSLResult<()> {
        let data_idx = get_or_init_ec_key_data_idx()?;

        if unsafe { EC_KEY_set_ex_data(self.key, data_idx, null_mut()) } == -1 {
            openssl_log!(
                OpenSSLError::KeyDataIndexError,
                tracing::Level::ERROR,
                "EcKey::reset_data: could not set data",
            );
            Err(OpenSSLError::KeyDataIndexError)?;
        }

        Ok(())
    }

    /// Generate key with current key pointer
    ///
    /// # Return
    /// Result of key generation
    pub fn generate_key(&self) -> OpenSSLResult<()> {
        let result = unsafe { EC_KEY_generate_key(self.key) };
        if result == 0 {
            openssl_log!(
                OpenSSLError::KeyDataIndexError,
                tracing::Level::ERROR,
                "EcKey::generate_key: error generating key",
            );
            Err(OpenSSLError::KeyGenerationError)?;
        }

        Ok(())
    }

    /// Sets the DER encoded public key as EC_POINT in the EC_KEY
    ///
    /// # Argument
    /// * pub_key_der: DER encoded public key
    ///
    /// # Return
    /// Result of setting the public key
    pub fn set_pubkey_der(&mut self, pub_key_der: Vec<u8>) -> OpenSSLResult<()> {
        // Create a new EC_KEY from der.
        let mut pub_ec_key: EcKey<T> = EcKey::from_der(pub_key_der)?;
        if self.curve_name()? != pub_ec_key.curve_name()? {
            openssl_log!(
                OpenSSLError::KeyGenerationError,
                tracing::Level::ERROR,
                "EcKey::set_pubkey_der: error getting curve name",
            );
            Err(OpenSSLError::KeyGenerationError)?;
        }

        // Allocate X & Y Bignums
        let x: *mut BIGNUM = unsafe { BN_new() };
        if x.is_null() {
            openssl_log!(
                OpenSSLError::KeyGenerationError,
                tracing::Level::ERROR,
                "EcKey::set_pubkey_der: error generating x coordinate",
            );
            Err(OpenSSLError::KeyGenerationError)?;
        }
        let y: *mut BIGNUM = unsafe { BN_new() };
        if y.is_null() {
            openssl_log!(
                OpenSSLError::KeyGenerationError,
                tracing::Level::ERROR,
                "EcKey::set_pubkey_der: error generating y coordinate",
            );
            Err(OpenSSLError::KeyGenerationError)?;
        }

        // Extract the affine coordinates of the public key
        pub_ec_key.get_affine_coordinates(x, y)?;

        // Set the affine coordinates on the EC_KEY
        self.set_affine_coordinates(x, y)?;

        // Free the Bignums and the pub_ec_key
        unsafe {
            BN_free(x);
            BN_free(y);
        }
        pub_ec_key.free();
        Ok(())
    }

    /// Get the DER encoded public key
    ///
    /// # Return
    /// DER encoded public key in Vec<u8> format
    pub fn get_pubkey_der(&self) -> OpenSSLResult<Vec<u8>> {
        let der_len = self.get_pubkey_der_len()?;
        let mut der = vec![0u8; der_len as usize];

        let mut der_ptr = der.as_mut_ptr();
        let result = unsafe { i2d_EC_PUBKEY(self.key, addr_of_mut!(der_ptr)) };
        if result == 0 {
            openssl_log!(
                OpenSSLError::KeyGenerationError,
                tracing::Level::ERROR,
                "EcKey::get_pubkey_der: error retrieving pubkey",
            );
            Err(OpenSSLError::KeyGenerationError)?;
        }
        Ok(der)
    }

    /// Free the underlying key structure
    pub fn free_key(&mut self) {
        if self.key.is_null() {
            return;
        }

        unsafe {
            EC_KEY_free(self.key);
        }

        self.key = null_mut();
    }

    /// Free the ancillary data attached to this object
    pub fn free_data(&mut self) {
        let data_idx = match get_or_init_ec_key_data_idx() {
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
            EC_KEY_set_ex_data(self.key, data_idx, null_mut());
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
        let data_idx = get_or_init_ec_key_data_idx()?;

        let data = unsafe { EC_KEY_get_ex_data(self.key, data_idx) } as *const T;
        if data.is_null() {
            return Ok(None);
        }

        Ok(Some(unsafe { &*data }))
    }

    /// Get pointer to data in the key
    ///
    /// # Return
    /// Pointer to data in key
    pub fn get_data_ptr(&self) -> OpenSSLResult<*mut T> {
        let data_idx = get_or_init_ec_key_data_idx()?;

        Ok(unsafe { EC_KEY_get_ex_data(self.key, data_idx) as *mut T })
    }

    /// Get OpenSSL EC key curve name
    ///
    /// # Return
    /// NID for key
    pub fn curve_name(&self) -> OpenSSLResult<i32> {
        let group = self.group()?;

        let result = unsafe { EC_GROUP_get_curve_name(group) };
        if result == 0 {
            openssl_log!(
                OpenSSLError::EcMissingCurveName,
                tracing::Level::ERROR,
                "EcKey::curve_name: error getting curve name",
            );
            Err(OpenSSLError::EcMissingCurveName)?;
        }
        Ok(result)
    }

    /// Get OpenSSL EC key group
    ///
    /// # Return
    /// a mutable pointer to the EC_GROUP of the key
    pub fn group(&self) -> OpenSSLResult<*mut EC_GROUP> {
        let result = unsafe { EC_KEY_get0_group(self.key) };
        if result.is_null() {
            openssl_log!(
                OpenSSLError::KeyGenerationError,
                tracing::Level::ERROR,
                "EcKey::group: error retrieving group",
            );
            Err(OpenSSLError::KeyGenerationError)?;
        }
        Ok(result as *mut EC_GROUP)
    }

    /// Set OpenSSL key group name
    ///
    /// # Argument
    /// * nid: NID of the curve
    ///
    /// # Return
    /// Result of setting the key group
    pub fn set_key_group_by_name(&self, nid: c_int) -> OpenSSLResult<()> {
        let group = unsafe { EC_GROUP_new_by_curve_name(nid) };
        if group.is_null() {
            openssl_log!(
                OpenSSLError::UnsupportedKeyType,
                tracing::Level::ERROR,
                "EcKey::set_key_group_by_name: invalid group",
            );
            Err(OpenSSLError::UnsupportedKeyType)?;
        }

        if unsafe { EC_KEY_set_group(self.key, group) } == 0 {
            openssl_log!(
                OpenSSLError::UnsupportedKeyType,
                tracing::Level::ERROR,
                "EcKey::set_key_group_by_name: unsupported group type",
            );
            Err(OpenSSLError::UnsupportedKeyType)?;
        }

        Ok(())
    }

    /// Get pointer to underlying OpenSSL key
    pub fn as_mut_ptr(&self) -> *mut EC_KEY {
        self.key
    }

    /// Get the flags of the key
    pub fn flags(&self) -> c_int {
        unsafe { EC_KEY_get_flags(self.key) }
    }

    /// Check if the key contains a specific flag
    pub fn contains_flag(&self, flag: i32) -> bool {
        let flags = self.flags();
        flags & flag != 0
    }

    /// Set the flags of the key
    ///
    /// # Argument
    /// * flags: flags to set
    ///
    /// # Return
    /// Result of setting the flags
    pub fn set_flags(&self, flags: c_int) {
        unsafe {
            EC_KEY_set_flags(self.key, flags);
        }
    }

    /// Get OpenSSL EC key point
    ///
    /// # Return
    /// a pointer to the EC_POINT of the key
    pub fn ec_point(&self) -> OpenSSLResult<*const EC_POINT> {
        let pubkey = unsafe { EC_KEY_get0_public_key(self.key) };
        if pubkey.is_null() {
            openssl_log!(
                OpenSSLError::KeyGenerationError,
                tracing::Level::ERROR,
                "EcKey::ec_point: error getting public key",
            );
            Err(OpenSSLError::KeyGenerationError)?;
        }
        Ok(pubkey)
    }

    /// Create a new key object from a DER encoded public key
    /// Caller must free the key object.
    pub fn from_der(pub_key: Vec<u8>) -> OpenSSLResult<Self> {
        let der_key_len = pub_key.len() as i64;
        let mut key_ptr = pub_key.as_ptr();

        let raw_ec_key = unsafe { d2i_EC_PUBKEY(null_mut(), addr_of_mut!(key_ptr), der_key_len) };
        if raw_ec_key.is_null() {
            openssl_log!(
                OpenSSLError::KeyGenerationError,
                tracing::Level::ERROR,
                "EcKey::raw_ec_key: error parsing public key",
            );
            Err(OpenSSLError::KeyGenerationError)?;
        }
        let ec_key: EcKey<T> = EcKey::new_from_ptr(raw_ec_key);
        Ok(ec_key)
    }

    /// Get the affine coordinates from the public key in the EC_KEY
    fn get_affine_coordinates(&self, x: *mut BIGNUM, y: *mut BIGNUM) -> OpenSSLResult<()> {
        let group = self.group()?;
        let ec_point = self.ec_point()?;
        let result =
            unsafe { EC_POINT_get_affine_coordinates_GFp(group, ec_point, x, y, null_mut()) };
        if result == 0 {
            openssl_log!(
                OpenSSLError::KeyGenerationError,
                tracing::Level::ERROR,
                "EcKey::get_affine_coordinates: error getting affine coordinates",
            );
            Err(OpenSSLError::KeyGenerationError)?;
        }
        Ok(())
    }

    /// Set the affine coordinates on the EC_KEY
    fn set_affine_coordinates(&self, x: *const BIGNUM, y: *const BIGNUM) -> OpenSSLResult<()> {
        let group = self.group()?;
        let new_ec_point = unsafe { EC_POINT_new(group) };
        if new_ec_point.is_null() {
            Err(OpenSSLError::KeyGenerationError)?;
        }

        let result =
            unsafe { EC_POINT_set_affine_coordinates_GFp(group, new_ec_point, x, y, null_mut()) };
        if result == 0 {
            openssl_log!(
                OpenSSLError::KeyGenerationError,
                tracing::Level::ERROR,
                "EcKey::set_affine_coordinates: error setting affine coordinates",
            );
            Err(OpenSSLError::KeyGenerationError)?;
        }

        self.set_public_key(new_ec_point)?;
        Ok(())
    }

    /// Set the public key(EC_POINT) on the EC_KEY
    fn set_public_key(&self, point: *const EC_POINT) -> OpenSSLResult<()> {
        let result = unsafe { EC_KEY_set_public_key(self.key, point) };
        if result == 0 {
            openssl_log!(
                OpenSSLError::KeyGenerationError,
                tracing::Level::ERROR,
                "EcKey::set_public_key: error setting public key",
            );
            Err(OpenSSLError::KeyGenerationError)?;
        }
        Ok(())
    }

    /// Get the length of the DER encoded public key
    fn get_pubkey_der_len(&self) -> OpenSSLResult<i32> {
        let len = unsafe { i2d_EC_PUBKEY(self.key, null_mut()) };
        if len == 0 {
            openssl_log!(
                OpenSSLError::KeyGenerationError,
                tracing::Level::ERROR,
                "EcKey::get_pubkey_der_len: error getting DER from key",
            );
            Err(OpenSSLError::KeyGenerationError)?;
        }
        Ok(len)
    }
}
