// Copyright (C) Microsoft Corporation. All rights reserved.

//! C-facing API for importing key data

use std::ffi::CStr;
use std::marker::PhantomData;
use std::slice::from_raw_parts;

use mcr_api::DigestKind;
use mcr_api::KeyAvailability;
use mcr_api::KeyUsage;
use openssl_rust::safeapi::error::OpenSSLError;
use openssl_rust::safeapi::error::OpenSSLResult;

use crate::AziHsmDigestKind;
use crate::AziHsmKeyAvailability;
use crate::AziHsmKeyImport;
use crate::AziHsmKeyUsage;

pub struct KeyImport<T> {
    inner: *mut AziHsmKeyImport,
    _phantom: PhantomData<T>,
}

impl<T> KeyImport<T> {
    pub fn new(c_data: *mut AziHsmKeyImport) -> OpenSSLResult<Self> {
        if c_data.is_null() {
            Err(OpenSSLError::InvalidWrappedKey)?;
        }

        Ok(Self {
            inner: c_data,
            _phantom: PhantomData,
        })
    }

    pub fn wrapped_key_slice(&self) -> OpenSSLResult<&[u8]> {
        if unsafe { (*self.inner).wrapped_key.is_null() || (*self.inner).wrapped_key_len == 0 } {
            Err(OpenSSLError::InvalidWrappedKey)?;
        }
        Ok(unsafe { from_raw_parts((*self.inner).wrapped_key, (*self.inner).wrapped_key_len) })
    }

    pub fn wrapped_key2_slice(&self) -> OpenSSLResult<&[u8]> {
        if unsafe { (*self.inner).wrapped_key2.is_null() || (*self.inner).wrapped_key2_len == 0 } {
            Err(OpenSSLError::InvalidWrappedKey)?;
        }
        Ok(unsafe { from_raw_parts((*self.inner).wrapped_key2, (*self.inner).wrapped_key2_len) })
    }

    pub fn digest_kind(&self) -> OpenSSLResult<DigestKind> {
        let digest_kind = unsafe { (*self.inner).digest_kind };
        match digest_kind {
            x if x == AziHsmDigestKind::AZIHSM_DIGEST_SHA1 as u32 => Ok(DigestKind::Sha1),
            x if x == AziHsmDigestKind::AZIHSM_DIGEST_SHA256 as u32 => Ok(DigestKind::Sha256),
            x if x == AziHsmDigestKind::AZIHSM_DIGEST_SHA384 as u32 => Ok(DigestKind::Sha384),
            x if x == AziHsmDigestKind::AZIHSM_DIGEST_SHA512 as u32 => Ok(DigestKind::Sha512),
            _ => Err(OpenSSLError::UnsupportedKeyType),
        }
    }

    pub fn key_usage(&self) -> OpenSSLResult<KeyUsage> {
        let key_usage = unsafe { (*self.inner).key_usage };
        match key_usage {
            x if x == AziHsmKeyUsage::AZIHSM_KEY_USAGE_SIGN_VERIFY as u32 => {
                Ok(KeyUsage::SignVerify)
            }
            x if x == AziHsmKeyUsage::AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT as u32 => {
                Ok(KeyUsage::EncryptDecrypt)
            }
            x if x == AziHsmKeyUsage::AZIHSM_KEY_USAGE_DERIVE as u32 => Ok(KeyUsage::Derive),
            _ => Err(OpenSSLError::UnsupportedKeyType),
        }
    }

    pub fn key_availability(&self) -> OpenSSLResult<KeyAvailability> {
        let key_availability = unsafe { (*self.inner).key_availability };
        match key_availability {
            x if x == AziHsmKeyAvailability::AZIHSM_AVAILABILITY_APP as u32 => {
                Ok(KeyAvailability::App)
            }
            x if x == AziHsmKeyAvailability::AZIHSM_AVAILABILITY_SESSION as u32 => {
                Ok(KeyAvailability::Session)
            }
            _ => Err(OpenSSLError::UnsupportedKeyType),
        }
    }

    pub fn key_name(&self) -> OpenSSLResult<Option<u16>> {
        let key_name_ptr = unsafe { (*self.inner).key_name };
        if key_name_ptr.is_null() {
            return Ok(None);
        }

        let key_name = unsafe { CStr::from_ptr(key_name_ptr) };
        let key_name = key_name
            .to_str()
            .map_err(|_| OpenSSLError::InvalidKeyName("<invalid UTF-8>".to_string()))?;
        let key_name = key_name
            .parse::<u16>()
            .map_err(|_| OpenSSLError::InvalidKeyName(key_name.to_string()))?;
        Ok(Some(key_name))
    }

    pub fn is_crt(&self) -> bool {
        unsafe { (*self.inner).is_crt }
    }

    pub fn data_as_ref(&self) -> &T {
        unsafe { &*self.data_ptr() }
    }

    pub fn data_as_mut_ref(&self) -> &T {
        unsafe { &*self.mut_data_ptr() }
    }

    pub fn data_ptr(&self) -> *const T {
        unsafe { (*self.inner).data as *const T }
    }

    pub fn mut_data_ptr(&self) -> *mut T {
        unsafe { (*self.inner).data as *mut T }
    }
}
