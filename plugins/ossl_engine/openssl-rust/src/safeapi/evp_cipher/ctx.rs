// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ptr;

use engine_common::handle_table::Handle;
use engine_common::*;

use crate::openssl_log;
use crate::safeapi::engine::Engine;
use crate::safeapi::error::*;
use crate::safeapi::evp_cipher::method::EvpCipherMethod;
#[cfg(feature = "openssl_111")]
use crate::EVP_CIPHER_CTX_encrypting;
use crate::EVP_CIPHER_CTX_free;
use crate::EVP_CIPHER_CTX_get_cipher_data;
#[cfg(feature = "openssl_3")]
use crate::EVP_CIPHER_CTX_get_iv_length;
#[cfg(feature = "openssl_3")]
use crate::EVP_CIPHER_CTX_get_key_length;
#[cfg(feature = "openssl_3")]
use crate::EVP_CIPHER_CTX_get_nid;
#[cfg(feature = "openssl_3")]
use crate::EVP_CIPHER_CTX_is_encrypting;
#[cfg(feature = "openssl_111")]
use crate::EVP_CIPHER_CTX_iv_length;
#[cfg(feature = "openssl_111")]
use crate::EVP_CIPHER_CTX_key_length;
use crate::EVP_CIPHER_CTX_new;
#[cfg(feature = "openssl_111")]
use crate::EVP_CIPHER_CTX_nid;
use crate::EVP_CipherInit_ex;
use crate::EVP_CIPHER_CTX;

/// Wrapper for an EVP_CIPHER_CTX
/// `cipher_data` member of EVP_CIPHER_CTX is used to store the Engine Cipher implementation specific data.
pub struct EvpCipherCtx {
    inner: *mut EVP_CIPHER_CTX,
    allocated: bool,
}

/// SAFETY: No one besides us has the raw pointer, so we can safely transfer the
/// ownership of the pointer.
unsafe impl Send for EvpCipherCtx {}
/// SAFETY: If multiple threads are accessing the same EVP_CIPHER_CTX, it is the application's
/// responsibility to ensure that the access is synchronized.
unsafe impl Sync for EvpCipherCtx {}

impl EvpCipherCtx {
    pub fn new() -> OpenSSLResult<Self> {
        let ctx = unsafe { EVP_CIPHER_CTX_new() };
        if ctx.is_null() {
            openssl_log!(
                OpenSSLError::AllocationFailed,
                tracing::Level::ERROR,
                "EvpCipherCtx::new: Could not allocate EVP_CIPHER_CTX",
            );
            Err(OpenSSLError::AllocationFailed)?;
        }

        Ok(EvpCipherCtx {
            inner: ctx,
            allocated: true,
        })
    }

    pub fn new_unowned() -> OpenSSLResult<Self> {
        let ctx = unsafe { EVP_CIPHER_CTX_new() };
        if ctx.is_null() {
            openssl_log!(
                OpenSSLError::AllocationFailed,
                tracing::Level::ERROR,
                "EvpCipherCtx::new_unowned: Could not allocate EVP_CIPHER_CTX",
            );
            Err(OpenSSLError::AllocationFailed)?;
        }

        Ok(EvpCipherCtx {
            inner: ctx,
            allocated: false,
        })
    }

    pub fn new_from_ptr(ctx: *mut EVP_CIPHER_CTX) -> Self {
        EvpCipherCtx {
            inner: ctx,
            allocated: false,
        }
    }

    pub fn as_ptr(&self) -> *mut EVP_CIPHER_CTX {
        self.inner
    }

    pub fn key_len(&self) -> i32 {
        #[cfg(feature = "openssl_3")]
        unsafe {
            EVP_CIPHER_CTX_get_key_length(self.inner)
        }
        #[cfg(feature = "openssl_111")]
        unsafe {
            EVP_CIPHER_CTX_key_length(self.inner)
        }
    }

    pub fn nid(&self) -> i32 {
        #[cfg(feature = "openssl_3")]
        unsafe {
            EVP_CIPHER_CTX_get_nid(self.inner)
        }
        #[cfg(feature = "openssl_111")]
        unsafe {
            EVP_CIPHER_CTX_nid(self.inner)
        }
    }

    pub fn iv_len(&self) -> i32 {
        #[cfg(feature = "openssl_3")]
        unsafe {
            EVP_CIPHER_CTX_get_iv_length(self.inner)
        }
        #[cfg(feature = "openssl_111")]
        unsafe {
            EVP_CIPHER_CTX_iv_length(self.inner)
        }
    }

    pub fn set_cipher_data(&self, handle: Handle) -> OpenSSLResult<()> {
        let c_cipher_data = unsafe { EVP_CIPHER_CTX_get_cipher_data(self.inner) };
        if c_cipher_data.is_null() {
            openssl_log!(
                OpenSSLError::CipherCtxGetDataError,
                tracing::Level::ERROR,
                "EvpCipherCtx::set_cipher_data: Could not get cipher data",
            );
            Err(OpenSSLError::CipherCtxGetDataError)?;
        }
        let data_be_bytes = handle.to_be_bytes();
        unsafe {
            ptr::copy_nonoverlapping(
                data_be_bytes.as_ptr(),
                c_cipher_data as *mut u8,
                ENGINE_KEY_HANDLE_SIZE,
            );
        }

        Ok(())
    }

    pub fn get_cipher_data(&self) -> OpenSSLResult<Handle> {
        let c_cipher_data = unsafe { EVP_CIPHER_CTX_get_cipher_data(self.inner) };
        if c_cipher_data.is_null() {
            openssl_log!(
                OpenSSLError::CipherCtxGetDataError,
                tracing::Level::ERROR,
                "EvpCipherCtx::get_cipher_data: Could not get cipher data",
            );
            Err(OpenSSLError::CipherCtxGetDataError)?;
        }

        let mut read_buf: [u8; ENGINE_KEY_HANDLE_SIZE] = [0; ENGINE_KEY_HANDLE_SIZE];
        unsafe {
            ptr::copy_nonoverlapping(
                c_cipher_data as *const u8,
                read_buf.as_mut_ptr(),
                ENGINE_KEY_HANDLE_SIZE,
            );
        }

        Ok(Handle::from_be_bytes(read_buf))
    }

    pub fn is_encrypting(&self) -> bool {
        #[cfg(feature = "openssl_3")]
        unsafe {
            EVP_CIPHER_CTX_is_encrypting(self.inner) == 1
        }
        #[cfg(feature = "openssl_111")]
        unsafe {
            EVP_CIPHER_CTX_encrypting(self.inner) == 1
        }
    }

    pub fn init(
        &self,
        cipher: &EvpCipherMethod,
        engine: &Engine,
        key: Option<&[u8]>,
        iv: Option<&[u8]>,
        enc: i32,
    ) -> OpenSSLResult<()> {
        let key_ptr = match key {
            Some(key) => key.as_ptr(),
            None => ptr::null(),
        };
        let iv_ptr = match iv {
            Some(iv) => iv.as_ptr(),
            None => ptr::null(),
        };
        unsafe {
            let result = EVP_CipherInit_ex(
                self.inner,
                cipher.as_ptr(),
                engine.as_mut_ptr(),
                key_ptr,
                iv_ptr,
                enc,
            );
            if result != 1 {
                openssl_log!(
                    OpenSSLError::CipherCtxInitFailed,
                    tracing::Level::ERROR,
                    "EvpCipherCtx::init: Could not init cipher",
                );
                Err(OpenSSLError::CipherCtxInitFailed)?;
            }
        }
        Ok(())
    }
}

impl Drop for EvpCipherCtx {
    fn drop(&mut self) {
        if self.allocated {
            unsafe {
                EVP_CIPHER_CTX_free(self.inner);
            }
        }
    }
}
