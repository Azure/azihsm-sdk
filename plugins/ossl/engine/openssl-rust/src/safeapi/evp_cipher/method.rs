// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ptr::null_mut;

use crate::openssl_log;
use crate::safeapi::error::*;
use crate::safeapi::evp_cipher::callback::*;
#[cfg(feature = "openssl_111")]
use crate::EVP_CIPHER_block_size;
#[cfg(feature = "openssl_111")]
use crate::EVP_CIPHER_flags;
#[cfg(feature = "openssl_3")]
use crate::EVP_CIPHER_get_block_size;
#[cfg(feature = "openssl_3")]
use crate::EVP_CIPHER_get_flags;
#[cfg(feature = "openssl_3")]
use crate::EVP_CIPHER_get_iv_length;
#[cfg(feature = "openssl_3")]
use crate::EVP_CIPHER_get_key_length;
#[cfg(feature = "openssl_3")]
use crate::EVP_CIPHER_get_nid;
#[cfg(feature = "openssl_111")]
use crate::EVP_CIPHER_iv_length;
#[cfg(feature = "openssl_111")]
use crate::EVP_CIPHER_key_length;
use crate::EVP_CIPHER_meth_free;
use crate::EVP_CIPHER_meth_new;
use crate::EVP_CIPHER_meth_set_cleanup;
use crate::EVP_CIPHER_meth_set_ctrl;
use crate::EVP_CIPHER_meth_set_do_cipher;
use crate::EVP_CIPHER_meth_set_flags;
use crate::EVP_CIPHER_meth_set_impl_ctx_size;
use crate::EVP_CIPHER_meth_set_init;
use crate::EVP_CIPHER_meth_set_iv_length;
#[cfg(feature = "openssl_111")]
use crate::EVP_CIPHER_nid;
use crate::EVP_CIPHER;

/// Wrapper for an EVP_CIPHER method
#[derive(Debug, PartialEq)]
pub struct EvpCipherMethod(*mut EVP_CIPHER);

/// SAFETY: No one besides us has the raw pointer, so we can safely transfer the
/// ownership of the pointer.
unsafe impl Send for EvpCipherMethod {}

/// SAFETY: This object is created only once during Engine binding per cipher.
/// Engine binding happens only once per app, so this object is Sync.
unsafe impl Sync for EvpCipherMethod {}

impl EvpCipherMethod {
    pub fn new_from_ptr(ptr: *mut EVP_CIPHER) -> EvpCipherMethod {
        EvpCipherMethod(ptr)
    }

    pub fn as_ptr(&self) -> *const EVP_CIPHER {
        self.0 as *const EVP_CIPHER
    }

    pub fn nid(&self) -> i32 {
        #[cfg(feature = "openssl_3")]
        unsafe {
            EVP_CIPHER_get_nid(self.0)
        }
        #[cfg(feature = "openssl_111")]
        unsafe {
            EVP_CIPHER_nid(self.0)
        }
    }

    pub fn key_len(&self) -> i32 {
        #[cfg(feature = "openssl_3")]
        unsafe {
            EVP_CIPHER_get_key_length(self.0)
        }
        #[cfg(feature = "openssl_111")]
        unsafe {
            EVP_CIPHER_key_length(self.0)
        }
    }

    pub fn block_size(&self) -> i32 {
        #[cfg(feature = "openssl_3")]
        unsafe {
            EVP_CIPHER_get_block_size(self.0)
        }
        #[cfg(feature = "openssl_111")]
        unsafe {
            EVP_CIPHER_block_size(self.0)
        }
    }

    pub fn iv_len(&self) -> i32 {
        #[cfg(feature = "openssl_3")]
        unsafe {
            EVP_CIPHER_get_iv_length(self.0)
        }
        #[cfg(feature = "openssl_111")]
        unsafe {
            EVP_CIPHER_iv_length(self.0)
        }
    }

    pub fn flags(&self) -> u64 {
        #[cfg(feature = "openssl_3")]
        unsafe {
            EVP_CIPHER_get_flags(self.0)
        }
        #[cfg(feature = "openssl_111")]
        unsafe {
            EVP_CIPHER_flags(self.0)
        }
    }
}

impl Drop for EvpCipherMethod {
    fn drop(&mut self) {
        unsafe { EVP_CIPHER_meth_free(self.0) };
    }
}

pub struct EvpCipherBuilder {
    inner: *mut EVP_CIPHER,
    result: Result<(), OpenSSLError>,
}

impl EvpCipherBuilder {
    /// Create a new builder for an EVP_CIPHER method
    pub fn new(nid: i32, block_size: i32, key_len: i32) -> EvpCipherBuilder {
        let mut result = Ok(());
        let inner = unsafe { EVP_CIPHER_meth_new(nid, block_size, key_len) };
        if inner.is_null() {
            openssl_log!(
                OpenSSLError::AllocationFailed,
                tracing::Level::ERROR,
                "EvpCipherBuilder::new: Could not create EVP_CIPHER method structure",
            );
            result = Err(OpenSSLError::AllocationFailed);
        }

        EvpCipherBuilder { inner, result }
    }

    /// Set the IV length for the cipher
    pub fn set_iv_length(&mut self, iv_len: i32) -> &mut EvpCipherBuilder {
        if self.result.is_err() {
            return self;
        }
        let result = unsafe { EVP_CIPHER_meth_set_iv_length(self.inner, iv_len) };
        if result != 1 {
            openssl_log!(
                OpenSSLError::CipherMethSetIvLengthFailed,
                tracing::Level::ERROR,
                "EvpCipherBuilder::set_iv_length: Could not set IV length",
            );
            self.result = Err(OpenSSLError::CipherMethSetIvLengthFailed);
        }
        self
    }

    /// Set the flags for the cipher
    pub fn set_flags(&mut self, flags: u64) -> &mut EvpCipherBuilder {
        if self.result.is_err() {
            return self;
        }
        let result = unsafe { EVP_CIPHER_meth_set_flags(self.inner, flags) };
        if result != 1 {
            openssl_log!(
                OpenSSLError::CipherMethSetFlagsFailed,
                tracing::Level::ERROR,
                "EvpCipherBuilder::set_flags: Could not set flags",
            );
            self.result = Err(OpenSSLError::CipherMethSetFlagsFailed);
        }

        self
    }

    /// Set ctx_size for the cipher
    pub fn set_impl_ctx_size(&mut self, ctx_size: usize) -> &mut EvpCipherBuilder {
        if self.result.is_err() {
            return self;
        }
        let result = unsafe { EVP_CIPHER_meth_set_impl_ctx_size(self.inner, ctx_size as i32) };
        if result != 1 {
            openssl_log!(
                OpenSSLError::CipherMethSetImplCtxSizeFailed,
                tracing::Level::ERROR,
                "EvpCipherBuilder::set_impl_ctx_size: Could not set CTX size",
            );
            self.result = Err(OpenSSLError::CipherMethSetImplCtxSizeFailed);
        }

        self
    }

    /// Set init callback for the cipher
    pub fn set_init(&mut self, init: CipherInitFn) -> &mut EvpCipherBuilder {
        if self.result.is_err() {
            return self;
        }

        AES_INIT_FN.get_or_init(|| init);
        let result = unsafe { EVP_CIPHER_meth_set_init(self.inner, Some(c_aes_init_cb)) };
        if result != 1 {
            openssl_log!(
                OpenSSLError::CipherMethSetInitFailed,
                tracing::Level::ERROR,
                "EvpCipherBuilder::set_init: Could not set init method",
            );
            self.result = Err(OpenSSLError::CipherMethSetInitFailed);
        }

        self
    }

    /// Set ctrl callback for the cipher
    pub fn set_ctrl(&mut self, ctrl: CipherCtrlFn) -> &mut EvpCipherBuilder {
        if self.result.is_err() {
            return self;
        }

        AES_CTRL_FN.get_or_init(|| ctrl);
        let result = unsafe { EVP_CIPHER_meth_set_ctrl(self.inner, Some(c_aes_ctrl_cb)) };
        if result != 1 {
            openssl_log!(
                OpenSSLError::CipherMethSetCtrlFailed,
                tracing::Level::ERROR,
                "EvpCipherBuilder::set_ctrl: Could not set ctrl method",
            );
            self.result = Err(OpenSSLError::CipherMethSetCtrlFailed);
        }
        self
    }

    /// Set do_cipher callback for the cipher
    pub fn set_do_cipher(&mut self, do_cipher: CipherFn) -> &mut EvpCipherBuilder {
        if self.result.is_err() {
            return self;
        }

        let result = match do_cipher {
            CipherFn::CipherAesCbc(func) => {
                AES_CBC_DO_CIPHER_FN.get_or_init(|| func);
                unsafe { EVP_CIPHER_meth_set_do_cipher(self.inner, Some(c_aes_cbc_do_cipher_cb)) }
            }
            CipherFn::CipherAesGcm(func) => {
                AES_GCM_DO_CIPHER_FN.get_or_init(|| func);
                unsafe { EVP_CIPHER_meth_set_do_cipher(self.inner, Some(c_aes_gcm_do_cipher_cb)) }
            }
            CipherFn::CipherAesXts(func) => {
                AES_XTS_DO_CIPHER_FN.get_or_init(|| func);
                unsafe { EVP_CIPHER_meth_set_do_cipher(self.inner, Some(c_aes_xts_do_cipher_cb)) }
            }
        };

        if result != 1 {
            openssl_log!(
                OpenSSLError::CipherMethSetDoCipherFailed,
                tracing::Level::ERROR,
                "EvpCipherBuilder::set_do_cipher: Could not set do cipher method",
            );
            self.result = Err(OpenSSLError::CipherMethSetDoCipherFailed);
        }

        self
    }

    /// Set cleanup callback for the cipher
    pub fn set_cleanup(&mut self, cleanup: CipherCleanupFn) -> &mut EvpCipherBuilder {
        if self.result.is_err() {
            return self;
        }

        AES_CLEANUP_FN.get_or_init(|| cleanup);
        let result = unsafe { EVP_CIPHER_meth_set_cleanup(self.inner, Some(c_aes_cleanup_cb)) };
        if result != 1 {
            openssl_log!(
                OpenSSLError::CipherMethSetCleanupFailed,
                tracing::Level::ERROR,
                "EvpCipherBuilder::set_ctrl: Could not set cleanup method",
            );
            self.result = Err(OpenSSLError::CipherMethSetCleanupFailed);
        }

        self
    }

    pub fn build(&mut self) -> OpenSSLResult<EvpCipherMethod> {
        if let Err(e) = &self.result {
            openssl_log!(
                e.clone(),
                tracing::Level::ERROR,
                "EvpCipherBuilder::build: Error in EvpCipherBuilder",
            );
        }
        self.result.clone().map(|_| EvpCipherMethod(self.inner))
    }
}

impl Drop for EvpCipherBuilder {
    fn drop(&mut self) {
        if self.result.is_err() && !self.inner.is_null() {
            unsafe { EVP_CIPHER_meth_free(self.inner) };
            self.inner = null_mut();
        }
    }
}
