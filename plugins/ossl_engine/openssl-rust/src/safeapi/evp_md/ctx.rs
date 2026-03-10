// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ffi::c_uint;
use std::ffi::c_void;
use std::ffi::CStr;

use crate::openssl_log;
use crate::safeapi::error::*;
use crate::safeapi::evp_md::md::EvpMd;
use crate::safeapi::evp_md::md::EvpMdType;
use crate::EVP_DigestFinal_ex;
use crate::EVP_DigestInit;
use crate::EVP_DigestUpdate;
use crate::EVP_MD_CTX_free;
#[cfg(feature = "openssl_3")]
use crate::EVP_MD_CTX_get0_md;
#[cfg(feature = "openssl_111")]
use crate::EVP_MD_CTX_md;
use crate::EVP_MD_CTX_new;
use crate::EVP_MD_CTX_set_flags;
#[cfg(feature = "openssl_3")]
use crate::EVP_MD_get0_name;
#[cfg(feature = "openssl_3")]
use crate::EVP_MD_get_size;
#[cfg(feature = "openssl_3")]
use crate::EVP_MD_get_type;
#[cfg(feature = "openssl_111")]
use crate::EVP_MD_size;
#[cfg(feature = "openssl_111")]
use crate::EVP_MD_type;
use crate::NID_sha1;
use crate::NID_sha256;
use crate::NID_sha384;
use crate::NID_sha512;
#[cfg(feature = "openssl_111")]
use crate::OBJ_nid2sn;
use crate::EVP_MD;
use crate::EVP_MD_CTX;

pub struct EvpMdCtx(*mut EVP_MD_CTX, bool);

impl EvpMdCtx {
    pub fn new() -> OpenSSLResult<Self> {
        let ctx = unsafe { EVP_MD_CTX_new() };
        if ctx.is_null() {
            openssl_log!(
                OpenSSLError::AllocationFailed,
                tracing::Level::ERROR,
                "EvpMdCtx::new: could not allocate EVP_MD_CTX",
            );
            Err(OpenSSLError::AllocationFailed)?;
        }

        Ok(Self(ctx, true))
    }

    pub fn new_from_ptr(ctx: *mut EVP_MD_CTX) -> Self {
        Self(ctx, false)
    }

    pub fn as_mut_ptr(&self) -> *mut EVP_MD_CTX {
        self.0
    }

    pub fn get_md_ptr(&self) -> *const EVP_MD {
        #[cfg(feature = "openssl_3")]
        unsafe {
            EVP_MD_CTX_get0_md(self.0)
        }
        #[cfg(feature = "openssl_111")]
        unsafe {
            EVP_MD_CTX_md(self.0)
        }
    }

    pub fn get_name(&self) -> String {
        let md = self.get_md_ptr();
        if md.is_null() {
            return String::new();
        }

        #[cfg(feature = "openssl_3")]
        let name = unsafe { EVP_MD_get0_name(md) };
        #[cfg(feature = "openssl_111")]
        let name = unsafe { OBJ_nid2sn(EVP_MD_type(md)) };
        if name.is_null() {
            return String::new();
        }

        let name = unsafe { CStr::from_ptr(name) };
        String::from_utf8_lossy(name.to_bytes()).to_string()
    }

    pub fn get_nid(&self) -> OpenSSLResult<c_uint> {
        #[cfg(feature = "openssl_3")]
        let nid = unsafe { EVP_MD_get_type(self.get_md_ptr()) };
        #[cfg(feature = "openssl_111")]
        let nid = unsafe { EVP_MD_type(self.get_md_ptr()) };

        if nid < 0 {
            openssl_log!(
                OpenSSLError::HashNotSupported,
                tracing::Level::ERROR,
                "EvpMdCtx::get_nid: unknown NID {nid} from MD type",
            );
            Err(OpenSSLError::HashNotSupported)?;
        }

        Ok(nid as c_uint)
    }

    pub fn get_md_type(&self) -> OpenSSLResult<EvpMdType> {
        match self.get_nid()? {
            NID_sha1 => Ok(EvpMdType::Sha1),
            NID_sha256 => Ok(EvpMdType::Sha256),
            NID_sha384 => Ok(EvpMdType::Sha384),
            NID_sha512 => Ok(EvpMdType::Sha512),
            _ => Err(OpenSSLError::HashNotSupported),
        }
    }

    pub fn md_size(&self) -> usize {
        let md = self.get_md_ptr();
        if md.is_null() {
            openssl_log!(
                OpenSSLError::MdPointerNull,
                tracing::Level::ERROR,
                "EvpMdCtx::md_size: md pointer is null",
            );
            return 0;
        }

        #[cfg(feature = "openssl_3")]
        unsafe {
            EVP_MD_get_size(md) as usize
        }
        #[cfg(feature = "openssl_111")]
        unsafe {
            EVP_MD_size(md) as usize
        }
    }

    pub fn digest_init(&self, md: &EvpMd) -> OpenSSLResult<()> {
        let result = unsafe { EVP_DigestInit(self.as_mut_ptr(), md.as_ptr()) };
        if result != 1 {
            openssl_log!(
                OpenSSLError::DigestInitError,
                tracing::Level::ERROR,
                "EvpMdCtx::digest_init: failed to init digest",
            );
            Err(OpenSSLError::DigestInitError)?;
        }

        Ok(())
    }

    pub fn digest_update(&self, data: &[u8]) -> OpenSSLResult<()> {
        let res = unsafe {
            EVP_DigestUpdate(
                self.as_mut_ptr(),
                data.as_ptr() as *const c_void,
                data.len(),
            )
        };
        if res == 0 {
            openssl_log!(
                OpenSSLError::DigestUpdateError,
                tracing::Level::ERROR,
                "EvpMdCtx::digest_init: failed to update digest",
            );
            Err(OpenSSLError::DigestUpdateError)?;
        }
        Ok(())
    }

    pub fn digest_final(&self) -> OpenSSLResult<Vec<u8>> {
        let mut digest = vec![0u8; self.md_size()];
        let mut digest_len = 0;
        let res =
            unsafe { EVP_DigestFinal_ex(self.as_mut_ptr(), digest.as_mut_ptr(), &mut digest_len) };
        if res == 0 {
            openssl_log!(
                OpenSSLError::DigestFinalError,
                tracing::Level::ERROR,
                "EvpMdCtx::digest_init: failed to finalize digest",
            );
            Err(OpenSSLError::DigestFinalError)?;
        }
        digest.truncate(digest_len as usize);
        Ok(digest)
    }

    pub fn set_flag(&self, flag: c_int) {
        unsafe {
            EVP_MD_CTX_set_flags(self.as_mut_ptr(), flag);
        }
    }
}

impl Drop for EvpMdCtx {
    fn drop(&mut self) {
        if self.1 {
            unsafe {
                EVP_MD_CTX_free(self.as_mut_ptr());
            }
        }
    }
}
