// Copyright (C) Microsoft Corporation. All rights reserved.

use std::cell::Cell;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_uint;
use std::ffi::c_void;
use std::ptr::null_mut;

use crate::safeapi::error::OpenSSLError;
use crate::safeapi::error::OpenSSLResult;
use crate::safeapi::evp_pkey::callback::common::*;
use crate::safeapi::evp_pkey::callback::ec::*;
use crate::safeapi::evp_pkey::callback::hkdf::*;
use crate::safeapi::evp_pkey::callback::rsa::*;
use crate::EVP_PKEY_meth_new;
use crate::EVP_PKEY_meth_set_cleanup;
use crate::EVP_PKEY_meth_set_copy;
use crate::EVP_PKEY_meth_set_ctrl;
use crate::EVP_PKEY_meth_set_decrypt;
use crate::EVP_PKEY_meth_set_derive;
use crate::EVP_PKEY_meth_set_encrypt;
use crate::EVP_PKEY_meth_set_init;
use crate::EVP_PKEY_meth_set_keygen;
use crate::EVP_PKEY_meth_set_paramgen;
use crate::EVP_PKEY_meth_set_sign;
use crate::EVP_PKEY_meth_set_signctx;
use crate::EVP_PKEY_meth_set_verify;
use crate::EVP_PKEY_meth_set_verifyctx;
use crate::NID_X9_62_id_ecPublicKey as NID_EC;
use crate::NID_hkdf as NID_HKDF;
use crate::NID_rsaEncryption as NID_RSAENCRYPTION;
use crate::EVP_MD_CTX;
use crate::EVP_PKEY;
use crate::EVP_PKEY_CTX;
use crate::EVP_PKEY_EC;
use crate::EVP_PKEY_HKDF;
use crate::EVP_PKEY_METHOD;
use crate::EVP_PKEY_RSA;

type OpInitCFn = unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> c_int;
type SignVerifyCtxInitCFn =
    unsafe extern "C" fn(ctx: *mut EVP_PKEY_CTX, mctx: *mut EVP_MD_CTX) -> c_int;

/// Type of EVP_PKEY
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EvpPKeyType {
    Rsa,
    Hkdf,
    Ec,
}

impl EvpPKeyType {
    pub fn from_nid(nid: c_uint) -> OpenSSLResult<Self> {
        match nid {
            NID_RSAENCRYPTION => Ok(EvpPKeyType::Rsa),
            NID_HKDF => Ok(EvpPKeyType::Hkdf),
            NID_EC => Ok(EvpPKeyType::Ec),
            _ => Err(OpenSSLError::PKeyNotSupported(nid)),
        }
    }

    pub fn nid(&self) -> c_uint {
        match self {
            EvpPKeyType::Rsa => NID_RSAENCRYPTION,
            EvpPKeyType::Hkdf => NID_HKDF,
            EvpPKeyType::Ec => NID_EC,
        }
    }

    pub fn pkey_type(&self) -> c_uint {
        match self {
            EvpPKeyType::Rsa => EVP_PKEY_RSA,
            EvpPKeyType::Hkdf => EVP_PKEY_HKDF,
            EvpPKeyType::Ec => EVP_PKEY_EC,
        }
    }
}

macro_rules! get_inner {
    ($self:expr) => {{
        let inner = $self.inner.get();
        if inner.is_null() {
            return $self;
        }
        inner
    }};
}

/// Wrapper for an EVP_PKEY method
#[derive(Clone, Debug, PartialEq)]
pub struct EvpPKeyMethod {
    inner: Cell<*mut EVP_PKEY_METHOD>,
    key_type: EvpPKeyType,
    flags: c_int,
}

/// SAFETY: No one besides us has the raw pointer, so we can safely transfer the
/// ownership of the pointer.
unsafe impl Send for EvpPKeyMethod {}

/// SAFETY: This object is created only once during Engine binding per cipher.
/// Engine binding happens only once per app, so this object is Sync.
unsafe impl Sync for EvpPKeyMethod {}

impl EvpPKeyMethod {
    /// Create a new EvpPKeyMethod object
    pub fn new(key_type: EvpPKeyType, flags: c_int) -> Self {
        Self {
            inner: Cell::new(null_mut()),
            key_type,
            flags,
        }
    }

    /// Initialize the method object with a new EVP_PKEY_METHOD
    pub fn init(&self) -> &Self {
        self.inner
            .set(unsafe { EVP_PKEY_meth_new(self.key_type.nid() as c_int, self.flags) });
        self
    }

    /// Set the init function of the internal EVP_PKEY_METHOD
    pub fn set_init(&self, init: Option<PKeyInitFn>) -> &Self {
        let inner = get_inner!(self);

        type InitCFn = unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> c_int;

        let mut c_init_cb: Option<InitCFn> = None;

        if let Some(init_fn) = init {
            match init_fn {
                PKeyInitFn::Ec(func) => {
                    EC_INIT_FN.get_or_init(|| func);
                    c_init_cb = Some(c_ec_init_cb);
                }
            }
        }

        unsafe {
            EVP_PKEY_meth_set_init(inner, c_init_cb);
        }

        self
    }

    /// Set the cleanup function of the internal EVP_PKEY_METHOD
    pub fn set_cleanup(&self, cleanup: Option<PKeyCleanupFn>) -> &Self {
        let inner = get_inner!(self);

        type CleanupCFn = unsafe extern "C" fn(ctx: *mut EVP_PKEY_CTX);
        let mut c_cleanup_cb: Option<CleanupCFn> = None;

        if let Some(cleanup_fn) = cleanup {
            match cleanup_fn {
                PKeyCleanupFn::Rsa(func) => {
                    RSA_CLEANUP_FN.get_or_init(|| func);
                    c_cleanup_cb = Some(c_rsa_cleanup_cb);
                }
                PKeyCleanupFn::Hkdf(func) => {
                    HKDF_CLEANUP_FN.get_or_init(|| func);
                    c_cleanup_cb = Some(c_hkdf_cleanup_cb);
                }
                PKeyCleanupFn::Ec(func) => {
                    EC_CLEANUP_FN.get_or_init(|| func);
                    c_cleanup_cb = Some(c_ec_cleanup_cb);
                }
            }
        }

        unsafe {
            EVP_PKEY_meth_set_cleanup(inner, c_cleanup_cb);
        }

        self
    }

    /// Set copy callback
    pub fn set_copy(&self, copy: Option<PKeyCopyFn>) -> &Self {
        let inner = get_inner!(self);

        #[cfg(feature = "openssl_3")]
        type CopyCFn = unsafe extern "C" fn(*mut EVP_PKEY_CTX, *const EVP_PKEY_CTX) -> c_int;
        #[cfg(feature = "openssl_111")]
        type CopyCFn = unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY_CTX) -> c_int;

        let mut c_copy_cb: Option<CopyCFn> = None;

        if let Some(copy_fn) = copy {
            match copy_fn {
                PKeyCopyFn::Ec(func) => {
                    EC_COPY_FN.get_or_init(|| func);
                    c_copy_cb = Some(c_ec_copy_cb);
                }
                PKeyCopyFn::Rsa(func) => {
                    RSA_COPY_FN.get_or_init(|| func);
                    c_copy_cb = Some(c_rsa_copy_cb);
                }
            }
        }

        unsafe {
            EVP_PKEY_meth_set_copy(inner, c_copy_cb);
        }

        self
    }

    /// Set the encryption function of the internal EVP_PKEY_METHOD
    pub fn set_encrypt(
        &self,
        encrypt_init: Option<PKeyEncDecInitFn>,
        encrypt: Option<PKeyEncDecFn>,
    ) -> &Self {
        let inner = get_inner!(self);

        let mut c_encrypt_init_cb: Option<OpInitCFn> = None;

        if let Some(encrypt_init_fn) = encrypt_init {
            match encrypt_init_fn {
                PKeyEncDecInitFn::Rsa(func) => {
                    RSA_ENCRYPT_INIT_FN.get_or_init(|| func);
                    c_encrypt_init_cb = Some(c_rsa_encrypt_init_cb);
                }
            }
        }

        type EncryptCFn = unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut c_uchar,
            *mut usize,
            *const c_uchar,
            usize,
        ) -> c_int;
        let mut c_encrypt_cb: Option<EncryptCFn> = None;

        if let Some(encrypt_fn) = encrypt {
            match encrypt_fn {
                PKeyEncDecFn::Rsa(func) => {
                    RSA_ENCRYPT_FN.get_or_init(|| func);
                    c_encrypt_cb = Some(c_rsa_encrypt_cb)
                }
            }
        }

        unsafe {
            EVP_PKEY_meth_set_encrypt(inner, c_encrypt_init_cb, c_encrypt_cb);
        }

        self
    }

    /// Set the decryption function of the internal EVP_PKEY_METHOD
    pub fn set_decrypt(
        &self,
        decrypt_init: Option<PKeyEncDecInitFn>,
        decrypt: Option<PKeyEncDecFn>,
    ) -> &Self {
        let inner = get_inner!(self);

        let mut c_decrypt_init_cb: Option<OpInitCFn> = None;

        if let Some(decrypt_init_fn) = decrypt_init {
            match decrypt_init_fn {
                PKeyEncDecInitFn::Rsa(func) => {
                    RSA_DECRYPT_INIT_FN.get_or_init(|| func);
                    c_decrypt_init_cb = Some(c_rsa_decrypt_init_cb);
                }
            }
        }

        type DecryptCFn = unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut c_uchar,
            *mut usize,
            *const c_uchar,
            usize,
        ) -> c_int;
        let mut c_decrypt_cb: Option<DecryptCFn> = None;

        if let Some(decrypt_fn) = decrypt {
            match decrypt_fn {
                PKeyEncDecFn::Rsa(func) => {
                    RSA_DECRYPT_FN.get_or_init(|| func);
                    c_decrypt_cb = Some(c_rsa_decrypt_cb);
                }
            }
        }

        unsafe {
            EVP_PKEY_meth_set_decrypt(inner, c_decrypt_init_cb, c_decrypt_cb);
        }

        self
    }

    /// Set the signing function of the internal EVP_PKEY_METHOD
    pub fn set_sign(
        &self,
        sign_init: Option<PKeySignVerifyInitFn>,
        sign: Option<PKeySignFn>,
    ) -> &Self {
        let inner = get_inner!(self);

        let mut c_sign_init_cb: Option<OpInitCFn> = None;
        if let Some(sign_init_fn) = sign_init {
            match sign_init_fn {
                PKeySignVerifyInitFn::Rsa(func) => {
                    RSA_SIGN_INIT_FN.get_or_init(|| func);
                    c_sign_init_cb = Some(c_rsa_sign_init_cb);
                }
                PKeySignVerifyInitFn::Ec(func) => {
                    EC_SIGN_INIT_FN.get_or_init(|| func);
                    c_sign_init_cb = Some(c_ec_sign_init_cb);
                }
            }
        }

        type SignCFn = unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut c_uchar,
            *mut usize,
            *const c_uchar,
            usize,
        ) -> c_int;
        let mut c_sign_cb: Option<SignCFn> = None;

        if let Some(sign_fn) = sign {
            match sign_fn {
                PKeySignFn::Rsa(func) => {
                    RSA_SIGN_FN.get_or_init(|| func);
                    c_sign_cb = Some(c_rsa_sign_cb)
                }
                PKeySignFn::Ec(func) => {
                    EC_SIGN_FN.get_or_init(|| func);
                    c_sign_cb = Some(c_ec_sign_cb)
                }
            }
        }

        unsafe {
            EVP_PKEY_meth_set_sign(inner, c_sign_init_cb, c_sign_cb);
        }

        self
    }

    /// Set the sign ctx functions of the internal EVP_PKEY_METHOD
    pub fn set_sign_ctx(
        &self,
        signctx_init: Option<PKeySignCtxInitFn>,
        signctx: Option<PKeySignCtxFn>,
    ) -> &Self {
        let inner = get_inner!(self);

        let mut c_signctx_init_cb: Option<SignVerifyCtxInitCFn> = None;

        if let Some(signctx_init_fn) = signctx_init {
            match signctx_init_fn {
                PKeySignCtxInitFn::Rsa(func) => {
                    RSA_SIGN_CTX_INIT_FN.get_or_init(|| func);
                    c_signctx_init_cb = Some(c_rsa_sign_ctx_init_cb);
                }
                PKeySignCtxInitFn::Ec(func) => {
                    EC_SIGN_CTX_INIT_FN.get_or_init(|| func);
                    c_signctx_init_cb = Some(c_ec_sign_ctx_init_cb);
                }
            }
        }

        type SignCtxCFn = unsafe extern "C" fn(
            ctx: *mut EVP_PKEY_CTX,
            sig: *mut c_uchar,
            siglen: *mut usize,
            mctx: *mut EVP_MD_CTX,
        ) -> c_int;

        let mut c_signctx_cb: Option<SignCtxCFn> = None;

        if let Some(signctx_fn) = signctx {
            match signctx_fn {
                PKeySignCtxFn::Rsa(func) => {
                    RSA_SIGN_CTX_FN.get_or_init(|| func);
                    c_signctx_cb = Some(c_rsa_sign_ctx_cb);
                }
                PKeySignCtxFn::Ec(func) => {
                    EC_SIGN_CTX_FN.get_or_init(|| func);
                    c_signctx_cb = Some(c_ec_sign_ctx_cb);
                }
            }
        }

        unsafe {
            EVP_PKEY_meth_set_signctx(inner, c_signctx_init_cb, c_signctx_cb);
        }

        self
    }

    /// Set the verify function of the internal EVP_PKEY_METHOD
    pub fn set_verify(
        &self,
        verify_init: Option<PKeySignVerifyInitFn>,
        verify: Option<PKeyVerifyFn>,
    ) -> &Self {
        let inner = get_inner!(self);

        let mut c_verify_init_cb: Option<OpInitCFn> = None;

        if let Some(verify_init_fn) = verify_init {
            match verify_init_fn {
                PKeySignVerifyInitFn::Rsa(func) => {
                    RSA_VERIFY_INIT_FN.get_or_init(|| func);
                    c_verify_init_cb = Some(c_rsa_verify_init_cb);
                }
                PKeySignVerifyInitFn::Ec(func) => {
                    EC_VERIFY_INIT_FN.get_or_init(|| func);
                    c_verify_init_cb = Some(c_ec_verify_init_cb);
                }
            }
        }

        type VerifyCFn = unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *const c_uchar,
            usize,
            *const c_uchar,
            usize,
        ) -> c_int;
        let mut c_verify_cb: Option<VerifyCFn> = None;

        if let Some(verify_fn) = verify {
            match verify_fn {
                PKeyVerifyFn::Rsa(func) => {
                    RSA_VERIFY_FN.get_or_init(|| func);
                    c_verify_cb = Some(c_rsa_verify_cb);
                }
                PKeyVerifyFn::Ec(func) => {
                    EC_VERIFY_FN.get_or_init(|| func);
                    c_verify_cb = Some(c_ec_verify_cb);
                }
            }
        }

        unsafe {
            EVP_PKEY_meth_set_verify(inner, c_verify_init_cb, c_verify_cb);
        }

        self
    }

    /// Set the sign ctx functions of the internal EVP_PKEY_METHOD
    pub fn set_verify_ctx(
        &self,
        verifyctx_init: Option<PKeyVerifyCtxInitFn>,
        verifyctx: Option<PKeyVerifyCtxFn>,
    ) -> &Self {
        let inner = get_inner!(self);

        let mut c_verifyctx_init_cb: Option<SignVerifyCtxInitCFn> = None;

        if let Some(verifyctx_init_fn) = verifyctx_init {
            match verifyctx_init_fn {
                PKeyVerifyCtxInitFn::Rsa(func) => {
                    RSA_VERIFY_CTX_INIT_FN.get_or_init(|| func);
                    c_verifyctx_init_cb = Some(c_rsa_verify_ctx_init_cb);
                }
                PKeyVerifyCtxInitFn::Ec(func) => {
                    EC_VERIFY_CTX_INIT_FN.get_or_init(|| func);
                    c_verifyctx_init_cb = Some(c_ec_verify_ctx_init_cb);
                }
            }
        }

        type VerifyCtxCFn = unsafe extern "C" fn(
            ctx: *mut EVP_PKEY_CTX,
            sig: *const c_uchar,
            siglen: c_int,
            mctx: *mut EVP_MD_CTX,
        ) -> c_int;

        let mut c_verifyctx_cb: Option<VerifyCtxCFn> = None;

        if let Some(verifyctx_fn) = verifyctx {
            match verifyctx_fn {
                PKeyVerifyCtxFn::Rsa(func) => {
                    RSA_VERIFY_CTX_FN.get_or_init(|| func);
                    c_verifyctx_cb = Some(c_rsa_verify_ctx_cb);
                }
                PKeyVerifyCtxFn::Ec(func) => {
                    EC_VERIFY_CTX_FN.get_or_init(|| func);
                    c_verifyctx_cb = Some(c_ec_verify_ctx_cb);
                }
            }
        }

        unsafe {
            EVP_PKEY_meth_set_verifyctx(inner, c_verifyctx_init_cb, c_verifyctx_cb);
        }

        self
    }

    /// Set the keygen functions of the internal EVP_PKEY_METHOD
    pub fn set_keygen(
        &self,
        keygen_init: Option<PKeyGenInitFn>,
        keygen: Option<PKeyGenFn>,
    ) -> &Self {
        let inner = get_inner!(self);

        let mut c_keygen_init_cb: Option<OpInitCFn> = None;

        if let Some(keygen_init_fn) = keygen_init {
            match keygen_init_fn {
                PKeyGenInitFn::Rsa(func) => {
                    RSA_KEYGEN_INIT_FN.get_or_init(|| func);
                    c_keygen_init_cb = Some(c_rsa_keygen_init_cb);
                }
                PKeyGenInitFn::Ec(func) => {
                    EC_KEYGEN_INIT_FN.get_or_init(|| func);
                    c_keygen_init_cb = Some(c_ec_keygen_init_cb);
                }
            }
        }

        type KeygenCFn = unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> c_int;
        let mut c_keygen_cb: Option<KeygenCFn> = None;

        if let Some(keygen_fn) = keygen {
            match keygen_fn {
                PKeyGenFn::Rsa(func) => {
                    RSA_KEYGEN_FN.get_or_init(|| func);
                    c_keygen_cb = Some(c_rsa_keygen_cb);
                }
                PKeyGenFn::Ec(func) => {
                    EC_KEYGEN_FN.get_or_init(|| func);
                    c_keygen_cb = Some(c_ec_keygen_cb);
                }
            }
        }

        unsafe {
            EVP_PKEY_meth_set_keygen(inner, c_keygen_init_cb, c_keygen_cb);
        }

        self
    }

    /// Set the paramgen functions of the internal EVP_PKEY_METHOD
    pub fn set_paramgen(
        &self,
        paramgen_init: Option<PKeyParamgenInitFn>,
        paramgen: Option<PKeyParamGenFn>,
    ) -> &Self {
        let inner = get_inner!(self);

        let mut c_paramgen_init_cb: Option<OpInitCFn> = None;

        if let Some(paramgen_init_fn) = paramgen_init {
            match paramgen_init_fn {
                PKeyParamgenInitFn::Rsa(func) => {
                    RSA_PARAMGEN_INIT_FN.get_or_init(|| func);
                    c_paramgen_init_cb = Some(c_rsa_paramgen_init_cb);
                }
                PKeyParamgenInitFn::Ec(func) => {
                    EC_PARAMGEN_INIT_FN.get_or_init(|| func);
                    c_paramgen_init_cb = Some(c_ec_paramgen_init_cb);
                }
            }
        }

        type ParamgenCFn = unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> c_int;
        let mut c_paramgen_cb: Option<ParamgenCFn> = None;

        if let Some(paramgen_fn) = paramgen {
            match paramgen_fn {
                PKeyParamGenFn::Rsa(func) => {
                    RSA_PARAMGEN_FN.get_or_init(|| func);
                    c_paramgen_cb = Some(c_rsa_paramgen_cb);
                }
                PKeyParamGenFn::Ec(func) => {
                    EC_PARAMGEN_FN.get_or_init(|| func);
                    c_paramgen_cb = Some(c_ec_paramgen_cb);
                }
            }
        }

        unsafe {
            EVP_PKEY_meth_set_paramgen(inner, c_paramgen_init_cb, c_paramgen_cb);
        }

        self
    }

    /// Set the derive functions of the internal EVP_PKEY_METHOD
    pub fn set_derive(
        &self,
        derive_init: Option<PKeyDeriveInitFn>,
        derive: Option<PKeyDeriveFn>,
    ) -> &Self {
        let inner = get_inner!(self);

        let mut c_derive_init_cb: Option<OpInitCFn> = None;

        if let Some(derive_init_fn) = derive_init {
            match derive_init_fn {
                PKeyDeriveInitFn::Hkdf(func) => {
                    HKDF_DERIVE_INIT_FN.get_or_init(|| func);
                    c_derive_init_cb = Some(c_hkdf_derive_init_cb);
                }
                PKeyDeriveInitFn::Ec(func) => {
                    EC_DERIVE_INIT_FN.get_or_init(|| func);
                    c_derive_init_cb = Some(c_ec_derive_init_cb);
                }
            }
        }

        type DeriveCFn = unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut c_uchar, *mut usize) -> c_int;
        let mut c_derive_cb: Option<DeriveCFn> = None;

        if let Some(derive_fn) = derive {
            match derive_fn {
                PKeyDeriveFn::Hkdf(func) => {
                    HKDF_DERIVE_FN.get_or_init(|| func);
                    c_derive_cb = Some(c_hkdf_derive_cb);
                }
                PKeyDeriveFn::Ec(func) => {
                    EC_DERIVE_FN.get_or_init(|| func);
                    c_derive_cb = Some(c_ec_derive_cb);
                }
            }
        }

        unsafe {
            EVP_PKEY_meth_set_derive(inner, c_derive_init_cb, c_derive_cb);
        }

        self
    }

    /// Set the control functions of the internal EVP_PKEY_METHOD
    pub fn set_ctrl(&self, ctrl: Option<PKeyCtrlFn>, _ctrl_str: Option<PKeyCtrlStrFn>) -> &Self {
        let inner = get_inner!(self);

        type CtrlCFn = unsafe extern "C" fn(*mut EVP_PKEY_CTX, c_int, c_int, *mut c_void) -> c_int;
        type CtrlStrCFn =
            unsafe extern "C" fn(*mut EVP_PKEY_CTX, *const c_char, *const c_char) -> c_int;
        let mut c_ctrl_cb: Option<CtrlCFn> = None;
        let c_ctrl_str_cb: Option<CtrlStrCFn> = None;

        if let Some(ctrl_fn) = ctrl {
            match ctrl_fn {
                PKeyCtrlFn::Rsa(func) => {
                    RSA_CTRL_FN.get_or_init(|| func);
                    c_ctrl_cb = Some(c_rsa_ctrl_cb);
                }
                PKeyCtrlFn::Hkdf(func) => {
                    HKDF_CTRL_FN.get_or_init(|| func);
                    c_ctrl_cb = Some(c_hkdf_ctrl_cb);
                }
                PKeyCtrlFn::Ec(func) => {
                    EC_CTRL_FN.get_or_init(|| func);
                    c_ctrl_cb = Some(c_ec_ctrl_cb);
                }
            }
        }

        unsafe {
            EVP_PKEY_meth_set_ctrl(inner, c_ctrl_cb, c_ctrl_str_cb);
        }

        self
    }

    /// Get the result of the method building
    pub fn result(&self) -> OpenSSLResult<&Self> {
        if self.inner.get().is_null() {
            Err(OpenSSLError::AllocationFailed)?;
        }
        Ok(self)
    }

    /// Get the NID of method
    pub fn nid(&self) -> c_uint {
        match self.key_type {
            EvpPKeyType::Rsa => NID_RSAENCRYPTION,
            EvpPKeyType::Hkdf => NID_HKDF,
            EvpPKeyType::Ec => NID_EC,
        }
    }

    /// Get mutable pointer to inner object
    pub fn as_mut_ptr(&self) -> *mut EVP_PKEY_METHOD {
        self.inner.get()
    }
}
