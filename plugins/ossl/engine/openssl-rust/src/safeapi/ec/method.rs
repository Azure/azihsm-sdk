// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_uint;
use std::ptr::null;
use std::ptr::null_mut;
use std::sync::OnceLock;

use crate::openssl_log;
use crate::safeapi::ec::callback::*;
use crate::safeapi::error::OpenSSLError;
use crate::safeapi::error::OpenSSLResult;
use crate::EC_KEY_METHOD_free;
use crate::EC_KEY_METHOD_new;
use crate::EC_KEY_METHOD_set_compute_key;
use crate::EC_KEY_METHOD_set_init;
use crate::EC_KEY_METHOD_set_keygen;
use crate::EC_KEY_METHOD_set_sign;
use crate::EC_KEY_METHOD_set_verify;
use crate::BIGNUM;
use crate::BN_CTX;
use crate::ECDSA_SIG;
use crate::EC_GROUP;
use crate::EC_KEY;
use crate::EC_KEY_METHOD;
use crate::EC_POINT;

/// Singleton result containing either the EcKeyMethod instance, or an error.
static EC_KEY_METHOD_INST: OnceLock<OpenSSLResult<EcKeyMethod>> = OnceLock::new();

pub struct EcKeyMethod(*mut EC_KEY_METHOD);

// It is safe to do this as the pointer is locked.
unsafe impl Send for EcKeyMethod {}
unsafe impl Sync for EcKeyMethod {}

impl EcKeyMethod {
    /// Get or initialize the singleton EcKeyMethod struct
    ///
    /// # Return
    ///   A reference to the result when the object was created
    pub fn get_or_init() -> &'static OpenSSLResult<Self> {
        EC_KEY_METHOD_INST.get_or_init(Self::new)
    }

    /// Create a new EcKeyMethod object
    ///
    /// # Return
    ///   A new EcKeyMethod object
    fn new() -> OpenSSLResult<Self> {
        let meth = unsafe { EC_KEY_METHOD_new(null()) };
        if meth.is_null() {
            openssl_log!(
                OpenSSLError::AllocationFailed,
                tracing::Level::ERROR,
                "EcKeyMethod::new: error allocating",
            );
            Err(OpenSSLError::AllocationFailed)?;
        }

        Ok(Self(meth))
    }

    /// Set the init functions for this object
    ///
    /// # Argument
    ///   init: optional initialization callback
    ///   finish: optional finishing callback
    ///   copy: optional key copying callback
    ///   set_group: optional group setting callback
    ///   set_priv_key: optional private key setting callback
    ///   set_pub_key: optional public key setting callback
    ///
    /// # Return
    ///   A reference to self
    pub fn set_init(
        &self,
        init: Option<EcInitFn>,
        finish: Option<EcFinishFn>,
        copy: Option<EcCopyFn>,
        set_group: Option<EcSetGroupFn>,
        set_priv_key: Option<EcSetPrivKeyFn>,
        set_pub_key: Option<EcSetPubKeyFn>,
    ) -> &Self {
        // C function prototypes, Rust can't figure out the type on its own.
        type InitCFn = unsafe extern "C" fn(*mut EC_KEY) -> c_int;
        type FinishCFn = unsafe extern "C" fn(*mut EC_KEY);
        type CopyCFn = unsafe extern "C" fn(*mut EC_KEY, *const EC_KEY) -> c_int;
        type SetGroupCFn = unsafe extern "C" fn(*mut EC_KEY, *const EC_GROUP) -> c_int;
        type SetPubKeyCFn = unsafe extern "C" fn(*mut EC_KEY, *const EC_POINT) -> c_int;
        type SetPrivKeyCFn = unsafe extern "C" fn(*mut EC_KEY, *const BIGNUM) -> c_int;

        debug_assert!(!self.0.is_null());

        let init_cb: Option<InitCFn>;
        if let Some(init_fn) = init {
            // TODO: because we can be loaded multiple times but are only initialized globally once, we need to do this below.
            // Eventually this should all be part of the engine data, but this workaround is fine for now, as we only deal with this once.
            let _ = INIT_FN.get_or_init(|| init_fn);
            init_cb = Some(c_init_cb);
        } else {
            init_cb = None;
        }

        let finish_cb: Option<FinishCFn>;
        if let Some(finish_fn) = finish {
            let _ = FINISH_FN.get_or_init(|| finish_fn);
            finish_cb = Some(c_finish_cb);
        } else {
            finish_cb = None;
        }

        let copy_cb: Option<CopyCFn>;
        if let Some(copy_fn) = copy {
            let _ = COPY_FN.get_or_init(|| copy_fn);
            copy_cb = Some(c_copy_cb);
        } else {
            copy_cb = None;
        }

        let set_group_cb: Option<SetGroupCFn>;
        if let Some(set_group_fn) = set_group {
            let _ = SET_GROUP_FN.get_or_init(|| set_group_fn);
            set_group_cb = Some(c_set_group_cb);
        } else {
            set_group_cb = None;
        }

        let set_priv_key_cb: Option<SetPrivKeyCFn>;
        if let Some(set_priv_key_fn) = set_priv_key {
            let _ = SET_PRIV_KEY_FN.get_or_init(|| set_priv_key_fn);
            set_priv_key_cb = Some(c_set_priv_key_cb);
        } else {
            set_priv_key_cb = None;
        }

        let set_pub_key_cb: Option<SetPubKeyCFn>;
        if let Some(set_pub_key_fn) = set_pub_key {
            let _ = SET_PUB_KEY_FN.get_or_init(|| set_pub_key_fn);
            set_pub_key_cb = Some(c_set_pub_key_cb);
        } else {
            set_pub_key_cb = None;
        }

        unsafe {
            EC_KEY_METHOD_set_init(
                self.0,
                init_cb,
                finish_cb,
                copy_cb,
                set_group_cb,
                set_priv_key_cb,
                set_pub_key_cb,
            )
        };
        self
    }

    /// Set the compute key function for this object
    ///
    /// # Argument
    ///   compute_key: optional compute key callback
    ///
    /// # Return
    ///   A reference to self
    pub fn set_compute_key(&self, compute_key: Option<EcComputeKeyFn>) -> &Self {
        debug_assert!(!self.0.is_null());

        // C function prototype, Rust can't figure out the type on its own
        type ComputeKeyCFn = unsafe extern "C" fn(
            *mut *mut c_uchar,
            *mut usize,
            *const EC_POINT,
            *const EC_KEY,
        ) -> c_int;

        let compute_key_cb: Option<ComputeKeyCFn>;
        if let Some(compute_key_fn) = compute_key {
            let _ = COMPUTE_KEY_FN.get_or_init(|| compute_key_fn);
            compute_key_cb = Some(c_compute_key_cb);
        } else {
            compute_key_cb = None;
        }

        unsafe { EC_KEY_METHOD_set_compute_key(self.0, compute_key_cb) };
        self
    }

    /// Set the keygen functions for this object
    ///
    /// # Argument
    ///   keygen: optional keygen callback
    ///
    /// # Return
    ///   A reference to self
    pub fn set_keygen(&self, keygen: Option<EcKeygenFn>) -> &Self {
        debug_assert!(!self.0.is_null());

        // C function prototype, Rust can't figure out the type on its own
        type KeygenCFn = unsafe extern "C" fn(*mut EC_KEY) -> c_int;

        let keygen_cb: Option<KeygenCFn>;
        if let Some(keygen_fn) = keygen {
            let _ = KEYGEN_FN.get_or_init(|| keygen_fn);
            keygen_cb = Some(c_keygen_cb);
        } else {
            keygen_cb = None;
        }

        unsafe { EC_KEY_METHOD_set_keygen(self.0, keygen_cb) };
        self
    }

    /// Set the signing functions for this object
    ///
    /// # Argument
    ///   sign: optional signing callback
    ///   sign_setup: optional signing setup callback
    ///   sign_sig: optional signing signature callback
    ///
    /// # Return
    ///   A reference to self
    pub fn set_sign(
        &self,
        sign: Option<EcSignFn>,
        sign_setup: Option<EcSignSetupFn>,
        sign_sig: Option<EcSignSigFn>,
    ) -> &Self {
        debug_assert!(!self.0.is_null());

        // C function prototypes, Rust can't figure out the type on its own
        type SignCFn = unsafe extern "C" fn(
            c_int,
            *const c_uchar,
            c_int,
            *mut c_uchar,
            *mut c_uint,
            *const BIGNUM,
            *const BIGNUM,
            *mut EC_KEY,
        ) -> c_int;
        type SignSetupCFn = unsafe extern "C" fn(
            *mut EC_KEY,
            *mut BN_CTX,
            *mut *mut BIGNUM,
            *mut *mut BIGNUM,
        ) -> c_int;
        type SignSigCFn = unsafe extern "C" fn(
            *const c_uchar,
            c_int,
            *const BIGNUM,
            *const BIGNUM,
            *mut EC_KEY,
        ) -> *mut ECDSA_SIG;

        let sign_cb: Option<SignCFn>;
        if let Some(sign_fn) = sign {
            SIGN_FN.get_or_init(|| sign_fn);
            sign_cb = Some(c_sign_cb);
        } else {
            sign_cb = None;
        }

        let sign_setup_cb: Option<SignSetupCFn>;
        if let Some(sign_setup_fn) = sign_setup {
            let _ = SIGN_SETUP_FN.get_or_init(|| sign_setup_fn);
            sign_setup_cb = Some(c_sign_setup_cb);
        } else {
            sign_setup_cb = None;
        }

        let sign_sig_cb: Option<SignSigCFn>;
        if let Some(sign_sig_fn) = sign_sig {
            SIGN_SIG_FN.get_or_init(|| sign_sig_fn);
            sign_sig_cb = Some(c_sign_sig_cb);
        } else {
            sign_sig_cb = None;
        }

        unsafe { EC_KEY_METHOD_set_sign(self.0, sign_cb, sign_setup_cb, sign_sig_cb) };
        self
    }

    /// Set the verification functions for this object
    ///
    /// # Argument
    ///   verify: optional verification callback
    ///   verify_sig: optional signature verification callback
    ///
    /// # Return
    ///   A reference to self
    pub fn set_verify(
        &self,
        verify: Option<EcVerifyFn>,
        verify_sig: Option<EcVerifySigFn>,
    ) -> &Self {
        debug_assert!(!self.0.is_null());

        // C function prototypes, Rust can't figure out the type on its own
        type VerifyCFn = unsafe extern "C" fn(
            c_int,
            *const c_uchar,
            c_int,
            *const c_uchar,
            c_int,
            *mut EC_KEY,
        ) -> c_int;
        type VerifySigCFn =
            unsafe extern "C" fn(*const c_uchar, c_int, *const ECDSA_SIG, *mut EC_KEY) -> c_int;

        let verify_cb: Option<VerifyCFn>;
        if let Some(verify_fn) = verify {
            VERIFY_FN.get_or_init(|| verify_fn);
            verify_cb = Some(c_verify_cb);
        } else {
            verify_cb = None;
        }

        let verify_sig_cb: Option<VerifySigCFn>;
        if let Some(verify_sig_fn) = verify_sig {
            VERIFY_SIG_FN.get_or_init(|| verify_sig_fn);
            verify_sig_cb = Some(c_verify_sig_cb);
        } else {
            verify_sig_cb = None;
        }

        unsafe { EC_KEY_METHOD_set_verify(self.0, verify_cb, verify_sig_cb) };
        self
    }

    /// Get the raw pointer to the underlying EC_KEY_METHOD
    ///
    /// # Return
    ///   Raw EC_KEY_METHOD pointer
    ///
    /// # Warning
    ///   Use of this pointer beyond passing to other functions is highly discouraged
    pub fn as_mut_ptr(&self) -> *mut EC_KEY_METHOD {
        self.0
    }
}

impl Drop for EcKeyMethod {
    fn drop(&mut self) {
        if self.0.is_null() {
            unsafe {
                EC_KEY_METHOD_free(self.0);
            }
        }

        self.0 = null_mut();
    }
}
