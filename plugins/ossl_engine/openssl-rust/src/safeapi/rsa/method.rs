// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_uint;
use std::ffi::CStr;
use std::sync::OnceLock;

use crate::safeapi::error::*;
use crate::safeapi::rsa::callback::*;
use crate::RSA_meth_new;
use crate::RSA_meth_set_finish;
use crate::RSA_meth_set_init;
use crate::RSA_meth_set_keygen;
use crate::RSA_meth_set_priv_dec;
use crate::RSA_meth_set_priv_enc;
use crate::RSA_meth_set_pub_dec;
use crate::RSA_meth_set_pub_enc;
use crate::RSA_meth_set_sign;
use crate::RSA_meth_set_verify;
use crate::BIGNUM;
use crate::BN_GENCB;
use crate::RSA;
use crate::RSA_METHOD;

/// Singleton result containing either the RSA method instance, or an error.
static RSA_METHOD_INST: OnceLock<OpenSSLResult<RsaMethod>> = OnceLock::new();

pub struct RsaMethod(*mut RSA_METHOD);

// This is not used in a thread-unsafe context, so this is safe.
unsafe impl Send for RsaMethod {}
unsafe impl Sync for RsaMethod {}

impl RsaMethod {
    /// Get or initialize the singleton RsaMethod struct
    ///
    /// # Return
    /// A reference to the result when the object was created
    pub fn get_or_init(name: &'static CStr) -> &'static OpenSSLResult<Self> {
        RSA_METHOD_INST.get_or_init(|| Self::new(name))
    }

    /// Create a new RsaMethod object
    ///
    /// # Return
    /// A new `RsaMethod` object
    fn new(name: &'static CStr) -> OpenSSLResult<Self> {
        let meth = unsafe { RSA_meth_new(name.as_ptr(), 0) };
        if meth.is_null() {
            Err(OpenSSLError::AllocationFailed)?;
        }

        Ok(Self(meth))
    }

    /// Set the init functions for this object
    ///
    /// # Argument
    /// `init` - optional initialization callback
    ///
    /// # Return
    /// A reference to self
    pub fn set_init(&self, init: Option<RsaInitFinishFn>) -> &Self {
        // C function prototypes, Rust can't figure out the type on its own.
        type RsaInitCFn = unsafe extern "C" fn(*mut RSA) -> c_int;
        let init_c_fn: Option<RsaInitCFn>;
        if let Some(init_fn) = init {
            let _ = RSA_INIT_FN.get_or_init(|| init_fn);
            init_c_fn = Some(c_rsa_init_cb);
        } else {
            init_c_fn = None;
        }

        unsafe {
            RSA_meth_set_init(self.0, init_c_fn);
        }
        self
    }

    /// Set the finish functions for this object
    ///
    /// # Argument
    /// `finish` - optional finalization callback
    ///
    /// # Return
    /// A reference to self
    pub fn set_finish(&self, finish: Option<RsaInitFinishFn>) -> &Self {
        // C function prototypes, Rust can't figure out the type on its own.
        type RsaFinishCFn = unsafe extern "C" fn(*mut RSA) -> c_int;
        let finish_c_fn: Option<RsaFinishCFn>;
        if let Some(finish_fn) = finish {
            let _ = RSA_FINISH_FN.get_or_init(|| finish_fn);
            finish_c_fn = Some(c_rsa_finish_cb);
        } else {
            finish_c_fn = None;
        }

        unsafe {
            RSA_meth_set_finish(self.0, finish_c_fn);
        }
        self
    }

    /// Set the keygen functions for this object
    ///
    /// # Argument
    /// `keygen` - optional keygen callback
    ///
    /// # Return
    /// A reference to self
    pub fn set_keygen(&self, keygen: Option<RsaKeygenFn>) -> &Self {
        // C function prototypes, Rust can't figure out the type on its own.
        type RsaKeygenCFn =
            unsafe extern "C" fn(*mut RSA, c_int, *mut BIGNUM, *mut BN_GENCB) -> c_int;
        let keygen_c_fn: Option<RsaKeygenCFn>;
        if let Some(keygen_fn) = keygen {
            let _ = RSA_KEYGEN_FN.get_or_init(|| keygen_fn);
            keygen_c_fn = Some(c_rsa_keygen_cb);
        } else {
            keygen_c_fn = None;
        }

        unsafe {
            RSA_meth_set_keygen(self.0, keygen_c_fn);
        }
        self
    }

    /// Set the private key decrypt functions for this object
    ///
    /// # Argument
    /// `priv_dec` - optional private key decrypt callback
    ///
    /// # Return
    /// A reference to self
    pub fn set_priv_dec(&self, priv_decrypt: Option<RsaEncDecFn>) -> &Self {
        // C function prototypes, Rust can't figure out the type on its own.
        type RsaPrivDecryptCFn =
            unsafe extern "C" fn(c_int, *const c_uchar, *mut c_uchar, *mut RSA, c_int) -> c_int;
        let priv_decrypt_c_fn: Option<RsaPrivDecryptCFn>;
        if let Some(priv_decrypt_fn) = priv_decrypt {
            let _ = RSA_PRIV_DECRYPT_FN.get_or_init(|| priv_decrypt_fn);
            priv_decrypt_c_fn = Some(c_rsa_priv_decrypt_cb);
        } else {
            priv_decrypt_c_fn = None;
        }

        unsafe {
            RSA_meth_set_priv_dec(self.0, priv_decrypt_c_fn);
        }
        self
    }

    /// Set the public key decrypt functions for this object
    ///
    /// # Argument
    /// `pub_dec` - optional public key decrypt callback
    ///
    /// # Return
    /// A reference to self
    pub fn set_pub_dec(&self, pub_decrypt: Option<RsaEncDecFn>) -> &Self {
        // C function prototypes, Rust can't figure out the type on its own.
        type RsaPubDecryptCFn =
            unsafe extern "C" fn(c_int, *const c_uchar, *mut c_uchar, *mut RSA, c_int) -> c_int;
        let pub_decrypt_c_fn: Option<RsaPubDecryptCFn>;
        if let Some(pub_decrypt_fn) = pub_decrypt {
            let _ = RSA_PUB_DECRYPT_FN.get_or_init(|| pub_decrypt_fn);
            pub_decrypt_c_fn = Some(c_rsa_pub_decrypt_cb);
        } else {
            pub_decrypt_c_fn = None;
        }

        unsafe {
            RSA_meth_set_pub_dec(self.0, pub_decrypt_c_fn);
        }
        self
    }

    /// Set the private key encrypt functions for this object
    ///
    /// # Argument
    /// `priv_dec` - optional private key decrypt callback
    ///
    /// # Return
    /// A reference to self
    pub fn set_priv_enc(&self, priv_encrypt: Option<RsaEncDecFn>) -> &Self {
        // C function prototypes, Rust can't figure out the type on its own.
        type RsaPrivEncryptCFn =
            unsafe extern "C" fn(c_int, *const c_uchar, *mut c_uchar, *mut RSA, c_int) -> c_int;
        let priv_encrypt_c_fn: Option<RsaPrivEncryptCFn>;
        if let Some(priv_encrypt_fn) = priv_encrypt {
            let _ = RSA_PRIV_ENCRYPT_FN.get_or_init(|| priv_encrypt_fn);
            priv_encrypt_c_fn = Some(c_rsa_priv_encrypt_cb);
        } else {
            priv_encrypt_c_fn = None;
        }

        unsafe {
            RSA_meth_set_priv_enc(self.0, priv_encrypt_c_fn);
        }
        self
    }

    /// Set the public key encrypt functions for this object
    ///
    /// # Argument
    /// `pub_dec` - optional public key decrypt callback
    ///
    /// # Return
    /// A reference to self
    pub fn set_pub_enc(&self, pub_encrypt: Option<RsaEncDecFn>) -> &Self {
        // C function prototypes, Rust can't figure out the type on its own.
        type RsaPubEncryptCFn =
            unsafe extern "C" fn(c_int, *const c_uchar, *mut c_uchar, *mut RSA, c_int) -> c_int;
        let pub_encrypt_c_fn: Option<RsaPubEncryptCFn>;
        if let Some(pub_encrypt_fn) = pub_encrypt {
            let _ = RSA_PUB_ENCRYPT_FN.get_or_init(|| pub_encrypt_fn);
            pub_encrypt_c_fn = Some(c_rsa_pub_encrypt_cb);
        } else {
            pub_encrypt_c_fn = None;
        }

        unsafe {
            RSA_meth_set_pub_enc(self.0, pub_encrypt_c_fn);
        }
        self
    }

    /// Set the sign functions for this object
    ///
    /// # Argument
    /// `sign` - optional signing callback
    ///
    /// # Return
    /// A reference to self
    pub fn set_sign(&self, sign: Option<RsaSignFn>) -> &Self {
        // C function prototypes, Rust can't figure out the type on its own.
        type RsaSignCFn = unsafe extern "C" fn(
            c_int,
            *const c_uchar,
            c_uint,
            *mut c_uchar,
            *mut c_uint,
            *const RSA,
        ) -> c_int;
        let sign_c_fn: Option<RsaSignCFn>;
        if let Some(sign_fn) = sign {
            let _ = RSA_SIGN_FN.get_or_init(|| sign_fn);
            sign_c_fn = Some(c_rsa_sign_cb);
        } else {
            sign_c_fn = None;
        }

        unsafe {
            RSA_meth_set_sign(self.0, sign_c_fn);
        }
        self
    }

    /// Set the verify functions for this object
    ///
    /// # Argument
    /// `verify` - optional verify callback
    ///
    /// # Return
    /// A reference to self
    pub fn set_verify(&self, verify: Option<RsaVerifyFn>) -> &Self {
        // C function prototypes, Rust can't figure out the type on its own.
        type RsaVerifyCFn = unsafe extern "C" fn(
            c_int,
            *const c_uchar,
            c_uint,
            *const c_uchar,
            c_uint,
            *const RSA,
        ) -> c_int;
        let verify_c_fn: Option<RsaVerifyCFn>;
        if let Some(verify_fn) = verify {
            let _ = RSA_VERIFY_FN.get_or_init(|| verify_fn);
            verify_c_fn = Some(c_rsa_verify_cb);
        } else {
            verify_c_fn = None;
        }

        unsafe {
            RSA_meth_set_verify(self.0, verify_c_fn);
        }
        self
    }

    /// Get pointer to underlying RSA method
    pub fn as_mut_ptr(&self) -> *mut RSA_METHOD {
        self.0
    }
}
