// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ptr::addr_of_mut;
use std::ptr::null;
use std::ptr::null_mut;

use crate::openssl_log;
use crate::safeapi::error::OpenSSLError;
use crate::safeapi::error::OpenSSLResult;
use crate::safeapi::util::bn_num_bytes;
use crate::BN_bin2bn;
use crate::BN_bn2binpad;
use crate::ECDSA_SIG_free;
use crate::ECDSA_SIG_get0;
use crate::ECDSA_SIG_new;
use crate::ECDSA_SIG_set0;
use crate::BIGNUM;
use crate::ECDSA_SIG;

pub struct Ecdsa_Sig {
    sig: *mut ECDSA_SIG,
    allocated: bool,
}

impl Ecdsa_Sig {
    /// Create a new Ecdsa_Sig from an ECDSA_SIG pointer
    ///
    /// # Argument
    ///   sig: ECDSA_SIG pointer
    ///
    /// # Return
    ///   Ecdsa_Sig object
    pub fn new_from_ptr(sig: *mut ECDSA_SIG) -> Self {
        debug_assert!(!sig.is_null());

        Self {
            sig,
            allocated: false,
        }
    }

    /// Get mutable pointer to internal object
    ///
    /// # Return
    ///   ECDSA_SIG pointer
    pub fn as_mut_ptr(&self) -> *mut ECDSA_SIG {
        self.sig
    }

    /// Free the underlying data if necessary
    pub fn free(&mut self) {
        if self.allocated {
            unsafe {
                ECDSA_SIG_free(self.sig);
                self.sig = null_mut();
            }
        }
    }

    /// Convert the underlying ECDSA_SIG to raw format
    ///
    /// # Argument
    ///   len: total expected length of the signature
    ///
    /// # Return
    ///   Raw signature in a vector, or error
    pub fn to_raw(&self, len: usize) -> OpenSSLResult<Vec<u8>> {
        let mut r: *const BIGNUM = null();
        let mut s: *const BIGNUM = null();

        unsafe {
            ECDSA_SIG_get0(self.sig, addr_of_mut!(r), addr_of_mut!(s));
        }

        if len < unsafe { bn_num_bytes(r) + bn_num_bytes(s) } {
            openssl_log!(
                OpenSSLError::BigNumConversionFailure,
                tracing::Level::ERROR,
                "Ecdsa_Sig::from_raw: Bignum to binary conversion failure for r and s",
            );
            Err(OpenSSLError::BigNumConversionFailure)?;
        }

        let mut data = vec![0u8; len];
        let len_param = len >> 1;

        if unsafe { BN_bn2binpad(r, data.as_mut_ptr(), len_param as c_int) } < 1 {
            openssl_log!(
                OpenSSLError::BigNumConversionFailure,
                tracing::Level::ERROR,
                "Ecdsa_Sig::from_raw: Bignum to binary conversion failure for r",
            );
            Err(OpenSSLError::BigNumConversionFailure)?;
        }

        if unsafe { BN_bn2binpad(s, data.as_mut_ptr().add(len_param), len_param as c_int) } < 1 {
            openssl_log!(
                OpenSSLError::BigNumConversionFailure,
                tracing::Level::ERROR,
                "Ecdsa_Sig::from_raw: Bignum to binary conversion failure for s",
            );
            Err(OpenSSLError::BigNumConversionFailure)?;
        }

        Ok(data)
    }

    /// Convert raw signature to ECDSA_SIG
    ///
    /// # Argument
    ///   sig: Signature vector in raw format
    ///
    /// # Return
    ///   EcDsa signature object, or error
    pub fn from_raw(sig_vec: Vec<u8>) -> OpenSSLResult<Self> {
        if sig_vec.is_empty() {
            openssl_log!(
                OpenSSLError::AllocationFailed,
                tracing::Level::ERROR,
                "Ecdsa_Sig::from_raw: Invalid signature length 0",
            );
            Err(OpenSSLError::InvalidSignatureLength(0))?;
        }

        let len = sig_vec.len() >> 1;

        let r = unsafe { BN_bin2bn(sig_vec.as_ptr(), len as c_int, null_mut()) };
        if r.is_null() {
            openssl_log!(
                OpenSSLError::AllocationFailed,
                tracing::Level::ERROR,
                "Ecdsa_Sig::from_raw: Could not create bignum r",
            );
            Err(OpenSSLError::AllocationFailed)?;
        }

        let s = unsafe { BN_bin2bn(sig_vec.as_ptr().add(len), len as c_int, null_mut()) };
        if s.is_null() {
            openssl_log!(
                OpenSSLError::AllocationFailed,
                tracing::Level::ERROR,
                "Ecdsa_Sig::from_raw: Could not create bignum s",
            );
            Err(OpenSSLError::AllocationFailed)?;
        }

        let sig = unsafe { ECDSA_SIG_new() };
        if sig.is_null() {
            openssl_log!(
                OpenSSLError::AllocationFailed,
                tracing::Level::ERROR,
                "Ecdsa_Sig::from_raw: Could not create signature",
            );
            Err(OpenSSLError::AllocationFailed)?;
        }

        unsafe {
            ECDSA_SIG_set0(sig, r, s);
        }

        Ok(Self {
            sig,
            allocated: true,
        })
    }
}
