// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_uint;
use std::ptr::copy_nonoverlapping;
use std::slice::from_raw_parts;
use std::sync::OnceLock;

use crate::openssl_log;
use crate::safeapi::callback::result_int_callback;
use crate::safeapi::error::*;
use crate::BIGNUM;
use crate::BN_GENCB;
use crate::RSA;

/// Rust RSA init/finish function callback
pub type RsaInitFinishFn = fn(*mut RSA) -> OpenSSLResult<()>;
/// Rust RSA keygen function callback
pub type RsaKeygenFn = fn(*mut RSA, c_int, *mut BIGNUM, *mut BN_GENCB) -> OpenSSLResult<()>;
/// Rust RSA pub/priv enc/dec function
pub type RsaEncDecFn = fn(&[u8], *mut RSA, c_int) -> OpenSSLResult<Vec<u8>>;
/// Rust RSA sign function
pub type RsaSignFn = fn(c_int, &[u8], *const RSA) -> OpenSSLResult<Vec<u8>>;
/// Rust RSA verify function
pub type RsaVerifyFn = fn(c_int, &[u8], &[u8], *const RSA) -> OpenSSLResult<()>;

pub(super) static RSA_INIT_FN: OnceLock<RsaInitFinishFn> = OnceLock::new();
pub(super) static RSA_FINISH_FN: OnceLock<RsaInitFinishFn> = OnceLock::new();
pub(super) static RSA_KEYGEN_FN: OnceLock<RsaKeygenFn> = OnceLock::new();
pub(super) static RSA_PUB_ENCRYPT_FN: OnceLock<RsaEncDecFn> = OnceLock::new();
pub(super) static RSA_PRIV_ENCRYPT_FN: OnceLock<RsaEncDecFn> = OnceLock::new();
pub(super) static RSA_PUB_DECRYPT_FN: OnceLock<RsaEncDecFn> = OnceLock::new();
pub(super) static RSA_PRIV_DECRYPT_FN: OnceLock<RsaEncDecFn> = OnceLock::new();
pub(super) static RSA_SIGN_FN: OnceLock<RsaSignFn> = OnceLock::new();
pub(super) static RSA_VERIFY_FN: OnceLock<RsaVerifyFn> = OnceLock::new();

/// C RSA init callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_rsa_init_cb(key: *mut RSA) -> c_int {
    if key.is_null() {
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback!(RSA_INIT_FN, key)
}

/// C RSA finish callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_rsa_finish_cb(key: *mut RSA) -> c_int {
    if key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key".to_string()),
            tracing::Level::ERROR,
            "c_rsa_finish_cb: to is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback!(RSA_FINISH_FN, key)
}

/// C RSA keygen callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_rsa_keygen_cb(
    key: *mut RSA,
    bits: c_int,
    e: *mut BIGNUM,
    cb: *mut BN_GENCB,
) -> c_int {
    result_int_callback!(RSA_KEYGEN_FN, key, bits, e, cb)
}

/// C RSA pub key encrypt callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_rsa_pub_encrypt_cb(
    flen: c_int,
    from: *const c_uchar,
    to: *mut c_uchar,
    key: *mut RSA,
    padding: c_int,
) -> c_int {
    if flen <= 0 {
        // Return 0 if from length is 0
        openssl_log!(
            OpenSSLError::IncorrectParam("flen".to_string(), "> 0".to_string(), format!("{flen}")),
            tracing::Level::ERROR,
            "c_rsa_pub_encrypt_cb: from length is <= 0",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if from.is_null() {
        // All other errors must return -1
        openssl_log!(
            OpenSSLError::NullParam("from".to_string()),
            tracing::Level::ERROR,
            "c_rsa_pub_encrypt_cb: from is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if to.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("to".to_string()),
            tracing::Level::ERROR,
            "c_rsa_pub_encrypt_cb: tp is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key".to_string()),
            tracing::Level::ERROR,
            "c_rsa_pub_encrypt_cb: key is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    match RSA_PUB_ENCRYPT_FN.get() {
        Some(func) => {
            let from = unsafe { from_raw_parts(from, flen as usize) };
            match on_unwind_abort(|| func(from, key, padding)) {
                Ok(data) => {
                    // Caller must allocate enough data for this
                    unsafe {
                        copy_nonoverlapping(data.as_ptr(), to, data.len());
                    }

                    // Return ciphertext length on success
                    data.len() as c_int
                }
                Err(e) => {
                    openssl_log!(
                        e.clone(),
                        tracing::Level::ERROR,
                        "Failure in RSA_PUB_ENCRYPT_FN",
                    );
                    OpenSSLErrorCode::Error.into()
                }
            }
        }
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "Could not get RSA_PUB_ENCRYPT_FN",
            );
            OpenSSLErrorCode::Error.into()
        }
    }
}

/// C RSA priv key encrypt callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_rsa_priv_encrypt_cb(
    flen: c_int,
    from: *const c_uchar,
    to: *mut c_uchar,
    key: *mut RSA,
    padding: c_int,
) -> c_int {
    if flen <= 0 {
        // Return 0 if from length is 0
        openssl_log!(
            OpenSSLError::IncorrectParam("flen".to_string(), "> 0".to_string(), format!("{flen}")),
            tracing::Level::ERROR,
            "c_rsa_priv_encrypt_cb: from length is <= 0",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if from.is_null() {
        // All other errors must return -1
        openssl_log!(
            OpenSSLError::NullParam("from".to_string()),
            tracing::Level::ERROR,
            "c_rsa_priv_encrypt_cb: from is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if to.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("to".to_string()),
            tracing::Level::ERROR,
            "c_rsa_priv_encrypt_cb: to is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key".to_string()),
            tracing::Level::ERROR,
            "c_rsa_priv_encrypt_cb: key is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    match RSA_PRIV_ENCRYPT_FN.get() {
        Some(func) => {
            let from = unsafe { from_raw_parts(from, flen as usize) };
            match on_unwind_abort(|| func(from, key, padding)) {
                Ok(data) => {
                    // Caller must allocate enough data for this
                    unsafe {
                        copy_nonoverlapping(data.as_ptr(), to, data.len());
                    }

                    // Return ciphertext length on success
                    data.len() as c_int
                }
                Err(e) => {
                    openssl_log!(
                        e.clone(),
                        tracing::Level::ERROR,
                        "Failure in RSA_PRIV_ENCRYPT_FN",
                    );
                    OpenSSLErrorCode::Fail.into()
                }
            }
        }
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "Could not get RSA_PRIV_ENCRYPT_FN",
            );
            OpenSSLErrorCode::Error.into()
        }
    }
}

/// C RSA pub key decrypt callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_rsa_pub_decrypt_cb(
    flen: c_int,
    from: *const c_uchar,
    to: *mut c_uchar,
    key: *mut RSA,
    padding: c_int,
) -> c_int {
    if flen <= 0 {
        // Return 0 if from length is 0
        openssl_log!(
            OpenSSLError::IncorrectParam("flen".to_string(), "> 0".to_string(), format!("{flen}")),
            tracing::Level::ERROR,
            "c_rsa_pub_decrypt_cb: from length is <= 0",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if from.is_null() {
        // All other errors must return -1
        openssl_log!(
            OpenSSLError::NullParam("from".to_string()),
            tracing::Level::ERROR,
            "c_rsa_pub_decrypt_cb: from is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if to.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("to".to_string()),
            tracing::Level::ERROR,
            "c_rsa_pub_decrypt_cb: to is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key".to_string()),
            tracing::Level::ERROR,
            "c_rsa_pub_decrypt_cb: key is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    match RSA_PUB_DECRYPT_FN.get() {
        Some(func) => {
            let from = unsafe { from_raw_parts(from, flen as usize) };
            match on_unwind_abort(|| func(from, key, padding)) {
                Ok(data) => {
                    // Caller must allocate enough data for this
                    unsafe {
                        copy_nonoverlapping(data.as_ptr(), to, data.len());
                    }

                    // Return plaintext length on success
                    data.len() as c_int
                }
                Err(e) => {
                    openssl_log!(
                        e.clone(),
                        tracing::Level::ERROR,
                        "Failure in RSA_PUB_DECRYPT_FN",
                    );
                    OpenSSLErrorCode::Error.into()
                }
            }
        }
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "Could not get RSA_PUB_DECRYPT_FN",
            );
            OpenSSLErrorCode::Error.into()
        }
    }
}

/// C RSA priv key decrypt callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_rsa_priv_decrypt_cb(
    flen: c_int,
    from: *const c_uchar,
    to: *mut c_uchar,
    key: *mut RSA,
    padding: c_int,
) -> c_int {
    if flen <= 0 {
        // Return 0 if from length is 0
        openssl_log!(
            OpenSSLError::IncorrectParam("flen".to_string(), "> 0".to_string(), format!("{flen}")),
            tracing::Level::ERROR,
            "c_rsa_priv_decrypt_cb: from length is <= 0",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if from.is_null() {
        // All other errors must return -1
        openssl_log!(
            OpenSSLError::NullParam("from".to_string()),
            tracing::Level::ERROR,
            "c_rsa_priv_decrypt_cb: from is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if to.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("to".to_string()),
            tracing::Level::ERROR,
            "c_rsa_priv_decrypt_cb: to is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key".to_string()),
            tracing::Level::ERROR,
            "c_rsa_priv_decrypt_cb: key is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    match RSA_PRIV_DECRYPT_FN.get() {
        Some(func) => {
            let from = unsafe { from_raw_parts(from, flen as usize) };
            match on_unwind_abort(|| func(from, key, padding)) {
                Ok(data) => {
                    // Caller must allocate enough data for this
                    unsafe {
                        copy_nonoverlapping(data.as_ptr(), to, data.len());
                    }

                    // Return plaintext length on success
                    data.len() as c_int
                }
                Err(e) => {
                    openssl_log!(
                        e.clone(),
                        tracing::Level::ERROR,
                        "Failure in RSA_PRIV_DECRYPT_FN",
                    );
                    OpenSSLErrorCode::Error.into()
                }
            }
        }
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "Could not get RSA_PRIV_DECRYPT_FN",
            );
            OpenSSLErrorCode::Error.into()
        }
    }
}

/// C RSA pub key sign callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_rsa_sign_cb(
    type_: c_int,
    dgst: *const c_uchar,
    dgstlen: c_uint,
    sigret: *mut c_uchar,
    siglen: *mut c_uint,
    key: *const RSA,
) -> c_int {
    if dgst.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("dgst".to_string()),
            tracing::Level::ERROR,
            "c_rsa_sign_cb: digest is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if dgstlen == 0 {
        openssl_log!(
            OpenSSLError::IncorrectParam(
                "dgstlen".to_string(),
                "> 0".to_string(),
                format!("{dgstlen}")
            ),
            tracing::Level::ERROR,
            "c_rsa_sign_cb: digest length is 0",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if sigret.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("sigret".to_string()),
            tracing::Level::ERROR,
            "c_rsa_sign_cb: signature buffer is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if siglen.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("siglen".to_string()),
            tracing::Level::ERROR,
            "c_rsa_sign_cb: signature length is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key".to_string()),
            tracing::Level::ERROR,
            "c_rsa_sign_cb: key is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    match RSA_SIGN_FN.get() {
        Some(func) => {
            let dgst = unsafe { from_raw_parts(dgst, dgstlen as usize) };
            match on_unwind_abort(|| func(type_, dgst, key)) {
                Ok(sig) => {
                    unsafe {
                        // Caller must allocate enough data for this
                        copy_nonoverlapping(sig.as_ptr(), sigret, sig.len());
                        *siglen = sig.len() as c_uint;
                    }
                    OpenSSLErrorCode::Success.into()
                }
                Err(e) => {
                    openssl_log!(e.clone(), tracing::Level::ERROR, "Failure in RSA_SIGN_FN",);
                    OpenSSLErrorCode::Fail.into()
                }
            }
        }
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "Could not get RSA_SIGN_FN",
            );
            OpenSSLErrorCode::Fail.into()
        }
    }
}

/// C RSA pub key verify callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_rsa_verify_cb(
    type_: c_int,
    dgst: *const c_uchar,
    dgstlen: c_uint,
    sig: *const c_uchar,
    siglen: c_uint,
    key: *const RSA,
) -> c_int {
    if dgst.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("dgst".to_string()),
            tracing::Level::ERROR,
            "c_rsa_verify_cb: digest is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if dgstlen == 0 {
        openssl_log!(
            OpenSSLError::IncorrectParam(
                "dgstlen".to_string(),
                "> 0".to_string(),
                format!("{dgstlen}")
            ),
            tracing::Level::ERROR,
            "c_rsa_verify_cb: digest len is 0",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if sig.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("sig".to_string()),
            tracing::Level::ERROR,
            "c_rsa_verify_cb: signature is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if siglen == 0 {
        openssl_log!(
            OpenSSLError::IncorrectParam(
                "siglen".to_string(),
                "> 0".to_string(),
                format!("{siglen}")
            ),
            tracing::Level::ERROR,
            "c_rsa_verify_cb: signature return length is 0",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key".to_string()),
            tracing::Level::ERROR,
            "c_rsa_verify_cb: key is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    match RSA_VERIFY_FN.get() {
        Some(func) => {
            let dgst = unsafe { from_raw_parts(dgst, dgstlen as usize) };
            let sig = unsafe { from_raw_parts(sig, siglen as usize) };
            match on_unwind_abort(|| func(type_, dgst, sig, key)) {
                Ok(_) => OpenSSLErrorCode::Success.into(),
                Err(e) => {
                    openssl_log!(
                        e.clone(),
                        tracing::Level::WARN,
                        "c_rsa_verify_cb: Failure in RSA_VERIFY_FN",
                    );
                    OpenSSLErrorCode::Fail.into()
                }
            }
        }
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::WARN,
                "c_rsa_verify_cb: Could not get RSA_VERIFY_FN",
            );
            OpenSSLErrorCode::Fail.into()
        }
    }
}
