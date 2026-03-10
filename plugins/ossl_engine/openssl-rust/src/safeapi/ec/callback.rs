// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_uint;
use std::ptr;
use std::ptr::null_mut;
use std::sync::OnceLock;

use engine_common::handle_table::Handle;
use engine_common::*;

use crate::openssl_log;
use crate::safeapi::callback::result_int_callback;
use crate::safeapi::error::convert_result_int;
use crate::safeapi::error::on_unwind_abort;
use crate::safeapi::error::OpenSSLError;
use crate::safeapi::error::OpenSSLErrorCode;
use crate::safeapi::error::OpenSSLResult;
use crate::safeapi::util::slice_to_u8_ptr;
use crate::safeapi::util::u8_ptr_to_vec;
use crate::CRYPTO_malloc;
use crate::BIGNUM;
use crate::BN_CTX;
use crate::ECDSA_SIG;
use crate::EC_GROUP;
use crate::EC_KEY;
use crate::EC_POINT;

/// Rust EC init function callback
pub type EcInitFn = fn(*mut EC_KEY) -> OpenSSLResult<()>;
/// Rust EC finish function callback
pub type EcFinishFn = fn(*mut EC_KEY);
/// Rust EC copy function callback
pub type EcCopyFn = fn(*mut EC_KEY, *const EC_KEY) -> OpenSSLResult<()>;
/// Rust EC set group function callback
pub type EcSetGroupFn = fn(*mut EC_KEY, *const EC_GROUP) -> OpenSSLResult<()>;
/// Rust EC set private key function callback
pub type EcSetPrivKeyFn = fn(*mut EC_KEY, *const BIGNUM) -> OpenSSLResult<()>;
/// Rust EC set public key function callback
pub type EcSetPubKeyFn = fn(*mut EC_KEY, *const EC_POINT) -> OpenSSLResult<()>;
/// Rust EC keygen function callback
pub type EcKeygenFn = fn(*mut EC_KEY) -> OpenSSLResult<()>;
/// Rust EC compute key function callback
pub type EcComputeKeyFn =
    fn(*mut *mut c_uchar, *mut usize, *const EC_POINT, *const EC_KEY) -> OpenSSLResult<Handle>;
pub type EcSignFn =
    fn(c_int, Vec<u8>, *const BIGNUM, *const BIGNUM, *mut EC_KEY) -> OpenSSLResult<Vec<u8>>;
/// Rust EC sign setup function callback
pub type EcSignSetupFn =
    fn(*mut EC_KEY, *mut BN_CTX, *mut *mut BIGNUM, *mut *mut BIGNUM) -> OpenSSLResult<()>;
/// Rust EC sign signature function callback
pub type EcSignSigFn =
    fn(Vec<u8>, *const BIGNUM, *const BIGNUM, *mut EC_KEY) -> OpenSSLResult<*mut ECDSA_SIG>;
/// Rust EC verify function callback
pub type EcVerifyFn = fn(c_int, Vec<u8>, Vec<u8>, *mut EC_KEY) -> OpenSSLResult<()>;
/// Rust EC verify signature function callback
pub type EcVerifySigFn = fn(Vec<u8>, *const ECDSA_SIG, *mut EC_KEY) -> OpenSSLResult<()>;

// OpenSSL (AFAIK) doesn't provide internal state... and C callbacks need access to this
// Hence we are forced to make these global.
// This is fine for our use, since this is for an engine.
pub(super) static INIT_FN: OnceLock<EcInitFn> = OnceLock::new();
pub(super) static FINISH_FN: OnceLock<EcFinishFn> = OnceLock::new();
pub(super) static COPY_FN: OnceLock<EcCopyFn> = OnceLock::new();
pub(super) static SET_GROUP_FN: OnceLock<EcSetGroupFn> = OnceLock::new();
pub(super) static SET_PUB_KEY_FN: OnceLock<EcSetPubKeyFn> = OnceLock::new();
pub(super) static SET_PRIV_KEY_FN: OnceLock<EcSetPrivKeyFn> = OnceLock::new();
pub(super) static KEYGEN_FN: OnceLock<EcKeygenFn> = OnceLock::new();
pub(super) static COMPUTE_KEY_FN: OnceLock<EcComputeKeyFn> = OnceLock::new();
pub(super) static SIGN_FN: OnceLock<EcSignFn> = OnceLock::new();
pub(super) static SIGN_SETUP_FN: OnceLock<EcSignSetupFn> = OnceLock::new();
pub(super) static SIGN_SIG_FN: OnceLock<EcSignSigFn> = OnceLock::new();
pub(super) static VERIFY_FN: OnceLock<EcVerifyFn> = OnceLock::new();
pub(super) static VERIFY_SIG_FN: OnceLock<EcVerifySigFn> = OnceLock::new();

/// C init callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_init_cb(key: *mut EC_KEY) -> c_int {
    if key.is_null() {
        return OpenSSLErrorCode::Error.into();
    }

    result_int_callback!(INIT_FN, key)
}

/// C finish callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_finish_cb(key: *mut EC_KEY) {
    if key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key".to_string()),
            tracing::Level::ERROR,
            "c_finish_cb: key is null",
        );
        return;
    }

    if let Some(func) = FINISH_FN.get() {
        on_unwind_abort(|| func(key));
    } else {
        openssl_log!(
            OpenSSLError::NotImplemented,
            tracing::Level::ERROR,
            "c_finish_cb: Could not get callback FINISH_FN",
        );
    }
}

/// C key copy callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_copy_cb(dst: *mut EC_KEY, src: *const EC_KEY) -> c_int {
    if dst.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("dst".to_string()),
            tracing::Level::ERROR,
            "c_copy_cb: destination key is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if src.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("src".to_string()),
            tracing::Level::ERROR,
            "c_copy_cb: source key is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    result_int_callback!(COPY_FN, dst, src)
}

/// C set group callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_set_group_cb(key: *mut EC_KEY, group: *const EC_GROUP) -> c_int {
    if key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key".to_string()),
            tracing::Level::ERROR,
            "c_set_group_cb: key is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if group.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("group".to_string()),
            tracing::Level::ERROR,
            "c_set_group_cb: group is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    result_int_callback!(SET_GROUP_FN, key, group)
}

/// C set private key callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_set_priv_key_cb(
    key: *mut EC_KEY,
    priv_key: *const BIGNUM,
) -> c_int {
    if key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key".to_string()),
            tracing::Level::ERROR,
            "c_set_priv_key_cb: key is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if priv_key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("priv_key".to_string()),
            tracing::Level::ERROR,
            "c_set_priv_key_cb: priv key is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    result_int_callback!(SET_PRIV_KEY_FN, key, priv_key)
}

/// C set public key callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_set_pub_key_cb(
    key: *mut EC_KEY,
    pub_key: *const EC_POINT,
) -> c_int {
    if key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key".to_string()),
            tracing::Level::ERROR,
            "c_set_pub_key_cb: key is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if pub_key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("pub_key".to_string()),
            tracing::Level::ERROR,
            "c_set_pub_key_cb: public key is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    result_int_callback!(SET_PUB_KEY_FN, key, pub_key)
}

/// C keygen callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_keygen_cb(key: *mut EC_KEY) -> c_int {
    if key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key".to_string()),
            tracing::Level::ERROR,
            "c_keygen_cb: key is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    result_int_callback!(KEYGEN_FN, key)
}

/// C compute key callback that calls our underlying Rust function
///
/// # Returns
/// 1 on success, 0 on failure/error
pub(super) unsafe extern "C" fn c_compute_key_cb(
    psec: *mut *mut c_uchar,
    pseclen: *mut usize,
    pub_key: *const EC_POINT,
    ecdh: *const EC_KEY,
) -> c_int {
    if pub_key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("pub_key".to_string()),
            tracing::Level::ERROR,
            "c_compute_key_cb: public key is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if ecdh.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ecdh".to_string()),
            tracing::Level::ERROR,
            "c_compute_key_cb: ECDH key is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    match COMPUTE_KEY_FN.get() {
        Some(func) => on_unwind_abort(|| match func(psec, pseclen, pub_key, ecdh) {
            Ok(handle) => {
                if !pseclen.is_null() {
                    unsafe {
                        *pseclen = ENGINE_KEY_HANDLE_SIZE;
                    }
                }

                if !psec.is_null() {
                    let psec_mem = unsafe { CRYPTO_malloc(ENGINE_KEY_HANDLE_SIZE, null_mut(), 0) };
                    if psec_mem.is_null() {
                        openssl_log!(
                            OpenSSLError::AllocationFailed,
                            tracing::Level::ERROR,
                            "c_compute_key_cb: Could not allocate psec_mem",
                        );
                        return OpenSSLErrorCode::Fail.into();
                    }

                    *psec = psec_mem as *mut u8;

                    let handle_be_bytes = handle.to_be_bytes();

                    unsafe {
                        ptr::copy_nonoverlapping(
                            handle_be_bytes.as_ptr(),
                            psec_mem as *mut u8,
                            ENGINE_KEY_HANDLE_SIZE,
                        );
                    }
                }

                OpenSSLErrorCode::Success.into()
            }
            Err(e) => {
                openssl_log!(
                    e.clone(),
                    tracing::Level::ERROR,
                    "c_compute_key_cb: Error in COMPUTE_KEY_FN",
                );
                OpenSSLErrorCode::Fail.into()
            }
        }),
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_compute_key_cb: Could not get callback COMPUTE_KEY_FN",
            );
            OpenSSLErrorCode::Fail.into()
        }
    }
}

/// C signing callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_sign_cb(
    type_: c_int,
    dgst: *const c_uchar,
    dgst_len: c_int,
    sig: *mut c_uchar,
    sig_len: *mut c_uint,
    kinv: *const BIGNUM,
    r: *const BIGNUM,
    eckey: *mut EC_KEY,
) -> c_int {
    if dgst.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("dgst".to_string()),
            tracing::Level::ERROR,
            "c_sign_cb: Digest is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if sig.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("sig".to_string()),
            tracing::Level::ERROR,
            "c_sign_cb: signature buffer is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if eckey.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("eckey".to_string()),
            tracing::Level::ERROR,
            "c_sign_cb: key is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    match SIGN_FN.get() {
        Some(func) => on_unwind_abort(|| {
            if dgst_len < 1 {
                openssl_log!(
                    OpenSSLError::IncorrectParam(
                        "dgst_len".to_string(),
                        "> 0".to_string(),
                        format!("{dgst_len}")
                    ),
                    tracing::Level::ERROR,
                    "c_sign_cb: digest length < 1",
                );
                return OpenSSLErrorCode::Fail.into();
            }
            let dgst_vec = unsafe { u8_ptr_to_vec(dgst, dgst_len as usize) };
            if dgst_vec.is_empty() {
                openssl_log!(
                    OpenSSLError::IncorrectParam(
                        "dgst_vec".to_string(),
                        "> 0".to_string(),
                        format!("{}", dgst_vec.len())
                    ),
                    tracing::Level::ERROR,
                    "c_sign_cb: digest length is empty",
                );
                return OpenSSLErrorCode::Error.into();
            }
            match func(type_, dgst_vec, kinv, r, eckey) {
                Ok(sig_vec) => {
                    if !sig_len.is_null() {
                        unsafe {
                            *sig_len = sig_vec.len() as c_uint;
                        }
                    }

                    if !sig.is_null() {
                        unsafe {
                            slice_to_u8_ptr(&sig_vec[..], sig, sig_vec.len());
                        }
                    }

                    OpenSSLErrorCode::Success.into()
                }
                Err(e) => {
                    openssl_log!(
                        e.clone(),
                        tracing::Level::ERROR,
                        "c_sign_cb: signing failed with fatal error",
                    );
                    OpenSSLErrorCode::Fail.into()
                }
            }
        }),
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_sign_cb: Could not get callback SIGN_FN",
            );
            OpenSSLErrorCode::Fail.into()
        }
    }
}

/// C signing setup callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_sign_setup_cb(
    eckey: *mut EC_KEY,
    ctx_in: *mut BN_CTX,
    kinvp: *mut *mut BIGNUM,
    rp: *mut *mut BIGNUM,
) -> c_int {
    if eckey.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("eckey".to_string()),
            tracing::Level::ERROR,
            "c_sign_setup_cb: EC key is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    result_int_callback!(SIGN_SETUP_FN, eckey, ctx_in, kinvp, rp)
}

/// C signing signature callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_sign_sig_cb(
    dgst: *const c_uchar,
    dgst_len: c_int,
    in_kinv: *const BIGNUM,
    in_r: *const BIGNUM,
    eckey: *mut EC_KEY,
) -> *mut ECDSA_SIG {
    if dgst.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("dgst".to_string()),
            tracing::Level::ERROR,
            "c_sign_sig_cb: digest is null",
        );
        return null_mut();
    }

    if eckey.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("eckey".to_string()),
            tracing::Level::ERROR,
            "c_sign_sig_cb: EC key is null",
        );
        return null_mut();
    }

    match SIGN_SIG_FN.get() {
        Some(func) => on_unwind_abort(|| {
            if dgst_len < 1 {
                openssl_log!(
                    OpenSSLError::IncorrectParam(
                        "dgst_len".to_string(),
                        "> 0".to_string(),
                        format!("{dgst_len}")
                    ),
                    tracing::Level::ERROR,
                    "c_sign_sig_cb: digest length < 1",
                );
                return null_mut();
            }
            let dgst = unsafe { u8_ptr_to_vec(dgst, dgst_len as usize) };
            match func(dgst, in_kinv, in_r, eckey) {
                Ok(v) => v,
                Err(e) => {
                    openssl_log!(
                        e.clone(),
                        tracing::Level::ERROR,
                        "c_sign_sig_cb: Error in SIGN_SIG_FN callback",
                    );
                    null_mut()
                }
            }
        }),
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_sign_sig_cb: Could not get callback SIGN_SIG_FN",
            );
            null_mut()
        }
    }
}

/// C verification callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_verify_cb(
    type_: c_int,
    dgst: *const c_uchar,
    dgst_len: c_int,
    sigbuf: *const c_uchar,
    sig_len: c_int,
    eckey: *mut EC_KEY,
) -> c_int {
    if dgst.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("dgst".to_string()),
            tracing::Level::ERROR,
            "c_verify_cb: digest is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if sigbuf.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("sigbuf".to_string()),
            tracing::Level::ERROR,
            "c_verify_cb: signature buffer is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if eckey.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("eckey".to_string()),
            tracing::Level::ERROR,
            "c_verify_cb: EC key is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    match VERIFY_FN.get() {
        Some(func) => on_unwind_abort(|| {
            if dgst_len < 1 {
                openssl_log!(
                    OpenSSLError::IncorrectParam(
                        "dgst_len".to_string(),
                        "> 0".to_string(),
                        format!("{dgst_len}")
                    ),
                    tracing::Level::ERROR,
                    "c_verify_cb: digest length < 1",
                );
                return OpenSSLErrorCode::Error.into();
            }

            if sig_len < 1 {
                openssl_log!(
                    OpenSSLError::IncorrectParam(
                        "sig_len".to_string(),
                        "> 0".to_string(),
                        format!("{sig_len}")
                    ),
                    tracing::Level::ERROR,
                    "c_verify_cb: signature length length < 1",
                );
                return OpenSSLErrorCode::Error.into();
            }

            let dgst = unsafe { u8_ptr_to_vec(dgst, dgst_len as usize) };
            let sigbuf = unsafe { u8_ptr_to_vec(sigbuf, sig_len as usize) };
            match func(type_, dgst, sigbuf, eckey) {
                Ok(_) => OpenSSLErrorCode::Success.into(),
                Err(OpenSSLError::VerifyFailed) => {
                    // Do not log debug stuff into OpenSSL
                    tracing::debug!("c_verify_cb: Verification of signature failed");
                    OpenSSLErrorCode::Fail.into()
                }
                Err(OpenSSLError::IncorrectHsmParam(e)) => {
                    openssl_log!(
                        OpenSSLError::IncorrectHsmParam(e.clone()),
                        tracing::Level::ERROR,
                        "c_verify_cb: incorrect HSM parameteters",
                    );
                    OpenSSLErrorCode::Fail.into()
                }
                Err(e) => {
                    openssl_log!(
                        e.clone(),
                        tracing::Level::ERROR,
                        "c_verify_cb: Verifying signature failed with fatal error",
                    );
                    OpenSSLErrorCode::Error.into()
                }
            }
        }),
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_verify_cb: Could not get callback VERIFY_FN",
            );
            OpenSSLErrorCode::Error.into()
        }
    }
}

/// C signature verification callback that calls our underlying Rust function
pub(super) unsafe extern "C" fn c_verify_sig_cb(
    dgst: *const c_uchar,
    dgst_len: c_int,
    sig: *const ECDSA_SIG,
    key: *mut EC_KEY,
) -> c_int {
    if dgst.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("dgst".to_string()),
            tracing::Level::ERROR,
            "c_verify_sig_cb: digest is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if sig.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("sig".to_string()),
            tracing::Level::ERROR,
            "c_verify_sig_cb: signature is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if key.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key".to_string()),
            tracing::Level::ERROR,
            "c_verify_sig_cb: key is null",
        );
        return OpenSSLErrorCode::Error.into();
    }

    match VERIFY_SIG_FN.get() {
        Some(func) => on_unwind_abort(|| {
            if dgst_len < 1 {
                openssl_log!(
                    OpenSSLError::IncorrectParam(
                        "dgst_len".to_string(),
                        "> 0".to_string(),
                        format!("{dgst_len}")
                    ),
                    tracing::Level::ERROR,
                    "c_verify_cb: digest length length < 1",
                );
                return OpenSSLErrorCode::Error.into();
            }
            let dgst = unsafe { u8_ptr_to_vec(dgst, dgst_len as usize) };
            convert_result_int(func(dgst, sig, key))
        }),
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_verify_cb: Could not get callback VERIFY_SIG_FN",
            );
            OpenSSLErrorCode::Error.into()
        }
    }
}
