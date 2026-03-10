// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_uint;
use std::ffi::c_ushort;
use std::ffi::c_void;
use std::slice::from_raw_parts;
use std::sync::OnceLock;

use crate::openssl_log;
use crate::safeapi::callback::result_int_callback_notfound;
use crate::safeapi::error::*;
use crate::safeapi::evp_pkey::callback::common::SignCtxResult;
use crate::safeapi::util::get_evp_md_by_nid;
use crate::safeapi::util::slice_to_u8_ptr;
#[cfg(feature = "openssl_3")]
use crate::EVP_MD_get_type;
#[cfg(feature = "openssl_111")]
use crate::EVP_MD_type;
use crate::EVP_MD;
use crate::EVP_MD_CTX;
use crate::EVP_PKEY;
use crate::EVP_PKEY_CTRL_DIGESTINIT;
use crate::EVP_PKEY_CTRL_GET_MD;
use crate::EVP_PKEY_CTRL_GET_RSA_OAEP_MD;
use crate::EVP_PKEY_CTRL_GET_RSA_PADDING;
use crate::EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN;
use crate::EVP_PKEY_CTRL_MD;
use crate::EVP_PKEY_CTRL_RSA_OAEP_MD;
use crate::EVP_PKEY_CTRL_RSA_PADDING;
use crate::EVP_PKEY_CTRL_RSA_PSS_SALTLEN;
use crate::EVP_PKEY_CTX;

/// RSA EVP_PKEY control operation
#[derive(Debug)]
pub enum RsaCtrlOp {
    SetMd(c_uint),
    SetOaepMd(c_uint),
    SetPadding(c_uint),
    SetPssSaltLen(c_int),
    GetMd,
    GetOaepMd,
    GetPadding,
    GetPssSaltLen,
    DigestInit,
}

/// RSA EVP_PKEY control operation result
#[derive(Debug)]
pub enum RsaCtrlOpResult {
    GetMd(c_uint),
    GetOaepMd(c_uint),
    GetPadding(c_uint),
    GetPssSaltLen(c_ushort),
}

pub type RsaOpInitFn = fn(*mut EVP_PKEY_CTX) -> OpenSSLResult<()>;
pub type RsaGenFn = fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> OpenSSLResult<()>;
pub type RsaCopyFn = fn(*mut EVP_PKEY_CTX, *const EVP_PKEY_CTX) -> OpenSSLResult<()>;
pub type RsaCleanupFn = fn(*mut EVP_PKEY_CTX);
pub type RsaCtrlFn = fn(*mut EVP_PKEY_CTX, RsaCtrlOp) -> OpenSSLResult<Option<RsaCtrlOpResult>>;
pub type RsaParamGenInitFn = RsaOpInitFn;
pub type RsaKeyGenInitFn = RsaOpInitFn;
pub type RsaParamGenFn = RsaGenFn;
pub type RsaKeyGenFn = RsaGenFn;
pub type RsaEncDecInitFn = RsaOpInitFn;
pub type RsaEncDecFn = fn(*mut EVP_PKEY_CTX, &[u8]) -> OpenSSLResult<Vec<u8>>;
pub type RsaSignVerifyInitFn = RsaOpInitFn;
pub type RsaSignVerifyCtxInitFn = fn(*mut EVP_PKEY_CTX, *mut EVP_MD_CTX) -> OpenSSLResult<()>;
pub type RsaSignCtxInitFn = RsaSignVerifyCtxInitFn;
pub type RsaVerifyCtxInitFn = RsaSignVerifyCtxInitFn;
pub type RsaSignFn = fn(*mut EVP_PKEY_CTX, &[u8]) -> OpenSSLResult<Vec<u8>>;
pub type RsaSignCtxFn =
    fn(*mut EVP_PKEY_CTX, *mut EVP_MD_CTX, bool) -> OpenSSLResult<SignCtxResult>;
pub type RsaVerifyFn = fn(*mut EVP_PKEY_CTX, &[u8], &[u8]) -> OpenSSLResult<()>;
pub type RsaVerifyCtxFn = fn(*mut EVP_PKEY_CTX, &[u8], *mut EVP_MD_CTX) -> OpenSSLResult<()>;

pub(crate) static RSA_CLEANUP_FN: OnceLock<RsaCleanupFn> = OnceLock::new();
pub(crate) static RSA_CTRL_FN: OnceLock<RsaCtrlFn> = OnceLock::new();
pub(crate) static RSA_ENCRYPT_INIT_FN: OnceLock<RsaEncDecInitFn> = OnceLock::new();
pub(crate) static RSA_ENCRYPT_FN: OnceLock<RsaEncDecFn> = OnceLock::new();
pub(crate) static RSA_DECRYPT_INIT_FN: OnceLock<RsaEncDecInitFn> = OnceLock::new();
pub(crate) static RSA_DECRYPT_FN: OnceLock<RsaEncDecFn> = OnceLock::new();
pub(crate) static RSA_KEYGEN_INIT_FN: OnceLock<RsaKeyGenInitFn> = OnceLock::new();
pub(crate) static RSA_KEYGEN_FN: OnceLock<RsaKeyGenFn> = OnceLock::new();
pub(crate) static RSA_PARAMGEN_INIT_FN: OnceLock<RsaParamGenInitFn> = OnceLock::new();
pub(crate) static RSA_PARAMGEN_FN: OnceLock<RsaParamGenFn> = OnceLock::new();
pub(crate) static RSA_COPY_FN: OnceLock<RsaCopyFn> = OnceLock::new();
pub(crate) static RSA_SIGN_INIT_FN: OnceLock<RsaSignVerifyInitFn> = OnceLock::new();
pub(crate) static RSA_SIGN_CTX_INIT_FN: OnceLock<RsaSignCtxInitFn> = OnceLock::new();
pub(crate) static RSA_SIGN_FN: OnceLock<RsaSignFn> = OnceLock::new();
pub(crate) static RSA_SIGN_CTX_FN: OnceLock<RsaSignCtxFn> = OnceLock::new();
pub(crate) static RSA_VERIFY_INIT_FN: OnceLock<RsaSignVerifyInitFn> = OnceLock::new();
pub(crate) static RSA_VERIFY_CTX_INIT_FN: OnceLock<RsaVerifyCtxInitFn> = OnceLock::new();
pub(crate) static RSA_VERIFY_FN: OnceLock<RsaVerifyFn> = OnceLock::new();
pub(crate) static RSA_VERIFY_CTX_FN: OnceLock<RsaVerifyCtxFn> = OnceLock::new();

/// RSA copy C-facing callback
#[cfg(feature = "openssl_3")]
pub(crate) unsafe extern "C" fn c_rsa_copy_cb(
    dst: *mut EVP_PKEY_CTX,
    src: *const EVP_PKEY_CTX,
) -> c_int {
    if dst.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("dst".to_string()),
            tracing::Level::ERROR,
            "c_rsa_copy_cb: destination is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if src.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("src".to_string()),
            tracing::Level::ERROR,
            "c_rsa_copy_cb: source is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(RSA_COPY_FN, OpenSSLErrorCode::NotSupported, dst, src)
}

#[cfg(feature = "openssl_111")]
pub(crate) unsafe extern "C" fn c_rsa_copy_cb(
    dst: *mut EVP_PKEY_CTX,
    src: *mut EVP_PKEY_CTX,
) -> c_int {
    if dst.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("dst".to_string()),
            tracing::Level::ERROR,
            "c_rsa_copy_cb: destination is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if src.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("src".to_string()),
            tracing::Level::ERROR,
            "c_rsa_copy_cb: source is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(RSA_COPY_FN, OpenSSLErrorCode::NotSupported, dst, src)
}

/// RSA encrypt init C-facing callback
pub(crate) unsafe extern "C" fn c_rsa_encrypt_init_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_encrypt_init_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(RSA_ENCRYPT_INIT_FN, OpenSSLErrorCode::NotSupported, ctx_ptr)
}

/// RSA encryption C-facing callback
pub(crate) unsafe extern "C" fn c_rsa_encrypt_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    outbuf: *mut c_uchar,
    outlen: *mut usize,
    inbuf: *const c_uchar,
    inlen: usize,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_encrypt_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if inbuf.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("inbuf".to_string()),
            tracing::Level::ERROR,
            "c_rsa_encrypt_cb: inbuf is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    let inbuf_slice = unsafe { from_raw_parts(inbuf, inlen) };

    match RSA_ENCRYPT_FN.get() {
        Some(func) => match on_unwind_abort(|| func(ctx_ptr, inbuf_slice)) {
            Ok(outvec) => {
                if !outlen.is_null() {
                    unsafe {
                        *outlen = outvec.len();
                    }
                }

                if !outbuf.is_null() {
                    unsafe {
                        slice_to_u8_ptr(&outvec[..], outbuf, outvec.len());
                    }
                }

                OpenSSLErrorCode::Success.into()
            }
            Err(e) => {
                openssl_log!(
                    e.clone(),
                    tracing::Level::ERROR,
                    "c_rsa_encrypt_cb: Error in RSA_ENCRYPT_FN",
                );
                OpenSSLErrorCode::Fail.into()
            }
        },
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_rsa_encrypt_cb: Could not get callback RSA_ENCRYPT_FN",
            );
            OpenSSLErrorCode::NotSupported.into()
        }
    }
}

/// RSA decrypt init C-facing callback
pub(crate) unsafe extern "C" fn c_rsa_decrypt_init_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_decrypt_init_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(RSA_DECRYPT_INIT_FN, OpenSSLErrorCode::NotSupported, ctx_ptr)
}

/// RSA decryption C-facing callback
pub(crate) unsafe extern "C" fn c_rsa_decrypt_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    outbuf: *mut c_uchar,
    outlen: *mut usize,
    inbuf: *const c_uchar,
    inlen: usize,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_decrypt_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if inbuf.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("inbuf".to_string()),
            tracing::Level::ERROR,
            "c_rsa_decrypt_cb: inbuf is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    let inbuf_slice = unsafe { from_raw_parts(inbuf, inlen) };

    match RSA_DECRYPT_FN.get() {
        Some(func) => match on_unwind_abort(|| func(ctx_ptr, inbuf_slice)) {
            Ok(outvec) => {
                if !outlen.is_null() {
                    unsafe {
                        *outlen = outvec.len();
                    }
                }

                if !outbuf.is_null() {
                    unsafe {
                        slice_to_u8_ptr(&outvec, outbuf, outvec.len());
                    }
                }

                OpenSSLErrorCode::Success.into()
            }
            Err(e) => {
                openssl_log!(
                    e.clone(),
                    tracing::Level::ERROR,
                    "c_rsa_decrypt_cb: Error in RSA_DECRYPT_FN",
                );
                OpenSSLErrorCode::Fail.into()
            }
        },
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_rsa_encrypt_cb: Could not get callback RSA_DECRYPT_FN",
            );
            OpenSSLErrorCode::NotSupported.into()
        }
    }
}

/// EVP_PKEY keygen init C-facing callback
pub(crate) unsafe extern "C" fn c_rsa_keygen_init_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_keygen_init_cb: null parameter passed",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(RSA_KEYGEN_INIT_FN, OpenSSLErrorCode::NotSupported, ctx_ptr)
}

/// EVP_PKEY paramgen init C-facing callback
pub(crate) unsafe extern "C" fn c_rsa_paramgen_init_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_paramgen_init_cb: null parameter passed",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(
        RSA_PARAMGEN_INIT_FN,
        OpenSSLErrorCode::NotSupported,
        ctx_ptr
    )
}

/// RSA keygen C-facing callback
pub(crate) unsafe extern "C" fn c_rsa_keygen_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    key_ptr: *mut EVP_PKEY,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_keygen_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if key_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_keygen_cb: key is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(
        RSA_KEYGEN_FN,
        OpenSSLErrorCode::NotSupported,
        ctx_ptr,
        key_ptr
    )
}

/// RSA paramgen C-facing callback
pub(crate) unsafe extern "C" fn c_rsa_paramgen_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    key_ptr: *mut EVP_PKEY,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_paramgen_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if key_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_paramgen_cb: key is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(
        RSA_PARAMGEN_FN,
        OpenSSLErrorCode::NotSupported,
        ctx_ptr,
        key_ptr
    )
}

/// RSA sign init C-facing callback
pub(crate) unsafe extern "C" fn c_rsa_sign_init_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_sign_init_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(RSA_SIGN_INIT_FN, OpenSSLErrorCode::NotSupported, ctx_ptr)
}

/// RSA sign ctx init C-facing callback
pub(crate) extern "C" fn c_rsa_sign_ctx_init_cb(
    pkey_ctx_ptr: *mut EVP_PKEY_CTX,
    md_ctx_ptr: *mut EVP_MD_CTX,
) -> c_int {
    if pkey_ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("pkey_ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_sign_ctx_init_cb: pkey_ctx_ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if md_ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("md_ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_sign_ctx_init_cb: md_ctx_ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(
        RSA_SIGN_CTX_INIT_FN,
        OpenSSLErrorCode::NotSupported,
        pkey_ctx_ptr,
        md_ctx_ptr
    )
}

/// RSA verify ctx init C-facing callback
pub(crate) extern "C" fn c_rsa_verify_ctx_init_cb(
    pkey_ctx_ptr: *mut EVP_PKEY_CTX,
    md_ctx_ptr: *mut EVP_MD_CTX,
) -> c_int {
    if pkey_ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("pkey_ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_verify_ctx_init_cb: pkey_ctx_ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if md_ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("md_ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_verify_ctx_init_cb: md_ctx_ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(
        RSA_VERIFY_CTX_INIT_FN,
        OpenSSLErrorCode::NotSupported,
        pkey_ctx_ptr,
        md_ctx_ptr
    )
}

/// RSA signing C-facing callback
pub(crate) unsafe extern "C" fn c_rsa_sign_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    sigbuf: *mut c_uchar,
    siglen: *mut usize,
    tbsbuf: *const c_uchar,
    tbslen: usize,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_sign_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if tbsbuf.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("tbsbuf".to_string()),
            tracing::Level::ERROR,
            "c_rsa_sign_cb: tbsbuf is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    let tbs_slice = unsafe { from_raw_parts(tbsbuf, tbslen) };

    match RSA_SIGN_FN.get() {
        Some(func) => match on_unwind_abort(|| func(ctx_ptr, tbs_slice)) {
            Ok(sigvec) => {
                if !siglen.is_null() {
                    unsafe {
                        *siglen = sigvec.len();
                    }
                }

                if !sigbuf.is_null() {
                    unsafe {
                        slice_to_u8_ptr(&sigvec, sigbuf, sigvec.len());
                    }
                }

                OpenSSLErrorCode::Success.into()
            }
            Err(e) => {
                openssl_log!(
                    e.clone(),
                    tracing::Level::ERROR,
                    "c_rsa_sign_cb: Error in callback RSA_SIGN_FN",
                );
                OpenSSLErrorCode::Fail.into()
            }
        },
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_rsa_sign_cb: Could not get callback RSA_SIGN_FN",
            );
            OpenSSLErrorCode::NotSupported.into()
        }
    }
}

/// RSA sign ctx C-facing callback
pub(crate) extern "C" fn c_rsa_sign_ctx_cb(
    pkey_ctx: *mut EVP_PKEY_CTX,
    sig: *mut c_uchar,
    siglen: *mut usize,
    md_ctx: *mut EVP_MD_CTX,
) -> c_int {
    if pkey_ctx.is_null() {
        openssl_log!(
            OpenSSLError::NotImplemented,
            tracing::Level::ERROR,
            "c_rsa_sign_ctx_cb: pkey ctx is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if siglen.is_null() {
        openssl_log!(
            OpenSSLError::NotImplemented,
            tracing::Level::ERROR,
            "c_rsa_sign_ctx_cb: siglen is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if md_ctx.is_null() {
        openssl_log!(
            OpenSSLError::NotImplemented,
            tracing::Level::ERROR,
            "c_rsa_sign_ctx_cb: md ctx is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    let get_siglen = sig.is_null();

    match RSA_SIGN_CTX_FN.get() {
        Some(func) => match on_unwind_abort(|| func(pkey_ctx, md_ctx, get_siglen)) {
            Ok(sigvec) => {
                let sig_len = match sigvec {
                    SignCtxResult::SigLen(len) => len,
                    SignCtxResult::Sig(sigvec) => {
                        if !sig.is_null() {
                            unsafe {
                                slice_to_u8_ptr(&sigvec, sig, sigvec.len());
                            }
                        }
                        sigvec.len()
                    }
                };

                if !siglen.is_null() {
                    unsafe {
                        *siglen = sig_len;
                    }
                }

                OpenSSLErrorCode::Success.into()
            }
            Err(e) => {
                openssl_log!(
                    e.clone(),
                    tracing::Level::ERROR,
                    "c_rsa_sign_ctx_cb: Error in RSA_SIGN_CTX_FN",
                );
                OpenSSLErrorCode::Fail.into()
            }
        },
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_rsa_sign_ctx_cb: Could not get RSA_SIGN_CTX_FN callback",
            );
            OpenSSLErrorCode::NotSupported.into()
        }
    }
}

/// RSA verify init C-facing callback
pub(crate) unsafe extern "C" fn c_rsa_verify_init_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_verify_init_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(RSA_VERIFY_INIT_FN, OpenSSLErrorCode::NotSupported, ctx_ptr)
}

/// RSA verify C-facing callback
pub(crate) unsafe extern "C" fn c_rsa_verify_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    sigbuf: *const c_uchar,
    siglen: usize,
    tbsbuf: *const c_uchar,
    tbslen: usize,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_verify_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if sigbuf.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("sigbuf".to_string()),
            tracing::Level::ERROR,
            "c_rsa_verify_cb: signature buffer is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if tbsbuf.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("tbsbuf".to_string()),
            tracing::Level::ERROR,
            "c_rsa_verify_cb: tbs buffer is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    let sig_slice = unsafe { from_raw_parts(sigbuf, siglen) };
    let tbs_slice = unsafe { from_raw_parts(tbsbuf, tbslen) };

    result_int_callback_notfound!(
        RSA_VERIFY_FN,
        OpenSSLErrorCode::NotSupported,
        ctx_ptr,
        sig_slice,
        tbs_slice
    )
}

/// RSA verify ctx C-facing callback
pub(crate) extern "C" fn c_rsa_verify_ctx_cb(
    pkey_ctx: *mut EVP_PKEY_CTX,
    sig: *const c_uchar,
    siglen: c_int,
    md_ctx: *mut EVP_MD_CTX,
) -> c_int {
    if pkey_ctx.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_verify_ctx_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if sig.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("sig".to_string()),
            tracing::Level::ERROR,
            "c_rsa_verify_ctx_cb: signature is null",
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
            "c_rsa_verify_ctx_cb: signature length is zero",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if md_ctx.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("md_ctx".to_string()),
            tracing::Level::ERROR,
            "c_rsa_verify_ctx_cb: md ctx is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    let sig_slice = unsafe { from_raw_parts(sig, siglen as usize) };

    match RSA_VERIFY_CTX_FN.get() {
        Some(func) => match on_unwind_abort(|| func(pkey_ctx, sig_slice, md_ctx)) {
            Ok(_) => OpenSSLErrorCode::Success.into(),
            Err(e) => {
                openssl_log!(
                    e.clone(),
                    tracing::Level::ERROR,
                    "c_rsa_verify_ctx_cb: Error in RSA_VERIFY_CTX_FN",
                );
                OpenSSLErrorCode::Fail.into()
            }
        },
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_rsa_verify_ctx_cb: Could not get callback RSA_VERIFY_CTX_FN",
            );
            OpenSSLErrorCode::NotSupported.into()
        }
    }
}

/// RSA cleanup C-facing callback
pub(crate) unsafe extern "C" fn c_rsa_cleanup_cb(ctx_ptr: *mut EVP_PKEY_CTX) {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_cleanup_cb: ctx ptr is null",
        );
        return;
    }

    if let Some(func) = RSA_CLEANUP_FN.get() {
        on_unwind_abort(|| func(ctx_ptr));
    } else {
        openssl_log!(
            OpenSSLError::NotImplemented,
            tracing::Level::ERROR,
            "c_rsa_cleanup_cb: Could not get callback RSA_CLEANUP_FN",
        );
    }
}

/// RSA ctrl C-facing callback
pub(crate) unsafe extern "C" fn c_rsa_ctrl_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    op: c_int,
    arg1: c_int,
    arg2: *mut c_void,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_rsa_ctrl_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    let op_type = match op as c_uint {
        EVP_PKEY_CTRL_GET_MD => RsaCtrlOp::GetMd,
        EVP_PKEY_CTRL_GET_RSA_OAEP_MD => RsaCtrlOp::GetOaepMd,
        EVP_PKEY_CTRL_GET_RSA_PADDING => RsaCtrlOp::GetPadding,
        EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN => RsaCtrlOp::GetPssSaltLen,
        EVP_PKEY_CTRL_MD => {
            let md_ptr = arg2 as *const EVP_MD;
            #[cfg(feature = "openssl_3")]
            let md_type = unsafe { EVP_MD_get_type(md_ptr) } as c_uint;
            #[cfg(feature = "openssl_111")]
            let md_type = unsafe { EVP_MD_type(md_ptr) } as c_uint;
            RsaCtrlOp::SetMd(md_type)
        }
        EVP_PKEY_CTRL_RSA_OAEP_MD => {
            let md_ptr = arg2 as *const EVP_MD;
            #[cfg(feature = "openssl_3")]
            let md_type = unsafe { EVP_MD_get_type(md_ptr) } as c_uint;
            #[cfg(feature = "openssl_111")]
            let md_type = unsafe { EVP_MD_type(md_ptr) } as c_uint;
            RsaCtrlOp::SetOaepMd(md_type)
        }
        EVP_PKEY_CTRL_RSA_PADDING => RsaCtrlOp::SetPadding(arg1 as c_uint),
        EVP_PKEY_CTRL_RSA_PSS_SALTLEN => RsaCtrlOp::SetPssSaltLen(arg1),
        EVP_PKEY_CTRL_DIGESTINIT => RsaCtrlOp::DigestInit,
        _ => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_rsa_ctrl_cb: Unsupported operation {op}",
            );
            return OpenSSLErrorCode::NotSupported.into();
        }
    };

    if let Some(func) = RSA_CTRL_FN.get() {
        match on_unwind_abort(|| func(ctx_ptr, op_type)) {
            Ok(None) => {}
            Ok(Some(RsaCtrlOpResult::GetMd(nid))) => {
                let md = unsafe { get_evp_md_by_nid(nid) };
                if md.is_null() {
                    openssl_log!(
                        OpenSSLError::HashNotSupported,
                        tracing::Level::ERROR,
                        "c_rsa_ctrl_cb: Could not get digest from NID: {nid}",
                    );
                    return OpenSSLErrorCode::Fail.into();
                }
                unsafe {
                    *(arg2 as *mut *const EVP_MD) = md;
                }
            }
            Ok(Some(RsaCtrlOpResult::GetOaepMd(nid))) => {
                let md = unsafe { get_evp_md_by_nid(nid) };
                if md.is_null() {
                    openssl_log!(
                        OpenSSLError::HashNotSupported,
                        tracing::Level::ERROR,
                        "c_rsa_ctrl_cb: Could not get digest from NID: {nid}",
                    );
                    return OpenSSLErrorCode::Fail.into();
                }
                unsafe {
                    *(arg2 as *mut *const EVP_MD) = md;
                }
            }
            Ok(Some(RsaCtrlOpResult::GetPadding(len))) => unsafe {
                *(arg2 as *mut c_int) = len as c_int
            },
            Ok(Some(RsaCtrlOpResult::GetPssSaltLen(len))) => unsafe {
                *(arg2 as *mut c_ushort) = len as c_ushort
            },
            Err(e) => {
                openssl_log!(
                    e.clone(),
                    tracing::Level::ERROR,
                    "c_rsa_ctrl_cb: Error calling RSA_CTRL_FN",
                );
                return OpenSSLErrorCode::Fail.into();
            }
        };
    } else {
        openssl_log!(
            OpenSSLError::NotImplemented,
            tracing::Level::ERROR,
            "c_rsa_ctrl_cb: Could not get callback RSA_CTRL_FN",
        );
        return OpenSSLErrorCode::NotSupported.into();
    }

    OpenSSLErrorCode::Success.into()
}
