// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_uint;
use std::ffi::c_void;
use std::slice::from_raw_parts;
use std::sync::OnceLock;

use engine_common::handle_table::Handle;
use engine_common::*;

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
use crate::EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID;
use crate::EVP_PKEY_CTRL_GET_MD;
use crate::EVP_PKEY_CTRL_MD;
use crate::EVP_PKEY_CTRL_PEER_KEY;
use crate::EVP_PKEY_CTX;

#[derive(Debug)]
pub enum EcCtrlOp {
    ParamgenCurveNid(c_int),
    KeyUsageEcdh,
    PeerKey(*mut EVP_PKEY),
    GetMd,
    SetMd(c_uint),
    DigestInit,
}

/// ECC EVP_PKEY control operation result
#[derive(Debug)]
pub enum EcCtrlOpResult {
    GetMd(c_uint),
}

pub type EcInitFn = fn(*mut EVP_PKEY_CTX) -> OpenSSLResult<()>;
pub type EcCopyFn = fn(*mut EVP_PKEY_CTX, *const EVP_PKEY_CTX) -> OpenSSLResult<()>;
pub type EcCleanupFn = fn(*mut EVP_PKEY_CTX);
pub type EcSignVerifyCtxInitFn = fn(*mut EVP_PKEY_CTX, *mut EVP_MD_CTX) -> OpenSSLResult<()>;
pub type EcSignCtxInitFn = EcSignVerifyCtxInitFn;
pub type EcVerifyCtxInitFn = EcSignVerifyCtxInitFn;
pub type EcGenFn = fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> OpenSSLResult<()>;
pub type EcDeriveFn = fn(*mut EVP_PKEY_CTX) -> OpenSSLResult<Handle>;
pub type EcSignFn = fn(*mut EVP_PKEY_CTX, &[u8]) -> OpenSSLResult<Vec<u8>>;
pub type EcSignCtxFn = fn(*mut EVP_PKEY_CTX, *mut EVP_MD_CTX, bool) -> OpenSSLResult<SignCtxResult>;
pub type EcVerifyFn = fn(*mut EVP_PKEY_CTX, &[u8], &[u8]) -> OpenSSLResult<()>;
pub type EcVerifyCtxFn = fn(*mut EVP_PKEY_CTX, &[u8], *mut EVP_MD_CTX) -> OpenSSLResult<()>;

pub type EcOpInitFn = EcInitFn;
pub type EcParamGenInitFn = EcOpInitFn;
pub type EcKeyGenInitFn = EcOpInitFn;
pub type EcSignVerifyInitFn = EcOpInitFn;
pub type EcDeriveInitFn = EcOpInitFn;
pub type EcParamGenFn = EcGenFn;
pub type EcKeyGenFn = EcGenFn;
pub type EcCtrlFn = fn(*mut EVP_PKEY_CTX, EcCtrlOp) -> OpenSSLResult<Option<EcCtrlOpResult>>;

pub(crate) static EC_INIT_FN: OnceLock<EcInitFn> = OnceLock::new();
pub(crate) static EC_COPY_FN: OnceLock<EcCopyFn> = OnceLock::new();
pub(crate) static EC_CLEANUP_FN: OnceLock<EcCleanupFn> = OnceLock::new();
pub(crate) static EC_PARAMGEN_INIT_FN: OnceLock<EcParamGenInitFn> = OnceLock::new();
pub(crate) static EC_PARAMGEN_FN: OnceLock<EcParamGenFn> = OnceLock::new();
pub(crate) static EC_KEYGEN_INIT_FN: OnceLock<EcKeyGenInitFn> = OnceLock::new();
pub(crate) static EC_KEYGEN_FN: OnceLock<EcKeyGenFn> = OnceLock::new();
pub(crate) static EC_CTRL_FN: OnceLock<EcCtrlFn> = OnceLock::new();
pub(crate) static EC_DERIVE_INIT_FN: OnceLock<EcDeriveInitFn> = OnceLock::new();
pub(crate) static EC_DERIVE_FN: OnceLock<EcDeriveFn> = OnceLock::new();
pub(crate) static EC_SIGN_INIT_FN: OnceLock<EcSignVerifyInitFn> = OnceLock::new();
pub(crate) static EC_SIGN_CTX_INIT_FN: OnceLock<EcSignCtxInitFn> = OnceLock::new();
pub(crate) static EC_VERIFY_INIT_FN: OnceLock<EcSignVerifyInitFn> = OnceLock::new();
pub(crate) static EC_VERIFY_CTX_INIT_FN: OnceLock<EcVerifyCtxInitFn> = OnceLock::new();
pub(crate) static EC_SIGN_FN: OnceLock<EcSignFn> = OnceLock::new();
pub(crate) static EC_SIGN_CTX_FN: OnceLock<EcSignCtxFn> = OnceLock::new();
pub(crate) static EC_VERIFY_FN: OnceLock<EcVerifyFn> = OnceLock::new();
pub(crate) static EC_VERIFY_CTX_FN: OnceLock<EcVerifyCtxFn> = OnceLock::new();

const EVP_PKEY_CTRL_EC_CUSTOM_USECASE_ECDH: u32 = 0x2003;

/// EC init C-facing callback
pub(crate) unsafe extern "C" fn c_ec_init_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_ec_init_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(EC_INIT_FN, OpenSSLErrorCode::NotSupported, ctx_ptr)
}

/// EC copy C-facing callback
#[cfg(feature = "openssl_3")]
pub(crate) unsafe extern "C" fn c_ec_copy_cb(
    dst: *mut EVP_PKEY_CTX,
    src: *const EVP_PKEY_CTX,
) -> c_int {
    if dst.is_null() || src.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("dst or src".to_string()),
            tracing::Level::ERROR,
            "c_ec_copy_cb: destination or source is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(EC_COPY_FN, OpenSSLErrorCode::NotSupported, dst, src)
}

#[cfg(feature = "openssl_111")]
pub(crate) unsafe extern "C" fn c_ec_copy_cb(
    dst: *mut EVP_PKEY_CTX,
    src: *mut EVP_PKEY_CTX,
) -> c_int {
    if dst.is_null() || src.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("dst or src".to_string()),
            tracing::Level::ERROR,
            "c_ec_copy_cb: destination or source is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(EC_COPY_FN, OpenSSLErrorCode::NotSupported, dst, src)
}

/// EC cleanup C-facing callback
pub(crate) unsafe extern "C" fn c_ec_cleanup_cb(ctx_ptr: *mut EVP_PKEY_CTX) {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_ec_cleanup_cb: ctx ptr is null",
        );
        return;
    }

    match EC_CLEANUP_FN.get() {
        Some(func) => {
            func(ctx_ptr);
        }
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_ec_cleanup_cb: Error in EC_CLEANUP_FN: No callback function found.",
            );
        }
    }
}

/// EC paramgen-init C-facing callback
pub(crate) unsafe extern "C" fn c_ec_paramgen_init_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_ec_paramgen_init_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(EC_PARAMGEN_INIT_FN, OpenSSLErrorCode::NotSupported, ctx_ptr)
}

/// EC paramgen C-facing callback
pub(crate) unsafe extern "C" fn c_ec_paramgen_cb(
    ctx: *mut EVP_PKEY_CTX,
    pkey: *mut EVP_PKEY,
) -> c_int {
    if ctx.is_null() || pkey.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr or pkey".to_string()),
            tracing::Level::ERROR,
            "c_ec_paramgen_cb: ctx ptr or pkey is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(EC_PARAMGEN_FN, OpenSSLErrorCode::NotSupported, ctx, pkey)
}

/// EC keygen-init C-facing callback
pub(crate) unsafe extern "C" fn c_ec_keygen_init_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_ec_keygen_init_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(EC_KEYGEN_INIT_FN, OpenSSLErrorCode::NotSupported, ctx_ptr)
}

/// EC keygen C-facing callback
pub(crate) unsafe extern "C" fn c_ec_keygen_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    pkey_ptr: *mut EVP_PKEY,
) -> c_int {
    if ctx_ptr.is_null() || pkey_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr or pkey_ptr".to_string()),
            tracing::Level::ERROR,
            "c_ec_keygen_cb: ctx or pkey ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(
        EC_KEYGEN_FN,
        OpenSSLErrorCode::NotSupported,
        ctx_ptr,
        pkey_ptr
    )
}

/// EC ctrl C-facing callback
pub(crate) unsafe extern "C" fn c_ec_ctrl_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    op: c_int,
    arg1: c_int,
    arg2: *mut c_void,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_ec_ctrl_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    let op_type = match op as c_uint {
        EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID => EcCtrlOp::ParamgenCurveNid(arg1),
        EVP_PKEY_CTRL_EC_CUSTOM_USECASE_ECDH => EcCtrlOp::KeyUsageEcdh,
        EVP_PKEY_CTRL_PEER_KEY => {
            if arg2.is_null() {
                openssl_log!(
                    OpenSSLError::NullParam("arg2".to_string()),
                    tracing::Level::ERROR,
                    "c_ec_ctrl_cb: invalid argument",
                );
                return OpenSSLErrorCode::Fail.into();
            }
            EcCtrlOp::PeerKey(arg2 as *mut EVP_PKEY)
        }
        EVP_PKEY_CTRL_GET_MD => EcCtrlOp::GetMd,
        EVP_PKEY_CTRL_MD => {
            let md_ptr = arg2 as *const EVP_MD;
            #[cfg(feature = "openssl_3")]
            let md_type = unsafe { EVP_MD_get_type(md_ptr) } as c_uint;
            #[cfg(feature = "openssl_111")]
            let md_type = unsafe { EVP_MD_type(md_ptr) } as c_uint;
            EcCtrlOp::SetMd(md_type)
        }
        EVP_PKEY_CTRL_DIGESTINIT => EcCtrlOp::DigestInit,
        _ => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_ec_ctrl_cb: Error in EC_CTRL_FN: Invalid operation",
            );
            return OpenSSLErrorCode::Fail.into();
        }
    };

    if let Some(func) = EC_CTRL_FN.get() {
        match on_unwind_abort(|| func(ctx_ptr, op_type)) {
            Ok(None) => {}
            Ok(Some(EcCtrlOpResult::GetMd(nid))) => {
                let md = unsafe { get_evp_md_by_nid(nid) };
                if md.is_null() {
                    openssl_log!(
                        OpenSSLError::HashNotSupported,
                        tracing::Level::ERROR,
                        "c_ec_ctrl_cb: Could not get digest from NID: {nid}",
                    );
                    return OpenSSLErrorCode::Fail.into();
                }
                unsafe {
                    *(arg2 as *mut *const EVP_MD) = md;
                }
            }
            Err(e) => {
                openssl_log!(
                    e.clone(),
                    tracing::Level::ERROR,
                    "c_ec_ctrl_cb: Error calling EC_CTRL_FN",
                );
                return OpenSSLErrorCode::Fail.into();
            }
        };
    } else {
        openssl_log!(
            OpenSSLError::NotImplemented,
            tracing::Level::ERROR,
            "c_ec_ctrl_cb: Could not get callback EC_CTRL_FN",
        );
        return OpenSSLErrorCode::NotSupported.into();
    }

    OpenSSLErrorCode::Success.into()
}

/// EC derive-init C-facing callback
pub(crate) unsafe extern "C" fn c_ec_derive_init_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_ec_derive_init_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(EC_DERIVE_INIT_FN, OpenSSLErrorCode::NotSupported, ctx_ptr)
}

/// EC derive C-facing callback
pub(crate) unsafe extern "C" fn c_ec_derive_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    key: *mut c_uchar,
    keylen: *mut usize,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_ec_derive_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if key.is_null() && keylen.is_null() {
        openssl_log!(
            OpenSSLError::InvalidKey,
            tracing::Level::ERROR,
            "c_ec_derive_cb: Invalid key",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if key.is_null() && !keylen.is_null() {
        *keylen = ENGINE_KEY_HANDLE_SIZE;
        return OpenSSLErrorCode::Success.into();
    }

    match EC_DERIVE_FN.get() {
        Some(func) => on_unwind_abort(|| match func(ctx_ptr) {
            Ok(handle) => {
                if !keylen.is_null() {
                    *keylen = ENGINE_KEY_HANDLE_SIZE;
                }
                if !key.is_null() {
                    let handle_be_bytes = handle.to_be_bytes();
                    unsafe {
                        slice_to_u8_ptr(&handle_be_bytes[..], key, ENGINE_KEY_HANDLE_SIZE);
                    }
                }
                OpenSSLErrorCode::Success.into()
            }
            Err(e) => {
                openssl_log!(
                    e.clone(),
                    tracing::Level::ERROR,
                    "c_ec_derive_cb: Error in EC_DERIVE_FN",
                );
                OpenSSLErrorCode::Fail.into()
            }
        }),
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_ec_derive_cb: Error in EC_DERIVE_FN: No callback function found",
            );
            OpenSSLErrorCode::Fail.into()
        }
    }
}

/// EC sign-init C-facing callback
pub(crate) unsafe extern "C" fn c_ec_sign_init_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_ec_sign_init_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(EC_SIGN_INIT_FN, OpenSSLErrorCode::NotSupported, ctx_ptr)
}

/// EC sign ctx init C-facing callback
pub(crate) extern "C" fn c_ec_sign_ctx_init_cb(
    pkey_ctx_ptr: *mut EVP_PKEY_CTX,
    md_ctx_ptr: *mut EVP_MD_CTX,
) -> c_int {
    if pkey_ctx_ptr.is_null() || md_ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("pkey_ctx_ptr or md_ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_ec_sign_ctx_init_cb: pkey or md ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(
        EC_SIGN_CTX_INIT_FN,
        OpenSSLErrorCode::NotSupported,
        pkey_ctx_ptr,
        md_ctx_ptr
    )
}

/// EC sign C-facing callback
pub(crate) unsafe extern "C" fn c_ec_sign_cb(
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
            "c_ec_sign_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if tbsbuf.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("tbsbuf".to_string()),
            tracing::Level::ERROR,
            "c_ec_sign_cb: tbsbuf ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    let tbs_slice = unsafe { from_raw_parts(tbsbuf, tbslen) };

    match EC_SIGN_FN.get() {
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

                1
            }
            Err(e) => {
                openssl_log!(
                    e.clone(),
                    tracing::Level::ERROR,
                    "c_ec_sign_cb: Error in EC_SIGN_FN",
                );
                OpenSSLErrorCode::Fail.into()
            }
        },
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_ec_sign_cb: Error in EC_SIGN_FN: could not get callback",
            );
            OpenSSLErrorCode::NotSupported.into()
        }
    }
}

/// EC sign ctx C-facing callback
pub(crate) extern "C" fn c_ec_sign_ctx_cb(
    pkey_ctx: *mut EVP_PKEY_CTX,
    sig: *mut c_uchar,
    siglen: *mut usize,
    md_ctx: *mut EVP_MD_CTX,
) -> c_int {
    if pkey_ctx.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("pkey_ctx".to_string()),
            tracing::Level::ERROR,
            "c_ec_sign_ctx_cb: pkey ctx is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if siglen.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("siglen".to_string()),
            tracing::Level::ERROR,
            "c_ec_sign_ctx_cb: siglen is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if md_ctx.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("md_ctx".to_string()),
            tracing::Level::ERROR,
            "c_ec_sign_ctx_cb: md ctx is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    let get_siglen = sig.is_null();

    match EC_SIGN_CTX_FN.get() {
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
                    "c_ec_sign_ctx_cb: Error in EC_SIGN_CTX_FN",
                );
                OpenSSLErrorCode::Fail.into()
            }
        },
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_ec_sign_ctx_cb: Error in EC_SIGN_CTX_FN: could not get callback",
            );
            OpenSSLErrorCode::NotSupported.into()
        }
    }
}

/// EC verify-init C-facing callback
pub(crate) unsafe extern "C" fn c_ec_verify_init_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_ec_verify_init_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(EC_VERIFY_INIT_FN, OpenSSLErrorCode::NotSupported, ctx_ptr)
}

/// RSA verify ctx init C-facing callback
pub(crate) extern "C" fn c_ec_verify_ctx_init_cb(
    pkey_ctx_ptr: *mut EVP_PKEY_CTX,
    md_ctx_ptr: *mut EVP_MD_CTX,
) -> c_int {
    result_int_callback_notfound!(
        EC_VERIFY_CTX_INIT_FN,
        OpenSSLErrorCode::NotSupported,
        pkey_ctx_ptr,
        md_ctx_ptr
    )
}

/// EC verify C-facing callback
pub(crate) unsafe extern "C" fn c_ec_verify_cb(
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
            "c_ec_verify_cb: ctx ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if sigbuf.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("sigbuf".to_string()),
            tracing::Level::ERROR,
            "c_ec_verify_cb: signature buffer is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if tbsbuf.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("tbsbuf".to_string()),
            tracing::Level::ERROR,
            "c_ec_verify_cb: verify data is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    let sig_slice = unsafe { from_raw_parts(sigbuf, siglen) };
    let tbs_slice = unsafe { from_raw_parts(tbsbuf, tbslen) };

    result_int_callback_notfound!(
        EC_VERIFY_FN,
        OpenSSLErrorCode::NotSupported,
        ctx_ptr,
        sig_slice,
        tbs_slice
    )
}

/// RSA verify ctx C-facing callback
pub(crate) extern "C" fn c_ec_verify_ctx_cb(
    pkey_ctx: *mut EVP_PKEY_CTX,
    sig: *const c_uchar,
    siglen: c_int,
    md_ctx: *mut EVP_MD_CTX,
) -> c_int {
    if pkey_ctx.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("pkey_ctx".to_string()),
            tracing::Level::ERROR,
            "c_ec_verify_ctx_cb: pkey ctx is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if sig.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("sig".to_string()),
            tracing::Level::ERROR,
            "c_ec_verify_ctx_cb: signature is null",
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
            "c_ec_verify_ctx_cb: siglen is 0",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if md_ctx.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("md_ctx".to_string()),
            tracing::Level::ERROR,
            "c_ec_verify_ctx_cb: md ctx is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    let sig_slice = unsafe { from_raw_parts(sig, siglen as usize) };

    match EC_VERIFY_CTX_FN.get() {
        Some(func) => match on_unwind_abort(|| func(pkey_ctx, sig_slice, md_ctx)) {
            Ok(_) => OpenSSLErrorCode::Success.into(),
            Err(e) => {
                openssl_log!(
                    e.clone(),
                    tracing::Level::ERROR,
                    "c_ec_verify_ctx_cb: Error in EC_VERIFY_CTX_FN",
                );
                OpenSSLErrorCode::Fail.into()
            }
        },
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_ec_verify_ctx_cb: Error in EC_VERIFY_CTX_FN: could not get callback",
            );
            OpenSSLErrorCode::NotSupported.into()
        }
    }
}
