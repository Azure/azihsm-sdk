// Copyright (C) Microsoft Corporation. All rights reserved.

//! callbacks for cipher methods

use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_void;
use std::ptr;
use std::sync::OnceLock;

use engine_common::handle_table::Handle;
use engine_common::*;

use crate::openssl_log;
use crate::safeapi::error::*;
use crate::safeapi::evp_cipher::ctx::*;
use crate::EVP_CIPHER_CTX;
use crate::EVP_CTRL_AEAD_TLS1_AAD;
use crate::EVP_CTRL_COPY;
use crate::EVP_CTRL_GCM_GET_TAG;
use crate::EVP_CTRL_GCM_SET_IVLEN;
use crate::EVP_CTRL_GCM_SET_TAG;
use crate::EVP_CTRL_GET_IVLEN;
use crate::EVP_CTRL_INIT;
use crate::EVP_CTRL_RAND_KEY;

pub enum CipherCtrlOp<'a> {
    RandKey,
    CtxCopy(&'a EvpCipherCtx),
    CtrlInit,
    SetIvLen(i32),
    GetIvLen,
    SetTag(Option<Vec<u8>>, i32),
    GetTag,
    SetTls1Aad(Vec<u8>),
}

#[derive(Debug, PartialEq)]
pub enum CipherCtrlResult {
    KeyHandle(Handle),
    CopySuccess,
    CtrlInitSuccess,
    SetIvLenSuccess,
    IvLen(i32),
    SetTagSuccess,
    Tag(Vec<u8>),
    SetTls1AadSuccess,
}

pub enum CipherFn {
    CipherAesCbc(CipherCbcDoCipherFn),
    CipherAesGcm(CipherGcmDoCipherFn),
    CipherAesXts(CipherXtsDoCipherFn),
}

pub type CipherInitFn = fn(&EvpCipherCtx, Option<Handle>, Option<Vec<u8>>) -> OpenSSLResult<()>;
pub type CipherCtrlFn = fn(&EvpCipherCtx, CipherCtrlOp) -> OpenSSLResult<CipherCtrlResult>;
pub type CipherCleanupFn = fn(&EvpCipherCtx) -> OpenSSLResult<()>;
pub type CipherCbcDoCipherFn = fn(&EvpCipherCtx, Vec<u8>) -> OpenSSLResult<Vec<u8>>;
pub type CipherGcmDoCipherFn = fn(&EvpCipherCtx, Vec<u8>, bool) -> OpenSSLResult<Option<Vec<u8>>>;
pub type CipherXtsDoCipherFn = fn(&EvpCipherCtx, Vec<u8>) -> OpenSSLResult<Vec<u8>>;

pub(super) static AES_INIT_FN: OnceLock<CipherInitFn> = OnceLock::new();
pub(super) static AES_CTRL_FN: OnceLock<CipherCtrlFn> = OnceLock::new();
pub(super) static AES_CLEANUP_FN: OnceLock<CipherCleanupFn> = OnceLock::new();
pub(super) static AES_CBC_DO_CIPHER_FN: OnceLock<CipherCbcDoCipherFn> = OnceLock::new();
pub(super) static AES_GCM_DO_CIPHER_FN: OnceLock<CipherGcmDoCipherFn> = OnceLock::new();
pub(super) static AES_XTS_DO_CIPHER_FN: OnceLock<CipherXtsDoCipherFn> = OnceLock::new();

/// AES cipher method key init callback
pub(super) unsafe extern "C" fn c_aes_init_cb(
    ctx_ptr: *mut EVP_CIPHER_CTX,
    c_key_buf: *const c_uchar,
    iv: *const c_uchar,
    _enc: c_int,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_aes_init_cb: ctx_ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    match AES_INIT_FN.get() {
        Some(func) => on_unwind_abort(|| {
            let ctx = EvpCipherCtx::new_from_ptr(ctx_ptr);
            let iv_len = ctx.iv_len() as usize;
            let iv_in = if !iv.is_null() {
                Some(std::slice::from_raw_parts(iv, iv_len).to_vec())
            } else {
                None
            };

            let key_handle = if !c_key_buf.is_null() {
                let mut read_buf: [u8; ENGINE_KEY_HANDLE_SIZE] = [0; ENGINE_KEY_HANDLE_SIZE];
                ptr::copy_nonoverlapping(
                    c_key_buf,
                    &mut read_buf as *mut u8,
                    ENGINE_KEY_HANDLE_SIZE,
                );
                Some(Handle::from_be_bytes(read_buf))
            } else {
                None
            };

            match func(&ctx, key_handle, iv_in) {
                Ok(_) => OpenSSLErrorCode::Success.into(),
                Err(e) => {
                    openssl_log!(
                        e.clone(),
                        tracing::Level::ERROR,
                        "c_aes_init_cb: Error in AES_INIT_FN",
                    );
                    OpenSSLErrorCode::Fail.into()
                }
            }
        }),
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_aes_init_cb: could not get AES_INIT_FN",
            );
            OpenSSLErrorCode::Fail.into()
        }
    }
}

/// AES Cipher method key ctrl callback
pub(super) unsafe extern "C" fn c_aes_ctrl_cb(
    ctx_ptr: *mut EVP_CIPHER_CTX,
    ctrl_type: c_int,
    arg: c_int,
    c_ptr: *mut c_void,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_aes_ctrl_cb: ctx_ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    match AES_CTRL_FN.get() {
        Some(func) => on_unwind_abort(|| {
            let ctx = EvpCipherCtx::new_from_ptr(ctx_ptr);
            let out_ctx: EvpCipherCtx;

            let ctrl_op_type = match ctrl_type as u32 {
                EVP_CTRL_INIT => CipherCtrlOp::CtrlInit,
                EVP_CTRL_COPY => {
                    if c_ptr.is_null() {
                        openssl_log!(
                            OpenSSLError::NullParam("c_ptr".to_string()),
                            tracing::Level::ERROR,
                            "c_aes_ctrl_cb: c_ptr is null for EVP_CTRL_COPY",
                        );
                        return OpenSSLErrorCode::Fail.into();
                    }
                    out_ctx = EvpCipherCtx::new_from_ptr(c_ptr as *mut EVP_CIPHER_CTX);
                    CipherCtrlOp::CtxCopy(&out_ctx)
                }
                EVP_CTRL_RAND_KEY => CipherCtrlOp::RandKey,
                EVP_CTRL_GCM_SET_IVLEN => CipherCtrlOp::SetIvLen(arg),
                EVP_CTRL_GET_IVLEN => CipherCtrlOp::GetIvLen,
                EVP_CTRL_GCM_SET_TAG => {
                    if arg <= 0 {
                        openssl_log!(
                            OpenSSLError::IncorrectParam(
                                "arg".to_string(),
                                "> 0".to_string(),
                                format!("{arg}")
                            ),
                            tracing::Level::ERROR,
                            "c_aes_ctrl_cb: invalid arg for EVP_CTRL_GCM_SET_TAG",
                        );
                        return OpenSSLErrorCode::Fail.into();
                    }
                    let tag = if c_ptr.is_null() {
                        None
                    } else {
                        Some(std::slice::from_raw_parts(c_ptr as *const u8, arg as usize).to_vec())
                    };
                    CipherCtrlOp::SetTag(tag, arg)
                }
                EVP_CTRL_GCM_GET_TAG => CipherCtrlOp::GetTag,
                EVP_CTRL_AEAD_TLS1_AAD => {
                    if c_ptr.is_null() {
                        openssl_log!(
                            OpenSSLError::NullParam("c_ptr".to_string()),
                            tracing::Level::ERROR,
                            "c_aes_ctrl_cb: invalid c_ptr for EVP_CTRL_AEAD_TLS1_AAD",
                        );
                        return OpenSSLErrorCode::Fail.into();
                    }

                    if arg <= 0 {
                        openssl_log!(
                            OpenSSLError::IncorrectParam(
                                "arg".to_string(),
                                "> 0".to_string(),
                                format!("{arg}")
                            ),
                            tracing::Level::ERROR,
                            "c_aes_ctrl_cb: invalid arg for EVP_CTRL_AEAD_TLS1_AAD",
                        );
                        return OpenSSLErrorCode::Fail.into();
                    }
                    let aad = std::slice::from_raw_parts(c_ptr as *const u8, arg as usize).to_vec();
                    CipherCtrlOp::SetTls1Aad(aad)
                }
                _ => {
                    openssl_log!(
                        OpenSSLError::NotImplemented,
                        tracing::Level::ERROR,
                        "c_aes_ctrl_cb: unknown ctrl type {ctrl_type}",
                    );
                    return OpenSSLErrorCode::Fail.into();
                }
            };

            match func(&ctx, ctrl_op_type) {
                Ok(CipherCtrlResult::CopySuccess) => 1,
                Ok(CipherCtrlResult::KeyHandle(handle)) => {
                    let handle_be_bytes = handle.to_be_bytes();
                    ptr::copy_nonoverlapping(
                        handle_be_bytes.as_ptr(),
                        c_ptr as *mut u8,
                        ENGINE_KEY_HANDLE_SIZE,
                    );
                    OpenSSLErrorCode::Success.into()
                }
                Ok(CipherCtrlResult::CtrlInitSuccess) => 1,
                Ok(CipherCtrlResult::SetIvLenSuccess) => 1,
                Ok(CipherCtrlResult::IvLen(len)) => {
                    ptr::write(c_ptr as *mut i32, len);
                    OpenSSLErrorCode::Success.into()
                }
                Ok(CipherCtrlResult::SetTagSuccess) => 1,
                Ok(CipherCtrlResult::Tag(tag)) => {
                    ptr::copy_nonoverlapping(tag.as_ptr(), c_ptr as *mut u8, tag.len());
                    OpenSSLErrorCode::Success.into()
                }
                Ok(CipherCtrlResult::SetTls1AadSuccess) => 1,
                Err(e) => {
                    openssl_log!(
                        e.clone(),
                        tracing::Level::ERROR,
                        "c_aes_ctrl_cb: Error in AES_CTRL_FN",
                    );
                    OpenSSLErrorCode::Fail.into()
                }
            }
        }),
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_aes_ctrl_cb: Could not get AES_CTRL_FN",
            );
            OpenSSLErrorCode::Error.into()
        }
    }
}

/// AES CBC cipher method do_cipher callback
pub(super) unsafe extern "C" fn c_aes_cbc_do_cipher_cb(
    ctx_ptr: *mut EVP_CIPHER_CTX,
    out_buf: *mut c_uchar,
    in_buf: *const c_uchar,
    inl: usize,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_aes_cbc_do_cipher_cb: ctx_ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if in_buf.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("in_buf".to_string()),
            tracing::Level::ERROR,
            "c_aes_cbc_do_cipher_cb: in_buf is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if inl == 0 {
        openssl_log!(
            OpenSSLError::IncorrectParam("inl".to_string(), "> 0".to_string(), format!("{inl}")),
            tracing::Level::ERROR,
            "c_aes_cbc_do_cipher_cb: inl is 0",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if out_buf.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("out_buf".to_string()),
            tracing::Level::ERROR,
            "c_aes_cbc_do_cipher_cb: out_buf is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    match AES_CBC_DO_CIPHER_FN.get() {
        Some(func) => on_unwind_abort(|| {
            let ctx = EvpCipherCtx::new_from_ptr(ctx_ptr);
            let input = std::slice::from_raw_parts(in_buf, inl).to_vec();
            match func(&ctx, input) {
                Ok(output) => {
                    ptr::copy_nonoverlapping(output.as_ptr(), out_buf, output.len());
                    OpenSSLErrorCode::Success.into()
                }
                Err(e) => {
                    openssl_log!(
                        e.clone(),
                        tracing::Level::ERROR,
                        "c_aes_cbc_do_cipher_cb: Error in AES_CBC_DO_CIPHER_FN",
                    );
                    OpenSSLErrorCode::Fail.into()
                }
            }
        }),
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_aes_cbc_do_cipher_cb: Could not get AES_CBC_DO_CIPHER_FN",
            );
            OpenSSLErrorCode::Fail.into()
        }
    }
}

/// AES GCM cipher method do_cipher callback
pub(super) unsafe extern "C" fn c_aes_gcm_do_cipher_cb(
    ctx_ptr: *mut EVP_CIPHER_CTX,
    out_buf: *mut c_uchar,
    in_buf: *const c_uchar,
    inl: usize,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_aes_gcm_do_cipher_cb: ctx_ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if in_buf.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("in_buf".to_string()),
            tracing::Level::ERROR,
            "c_aes_gcm_do_cipher_cb: in_buf is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if out_buf.is_null() && inl == 0 {
        openssl_log!(
            OpenSSLError::IncorrectParam(
                "out_buf && inl".to_string(),
                "nonnull && > 0".to_string(),
                format!("{inl}")
            ),
            tracing::Level::ERROR,
            "c_aes_gcm_do_cipher_cb: inl is 0",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    match AES_GCM_DO_CIPHER_FN.get() {
        Some(func) => on_unwind_abort(|| {
            let ctx = EvpCipherCtx::new_from_ptr(ctx_ptr);
            let input = std::slice::from_raw_parts(in_buf, inl).to_vec();
            let aad = out_buf.is_null();
            match func(&ctx, input, aad) {
                Ok(output) => {
                    if let Some(outdata) = output {
                        ptr::copy_nonoverlapping(outdata.as_ptr(), out_buf, outdata.len());
                        outdata.len() as c_int
                    } else {
                        OpenSSLErrorCode::Success.into()
                    }
                }
                Err(e) => {
                    openssl_log!(
                        e.clone(),
                        tracing::Level::ERROR,
                        "c_aes_gcm_do_cipher_cb: Error in AES_GCM_DO_CIPHER_FN",
                    );
                    OpenSSLErrorCode::Error.into()
                }
            }
        }),
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_aes_gcm_do_cipher_cb: Could not get AES_GCM_DO_CIPHER_FN",
            );
            OpenSSLErrorCode::Error.into()
        }
    }
}

/// AES XTS cipher method do_cipher callback
pub(super) unsafe extern "C" fn c_aes_xts_do_cipher_cb(
    ctx_ptr: *mut EVP_CIPHER_CTX,
    out_buf: *mut c_uchar,
    in_buf: *const c_uchar,
    inl: usize,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_aes_xts_do_cipher_cb: ctx_ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if inl == 0 {
        openssl_log!(
            OpenSSLError::IncorrectParam("inl".to_string(), "> 0".to_string(), format!("{inl}")),
            tracing::Level::ERROR,
            "c_aes_xts_do_cipher_cb: inl is 0",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if out_buf.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("out_buf".to_string()),
            tracing::Level::ERROR,
            "c_aes_xts_do_cipher_cb: out_buf is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    match AES_XTS_DO_CIPHER_FN.get() {
        Some(func) => on_unwind_abort(|| {
            let ctx = EvpCipherCtx::new_from_ptr(ctx_ptr);
            let input = std::slice::from_raw_parts(in_buf, inl).to_vec();
            match func(&ctx, input) {
                Ok(output) => {
                    ptr::copy_nonoverlapping(output.as_ptr(), out_buf, output.len());
                    output.len() as c_int
                }
                Err(e) => {
                    openssl_log!(
                        e.clone(),
                        tracing::Level::ERROR,
                        "c_aes_xts_do_cipher_cb: Error in AES_XTS_DO_CIPHER_FN",
                    );
                    OpenSSLErrorCode::Error.into()
                }
            }
        }),
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_aes_xts_do_cipher_cb: Could not get AES_XTS_DO_CIPHER_FN",
            );
            OpenSSLErrorCode::Error.into()
        }
    }
}

/// AES cipher method key cleanup callback
pub(super) unsafe extern "C" fn c_aes_cleanup_cb(ctx_ptr: *mut EVP_CIPHER_CTX) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_aes_cleanup_cb: ctx_ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    match AES_CLEANUP_FN.get() {
        Some(func) => on_unwind_abort(|| {
            let ctx = EvpCipherCtx::new_from_ptr(ctx_ptr);
            convert_result_int(func(&ctx))
        }),
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_aes_xts_do_cipher_cb: Could not get AES_CLEANUP_FN",
            );
            OpenSSLErrorCode::Fail.into()
        }
    }
}
