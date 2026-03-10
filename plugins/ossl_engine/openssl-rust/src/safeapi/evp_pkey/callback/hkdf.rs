// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_void;
use std::ptr;
use std::slice;
use std::sync::OnceLock;

use engine_common::handle_table::Handle;
use engine_common::*;

use crate::openssl_log;
#[cfg(feature = "openssl_3")]
use crate::EVP_MD_get_type;
#[cfg(feature = "openssl_111")]
use crate::EVP_MD_type;
use crate::EVP_MD;
use crate::EVP_PKEY_ALG_CTRL;
use crate::EVP_PKEY_CTX;

const PKEY_ALG_CTRL: c_int = EVP_PKEY_ALG_CTRL as c_int;
// Define OpenSSL constants
const EVP_PKEY_CTRL_HKDF_MD: c_int = PKEY_ALG_CTRL + 3;
const EVP_PKEY_CTRL_HKDF_SALT: c_int = PKEY_ALG_CTRL + 4;
const EVP_PKEY_CTRL_HKDF_KEY: c_int = PKEY_ALG_CTRL + 5;
const EVP_PKEY_CTRL_HKDF_INFO: c_int = PKEY_ALG_CTRL + 6;
const EVP_PKEY_CTRL_HKDF_MODE: c_int = PKEY_ALG_CTRL + 7;

const EVP_PKEY_CTRL_HKDF_CUSTOM_KEY_TYPE: c_int = 0x2000;
const EVP_PKEY_CTRL_HKDF_CUSTOM_KBKDF: c_int = 0x2001;

pub const EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND: i32 = 0;
pub const EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY: i32 = 1;
pub const EVP_PKEY_HKDEF_MODE_EXPAND_ONLY: i32 = 2;

use crate::safeapi::callback::result_int_callback_notfound;
use crate::safeapi::error::*;

#[derive(Debug)]
pub enum HkdfDeriveResult {
    Handle(Handle),
    SecretLen(usize),
}

#[derive(Debug)]
pub enum HkdfCtrlOp {
    SetKey(Handle),
    SetSalt(Vec<u8>),
    AddInfo(Vec<u8>),
    SetMd(c_int), //EVP_MD_type
    SetMode(c_int),
    SetKeyType(c_int),
    SetKbkdf,
}

pub type HkdfDeriveInitFn = fn(*mut EVP_PKEY_CTX) -> OpenSSLResult<()>;
pub type HkdfDeriveFn = fn(*mut EVP_PKEY_CTX, out_len: usize) -> OpenSSLResult<HkdfDeriveResult>;
pub type HkdfCtrlFn = fn(*mut EVP_PKEY_CTX, HkdfCtrlOp) -> OpenSSLResult<()>;
pub type HkdfCleanupFn = fn(*mut EVP_PKEY_CTX);

pub(crate) static HKDF_DERIVE_INIT_FN: OnceLock<HkdfDeriveInitFn> = OnceLock::new();
pub(crate) static HKDF_DERIVE_FN: OnceLock<HkdfDeriveFn> = OnceLock::new();
pub(crate) static HKDF_CTRL_FN: OnceLock<HkdfCtrlFn> = OnceLock::new();
pub(crate) static HKDF_CLEANUP_FN: OnceLock<HkdfCleanupFn> = OnceLock::new();

/// HKDF derive C-facing callback
pub(crate) unsafe extern "C" fn c_hkdf_derive_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    key_ptr: *mut c_uchar,
    key_len_ptr: *mut usize,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_hkdf_derive_cb: ctx_ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if key_len_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("key_len_ptr".to_string()),
            tracing::Level::ERROR,
            "c_hkdf_derive_cb: key_len_ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if (*key_len_ptr != 0 && key_ptr.is_null()) || (*key_len_ptr == 0 && !key_ptr.is_null()) {
        openssl_log!(
            OpenSSLError::InvalidKey,
            tracing::Level::ERROR,
            "c_hkdf_derive_cb: invalid key",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    match HKDF_DERIVE_FN.get() {
        Some(func) => on_unwind_abort(|| {
            let out_len = *key_len_ptr;

            match func(ctx_ptr, out_len) {
                Ok(HkdfDeriveResult::SecretLen(len)) => {
                    *key_len_ptr = len;
                    OpenSSLErrorCode::Success.into()
                }
                Ok(HkdfDeriveResult::Handle(handle)) => {
                    if key_ptr.is_null() {
                        openssl_log!(
                            OpenSSLError::NullParam("key_ptr".to_string()),
                            tracing::Level::ERROR,
                            "c_hkdf_derive_cb: key_ptr is null",
                        );
                        return OpenSSLErrorCode::Fail.into();
                    }
                    *key_len_ptr = ENGINE_KEY_HANDLE_SIZE;
                    let handle_be_bytes = handle.to_be_bytes();
                    ptr::copy_nonoverlapping(
                        handle_be_bytes.as_ptr(),
                        key_ptr,
                        ENGINE_KEY_HANDLE_SIZE,
                    );
                    OpenSSLErrorCode::Success.into()
                }
                Err(e) => {
                    openssl_log!(
                        e.clone(),
                        tracing::Level::ERROR,
                        "c_hkdf_derive_cb: Error in HKDF_DERIVE_FN",
                    );
                    OpenSSLErrorCode::Fail.into()
                }
            }
        }),
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_hkdf_derive_cb: Error retrieving HKDF_DERIVE_FN callback",
            );
            OpenSSLErrorCode::NotSupported.into()
        }
    }
}

/// HKDF control C-facing callback
pub(crate) unsafe extern "C" fn c_hkdf_ctrl_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    op_type: c_int,
    p1: c_int,
    p2_ptr: *mut c_void,
) -> c_int {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_hkdf_ctrl_cb: ctx_ptr is null",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    if p2_ptr.is_null()
        && (op_type == EVP_PKEY_CTRL_HKDF_MD
            || op_type == EVP_PKEY_CTRL_HKDF_KEY
            || op_type == EVP_PKEY_CTRL_HKDF_SALT
            || op_type == EVP_PKEY_CTRL_HKDF_INFO)
    {
        openssl_log!(
            OpenSSLError::NotImplemented,
            tracing::Level::ERROR,
            "c_hkdf_ctrl_cb: Unsupported operation parameters",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    match HKDF_CTRL_FN.get() {
        Some(func) => on_unwind_abort(|| {
            let ctrl_op = match op_type {
                EVP_PKEY_CTRL_HKDF_MD => {
                    let md_ptr = p2_ptr as *const EVP_MD;
                    let md_type = get_md_type(md_ptr);
                    HkdfCtrlOp::SetMd(md_type)
                }
                EVP_PKEY_CTRL_HKDF_KEY => {
                    let mut read_buf = [0u8; ENGINE_KEY_HANDLE_SIZE];
                    ptr::copy_nonoverlapping(
                        p2_ptr as *const u8,
                        read_buf.as_mut_ptr(),
                        ENGINE_KEY_HANDLE_SIZE,
                    );
                    let handle = Handle::from_be_bytes(read_buf);
                    HkdfCtrlOp::SetKey(handle)
                }
                EVP_PKEY_CTRL_HKDF_SALT => {
                    let salt = slice::from_raw_parts(p2_ptr as *const u8, p1 as usize);
                    HkdfCtrlOp::SetSalt(salt.to_vec())
                }
                EVP_PKEY_CTRL_HKDF_INFO => {
                    let info = slice::from_raw_parts(p2_ptr as *const u8, p1 as usize);
                    HkdfCtrlOp::AddInfo(info.to_vec())
                }
                EVP_PKEY_CTRL_HKDF_MODE => HkdfCtrlOp::SetMode(p1),
                EVP_PKEY_CTRL_HKDF_CUSTOM_KEY_TYPE => HkdfCtrlOp::SetKeyType(p1),
                EVP_PKEY_CTRL_HKDF_CUSTOM_KBKDF => HkdfCtrlOp::SetKbkdf,
                _ => {
                    openssl_log!(
                        OpenSSLError::NotImplemented,
                        tracing::Level::ERROR,
                        "c_hkdf_ctrl_cb: op type {op_type} not supported",
                    );
                    return OpenSSLErrorCode::NotSupported.into();
                }
            };

            match func(ctx_ptr, ctrl_op) {
                Ok(_) => OpenSSLErrorCode::Success.into(),
                Err(e) => {
                    openssl_log!(
                        e.clone(),
                        tracing::Level::ERROR,
                        "c_hkdf_ctrl_cb: error in HKDF ctrl operation",
                    );
                    OpenSSLErrorCode::Fail.into()
                }
            }
        }),
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_hkdf_ctrl_cb: could not get HKDF_CTRL_FN callback",
            );
            OpenSSLErrorCode::Fail.into()
        }
    }
}

/// HKDF cleanup C-facing callback
pub(crate) unsafe extern "C" fn c_hkdf_cleanup_cb(ctx_ptr: *mut EVP_PKEY_CTX) {
    if ctx_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("ctx_ptr".to_string()),
            tracing::Level::ERROR,
            "c_hkdf_cleanup_cb: ctx_ptr is null",
        );
        return;
    }

    if let Some(func) = HKDF_CLEANUP_FN.get() {
        on_unwind_abort(|| func(ctx_ptr));
    } else {
        openssl_log!(
            OpenSSLError::NotImplemented,
            tracing::Level::ERROR,
            "c_hkdf_cleanup_cb: Could not get callback HKDF_CLEANUP_FN",
        );
    }
}

/// HKDF derive-init C-facing callback
pub(crate) unsafe extern "C" fn c_hkdf_derive_init_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> c_int {
    if ctx_ptr.is_null() {
        return OpenSSLErrorCode::Fail.into();
    }

    result_int_callback_notfound!(HKDF_DERIVE_INIT_FN, OpenSSLErrorCode::NotSupported, ctx_ptr)
}

fn get_md_type(md: *const EVP_MD) -> c_int {
    #[cfg(feature = "openssl_3")]
    unsafe {
        EVP_MD_get_type(md)
    }
    #[cfg(feature = "openssl_111")]
    unsafe {
        EVP_MD_type(md)
    }
}
