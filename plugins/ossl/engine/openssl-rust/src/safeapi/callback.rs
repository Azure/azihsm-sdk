// Copyright (C) Microsoft Corporation. All rights reserved.

//! Callbacks for ENGINE operations

use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_long;
use std::ffi::c_uint;
use std::ffi::c_void;
use std::ffi::CStr;
use std::ptr::null_mut;
use std::sync::OnceLock;

use crate::openssl_log;
use crate::safeapi::engine::Engine;
use crate::safeapi::engine_ctrl::*;
use crate::safeapi::error::convert_result_int;
use crate::safeapi::error::on_unwind_abort;
use crate::safeapi::error::OpenSSLError;
use crate::safeapi::error::OpenSSLErrorCode;
use crate::safeapi::error::OpenSSLResult;
use crate::safeapi::evp_cipher::method::EvpCipherMethod;
use crate::safeapi::evp_pkey::method::EvpPKeyMethod;
use crate::ENGINE;
use crate::EVP_CIPHER;
use crate::EVP_PKEY;
use crate::EVP_PKEY_METHOD;
use crate::UI_METHOD;

/// Macro for simple callbacks using convert_result_int
macro_rules! result_int_callback_notfound {
    ($callback:expr, $ret_if_none:expr $(, $args:expr)*) => {
        match $callback.get() {
            Some(func) => on_unwind_abort(|| convert_result_int(func($($args),*))),
            None => {
                openssl_log!(
                    OpenSSLError::NotImplemented,
                    tracing::Level::ERROR,
                    "Could not get callback {}",
                    stringify!($callback),
                );
                $ret_if_none.into()
            }
        }
    };
}

macro_rules! result_int_callback {
    ($callback:expr $(, $args:expr)*) => {
        crate::safeapi::callback::result_int_callback_notfound!(
            $callback,
            crate::safeapi::error::OpenSSLErrorCode::Fail,
            $($args),*
        )
    }
}

// Only visible after macros are declared
pub(crate) use result_int_callback;
pub(crate) use result_int_callback_notfound;

pub enum EngineCiphersResult<'a> {
    Cipher(&'a EvpCipherMethod),
    Nids((&'a [c_int], c_int)),
}

pub enum EnginePKeyResult<'a> {
    PKey(&'a EvpPKeyMethod),
    Nids((&'a [c_uint], c_uint)),
}

/// Generic function pointer for ENGINE callbacks
type EngineGenIntFn = fn(&Engine) -> OpenSSLResult<()>;
/// Engine destroy callback
pub type EngineDestroyFn = EngineGenIntFn;
/// Engine ciphers callback
pub type EngineCiphersFn = fn(&Engine, c_int) -> OpenSSLResult<EngineCiphersResult>;
/// Engine PKEY callback
pub type EnginePKeyFn = fn(&Engine, c_uint) -> OpenSSLResult<EnginePKeyResult>;
/// Engine load key function
pub type EngineLoadKeyFn =
    fn(&Engine, &str, *mut UI_METHOD, *mut c_void) -> OpenSSLResult<*mut EVP_PKEY>;

pub(super) static ENGINE_DESTROY: OnceLock<EngineDestroyFn> = OnceLock::new();
pub(super) static ENGINE_CIPHERS: OnceLock<EngineCiphersFn> = OnceLock::new();
pub(super) static ENGINE_PKEY: OnceLock<EnginePKeyFn> = OnceLock::new();
pub(super) static ENGINE_PRIVKEY: OnceLock<EngineLoadKeyFn> = OnceLock::new();

/// Engine destroy callback
pub(super) unsafe extern "C" fn c_engine_destroy_cb(e: *mut ENGINE) -> c_int {
    let engine = Engine::new_from_ptr(e);
    result_int_callback!(ENGINE_DESTROY, &engine)
}

/// Engine ciphers callback
///
/// # Arguments
/// * `e` - The engine to get ciphers from
/// * `cipher` - The cipher to return
/// * `nids` - The nids to return
/// * `nid` - The nid of cipher algorithm to get
///
///# Returns
/// When cipher is null, returns the number of nids on success, -1 on error
/// When cipher is not null, returns 1 if the cipher is found, 0 otherwise
pub(super) unsafe extern "C" fn c_engine_ciphers_cb(
    e: *mut ENGINE,
    cipher: *mut *const EVP_CIPHER,
    nids: *mut *const c_int,
    nid: c_int,
) -> c_int {
    if nid == 0 && nids.is_null() {
        openssl_log!(
            OpenSSLError::NoCiphersAvailable,
            tracing::Level::ERROR,
            "c_engine_ciphers_cb: no nid's requested for information",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if nid > 0 && cipher.is_null() {
        openssl_log!(
            OpenSSLError::NoCiphersAvailable,
            tracing::Level::ERROR,
            "c_engine_ciphers_cb: no cipher requested for information",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    let engine = Engine::new_from_ptr(e);

    let result = match ENGINE_CIPHERS.get() {
        Some(func) => on_unwind_abort(|| func(&engine, nid)),
        None => Err(OpenSSLError::CipherMethodRetrievalError),
    };

    match result {
        Ok(EngineCiphersResult::Cipher(cipher_method)) => {
            *cipher = cipher_method.as_ptr();
            OpenSSLErrorCode::Success.into()
        }
        Ok(EngineCiphersResult::Nids((s_nids, count))) => {
            *nids = s_nids.as_ptr();
            count
        }
        Err(e) => {
            openssl_log!(
                e.clone(),
                tracing::Level::ERROR,
                "c_engine_ciphers_cb: could not get engine ciphers information",
            );
            OpenSSLErrorCode::Fail.into()
        }
    }
}

/// Engine PKey callback
/// # Arguments
/// * `e` - The engine to get PKEY methods from
/// * `method` - The pkey methods to return
/// * `nids` - The nids to return
/// * `nid` - The nid of pkey algorithm to get
///
///# Returns
/// When method is null, returns the number of nids on success, -1 on error
/// When method is not null, returns 1 if the method is found, 0 otherwise
pub(super) unsafe extern "C" fn c_engine_pkey_cb(
    e: *mut ENGINE,
    method: *mut *mut EVP_PKEY_METHOD,
    nids: *mut *const c_int,
    nid: c_int,
) -> c_int {
    if nid == 0 && nids.is_null() {
        openssl_log!(
            OpenSSLError::NoPKeyMethodsAvailable,
            tracing::Level::ERROR,
            "c_engine_pkey_cb: no nid's requested for information",
        );
        return OpenSSLErrorCode::Error.into();
    }

    if nid > 0 && method.is_null() {
        openssl_log!(
            OpenSSLError::NoPKeyMethodsAvailable,
            tracing::Level::ERROR,
            "c_engine_pkey_cb: no method requested for information",
        );
        return OpenSSLErrorCode::Fail.into();
    }

    let engine = Engine::new_from_ptr(e);
    let result = match ENGINE_PKEY.get() {
        Some(func) => on_unwind_abort(|| func(&engine, nid as c_uint)),
        None => {
            openssl_log!(
                OpenSSLError::PKeyMethodRetrievalError,
                tracing::Level::ERROR,
                "c_engine_pkey_cb: Could not get ENGINE_PKEY callback",
            );
            Err(OpenSSLError::PKeyMethodRetrievalError)
        }
    };

    match result {
        Ok(EnginePKeyResult::PKey(pkey_method)) => {
            *method = pkey_method.as_mut_ptr();
            OpenSSLErrorCode::Success.into()
        }
        Ok(EnginePKeyResult::Nids((s_nids, count))) => {
            *nids = s_nids.as_ptr() as *const c_int;
            count as c_int
        }
        Err(e) => {
            openssl_log!(
                e.clone(),
                tracing::Level::ERROR,
                "c_engine_pkey_cb: Could not get engine PKey information",
            );
            OpenSSLErrorCode::Fail.into()
        }
    }
}

/// Engine control callback
pub(super) unsafe extern "C" fn c_engine_ctrl_cb(
    engine_ptr: *mut ENGINE,
    num: c_int,
    i: c_long,
    ptr: *mut c_void,
    _f: Option<unsafe extern "C" fn()>,
) -> c_int {
    let num = num as c_uint;
    let engine = Engine::new_from_ptr(engine_ptr);

    let cmds = match ENGINE_CTRL_CMDS.get() {
        Some(cmds) => cmds,
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_engine_ctrl_cb: Could not get ENGINE_CTRL_CMDS callback",
            );
            return OpenSSLErrorCode::Fail.into();
        }
    };

    let result = cmds.iter().find(|&cmd| cmd.num() == num);
    match result {
        Some(cmd) => match cmd.callback(&engine, num, i, ptr) {
            Ok(_) => OpenSSLErrorCode::Success.into(),
            Err(e) => {
                openssl_log!(
                    e.clone(),
                    tracing::Level::ERROR,
                    "c_engine_ctrl_cb: Error calling ctrl callback {}",
                    cmd.name(),
                );
                OpenSSLErrorCode::Fail.into()
            }
        },
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_engine_ctrl_cb: Could not find command {num}",
            );
            OpenSSLErrorCode::NotSupported.into()
        }
    }
}

/// Engine privkey retrieval callback
///
/// # Arguments
/// * `engine_ptr` - The engine to call this on
/// * `id` - C char array of key ID
/// * `ui_method` - UI method callback
/// * `data` - Callback data
///
/// # Returns
/// `EVP_PKEY` structure on success, `null` on error
pub(super) unsafe extern "C" fn c_engine_load_private_key(
    engine_ptr: *mut ENGINE,
    id: *const c_char,
    ui_method: *mut UI_METHOD,
    data: *mut c_void,
) -> *mut EVP_PKEY {
    if engine_ptr.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("engine_ptr".to_string()),
            tracing::Level::ERROR,
            "c_engine_load_private_key: engine is null",
        );
        return null_mut();
    }

    if id.is_null() {
        openssl_log!(
            OpenSSLError::NullParam("id".to_string()),
            tracing::Level::ERROR,
            "c_engine_load_private_key: id is null",
        );
        return null_mut();
    }

    let engine = Engine::new_from_ptr(engine_ptr);
    let id = unsafe { CStr::from_ptr(id) };
    let id = match id.to_str() {
        Ok(str) => str,
        Err(e) => {
            openssl_log!(
                OpenSSLError::InvalidKey,
                tracing::Level::ERROR,
                "c_engine_load_private_key: invalid key ID: {e}",
            );
            return null_mut();
        }
    };

    match ENGINE_PRIVKEY.get() {
        Some(func) => match func(&engine, id, ui_method, data) {
            Ok(pkey) => pkey,
            Err(e) => {
                openssl_log!(
                    e.clone(),
                    tracing::Level::ERROR,
                    "c_engine_load_private_key: error getting pkey",
                );
                null_mut()
            }
        },
        None => {
            openssl_log!(
                OpenSSLError::NotImplemented,
                tracing::Level::ERROR,
                "c_engine_load_private_key: could not get ENGINE_PRIVKEY callback",
            );
            null_mut()
        }
    }
}
