// Copyright (C) Microsoft Corporation. All rights reserved.

use std::env::var_os;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_ulong;
use std::ffi::CStr;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::sync::OnceLock;

use openssl_rust::safeapi::engine::Engine;
use openssl_rust::safeapi::engine::EngineExData;
use openssl_rust::safeapi::error::on_unwind_abort;
use openssl_rust::safeapi::error::OpenSSLError;
use openssl_rust::safeapi::error::OpenSSLErrorCode;
use openssl_rust::safeapi::error::OpenSSLResult;
use openssl_rust::*;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

pub mod ciphers;
use ciphers::init::init_ciphers;

pub mod common;
use common::base_key::ENGINE_KEY_HANDLE_TABLE;

pub mod ec;
use ec::init::init_ec;

pub mod engine_ctrl;
use engine_ctrl::init::init_engine_ctrl;

pub mod engine_data;
use engine_data::EngineData;

pub mod load_key;
use load_key::init_load_key;

pub mod engine_internal;
use engine_internal::azihsm_engine;

pub mod pkey;
use pkey::init::init_pkeys;

pub mod rsa;
use rsa::init::init_rsa;

const ENGINE_ID: &str = "azihsmengine";
const ENGINE_NAME: &str = "AZIHSM OpenSSL engine";

// C strings are dynamically allocated... so we have to do this.
static C_ENGINE_ID: OnceLock<CString> = OnceLock::new();
static C_ENGINE_NAME: OnceLock<CString> = OnceLock::new();

/// Destroy the Engine object
pub(crate) fn engine_destroy(engine: &Engine) -> OpenSSLResult<()> {
    // delete the keys in the key handle table
    ENGINE_KEY_HANDLE_TABLE.delete_keys();

    // Destroy the AZIHSM engine
    let result = azihsm_engine().write().destroy();

    // Delete engine data
    let mut engine_ex_data: EngineExData<EngineData> =
        EngineExData::new_from_ptr(engine.as_mut_ptr());
    engine_ex_data.free_data();

    result
}

/// Configure engine logging
pub fn init_log(engine: *mut ENGINE) -> OpenSSLResult<()> {
    let mut layers = Vec::new();

    if var_os("AZIHSM_ENGINE_LOG_STDERR").is_some() {
        let layer = tracing_subscriber::fmt::layer()
            .pretty()
            .with_thread_names(true)
            .with_target(true)
            .with_writer(io::stderr)
            .boxed();
        layers.push(layer);
    }

    if let Some(path) = var_os("AZIHSM_ENGINE_LOG_FILE") {
        let file = File::create(path).map_err(|e| OpenSSLError::LogFileError(format!("{e}")))?;
        let layer = tracing_subscriber::fmt::layer()
            .compact()
            .with_thread_names(true)
            .with_target(true)
            .with_writer(file)
            .boxed();
        layers.push(layer);
    }

    let registry = tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(layers);

    // Attach the guard to the engine, this will live as long as the engine
    let guard = tracing::subscriber::set_default(registry);
    let mut engine_ex_data: EngineExData<EngineData> = EngineExData::new_from_ptr(engine);
    engine_ex_data.set_data(EngineData::new(guard))?;

    tracing::info!("azihsmengine: logging started");
    Ok(())
}

/// Actually perform engine init
///
/// # Argument
/// * `engine` - pointer to the current ENGINE
/// * `id` - id of the engine
///
/// # Return
/// Appropriate error code on failure
pub fn bind_helper(engine: &Engine, id: &CStr) -> OpenSSLResult<()> {
    let engine_id = CString::new(ENGINE_ID).map_err(OpenSSLError::CStringNulError)?;
    let engine_id = C_ENGINE_ID.get_or_init(|| engine_id);

    let engine_name = CString::new(ENGINE_NAME).map_err(OpenSSLError::CStringNulError)?;
    let engine_name = C_ENGINE_NAME.get_or_init(|| engine_name);

    if !id.is_empty() && id != engine_id.as_ref() {
        Err(OpenSSLError::IdMismatch)?;
    }

    engine.set_id(engine_id)?;
    engine.set_name(engine_name)?;

    // Initialize the AZIHSM engine
    azihsm_engine().write().init()?;

    init_ec(engine)?;
    init_engine_ctrl(engine)?;

    init_ciphers(engine)?;
    init_pkeys(engine)?;
    init_rsa(engine)?;
    init_load_key(engine)?;

    engine.set_destroy_function(engine_destroy)?;

    Ok(())
}

/// Main C entrypoint into the engine
///
/// # Argument
/// * `engine_ptr` - pointer to the current ENGINE
/// * `id` - id of the engine
/// * `fns` - OpenSSL dynamic function table
///
/// # Return
/// Appropriate error code on failure
#[no_mangle]
pub extern "C" fn bind_engine(
    engine_ptr: *mut ENGINE,
    id: *const c_char,
    fns: *const dynamic_fns,
) -> c_int {
    if let Err(e) = init_log(engine_ptr) {
        eprintln!("Could not setup logging: {e}");
        return OpenSSLErrorCode::Fail.into();
    }

    let engine = Engine::new_from_ptr(engine_ptr);

    // Call into the actual init function
    match on_unwind_abort(|| engine.bind(id, fns, bind_helper)) {
        Ok(_) => OpenSSLErrorCode::Success.into(),
        Err(e) => {
            tracing::error!("Could not load engine: {e}");
            OpenSSLErrorCode::Fail.into()
        }
    }
}

/// C-facing OpenSSL v_check function
#[no_mangle]
pub extern "C" fn v_check(v: c_ulong) -> c_ulong {
    if v >= DYNAMIC_OLDEST {
        return DYNAMIC_VERSION;
    }

    0
}

/// This function is used in tests only
#[cfg(test)]
pub(crate) fn load_engine() -> Engine {
    let engine = Engine::new_engine().expect("Could not make engine");
    let id = CString::new("azihsmengine").expect("Could not make id");
    let result = bind_helper(&engine, id.as_ref());
    assert!(result.is_ok());
    engine
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_same_id() {
        let engine = Engine::new_engine().expect("Could not make engine");
        let id = CString::new("azihsmengine").expect("Could not make id");
        let result = bind_helper(&engine, id.as_ref());
        assert!(result.is_ok());
    }

    #[test]
    fn test_bind_different_id() {
        let engine = Engine::new_engine().expect("Could not make engine");
        let id = CString::new("test").expect("Could not make id");
        let result = bind_helper(&engine, id.as_ref());
        assert!(result.is_err(), "result {:?}", result);
    }
}
