// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Engine bind/destroy wiring and the exported dynamic-engine entry points
//! (`bind_engine`/`v_check`) OpenSSL's dynamic loader calls.

use std::ffi::CStr;
use std::ffi::c_int;
use std::ffi::c_ulong;
use std::ptr::NonNull;
use std::sync::OnceLock;

use azihsm_ossl_engine_core::engine::DestroyHandler;
use azihsm_ossl_engine_core::engine::Engine;
use azihsm_ossl_engine_core::engine::LoadPrivKeyHandler;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
use azihsm_ossl_engine_core::error::RetCode;
use azihsm_ossl_engine_core::error::catch_panic;
use azihsm_ossl_engine_core::error::result_to_int;
use azihsm_ossl_engine_core::exdata::EngineExData;
use azihsm_ossl_engine_core::ffi;
use parking_lot::Mutex;

use crate::context::EngineData;
use crate::logging;

const ENGINE_ID: &CStr = c"azihsm";
const ENGINE_NAME: &CStr = c"Azure Integrated HSM Engine";

/// Process-global cached ex_data slot for `EngineData`.
/// `CRYPTO_get_ex_new_index` does not dedupe, so we register at most once.
static ENGINE_DATA_SLOT: OnceLock<EngineExData<EngineData>> = OnceLock::new();

fn engine_data_slot() -> EngineResult<EngineExData<EngineData>> {
    if let Some(slot) = ENGINE_DATA_SLOT.get() {
        return Ok(*slot);
    }
    // Serialize registration so two concurrent binds can't each allocate an
    // ex_data index (OpenSSL never dedupes them).
    static INIT: Mutex<()> = Mutex::new(());
    let _guard = INIT.lock();
    if let Some(slot) = ENGINE_DATA_SLOT.get() {
        return Ok(*slot);
    }
    let slot = EngineExData::<EngineData>::register()?;
    let _ = ENGINE_DATA_SLOT.set(slot);
    Ok(slot)
}

struct AzihsmLoadPrivKey;
impl LoadPrivKeyHandler for AzihsmLoadPrivKey {
    fn load(engine: &Engine, key_id: &CStr) -> EngineResult<*mut ffi::EVP_PKEY> {
        let slot = engine_data_slot()?;
        let data = slot
            .get(engine)
            .ok_or(EngineError::NullParam("engine_data"))?;
        // Key ids (azihsm:// URIs) must be UTF-8. A non-UTF-8 path — legal on
        // Unix but exotic for a masked-key file — is rejected rather than
        // handled as raw bytes; revisit with OsStr/byte parsing if needed.
        let key_id = key_id
            .to_str()
            .map_err(|_| EngineError::Other("key id is not valid UTF-8".into()))?;
        crate::keyload::load_key(engine, data, key_id)
    }
}

struct AzihsmDestroy;
impl DestroyHandler for AzihsmDestroy {
    fn destroy(engine: &mut Engine) -> EngineResult<()> {
        // The ex_data slot has no auto-free callback (see exdata.rs module
        // docs); the destroy handler drops the Box. Use the already-cached
        // slot: if it was never registered there is nothing to clear, and
        // registering one here would just leak an index.
        if let Some(slot) = ENGINE_DATA_SLOT.get() {
            slot.take(engine)?;
        }
        Ok(())
    }
}

#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub extern "C" fn v_check(v: c_ulong) -> c_ulong {
    if v >= ffi::OSSL_DYNAMIC_OLDEST_CONST {
        ffi::OSSL_DYNAMIC_VERSION_CONST
    } else {
        0
    }
}

/// Engine entry point exported for OpenSSL's dynamic loader.
///
/// Validates the raw pointers, then runs the bind logic inside
/// [`catch_panic`] so a panic can never unwind across the FFI boundary;
/// failures are reported through the OpenSSL error queue and a `0` return.
///
/// # Safety
/// `engine_ptr` and `fns` must be valid for the duration of the call and
/// `id` must be null or a valid C string — guaranteed by OpenSSL's dynamic
/// engine loader per the `bind_engine`/`v_check` ABI contract.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn bind_engine(
    engine_ptr: *mut ffi::ENGINE,
    id: *const std::ffi::c_char,
    fns: *mut ffi::dynamic_fns,
) -> c_int {
    catch_panic(
        || {
            // SAFETY: forwarding the pointers OpenSSL's dynamic loader
            // passed to bind_engine, per its ABI contract.
            result_to_int(unsafe { bind_inner(engine_ptr, id, fns) })
        },
        RetCode::Fail.into(),
    )
}

/// Validate the raw pointers from OpenSSL's dynamic loader and dispatch
/// to [`bind_helper`] with a safe [`Engine`].
///
/// # Safety
/// `engine_ptr`, `id`, and `fns` must be the pointers OpenSSL's dynamic
/// loader passes to [`bind_engine`] (see its contract).
#[allow(unsafe_code)]
unsafe fn bind_inner(
    engine_ptr: *mut ffi::ENGINE,
    id: *const std::ffi::c_char,
    fns: *mut ffi::dynamic_fns,
) -> EngineResult<()> {
    let engine_ptr = NonNull::new(engine_ptr).ok_or(EngineError::NullParam("engine"))?;
    let fns = NonNull::new(fns).ok_or(EngineError::NullParam("fns"))?;

    // SAFETY: engine_ptr and fns are non-null (checked above) and valid
    // for this call (provided by OpenSSL's dynamic loader).
    unsafe { Engine::from_ptr(engine_ptr).bind(id, fns, bind_helper) }
}

/// Engine setup invoked by [`Engine::bind`]: reject a request for a
/// different engine id, then register this engine's id and name.
fn bind_helper(engine: &mut Engine, id: &CStr) -> EngineResult<()> {
    let id_bytes = id.to_bytes();
    if !id_bytes.is_empty() && !id_bytes.contains(&b'/') && id != ENGINE_ID {
        return Err(EngineError::IdMismatch);
    }

    // Best-effort logging install. A misconfigured AZIHSM_ENGINE_LOG_FILE
    // surfaces as an error here; everything else is silently ignored
    // (already-installed subscriber is fine).
    logging::install_from_env()?;

    engine.set_id(ENGINE_ID)?;
    engine.set_name(ENGINE_NAME)?;
    engine.set_destroy::<AzihsmDestroy>()?;
    engine.set_load_privkey::<AzihsmLoadPrivKey>()?;
    // Advertise an EC method so the loader can bind returned keys to the
    // engine (EC_KEY_new_method), which keeps the engine alive while any
    // loaded key lives. Software EC ops for now; signing is wired later.
    engine.set_default_ec_method()?;
    engine.set_default_rsa_method()?;

    // Park an empty EngineData. Its HSM session is opened on demand via
    // EngineData::open_hsm_from_env; AzihsmDestroy::destroy takes() and
    // drops the Box at ENGINE_free time.
    let slot = engine_data_slot()?;
    slot.set(engine, Box::new(EngineData::new()))?;

    tracing::info!(target: "azihsm", "azihsm engine bound");
    Ok(())
}
