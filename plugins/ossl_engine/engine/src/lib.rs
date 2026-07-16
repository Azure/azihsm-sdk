// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![warn(clippy::cast_possible_truncation)]
#![warn(clippy::arithmetic_side_effects)]

//! Azure Integrated HSM -- OpenSSL 1.1.x Engine. Linux only.

/// File mode for secret material the engine writes (the cached MOBK and the
/// log file): owner read/write only, no group/other. Mirrors the provider's
/// 0600 hardening.
#[cfg(all(target_os = "linux", feature = "engine"))]
pub(crate) const SECRET_FILE_MODE: u32 = 0o600;

// `context` is `pub` so the engine's HSM-open API (EngineData and its
// open_hsm_* methods) is public crate API rather than dead code. The cdylib
// entry point (`bind_helper`) constructs an EngineData and parks it in the
// ENGINE's ex_data.
#[cfg(all(target_os = "linux", feature = "engine"))]
pub mod context;

#[cfg(all(target_os = "linux", feature = "engine"))]
mod logging;

#[cfg(all(target_os = "linux", feature = "engine"))]
mod engine_impl {
    use std::ffi::CStr;
    use std::ffi::c_int;
    use std::ffi::c_ulong;
    use std::ptr::NonNull;
    use std::sync::OnceLock;

    use openssl_engine::engine::DestroyHandler;
    use openssl_engine::engine::Engine;
    use openssl_engine::error::EngineError;
    use openssl_engine::error::EngineResult;
    use openssl_engine::error::RetCode;
    use openssl_engine::error::catch_panic;
    use openssl_engine::error::result_to_int;
    use openssl_engine::exdata::EngineExData;
    use openssl_engine::ffi;
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

        // Park an empty EngineData. Its HSM session is opened on demand via
        // EngineData::open_hsm_from_env; AzihsmDestroy::destroy takes() and
        // drops the Box at ENGINE_free time.
        let slot = engine_data_slot()?;
        slot.set(engine, Box::new(EngineData::new()))?;

        tracing::info!(target: "azihsm", "azihsm engine bound");
        Ok(())
    }
}
