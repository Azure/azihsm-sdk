// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![warn(clippy::cast_possible_truncation)]
#![warn(clippy::arithmetic_side_effects)]

//! Azure Integrated HSM -- OpenSSL 1.1.x Engine. Linux only.

#[cfg(all(target_os = "linux", feature = "engine"))]
mod engine_impl {
    use std::ffi::CStr;
    use std::ffi::c_int;
    use std::ffi::c_ulong;
    use std::ptr::NonNull;

    use openssl_engine::engine::Engine;
    use openssl_engine::error::EngineError;
    use openssl_engine::error::EngineResult;
    use openssl_engine::error::RetCode;
    use openssl_engine::error::catch_panic;
    use openssl_engine::error::result_to_int;
    use openssl_engine::ffi;

    const ENGINE_ID: &CStr = c"azihsm";
    const ENGINE_NAME: &CStr = c"Azure Integrated HSM Engine";

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
    fn bind_helper(engine: &Engine, id: &CStr) -> EngineResult<()> {
        let id_bytes = id.to_bytes();
        if !id_bytes.is_empty() && !id_bytes.contains(&b'/') && id != ENGINE_ID {
            return Err(EngineError::IdMismatch);
        }

        engine.set_id(ENGINE_ID)?;
        engine.set_name(ENGINE_NAME)?;

        Ok(())
    }
}
