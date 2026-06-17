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

    use openssl_engine::engine::Engine;
    use openssl_engine::engine::bind_entry;
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
    /// The raw-pointer validation and the unsafe FFI glue live in
    /// [`openssl_engine::engine::bind_entry`]; this export just forwards to it.
    ///
    /// # Safety
    /// `engine_ptr` and `fns` must be valid for the duration of the call and
    /// `id` must be null or a valid C string — guaranteed by OpenSSL's dynamic
    /// engine loader per the `bind_engine`/`v_check` ABI contract.
    // `#[allow(unsafe_code)]` covers the `#[unsafe(no_mangle)]` export
    // attribute and the `unsafe extern "C"` signature; the body itself
    // contains no `unsafe` block.
    #[unsafe(no_mangle)]
    #[allow(unsafe_code)]
    #[allow(unsafe_op_in_unsafe_fn)]
    pub unsafe extern "C" fn bind_engine(
        engine_ptr: *mut ffi::ENGINE,
        id: *const std::ffi::c_char,
        fns: *mut ffi::dynamic_fns,
    ) -> c_int {
        bind_entry(engine_ptr, id, fns, bind_helper)
    }

    fn bind_helper(engine: &Engine, id: &CStr) -> c_int {
        let id_bytes = id.to_bytes();
        if !id_bytes.is_empty() && !id_bytes.contains(&b'/') && id != ENGINE_ID {
            return 0;
        }

        if engine.set_id(ENGINE_ID) != 1 {
            return 0;
        }
        if engine.set_name(ENGINE_NAME) != 1 {
            return 0;
        }

        1
    }
}
