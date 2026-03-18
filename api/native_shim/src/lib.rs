// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Link shim for `azihsm_api_native`.
//!
//! This crate exists solely to ensure every `#[no_mangle] pub extern "C"` symbol
//! exported by `azihsm_api_native` is reachable from the linker when building the
//! workspace with Cargo.
//!
//! `azihsm_api_native` is a `cdylib` whose public API consists of FFI entry-points
//! that Rust code never calls directly.  Without an explicit reference to each
//! symbol the linker is free to discard them.  This shim calls
//! `azihsm_api_native::__azihsm_force_link` inside an exported C symbol
//! (`azihsm_link_symbols`) which the linker must retain.  That helper holds a
//! `black_box`-guarded reference to every `azihsm_*` entry-point, forcing the
//! linker to include all of them in the final artifact.
//!
//! Using a plain Rust function call (rather than `extern "C"` declarations)
//! means the dependency is resolved through Cargo's normal rlib mechanism,
//! which works correctly on all platforms including Windows/MSVC.

/// Force the linker to retain every public API symbol from `azihsm_api_native`.
///
/// This function is exported as a C symbol so that the linker cannot discard it.
/// Calling `azihsm_api_native::__azihsm_force_link` causes the linker to pull
/// in all `#[no_mangle]` entry-points from that crate.
///
/// This function must never be called at runtime; it exists solely as a
/// link-time anchor.
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub extern "C" fn azihsm_link_symbols() {
    azihsm_api_native::__azihsm_force_link();
}
