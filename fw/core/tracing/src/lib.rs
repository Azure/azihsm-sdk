// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM tracing facade.
//!
//! Provides level-gated tracing macros with a target string parameter.
//! The PAL provides the emit implementation via `__hsm_trace_emit`.
//!
//! ## Usage
//!
//! ```ignore
//! use azihsm_fw_hsm_tracing::{debug, info, error};
//! info!("iic", "initialized depth={}", depth);
//! error!("core", HsmCoreError::POLL_IO_FAILURE, "poll_io failed");
//! ```
//!
//! ## Log level threshold
//!
//! Enable one of: `level-trace`, `level-debug`, `level-info`, `level-warn`,
//! `level-error`. Messages below the threshold compile to nothing.

#![no_std]

extern "Rust" {
    #[doc(hidden)]
    pub fn __hsm_trace_emit(level: u8, target: &str, args: core::fmt::Arguments<'_>);
}

// ── trace ───────────────────────────────────────────────────────────

#[macro_export]
#[cfg(feature = "level-trace")]
macro_rules! trace {
    ($tgt:expr, $($t:tt)*) => { unsafe { $crate::__hsm_trace_emit(b'T', $tgt, format_args!($($t)*)) } };
}
#[macro_export]
#[cfg(not(feature = "level-trace"))]
macro_rules! trace {
    ($tgt:expr, $($t:tt)*) => {};
}

// ── debug ───────────────────────────────────────────────────────────

#[macro_export]
#[cfg(any(feature = "level-trace", feature = "level-debug"))]
macro_rules! debug {
    ($tgt:expr, $($t:tt)*) => { unsafe { $crate::__hsm_trace_emit(b'D', $tgt, format_args!($($t)*)) } };
}
#[macro_export]
#[cfg(not(any(feature = "level-trace", feature = "level-debug")))]
macro_rules! debug {
    ($tgt:expr, $($t:tt)*) => {};
}

// ── info ────────────────────────────────────────────────────────────

#[macro_export]
#[cfg(any(
    feature = "level-trace",
    feature = "level-debug",
    feature = "level-info"
))]
macro_rules! info {
    ($tgt:expr, $($t:tt)*) => { unsafe { $crate::__hsm_trace_emit(b'I', $tgt, format_args!($($t)*)) } };
}
#[macro_export]
#[cfg(not(any(
    feature = "level-trace",
    feature = "level-debug",
    feature = "level-info"
)))]
macro_rules! info {
    ($tgt:expr, $($t:tt)*) => {};
}

// ── warn ────────────────────────────────────────────────────────────

#[macro_export]
#[cfg(any(
    feature = "level-trace",
    feature = "level-debug",
    feature = "level-info",
    feature = "level-warn"
))]
macro_rules! warn {
    ($tgt:expr, $($t:tt)*) => { unsafe { $crate::__hsm_trace_emit(b'W', $tgt, format_args!($($t)*)) } };
}
#[macro_export]
#[cfg(not(any(
    feature = "level-trace",
    feature = "level-debug",
    feature = "level-info",
    feature = "level-warn"
)))]
macro_rules! warn {
    ($tgt:expr, $($t:tt)*) => {};
}

// ── error ───────────────────────────────────────────────────────────

#[macro_export]
#[cfg(any(
    feature = "level-trace",
    feature = "level-debug",
    feature = "level-info",
    feature = "level-warn",
    feature = "level-error"
))]
macro_rules! error {
    ($tgt:expr, $err:expr, $($t:tt)*) => {
        unsafe {
            $crate::__hsm_trace_emit(
                b'E', $tgt,
                format_args!("{} [err:{:08x}]", format_args!($($t)*), $err.0),
            )
        }
    };
    ($tgt:expr, $($t:tt)*) => { unsafe { $crate::__hsm_trace_emit(b'E', $tgt, format_args!($($t)*)) } };
}
#[macro_export]
#[cfg(not(any(
    feature = "level-trace",
    feature = "level-debug",
    feature = "level-info",
    feature = "level-warn",
    feature = "level-error"
)))]
macro_rules! error {
    ($($t:tt)*) => {};
}
