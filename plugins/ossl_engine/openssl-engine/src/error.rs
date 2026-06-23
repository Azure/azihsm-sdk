// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types and OpenSSL error queue integration for the engine toolkit.
//!
//! Engine callbacks run across an FFI boundary that cannot unwind Rust
//! panics.  This module provides three pieces that together make that
//! boundary safe and observable:
//!
//! - [`EngineError`] + [`EngineResult`] — typed failure modes the toolkit
//!   emits.  Variants are added as features land.
//! - [`openssl_err`] / [`result_to_int`] — record the reason code on the
//!   OpenSSL ERR queue, with a human-readable detail string attached via
//!   `ERR_add_error_data`. Callers read the code with `ERR_get_error`; the
//!   detail string is surfaced via `ERR_print_errors*` (or programmatically
//!   via `ERR_get_error_line_data`).
//! - [`catch_panic`] — wrap a C entry point so a Rust panic returns a
//!   caller-supplied fallback instead of unwinding into C (which is UB).

use std::ffi::CString;
use std::ffi::c_int;
use std::panic::UnwindSafe;
use std::panic::catch_unwind;

use openssl_sys_engine as ffi;

/// Result type used throughout the engine toolkit.
pub type EngineResult<T> = Result<T, EngineError>;

/// Failure modes emitted by the engine toolkit.
///
/// Variants are added as features land — only the ones currently
/// emitted appear here.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("engine ID mismatch")]
    IdMismatch,

    #[error("ENGINE_set_id failed")]
    SetIdFailed,

    #[error("ENGINE_set_name failed")]
    SetNameFailed,

    #[error("CRYPTO_set_mem_functions failed")]
    CryptoSetMemFunctionsFailed,

    #[error("OPENSSL_init_crypto failed")]
    OpensslInitCryptoFailed,

    #[error("null parameter: {0}")]
    NullParam(&'static str),

    #[error("CRYPTO_get_ex_new_index failed")]
    ExDataRegisterFailed,

    #[error("ENGINE_set_ex_data failed")]
    ExDataSetFailed,

    #[error("ENGINE_set_destroy_function failed")]
    SetDestroyFailed,

    /// A standalone message with no underlying error.
    #[error("{0}")]
    Other(String),

    /// A contextual message wrapping an underlying error. Display renders
    /// `context: source`; the source is preserved for programmatic
    /// inspection via [`std::error::Error::source`].
    #[error("{context}: {source}")]
    Wrapped {
        context: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

impl EngineError {
    /// Wrap `source` with human-readable `context`, preserving the error
    /// chain. Prefer this over `Other(format!("…: {e}"))` when there is an
    /// underlying error, so callers can still walk `.source()`.
    pub fn wrap(
        context: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Wrapped {
            context: context.into(),
            source: Box::new(source),
        }
    }
}

impl From<&EngineError> for c_int {
    fn from(e: &EngineError) -> c_int {
        match e {
            EngineError::NullParam(_) => ffi::ERR_R_PASSED_NULL_PARAMETER as c_int,
            _ => ffi::ERR_R_INTERNAL_ERROR as c_int,
        }
    }
}

/// OpenSSL return-code convention: 1 success, 0 failure.
#[repr(i32)]
#[derive(Clone, Copy)]
pub enum RetCode {
    Fail = 0,
    Success = 1,
}

impl From<RetCode> for c_int {
    fn from(code: RetCode) -> c_int {
        code as c_int
    }
}

/// Map an OpenSSL `1`(success)/`0`(failure) return code into a result,
/// attaching `err` on failure. Keeps the bare `1`/`!= 1` literal out of
/// the call sites.
pub(crate) fn ossl_check(rc: c_int, err: EngineError) -> EngineResult<()> {
    if rc == RetCode::Success as c_int {
        Ok(())
    } else {
        Err(err)
    }
}

/// Push a human-readable message onto the OpenSSL ERR queue.
///
/// `reason` is an `ERR_R_*` constant from `openssl-sys-engine`.  The reason
/// code is always recorded; the message is best-effort and is truncated at
/// the first interior NUL (rather than dropping the error entirely), since
/// OpenSSL cannot represent the bytes past it.  OpenSSL copies the string
/// internally; callers may free after return.
#[allow(unsafe_code)]
pub fn openssl_err(reason: c_int, msg: &str) {
    // Truncate at the first interior NUL so the reason code is never lost.
    let msg = match msg.find('\0') {
        Some(i) => &msg[..i],
        None => msg,
    };
    let msg_c = CString::new(msg).unwrap_or_default();

    // SAFETY: ERR_put_error stores the file pointer as-is; we pass a
    // 'static empty C string so it remains valid for the lifetime of the
    // ERR queue entry. ERR_add_error_data copies its argument internally.
    // func is 0 ("unknown"): a negative value packs an invalid function code.
    unsafe {
        ffi::ERR_put_error(ffi::ERR_LIB_ENGINE as c_int, 0, reason, c"".as_ptr(), 0);
        ffi::ERR_add_error_data(1, msg_c.as_ptr());
    }
}

/// Convert an [`EngineResult`] into an OpenSSL C return code.
///
/// On `Err` the message is pushed onto the OpenSSL ERR queue and logged
/// via `tracing`.  Successful results return [`RetCode::Success`].
pub fn result_to_int<T>(result: EngineResult<T>) -> c_int {
    match result {
        Ok(_) => RetCode::Success.into(),
        Err(e) => {
            let reason = c_int::from(&e);
            openssl_err(reason, &e.to_string());
            tracing::error!("{e}");
            RetCode::Fail.into()
        }
    }
}

/// Run `f` under [`catch_unwind`].  A panic is logged and turned into the
/// caller-supplied `on_panic` value.
///
/// Every `extern "C"` entry point that calls into Rust should wrap its
/// body in this helper.  Letting a panic unwind across the FFI boundary
/// is undefined behavior.
pub fn catch_panic<F, R>(f: F, on_panic: R) -> R
where
    F: FnOnce() -> R + UnwindSafe,
{
    match catch_unwind(f) {
        Ok(v) => v,
        Err(_) => {
            tracing::error!("panic caught at FFI boundary");
            // Surface the panic on the ERR queue too, so a caller that only
            // inspects OpenSSL errors still sees why the call returned 0.
            openssl_err(
                ffi::ERR_R_INTERNAL_ERROR as c_int,
                "panic caught at FFI boundary",
            );
            on_panic
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    /// Round-trip: push a message and read back the reason code.
    #[test]
    #[allow(unsafe_code)]
    fn openssl_err_round_trip() {
        // SAFETY: ERR_clear_error / ERR_get_error are thread-safe and
        // take no arguments; the ERR queue is thread-local in 1.1.x.
        unsafe { ffi::ERR_clear_error() };

        openssl_err(ffi::ERR_R_INTERNAL_ERROR as c_int, "boom");

        // SAFETY: same as above.
        let code = unsafe { ffi::ERR_get_error() };
        assert_ne!(code, 0, "expected an error on the queue");

        // ERR_GET_REASON masks the reason out of the packed code; the
        // exact bit layout is internal to OpenSSL but the low 12 bits
        // hold the reason in 1.1.x.
        let reason = (code & 0xfff) as c_int;
        assert_eq!(reason, ffi::ERR_R_INTERNAL_ERROR as c_int);

        // Drain anything else this test pushed.
        // SAFETY: same as above.
        unsafe { ffi::ERR_clear_error() };
    }

    #[test]
    fn result_to_int_success() {
        let r: EngineResult<()> = Ok(());
        assert_eq!(result_to_int(r), RetCode::Success.into());
    }

    #[test]
    fn result_to_int_failure_pushes_error() {
        // SAFETY: see openssl_err_round_trip.
        #[allow(unsafe_code)]
        unsafe {
            ffi::ERR_clear_error()
        };

        let r: EngineResult<()> = Err(EngineError::IdMismatch);
        assert_eq!(result_to_int(r), RetCode::Fail.into());

        // SAFETY: see openssl_err_round_trip.
        #[allow(unsafe_code)]
        let code = unsafe { ffi::ERR_get_error() };
        assert_ne!(code, 0, "Err result should push onto the ERR queue");

        // SAFETY: see openssl_err_round_trip.
        #[allow(unsafe_code)]
        unsafe {
            ffi::ERR_clear_error()
        };
    }

    #[test]
    fn catch_panic_returns_normal_value() {
        let result = catch_panic(|| 42, 0);
        assert_eq!(result, 42);
    }

    #[test]
    fn catch_panic_returns_fallback_on_panic() {
        let result = catch_panic(
            || {
                panic!("simulated");
                #[allow(unreachable_code)]
                42
            },
            -1,
        );
        assert_eq!(result, -1);
    }

    /// A panic at the FFI boundary must also leave an entry on the ERR queue.
    #[test]
    #[allow(unsafe_code)]
    fn catch_panic_pushes_error_on_panic() {
        // SAFETY: see openssl_err_round_trip.
        unsafe { ffi::ERR_clear_error() };

        let result = catch_panic(
            || {
                panic!("simulated");
                #[allow(unreachable_code)]
                0
            },
            -1,
        );
        assert_eq!(result, -1);

        // SAFETY: same as above.
        let code = unsafe { ffi::ERR_get_error() };
        assert_ne!(code, 0, "a panic should push onto the ERR queue");
        assert_eq!((code & 0xfff) as c_int, ffi::ERR_R_INTERNAL_ERROR as c_int);

        // SAFETY: same as above.
        unsafe { ffi::ERR_clear_error() };
    }

    /// An interior NUL truncates the message but still records the reason.
    #[test]
    #[allow(unsafe_code)]
    fn openssl_err_with_interior_nul_still_records_reason() {
        // SAFETY: see openssl_err_round_trip.
        unsafe { ffi::ERR_clear_error() };

        openssl_err(ffi::ERR_R_INTERNAL_ERROR as c_int, "before\0after");

        // SAFETY: same as above.
        let code = unsafe { ffi::ERR_get_error() };
        assert_ne!(code, 0, "interior NUL must not drop the error");
        assert_eq!((code & 0xfff) as c_int, ffi::ERR_R_INTERNAL_ERROR as c_int);

        // SAFETY: same as above.
        unsafe { ffi::ERR_clear_error() };
    }

    #[test]
    fn null_param_maps_to_passed_null_parameter() {
        let e = EngineError::NullParam("engine");
        assert_eq!(c_int::from(&e), ffi::ERR_R_PASSED_NULL_PARAMETER as c_int);
    }

    #[test]
    fn id_mismatch_maps_to_internal_error() {
        let e = EngineError::IdMismatch;
        assert_eq!(c_int::from(&e), ffi::ERR_R_INTERNAL_ERROR as c_int);
    }
}
