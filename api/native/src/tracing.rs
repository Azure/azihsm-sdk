// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! File-based tracing initialization for the native API.
//!
//! When the environment variable `AZIHSM_NATIVEAPI_TRACE_FILE` is set to a file
//! path, this module installs a `tracing_subscriber` that writes all trace
//! output to that file. Initialization is idempotent and thread-safe thanks
//! to `std::sync::Once`.
//!
//! By default, the file is truncated on each run.
//! Set `AZIHSM_NATIVEAPI_TRACE_FILE_APPEND=1` to append instead.
//!
//! If the environment variable is not set, or if any step of the
//! initialization fails (file open, filter parse, subscriber install), the
//! function silently returns without installing a subscriber.

use std::sync::Mutex;
use std::sync::Once;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

/// Name of the environment variable that controls file-based tracing.
const TRACE_FILE_ENV_VAR: &str = "AZIHSM_NATIVEAPI_TRACE_FILE";

/// Name of the environment variable that controls append mode.
/// When set to `"1"`, the trace file is opened in append mode so that
/// output from successive runs accumulates.  Any other value (or unset)
/// causes the file to be truncated on each run.
const TRACE_FILE_APPEND_ENV_VAR: &str = "AZIHSM_NATIVEAPI_TRACE_FILE_APPEND";

/// Ensures file-based tracing is initialized exactly once.
///
/// This function is safe to call from any thread and any number of times.
/// On the first call it checks `AZIHSM_NATIVEAPI_TRACE_FILE`:
///
/// * If the variable is **not set**, no subscriber is installed.
/// * If it **is set**, the file is opened and a `tracing_subscriber::fmt`
///   subscriber is installed that writes timestamped, structured trace events
///   to the file.
///
/// All errors are silently ignored so that tracing failures never affect
/// normal library operation.
pub(crate) fn init_trace_file() {
    static ONCE: Once = Once::new();

    ONCE.call_once(|| {
        // If the env var is not set, do nothing.
        let trace_path = match std::env::var(TRACE_FILE_ENV_VAR) {
            Ok(p) if !p.is_empty() => p,
            _ => return,
        };

        // Check whether append mode is requested.
        let append = matches!(std::env::var(TRACE_FILE_APPEND_ENV_VAR).as_deref(), Ok("1"));

        // Attempt to open/create the trace file.
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true);
        if append {
            opts.append(true);
        } else {
            opts.write(true).truncate(true);
        }
        let file = match opts.open(&trace_path) {
            Ok(f) => f,
            Err(_) => return,
        };
        let writer = Mutex::new(file);

        // Build an EnvFilter from RUST_LOG, defaulting to `info`.
        let filter = match EnvFilter::try_from_default_env() {
            Ok(f) => f,
            Err(_) => match EnvFilter::try_new("info") {
                Ok(f) => f,
                Err(_) => return,
            },
        };

        // Build and install the subscriber.  If `set_global_default` fails
        // (e.g. another subscriber was already installed), silently ignore.
        let subscriber = tracing_subscriber::registry().with(filter).with(
            fmt::layer()
                .with_writer(writer)
                .with_ansi(false)
                .with_thread_ids(true)
                .with_target(true)
                .with_span_events(fmt::format::FmtSpan::FULL),
        );

        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Calling `init_trace_file` multiple times must never panic, regardless
    /// of whether the env var is set.
    #[test]
    fn init_trace_file_is_idempotent() {
        // Without the env var set, these are all no-ops.
        init_trace_file();
        init_trace_file();
        init_trace_file();
    }
}
