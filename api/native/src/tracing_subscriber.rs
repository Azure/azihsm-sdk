// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! File-based tracing initialization for the native API.
//!
//! When the environment variable `AZIHSM_NATIVEAPI_TRACE_FILE` is set to a file
//! path, this module installs a `tracing_subscriber` that writes all trace
//! output to that file. Initialization is idempotent and thread-safe thanks
//! to [`std::sync::Once`].
//!
//! By default, the file is truncated on each run.
//! Set `AZIHSM_NATIVEAPI_TRACE_FILE_APPEND=1` to append instead.
//!
//! If the environment variable is not set, or if any step of the
//! initialization fails (file open, filter parse, subscriber install), the
//! function silently returns without installing a subscriber.

use std::io::Write;
use std::sync::Once;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;

/// Name of the environment variable that controls file-based tracing.
const TRACE_FILE_ENV_VAR: &str = "AZIHSM_NATIVEAPI_TRACE_FILE";

/// Name of the environment variable that controls append mode.
/// When set to `"1"`, the trace file is opened in append mode so that
/// output from successive runs accumulates.  Any other value (or unset)
/// causes the file to be truncated on each run.
const TRACE_FILE_APPEND_ENV_VAR: &str = "AZIHSM_NATIVEAPI_TRACE_FILE_APPEND";

/// Thread-safe, non-poisoning file writer for the tracing subscriber.
///
/// Uses [`parking_lot::Mutex`] instead of [`std::sync::Mutex`] so that a
/// panic while holding the lock does not poison the mutex and silently
/// break all subsequent trace writes.
struct TraceFileWriter(parking_lot::Mutex<std::fs::File>);

/// RAII guard returned by [`TraceFileWriter`] that implements [`Write`].
struct TraceFileWriterGuard<'a>(parking_lot::MutexGuard<'a, std::fs::File>);

impl Write for TraceFileWriterGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl<'a> MakeWriter<'a> for TraceFileWriter {
    type Writer = TraceFileWriterGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        TraceFileWriterGuard(self.0.lock())
    }
}

/// Ensures file-based tracing is initialized exactly once.
///
/// This function is safe to call from any thread and any number of times.
/// On the first call it checks `AZIHSM_NATIVEAPI_TRACE_FILE`:
///
/// * If the variable is **not set**, no subscriber is installed.
/// * If it **is set**, the file is opened and a `tracing_subscriber::fmt`
///   subscriber is installed that writes timestamped, structured trace events
///   to the file.  Timestamps are always in UTC.
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
        opts.create(true).write(true);
        if append {
            opts.append(true);
        } else {
            opts.truncate(true);
        }
        let file = match opts.open(&trace_path) {
            Ok(f) => f,
            Err(_) => return,
        };
        let writer = TraceFileWriter(parking_lot::Mutex::new(file));

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
                .with_timer(fmt::time::SystemTime)
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

    /// Verifies that trace output is written to the file when the
    /// environment variable is set.  Runs as a subprocess so that the
    /// `Once` guard and global subscriber don't interfere with other tests.
    #[test]
    fn trace_output_written_to_file() {
        let trace_path = std::env::temp_dir().join("azihsm_nativeapi_trace_test.log");
        let _ = std::fs::remove_file(&trace_path);

        // Re-invoke *this* test binary running only the helper test, with
        // the trace env vars set.  The helper emits a known marker event.
        let exe = std::env::current_exe().expect("current_exe should be available");
        let status = std::process::Command::new(&exe)
            .arg("--exact")
            .arg("tracing_subscriber::tests::trace_output_helper")
            .arg("--nocapture")
            .env(TRACE_FILE_ENV_VAR, &trace_path)
            .env("RUST_LOG", "trace")
            .status()
            .expect("failed to spawn subprocess");

        assert!(status.success(), "helper subprocess failed: {status}");

        let contents = std::fs::read_to_string(&trace_path)
            .expect("trace file should exist after the helper ran");

        assert!(
            contents.contains("trace_init_marker_event"),
            "trace file should contain the marker event, but got:\n{contents}"
        );

        // Verify timestamps are UTC (end with 'Z').
        let first_line = contents.lines().next().unwrap_or("");
        assert!(
            first_line.contains('Z'),
            "timestamps should be UTC, but first line was:\n{first_line}"
        );

        let _ = std::fs::remove_file(&trace_path);
    }

    /// Helper test invoked as a subprocess by `trace_output_written_to_file`.
    /// Not meant to be run directly — it requires the trace env vars to be
    /// set by the parent process.
    #[test]
    fn trace_output_helper() {
        init_trace_file();
        tracing::info!("trace_init_marker_event");
    }
}
