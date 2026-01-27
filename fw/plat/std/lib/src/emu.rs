// Copyright (C) Microsoft Corporation. All rights reserved.

//! Azure Integrated HSM emulator implementation.
//!
//! This module provides [`AziHsmEmulator`], a software emulator for the Azure Integrated HSM.
//! The emulator runs async tasks on dedicated executor threads to simulate HSM behavior
//! in a standard environment without requiring actual HSM hardware.

use std::sync::Arc;
use std::sync::LazyLock;

use parking_lot::RwLock;
use strum::EnumCount;
use strum_macros::EnumCount;

use super::*;

/// Identifies the dedicated executor threads used by the emulator.
///
/// Each variant corresponds to a specific subsystem that runs on its own thread.
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumCount)]
enum ThreadName {
    /// Management subsystem thread.
    Mgmt,
    /// HSM subsystem thread.
    Hsm,
}

impl From<ThreadName> for usize {
    /// Converts a thread name to its corresponding executor slot index.
    fn from(name: ThreadName) -> Self {
        name as usize
    }
}

/// Global singleton instance of the Azure HSM emulator.
///
/// This is lazily initialized on first access and provides a shared emulator
/// instance that can be started and stopped as needed.
pub static AZIHSM_EMULATOR: LazyLock<AziHsmEmulator> = LazyLock::new(|| AziHsmEmulator::default());

/// Azure Integrated HSM software emulator.
///
/// Provides a thread-safe emulator that simulates HSM functionality using
/// Embassy async executors running on dedicated threads. The emulator can
/// be started and stopped, and is safe to clone (all clones share the same
/// underlying state).
#[derive(Clone)]
pub struct AziHsmEmulator {
    /// Thread-safe reference to the internal emulator state.
    inner: Arc<RwLock<Inner>>,
}

impl Default for AziHsmEmulator {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
        }
    }
}

impl AziHsmEmulator {
    /// Starts the emulator.
    ///
    /// Initializes and spawns all executor threads if not already running.
    /// If the emulator is already started, this is a no-op.
    pub fn start(&self) {
        self.with_write(|inner| {
            inner.start();
        });
    }

    /// Stops the emulator.
    ///
    /// Signals all executor threads to terminate and waits for them to complete.
    /// After stopping, the emulator can be started again with [`start`](Self::start).
    pub fn stop(&self) {
        self.with_write(|inner| {
            inner.stop();
        });
    }

    /// Executes a closure with read access to the inner state.
    ///
    /// Acquires a read lock on the internal state, allowing concurrent readers.
    fn _with_read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Inner) -> R,
    {
        let inner = self.inner.read();
        f(&inner)
    }

    /// Executes a closure with write access to the inner state.
    ///
    /// Acquires an exclusive write lock on the internal state.
    fn with_write<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Inner) -> R,
    {
        let mut inner = self.inner.write();
        f(&mut inner)
    }
}

/// Internal state of the emulator.
///
/// Manages the lifecycle of executor threads through the [`Executor`].
struct Inner {
    /// The executor manager, present only when the emulator is running.
    executor: Option<Executor>,
}

impl Default for Inner {
    fn default() -> Self {
        Self { executor: None }
    }
}

impl Inner {
    /// Starts the emulator by creating executor threads.
    ///
    /// Creates an [`Executor`] and spawns the management subsystem task.
    /// Does nothing if already started.
    fn start(&mut self) {
        if self.executor.is_none() {
            let mut executor = Executor::new(ThreadName::COUNT);
            executor.spawn(ThreadName::Mgmt.into(), azihsm_fw_plat_std_mgmt::start);
            executor.spawn(ThreadName::Hsm.into(), azihsm_fw_plat_std_hsm::run);
            self.executor = Some(executor);
        }
    }

    /// Stops the emulator by dropping the executor.
    ///
    /// Taking the executor triggers its [`Drop`] implementation,
    /// which signals all threads to stop and joins them.
    fn stop(&mut self) {
        self.executor.take();
    }
}

#[cfg(test)]
mod tests {

    use std::thread::sleep;
    use std::time::Duration;

    // use tracing_subscriber::{filter::{LevelFilter, Targets}, layer::SubscriberExt};
    use tracing::metadata::LevelFilter;
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::prelude::*;

    use super::*;

    #[test]
    #[allow(unsafe_code)]
    fn test_emu_start() {
        // env_logger::builder()
        //     .format_timestamp_nanos()
        //     .filter(None, log::LevelFilter::Trace)
        //     .init();

        static ONCE: std::sync::Once = std::sync::Once::new();

        ONCE.call_once(|| {
            let targets = if let Ok(var) = std::env::var("RUST_LOG") {
                var.parse()
                    .expect("Failed to parse RUST_LOG environment variable")
            } else {
                Targets::new().with_default(LevelFilter::DEBUG)
            };
            tracing_subscriber::fmt()
                .compact()
                .log_internal_errors(true)
                .with_test_writer()
                .with_max_level(LevelFilter::TRACE)
                .with_thread_ids(true)
                .finish()
                .with(targets)
                .init();
        });

        AZIHSM_EMULATOR.start();
        sleep(Duration::from_secs(10));
        AZIHSM_EMULATOR.stop();
    }
}
