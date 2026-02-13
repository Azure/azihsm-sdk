// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Async executor management for running Embassy-based async tasks on dedicated threads.
//!
//! This module provides [`ExecutorManager`], which manages a pool of Embassy executors,
//! each running on its own dedicated thread. This enables concurrent execution of async
//! tasks across multiple threads with graceful shutdown support.

use std::sync::Arc;
use std::sync::atomic::*;
use std::thread;
use std::thread::JoinHandle;

use embassy_executor::SpawnError;
use embassy_executor::SpawnToken;
use embassy_executor::Spawner;
use static_cell::StaticCell;

/// Global storage for Embassy executors.
///
/// Each executor is stored in a `StaticCell` to ensure it has a `'static` lifetime,
/// which is required by the Embassy executor API.
static mut EXECUTOR: Vec<StaticCell<embassy_executor::Executor>> = Vec::new();

/// Manages a pool of Embassy async executors running on dedicated threads.
///
/// `Executor` creates and manages multiple Embassy executors, each running
/// on its own thread. It provides graceful shutdown by signaling all executors
/// to stop when the manager is dropped.
pub(crate) struct Executor {
    threads: Vec<JoinHandle<()>>,
    done: Arc<AtomicBool>,
}

impl Executor {
    /// Creates a new `Executor` with capacity for the specified number of executors.
    ///
    /// This allocates static storage for each executor but does not start any threads.
    /// Threads are started when [`spawn`](Self::spawn) is called.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of executor slots to allocate.
    #[allow(unsafe_code)]
    pub(crate) fn new(count: usize) -> Self {
        let threads = Vec::with_capacity(count);
        for _ in 0..count {
            unsafe {
                #[allow(static_mut_refs)]
                EXECUTOR.push(StaticCell::new());
            }
        }
        Self {
            threads,
            done: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Spawns a new executor thread and schedules an async task on it.
    ///
    /// This creates a new thread with a dedicated Embassy executor and spawns the
    /// task produced by the provided closure onto that executor. The executor runs
    /// until the `ExecutorManager` is dropped or the done signal is set.
    ///
    /// # Arguments
    ///
    /// * `id` - The executor slot index (must be less than the count passed to [`new`](Self::new)).
    /// * `start_fn` - A closure that produces the spawn token for the async task to run.
    #[allow(unsafe_code)]
    pub fn spawn<S: Sized>(
        &mut self,
        id: usize,
        start_fn: impl Fn(Spawner) -> Result<SpawnToken<S>, SpawnError> + Send + 'static,
    ) {
        let done = self.done.clone();
        let thread = thread::spawn(move || {
            let e = unsafe { EXECUTOR[id].init(embassy_executor::Executor::new()) };
            e.run_until(
                |spawner| {
                    spawner.spawn(start_fn(spawner).unwrap());
                },
                || done.load(Ordering::SeqCst),
            );
        });
        self.threads.push(thread);
    }
}

impl Drop for Executor {
    /// Signals all executors to stop and waits for their threads to complete.
    ///
    /// This sets the done flag to `true`, causing all running executors to exit
    /// their run loops, then joins all spawned threads to ensure clean shutdown.
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}
