// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tokio-backed worker pool for offloading async work from Embassy.
//!
//! Embassy is a single-threaded cooperative executor — long or blocking
//! operations prevent other tasks from running. The worker pool offloads
//! work to tokio's multi-threaded runtime:
//!
//! 1. [`submit`](WorkerPool::submit) spawns an async closure on tokio.
//! 2. The calling Embassy task yields (`Pending`).
//! 3. When the tokio task completes, it wakes the Embassy task via `Waker`.
//! 4. The Embassy task resumes (`Ready`).
//!
//! This gives real async concurrency — the Embassy executor can poll
//! other tasks while the work runs on a separate thread.

#![allow(dead_code)]

use core::future::Future;
use core::pin::Pin;
use core::task::Context;
use core::task::Poll;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::runtime::Handle;

/// Dispatches async work to a tokio runtime.
///
/// Created internally by [`StdHsmPal`](crate::StdHsmPal) from the
/// tokio runtime handle.
#[derive(Clone)]
pub struct WorkerPool {
    /// Handle to the tokio runtime where work is spawned.
    pub(crate) handle: Handle,
}

impl WorkerPool {
    /// Create a worker pool backed by the given tokio runtime handle.
    pub fn new(handle: Handle) -> Self {
        Self { handle }
    }

    /// Submit an async task to tokio and await its completion.
    ///
    /// The calling Embassy task yields while the work runs on tokio's
    /// thread pool. When the work completes, the Embassy task is woken
    /// and resumes.
    ///
    /// # Example
    ///
    /// ```ignore
    /// self.pool.submit(async {
    ///     tokio::time::sleep(Duration::from_millis(50)).await;
    ///     // ... do real work ...
    /// }).await;
    /// ```
    pub fn submit<F>(&self, work: F) -> SubmitFuture
    where
        F: Future<Output = ()> + Send + 'static,
    {
        SubmitFuture {
            handle: self.handle.clone(),
            work: Some(Box::pin(work)),
            done: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Submit an async task to tokio and await its result.
    ///
    /// Like [`submit`](Self::submit) but returns a value from the worker.
    pub fn submit_with_result<T, F>(&self, work: F) -> SubmitResultFuture<T>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        SubmitResultFuture {
            handle: self.handle.clone(),
            work: Some(Box::pin(work)),
            rx: None,
            done: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Future that completes when a tokio-spawned task finishes.
///
/// On first poll, spawns the work on tokio and returns `Pending`.
/// The tokio task sets `done = true` and wakes this future when the work
/// completes. Subsequent polls check `done` and return `Ready` only after
/// the tokio task has confirmed completion, guarding against spurious wakes.
pub struct SubmitFuture {
    /// Handle to the tokio runtime.
    handle: Handle,

    /// The async work to run, consumed on first poll.
    work: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,

    /// Set to `true` by the tokio task after the work completes.
    done: Arc<AtomicBool>,
}

impl Future for SubmitFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // Return Ready only once the tokio task has signalled completion.
        if self.done.load(Ordering::Acquire) {
            return Poll::Ready(());
        }

        // Spawn work on first poll; subsequent spurious polls just fall through
        // to Pending because `work` will already be None.
        if let Some(work) = self.work.take() {
            let waker = cx.waker().clone();
            let done = Arc::clone(&self.done);
            self.handle.spawn(async move {
                work.await;
                // Signal completion before waking so the next poll sees Ready.
                done.store(true, Ordering::Release);
                waker.wake();
            });
        }

        Poll::Pending
    }
}

/// Future that completes with a value when a tokio-spawned task finishes.
///
/// Same as [`SubmitFuture`] but captures the task's return value via a
/// oneshot channel.
pub struct SubmitResultFuture<T> {
    handle: Handle,
    work: Option<Pin<Box<dyn Future<Output = T> + Send>>>,
    rx: Option<tokio::sync::oneshot::Receiver<T>>,
    done: Arc<AtomicBool>,
}

// SAFETY: The only non-Unpin field (`work`) is behind `Pin<Box<...>>`
// and is consumed on first poll. The remaining fields are all Unpin.
impl<T> Unpin for SubmitResultFuture<T> {}

impl<T: Send + 'static> Future for SubmitResultFuture<T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        // Check if the result is ready.
        if self.done.load(Ordering::Acquire) {
            if let Some(mut rx) = self.rx.take() {
                if let Ok(val) = rx.try_recv() {
                    return Poll::Ready(val);
                }
            }
        }

        // Spawn work on first poll.
        if let Some(work) = self.work.take() {
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.rx = Some(rx);
            let waker = cx.waker().clone();
            let done = Arc::clone(&self.done);
            self.handle.spawn(async move {
                let val = work.await;
                let _ = tx.send(val);
                done.store(true, Ordering::Release);
                waker.wake();
            });
        }

        Poll::Pending
    }
}
