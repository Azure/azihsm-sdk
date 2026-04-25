// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Top-level HSM application struct and Embassy task loop.
//!
//! [`Hsm`] owns the platform abstraction layer ([`Pal`]) and drives the
//! application lifecycle. A single global instance is stored in the
//! [`HSM`](super::HSM) `OnceLock` and shared by all Embassy tasks.
//!
//! # Lifecycle
//!
//! [`Hsm::run`] orchestrates the full startup-to-shutdown sequence:
//!
//! 1. **Init** — [`Pal::init`] performs one-time hardware/driver setup.
//! 2. **Spawn IO loop** — [`poll_io`] is spawned as a dedicated Embassy
//!    task that continuously receives IOs from the PAL submission queue.
//! 3. **Run** — [`Pal::run`] enters the PAL's main event loop (e.g.
//!    waiting for host shutdown or a fatal error). This call blocks the
//!    `run` future until the PAL signals completion.
//! 4. **Deinit** — [`Pal::deinit`] tears down hardware state.
//!
//! # Task architecture
//!
//! IO processing is split across two Embassy task layers:
//!
//! - **[`poll_io`]** (single instance) — Awaits the next IO from
//!   [`Pal::poll_io`], then spawns a [`handle_io`] task for each one.
//!   This keeps the receive path unblocked so new IOs can be accepted
//!   concurrently with in-flight completions.
//!
//! - **[`handle_io`]** (pool of 32) — Each task owns one [`Io`] for its
//!   entire lifetime, holding the submission queue slot until the
//!   completion DMA finishes. Delegates to [`Hsm::handle_io`](super::io)
//!   for SQE parsing, opcode dispatch, and CQE delivery.

use embassy_executor::*;

use super::*;

/// The top-level HSM application.
///
/// Holds a [`Pal`] instance that provides platform-specific IO
/// controllers, DMA, and interrupt wiring. The concrete [`Pal`] type is
/// selected at compile time via feature flags (`pal-ocelot` or `pal-std`).
///
/// A single `Hsm` lives in the [`HSM`](super::HSM) `OnceLock`. All
/// Embassy tasks access it through that global rather than receiving a
/// reference, because Embassy task functions cannot capture borrows.
#[derive(Default)]
pub struct Hsm {
    /// The platform abstraction layer.
    pal: Pal,
}

impl Hsm {
    /// Creates a new `Hsm` wrapping the given PAL.
    pub fn new(pal: Pal) -> Self {
        Self { pal }
    }

    /// Runs the full application lifecycle.
    ///
    /// Initialises the PAL, spawns the IO receive loop, awaits the PAL's
    /// main run loop, then deinitialises. Returns only after the PAL's
    /// `run` future completes (i.e. on shutdown or fatal error).
    ///
    /// If the [`poll_io`] task cannot be spawned (executor out of slots),
    /// the method returns immediately without entering the run loop.
    pub async fn run(&self, spawner: Spawner) {
        self.pal.init();

        if let Ok(token) = poll_io(spawner) {
            spawner.spawn(token);
        } else {
            return;
        }

        self.pal.run().await;
        self.pal.deinit();
    }

    /// Returns a reference to the PAL.
    pub fn pal(&self) -> &Pal {
        &self.pal
    }
}

/// IO receive loop — runs forever as a single Embassy task.
///
/// On each iteration:
/// 1. Awaits [`Pal::poll_io`] for the next submitted IO. If the poll
///    returns an error (e.g. the host tore down the queue), the error is
///    silently skipped and the loop retries.
/// 2. Attempts to spawn a [`handle_io`] task from the 32-slot pool. If
///    no pool slots are available, the IO is dropped (freeing its
///    submission queue entry) and the loop continues.
///
/// This task never returns (`-> !`), keeping the receive path alive for
/// the lifetime of the executor.
#[task]
async fn poll_io(spawner: Spawner) -> ! {
    loop {
        let Ok(io) = HSM.get_or_init(Hsm::default).pal().poll_io().await else {
            continue;
        };

        let Ok(token) = handle_io(io) else {
            continue;
        };
        spawner.spawn(token);
    }
}

/// Processes a single IO to completion.
///
/// Takes ownership of the [`Io`], keeping the underlying submission queue
/// slot reserved until the completion DMA finishes. Delegates all parsing,
/// validation, and CQE population to [`Hsm::handle_io`](super::io).
///
/// Runs in a 32-task Embassy pool, allowing up to 32 IOs to be processed
/// concurrently.
#[task(pool_size = 32)]
async fn handle_io(io: Io) {
    HSM.get_or_init(Hsm::default).handle_io(io).await;
}
