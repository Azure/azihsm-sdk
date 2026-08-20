// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std PAL — host-native HSM platform abstraction layer.
//!
//! Implements the HSM PAL traits ([`HsmPal`], [`HsmIoController`],
//! [`HsmGdmaController`]) for running HSM core logic natively on the
//! host without hardware or an emulator.
//!
//! # Architecture
//!
//! ```text
//! User (tokio)                    Embassy thread
//! ────────────                    ──────────────
//! HsmIoRequest ──► submit_rx ──► poll_io()
//!                                  alloc buffer slot
//!                                  wrap as StdHsmIo
//!                                  ▼
//!                                core recv_task / send_task
//!                                  ▼
//!                                complete_io()
//!                                  simulate delay (tokio worker)
//!                                  free buffer slot
//! HsmCqe      ◄─ reply_tx ◄── send response
//! ```
//!
//! ## Key components
//!
//! - [`StdHsmPal`] — implements PAL traits with channel-based IO
//!   transport and a tokio-backed worker pool for delay simulation.
//! - [`StdHsmIo`] — IO work item backed by a pool-allocated buffer
//!   slot. Implements [`HsmIo`] for the core's generic IO processing.
//! - [`BufferPool`](buf_pool::BufferPool) — pre-allocated 2KB + 8KB
//!   buffers with async bitmap allocation and waker-based backpressure.
//! - [`WorkerPool`](worker::WorkerPool) — dispatches delay tasks to
//!   tokio, wakes Embassy tasks on completion via cross-thread `Waker`.
//! - [`HsmIoRequest`] — request type for the submit channel.
//!
//! ## Thread model
//!
//! All PAL state (buffer pool, channels, wakers) lives on the Embassy
//! thread. The tokio runtime runs on separate threads and only
//! communicates via `Waker` (thread-safe). No mutexes are needed —
//! `Cell` and `RefCell` suffice for single-threaded Embassy access.
//!
//! [`HsmPal`]: azihsm_fw_hsm_pal_traits::HsmPal
//! [`HsmIoController`]: azihsm_fw_hsm_pal_traits::HsmIoController
//! [`HsmGdmaController`]: azihsm_fw_hsm_pal_traits::HsmGdmaController
//! [`HsmIo`]: azihsm_fw_hsm_pal_traits::HsmIo

mod aes;
mod alloc;
mod buf_pool;
mod cert;
mod drivers;
mod ecc;
mod gdma;
mod hash;
mod hmac;
mod io;
mod kdf;
mod pal;
mod part;
mod part_lock;
mod rng;
mod rsa;
mod seed;
mod session;
mod tracing;
mod vault;
mod worker;

pub use alloc::StdScopedAlloc;

use azihsm_fw_hsm_pal_traits::*;
pub use io::HsmIoRequest;
pub use io::StdHsmIo;
pub use pal::StdHsmPal;
pub use part::PartCommand;
