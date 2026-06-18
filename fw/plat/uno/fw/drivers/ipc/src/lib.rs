// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IPC driver for the INTC peripheral.
//!
//! Provides async message and event communication over doorbell
//! descriptor pairs. Each pair consists of an inbound descriptor
//! (we receive on) and an outbound descriptor (we send/reply on).
//!
//! # Pair types
//!
//! - **RecvMessage**: Single waiter. `recv()` awaits inbound doorbell,
//!   reads from RX shared-memory ring. `reply()` writes to TX ring
//!   and rings outbound descriptor (sync).
//!
//! - **SendMessage**: Multiple senders serialized via slot pool.
//!   `send()` writes to TX ring, rings outbound descriptor, awaits
//!   response on inbound descriptor, reads from RX ring.
//!
//! - **RecvEvent**: Single waiter. `recv_event()` awaits inbound
//!   doorbell, returns descriptor value. `ack_event()` writes value
//!   to outbound descriptor (sync).
//!
//! - **SendEvent**: Fire-and-forget. `send_event()` writes value to
//!   outbound descriptor (sync).
//!
//! # Interrupt model
//!
//! All descriptors share a single NVIC IRQ. The `wake()` method reads
//! the PEND_SET register, identifies which descriptors fired, and
//! wakes the appropriate pair's async waker. No ISR is installed —
//! the PAL polls `Nvic::is_pending()` and calls `wake()`.

#![no_std]

mod error;
mod ipc;

pub use error::*;
pub use ipc::*;
