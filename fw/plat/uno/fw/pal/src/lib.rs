// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Uno HSM Platform Abstraction Layer.
//!
//! Implements all [`azihsm_fw_hsm_pal_traits`] traits for the Uno
//! Cortex-M7 SoC, bridging the platform-agnostic HSM core to the
//! Uno hardware peripherals.
//!
//! # Module layout
//!
//! | Module   | Trait                  | Status         |
//! |----------|------------------------|----------------|
//! | `pal`    | [`HsmPal`]             | Implemented    |
//! | `io`     | [`HsmIoController`]    | Implemented    |
//! | `gdma`   | [`HsmGdmaController`]  | Implemented    |
//! | `part`   | [`HsmPartitionManager`]| Stub (Enabled) |
//! | `session`| [`HsmSessionManager`]  | Stub           |
//! | `vault`  | [`HsmVault`]           | Stub           |
//! | `cert`   | [`HsmCertStore`]       | Stub           |
//! | `crypto` | [`HsmCrypto`] et al.   | Stub           |
//! | `lock`   | [`HsmPartitionLock`]   | Stub (no-op)   |
//!
//! # Data flow
//!
//! ```text
//! Host ──► IIC (SQE into IO_SQ) ──► poll_io ──► HSM core
//!                                                    │
//!                                               GDMA (in-DMA)
//!                                               DDI dispatch
//!                                               GDMA (out-DMA)
//!                                                    │
//!                                               OIC (CQE from IO_CQ) ──► Host
//! ```

#![no_std]

mod alloc;
mod cert;
mod crypto;
mod gdma;
mod io;
mod ipc;
mod lock;
mod pal;
mod part;
mod seed;
mod session;
mod vault;

/// Re-export of the PAL trait types consumed by uno-PAL users.
///
/// Lets downstream crates (test harness, integration tests, sample
/// firmware) depend solely on `azihsm_fw_uno_pal` without taking an
/// additional path-dep into `azihsm_fw_hsm_pal_traits`.
pub use azihsm_fw_hsm_pal_traits::DmaBuf;
pub use azihsm_fw_hsm_pal_traits::HsmAlloc;
pub use azihsm_fw_hsm_pal_traits::HsmIo;
pub use azihsm_fw_hsm_pal_traits::HsmPal;
pub use io::*;
pub use ipc::*;
pub use pal::*;
