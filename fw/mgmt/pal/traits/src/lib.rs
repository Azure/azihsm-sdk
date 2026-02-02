// Copyright (C) Microsoft Corporation. All rights reserved.

//! Platform Abstraction Layer (PAL) traits and types.
//!
//! This crate defines the core abstractions for platform-specific hardware interactions,
//! including controller management, queue management, and I/O operations. Implementations
//! of these traits provide the platform-specific functionality required by the management
//! firmware.

#![no_std]

mod ctrl;
mod error;
mod gdma;
mod io;
mod pcie;
mod queue;

pub use ctrl::*;
pub use error::*;
pub use io::*;
pub use pcie::*;
pub use queue::*;

/// The main Platform Abstraction Layer trait.
///
/// This trait combines [`PcieMgr`] capabilities,
/// providing a unified interface for platform initialization, event processing,
/// and deinitialization.
pub trait Pal: PcieMgr + CtrlMgr {
    /// Initializes the platform abstraction layer.
    ///
    /// This should be called before any other PAL operations to set up
    /// required hardware resources and state.
    fn init(&self) -> PalMgmtResult<()>;

    /// Runs the main event loop for processing platform events.
    ///
    /// This is an asynchronous operation that processes incoming events
    /// until the platform is shut down.
    fn run(&self) -> impl Future<Output = ()> + Send;

    /// Deinitializes the platform abstraction layer.
    ///
    /// This should be called during shutdown to release hardware resources
    /// and perform cleanup operations.
    fn deinit(&self) -> PalMgmtResult<()>;
}

/// Unique identifier for a controller.
pub type CtrlId = u16;

/// Submission Queue (SQ) identifier.
pub type SqId = u16;

/// Completion Queue (CQ) identifier.
pub type CqId = u16;

/// Submission Queue (SQ) information.
///
/// Contains the configuration details for an NVMe submission queue.
pub struct SqInfo {
    /// The queue identifier.
    pub id: SqId,
    /// The number of entries in the queue.
    pub size: u16,
    /// The base address of the queue in memory.
    pub addr: u64,
}

/// Completion Queue (CQ) information.
///
/// Contains the configuration details for an NVMe completion queue.
pub struct CqInfo {
    /// The queue identifier.
    pub id: CqId,
    /// The number of entries in the queue.
    pub size: u16,
    /// The base address of the queue in memory.
    pub addr: u64,
    /// The interrupt vector associated with this queue.
    pub vec: u16,
}
