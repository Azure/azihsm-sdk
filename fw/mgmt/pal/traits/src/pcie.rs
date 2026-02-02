// Copyright (C) Microsoft Corporation. All rights reserved.

//! PCIe management types and traits for the Platform Abstraction Layer (PAL).
//!
//! This module provides abstractions for handling PCIe-specific events such as
//! platform resets (PERST), function-level resets (FLR), and virtual function resets.

use super::*;

/// Represents PCIe-related events that can occur on the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcieEvent {
    /// PCIe reset signal has been asserted (reset active).
    PerstUp,
    /// PCIe reset signal has been deasserted (reset complete).
    PerstDown,
    /// Function Level Reset (FLR) has been triggered on the physical function.
    FuncReset,
    /// Virtual Function Level Reset has been triggered.
    VirtFuncReset {
        /// The identifier of the virtual function's controller being reset.
        ctrl_id: CtrlId,
    },
}

/// Trait for managing PCIe events and reset acknowledgments.
///
/// Provides methods for polling PCIe events and signaling completion of
/// reset handling operations.
pub trait PcieMgr {
    /// Polls for the next PCIe event.
    ///
    /// This is an asynchronous operation that waits for and returns the next
    /// PCIe event (PERST assertion/deassertion, FLR, or VFLR).
    fn poll_pcie_event(&self) -> impl Future<Output = PcieEvent> + Send;

    /// Signals that PERST assertion handling is complete.
    ///
    /// Call this after processing a [`PcieEvent::PerstUp`] event.
    fn perst_up_done(&self) -> PalMgmtResult<()>;

    /// Signals that PERST deassertion handling is complete.
    ///
    /// Call this after processing a [`PcieEvent::PerstDown`] event.
    fn perst_down_done(&self) -> PalMgmtResult<()>;

    /// Signals that Function Level Reset handling is complete.
    ///
    /// Call this after processing a [`PcieEvent::FuncReset`] event.
    fn flr_done(&self) -> PalMgmtResult<()>;

    /// Signals that Virtual Function Level Reset handling is complete.
    ///
    /// Call this after processing a [`PcieEvent::VirtFuncReset`] event.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the virtual function's controller that was reset.
    fn vflr_done(&self, ctrl_id: CtrlId) -> PalMgmtResult<()>;
}
