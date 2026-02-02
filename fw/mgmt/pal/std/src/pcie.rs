// Copyright (C) Microsoft Corporation. All rights reserved.

//! PCIe manager implementation for the standard PAL.
//!
//! This module provides PCIe event tracking and management using bit arrays
//! to efficiently represent pending events for both physical and virtual functions.

use bitvec::array::BitArray;
use bitvec::bitarr;
use bitvec::order::Lsb0;
use embassy_sync::waitqueue::WakerRegistration;
use strum::EnumCount;
use strum_macros::EnumCount;

use super::*;

/// Indices for physical function PCIe events in the bit arrays.
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumCount)]
enum EventIndex {
    /// PERST assertion event index.
    PerstUp,
    /// PERST deassertion event index.
    PerstDown,
    /// Function Level Reset event index.
    Flr,
}

/// Standard PCIe manager for tracking and managing PCIe events.
///
/// Uses two bit arrays (`old` and `new`) to track event state transitions.
/// Physical function events are stored at the beginning of the arrays,
/// followed by virtual function events indexed by controller ID.
pub(crate) struct StdPcieMgr {
    /// Waker registration for PCIe event polling.
    waker: WakerRegistration,
    /// Previous event state bit array.
    old: BitArray<[u64; 2]>,
    /// Current event state bit array.
    new: BitArray<[u64; 2]>,
}

impl StdPcieMgr {
    /// Maximum number of virtual functions supported.
    const VF_COUNT: usize = 64;
    /// Total number of event slots (physical function events + virtual function events).
    const EVENT_COUNT: usize = EventIndex::COUNT + Self::VF_COUNT;

    /// Creates a new PCIe manager with all events cleared.
    pub const fn new() -> Self {
        Self {
            waker: WakerRegistration::new(),
            old: bitarr![u64, Lsb0; 0; StdPcieMgr::EVENT_COUNT],
            new: bitarr![u64, Lsb0; 0; StdPcieMgr::EVENT_COUNT],
        }
    }

    /// Sets the PERST up (assertion) event as pending.
    pub fn set_perst_up(&mut self) {
        self.new.set(EventIndex::PerstUp as usize, true);
    }

    /// Sets the PERST down (deassertion) event as pending.
    pub fn set_perst_down(&mut self) {
        self.new.set(EventIndex::PerstDown as usize, true);
    }

    /// Sets the Function Level Reset event as pending.
    pub fn set_flr(&mut self) {
        self.new.set(EventIndex::Flr as usize, true);
    }

    /// Sets a Virtual Function Level Reset event as pending.
    ///
    /// # Parameters
    /// - `ctrl_id`: The controller ID (1 to `VF_COUNT`, inclusive).
    ///              Controller IDs outside this range are ignored.
    pub fn set_vflr(&mut self, ctrl_id: CtrlId) {
        if ctrl_id > 0 && ctrl_id <= Self::VF_COUNT as u16 {
            self.new.set(EventIndex::COUNT + ctrl_id as usize, true);
        }
    }

    /// Returns whether a PERST up event is pending.
    pub fn perst_up_pending(&self) -> bool {
        self.new[EventIndex::PerstUp as usize]
    }

    /// Returns whether a PERST down event is pending.
    pub fn perst_down_pending(&self) -> bool {
        self.new[EventIndex::PerstDown as usize]
    }

    /// Returns whether a Function Level Reset event is pending.
    pub fn flr_pending(&self) -> bool {
        self.new[EventIndex::Flr as usize]
    }

    /// Returns whether a Virtual Function Level Reset event is pending.
    ///
    /// # Parameters
    /// - `ctrl_id`: The controller ID to check.
    ///
    /// Returns `false` if the controller ID is out of range.
    pub fn vflr_pending(&self, ctrl_id: CtrlId) -> bool {
        if ctrl_id > 0 && ctrl_id <= Self::VF_COUNT as u16 {
            let idx = EventIndex::COUNT + ctrl_id as usize;
            self.new[idx]
        } else {
            false
        }
    }

    /// Wakes the registered waker if any events have changed.
    ///
    /// This should be called after modifying event state to notify any
    /// pending pollers that new events are available.
    #[instrument(skip(self))]
    pub fn wake(&mut self) {
        if self.changed().any() {
            tracing::info!("Waking PCIe poller");
            self.waker.wake();
        }
    }

    /// Clears the PERST up event from both old and new state.
    fn clear_perst_up(&mut self) {
        self.old.set(EventIndex::PerstUp as usize, false);
        self.new.set(EventIndex::PerstUp as usize, false);
    }

    /// Clears the PERST down event from both old and new state.
    fn clear_perst_down(&mut self) {
        self.old.set(EventIndex::PerstDown as usize, false);
        self.new.set(EventIndex::PerstDown as usize, false);
    }

    /// Clears the Function Level Reset event from both old and new state.
    fn clear_flr(&mut self) {
        self.old.set(EventIndex::Flr as usize, false);
        self.new.set(EventIndex::Flr as usize, false);
    }

    /// Clears a Virtual Function Level Reset event from both old and new state.
    ///
    /// # Parameters
    /// - `ctrl_id`: The controller ID whose VFLR event to clear.
    ///              Controller IDs outside the valid range are ignored.
    fn clear_vflr(&mut self, ctrl_id: CtrlId) {
        if ctrl_id > 0 && ctrl_id <= Self::VF_COUNT as u16 {
            let idx = EventIndex::COUNT + ctrl_id as usize;
            self.old.set(idx, false);
            self.new.set(idx, false);
        }
    }

    /// Computes the set of events that have changed between old and new state.
    ///
    /// Returns a bit array where set bits indicate events that differ between
    /// the previous (`old`) and current (`new`) states.
    fn changed(&self) -> BitArray<[u64; 2]> {
        self.old ^ self.new
    }
}

impl PcieMgr for StdPal {
    /// Polls for the next PCIe event.
    ///
    /// Currently returns a pending future that never resolves,
    /// as the standard PAL does not receive real PCIe events.
    fn poll_pcie_event(&self) -> impl Future<Output = PcieEvent> + Send {
        poll_fn(|cx| {
            let mut inner = self.inner.lock();
            let pcie = &mut inner.pcie_mgr;
            let Some(idx) = pcie.changed().first_one() else {
                pcie.waker.register(cx.waker());
                return Poll::Pending;
            };
            pcie.old.set(idx, true);
            let event = match idx {
                _ if idx == EventIndex::PerstUp as usize => PcieEvent::PerstUp,
                _ if idx == EventIndex::PerstDown as usize => PcieEvent::PerstDown,
                _ if idx == EventIndex::Flr as usize => PcieEvent::FuncReset,
                _ => PcieEvent::VirtFuncReset {
                    ctrl_id: (idx - EventIndex::COUNT) as u16,
                },
            };
            Poll::Ready(event)
        })
    }

    /// Signals that PERST up handling is complete.
    ///
    /// Clears the PERST up pending state.
    fn perst_up_done(&self) -> PalMgmtResult<()> {
        self.with_pcie_mgr(|mgr| mgr.clear_perst_up());
        Ok(())
    }

    /// Signals that PERST down handling is complete.
    ///
    /// Clears the PERST down pending state.
    fn perst_down_done(&self) -> PalMgmtResult<()> {
        self.with_pcie_mgr(|mgr| mgr.clear_perst_down());
        Ok(())
    }

    /// Signals that Function Level Reset handling is complete.
    ///
    /// Clears the FLR pending state.
    fn flr_done(&self) -> PalMgmtResult<()> {
        self.with_pcie_mgr(|mgr| mgr.clear_flr());
        Ok(())
    }

    /// Signals that Virtual Function Level Reset handling is complete.
    ///
    /// Clears the VFLR pending state for the specified controller.
    ///
    /// # Parameters
    /// - `ctrl_id`: The controller ID whose VFLR handling is complete.
    fn vflr_done(&self, ctrl_id: CtrlId) -> PalMgmtResult<()> {
        self.with_pcie_mgr(|mgr| mgr.clear_vflr(ctrl_id));
        Ok(())
    }
}
