// Copyright (C) Microsoft Corporation. All rights reserved.

//! Standard Platform Abstraction Layer (PAL) controller management implementation.
//!
//! This module provides the standard implementation of the [`CtrlMgr`] trait
//! for managing hardware controllers, including register access and event polling.

use super::*;
use bitvec::vec::BitVec;
use embassy_sync::waitqueue::WakerRegistration;

/// Internal representation of controller registers.
///
/// Contains all the register values for a single controller.
#[derive(Clone, Copy, Default)]
struct CtrlReg {
    /// Controller capability register.
    cap: CtrlCapReg,
    /// Controller version register.
    vs: CtrlVsReg,
    /// Controller configuration register.
    cc: CtrlCcReg,
    /// Controller status register.
    csts: CtrlCstsReg,
    /// Admin queue attributes register.
    aqa: CtrlAqaReg,
    /// Admin submission queue base address register.
    asq: CtrlAsqReg,
    /// Admin completion queue base address register.
    acq: CtrlAcqReg,
}

/// Standard controller manager implementation.
///
/// Manages multiple hardware controllers and their associated registers.
pub(crate) struct StdCtrlMgr {
    /// Waker registration for async event notification.
    waker: WakerRegistration,
    /// Array of controller registers, one per controller.
    regs: [CtrlReg; StdCtrlMgr::CTRL_COUNT],
}

impl StdCtrlMgr {
    /// Maximum number of controllers supported.
    const CTRL_COUNT: usize = 65;

    /// Creates a new standard controller manager.
    ///
    /// Initializes all controller registers to their default values.
    pub fn new() -> Self {
        Self {
            waker: WakerRegistration::new(),
            regs: [CtrlReg::default(); StdCtrlMgr::CTRL_COUNT],
        }
    }

    /// Reads the controller capability register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn read_cap_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlCapReg> {
        if ctrl_id as usize >= Self::CTRL_COUNT {
            Err(CtrlMgrError::InvalidCtrlId)?;
        }
        Ok(self.regs[ctrl_id as usize].cap)
    }

    /// Writes to the controller capability register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The capability register value to write.
    fn write_cap_reg(&mut self, ctrl_id: CtrlId, reg: CtrlCapReg) -> PalMgmtResult<()> {
        if ctrl_id as usize >= Self::CTRL_COUNT {
            Err(CtrlMgrError::InvalidCtrlId)?;
        }
        self.regs[ctrl_id as usize].cap = reg;
        Ok(())
    }

    /// Reads the controller version register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn read_vs_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlVsReg> {
        if ctrl_id as usize >= Self::CTRL_COUNT {
            Err(CtrlMgrError::InvalidCtrlId)?;
        }
        Ok(self.regs[ctrl_id as usize].vs)
    }

    /// Writes to the controller version register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The version register value to write.
    fn write_vs_reg(&mut self, ctrl_id: CtrlId, reg: CtrlVsReg) -> PalMgmtResult<()> {
        if ctrl_id as usize >= Self::CTRL_COUNT {
            Err(CtrlMgrError::InvalidCtrlId)?;
        }
        self.regs[ctrl_id as usize].vs = reg;
        Ok(())
    }

    /// Reads the controller configuration register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn read_cc_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlCcReg> {
        if ctrl_id as usize >= Self::CTRL_COUNT {
            Err(CtrlMgrError::InvalidCtrlId)?;
        }
        Ok(self.regs[ctrl_id as usize].cc)
    }

    /// Writes to the controller configuration register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The configuration register value to write.
    pub fn write_cc_reg(&mut self, ctrl_id: CtrlId, reg: CtrlCcReg) -> PalMgmtResult<()> {
        if ctrl_id as usize >= Self::CTRL_COUNT {
            Err(CtrlMgrError::InvalidCtrlId)?;
        }
        self.regs[ctrl_id as usize].cc = reg;
        Ok(())
    }

    /// Reads the controller status register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn read_csts_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlCstsReg> {
        if ctrl_id as usize >= Self::CTRL_COUNT {
            Err(CtrlMgrError::InvalidCtrlId)?;
        }
        Ok(self.regs[ctrl_id as usize].csts)
    }

    /// Writes to the controller status register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The status register value to write.
    fn write_csts_reg(&mut self, ctrl_id: CtrlId, reg: CtrlCstsReg) -> PalMgmtResult<()> {
        if ctrl_id as usize >= Self::CTRL_COUNT {
            Err(CtrlMgrError::InvalidCtrlId)?;
        }
        self.regs[ctrl_id as usize].csts = reg;
        Ok(())
    }

    /// Reads the controller admin queue attribute register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn read_aqa_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlAqaReg> {
        if ctrl_id as usize >= Self::CTRL_COUNT {
            Err(CtrlMgrError::InvalidCtrlId)?;
        }
        Ok(self.regs[ctrl_id as usize].aqa)
    }

    /// Writes to the controller admin queue attribute register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The admin queue attribute register value to write.
    pub fn write_aqa_reg(&mut self, ctrl_id: CtrlId, reg: CtrlAqaReg) -> PalMgmtResult<()> {
        if ctrl_id as usize >= Self::CTRL_COUNT {
            Err(CtrlMgrError::InvalidCtrlId)?;
        }
        self.regs[ctrl_id as usize].aqa = reg;
        Ok(())
    }

    /// Reads the admin submission queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn read_asq_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlAsqReg> {
        if ctrl_id as usize >= Self::CTRL_COUNT {
            Err(CtrlMgrError::InvalidCtrlId)?;
        }
        Ok(self.regs[ctrl_id as usize].asq)
    }

    /// Writes to the admin submission queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The admin submission queue base address register value to write.
    pub fn write_asq_reg(&mut self, ctrl_id: CtrlId, reg: CtrlAsqReg) -> PalMgmtResult<()> {
        if ctrl_id as usize >= Self::CTRL_COUNT {
            Err(CtrlMgrError::InvalidCtrlId)?;
        }
        self.regs[ctrl_id as usize].asq = reg;
        Ok(())
    }

    /// Reads the admin completion queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn read_acq_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlAcqReg> {
        if ctrl_id as usize >= Self::CTRL_COUNT {
            Err(CtrlMgrError::InvalidCtrlId)?;
        }
        Ok(self.regs[ctrl_id as usize].acq)
    }

    /// Writes to the admin completion queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The admin completion queue base address register value to write.
    pub fn write_acq_reg(&mut self, ctrl_id: CtrlId, reg: CtrlAcqReg) -> PalMgmtResult<()> {
        if ctrl_id as usize >= Self::CTRL_COUNT {
            Err(CtrlMgrError::InvalidCtrlId)?;
        }
        self.regs[ctrl_id as usize].acq = reg;
        Ok(())
    }

    /// Wakes the registered waker if any events have changed.
    ///
    /// This should be called after modifying event state to notify any
    /// pending pollers that new events are available.
    #[instrument(skip(self))]
    pub fn wake(&mut self) {
        if self.changed().is_some() {
            tracing::info!("Waking Controller poller");
            self.waker.wake();
        }
    }

    /// Identifies a controller whose ready status has changed.
    ///
    /// Returns the controller ID if a change is detected, or `None` otherwise.
    fn changed(&self) -> Option<CtrlId> {
        let sts: BitVec<u64> = self.regs.iter().map(|r| r.csts.rdy()).collect();
        let rdy: BitVec<u64> = self.regs.iter().map(|r| r.cc.en()).collect();
        let changed = sts ^ rdy;
        changed.first_one().map(|id| id as CtrlId)
    }
}

impl CtrlMgr for StdPal {
    /// Polls for the next controller event.
    ///
    /// Waits asynchronously for and returns the next controller event.
    fn poll_ctrl_event(&self) -> impl Future<Output = CtrlEvent> + Send {
        poll_fn(|cx| {
            let mut inner = self.inner.lock();
            let ctrl_mgr = &mut inner.ctrl_mgr;
            let Some(ctrl_id) = ctrl_mgr.changed() else {
                ctrl_mgr.waker.register(cx.waker());
                return Poll::Pending;
            };
            let reg = &ctrl_mgr.regs[ctrl_id as usize];
            let event = if reg.cc.en() {
                CtrlEvent::Enable { ctrl_id }
            } else {
                CtrlEvent::Disable { ctrl_id }
            };
            Poll::Ready(event)
        })
    }

    /// Reads the controller capability register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn read_cap_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlCapReg> {
        self.with_ctrl_mgr(|mgr| mgr.read_cap_reg(ctrl_id))
    }

    /// Writes to the controller capability register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The capability register value to write.
    fn write_cap_reg(&self, ctrl_id: CtrlId, reg: CtrlCapReg) -> PalMgmtResult<()> {
        self.with_ctrl_mgr(|mgr| mgr.write_cap_reg(ctrl_id, reg))
    }

    /// Reads the controller version register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn read_vs_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlVsReg> {
        self.with_ctrl_mgr(|mgr| mgr.read_vs_reg(ctrl_id))
    }

    /// Writes to the controller version register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The version register value to write.
    fn write_vs_reg(&self, ctrl_id: CtrlId, reg: CtrlVsReg) -> PalMgmtResult<()> {
        self.with_ctrl_mgr(|mgr| mgr.write_vs_reg(ctrl_id, reg))
    }

    /// Reads the controller configuration register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn read_cc_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlCcReg> {
        self.with_ctrl_mgr(|mgr| mgr.read_cc_reg(ctrl_id))
    }

    /// Reads the controller status register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn read_csts_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlCstsReg> {
        self.with_ctrl_mgr(|mgr| mgr.read_csts_reg(ctrl_id))
    }

    /// Writes to the controller status register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The status register value to write.
    fn write_csts_reg(&self, ctrl_id: CtrlId, reg: CtrlCstsReg) -> PalMgmtResult<()> {
        self.with_ctrl_mgr(|mgr| mgr.write_csts_reg(ctrl_id, reg))
    }

    /// Reads the controller admin queue attribute register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn read_aqa_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlAqaReg> {
        self.with_ctrl_mgr(|mgr| mgr.read_aqa_reg(ctrl_id))
    }

    /// Reads the admin submission queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn read_asq_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlAsqReg> {
        self.with_ctrl_mgr(|mgr| mgr.read_asq_reg(ctrl_id))
    }

    /// Reads the admin completion queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn read_acq_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlAcqReg> {
        self.with_ctrl_mgr(|mgr| mgr.read_acq_reg(ctrl_id))
    }
}
