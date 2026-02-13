// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Standard Platform Abstraction Layer (PAL) controller management implementation.
//!
//! This module provides the standard implementation of the [`CtrlMgr`] trait
//! for managing hardware controllers, including register access and event polling.

use super::*;
use bitfield_struct::bitfield;
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
    pub fn read_cap_reg(&self, ctrl_id: CtrlId) -> MgmtPalResult<CtrlCapReg> {
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
    fn _write_cap_reg(&mut self, ctrl_id: CtrlId, reg: CtrlCapReg) -> MgmtPalResult<()> {
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
    pub fn read_vs_reg(&self, ctrl_id: CtrlId) -> MgmtPalResult<CtrlVsReg> {
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
    fn _write_vs_reg(&mut self, ctrl_id: CtrlId, reg: CtrlVsReg) -> MgmtPalResult<()> {
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
    pub fn read_cc_reg(&self, ctrl_id: CtrlId) -> MgmtPalResult<CtrlCcReg> {
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
    pub fn write_cc_reg(&mut self, ctrl_id: CtrlId, reg: CtrlCcReg) -> MgmtPalResult<()> {
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
    pub fn read_csts_reg(&self, ctrl_id: CtrlId) -> MgmtPalResult<CtrlCstsReg> {
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
    fn write_csts_reg(&mut self, ctrl_id: CtrlId, reg: CtrlCstsReg) -> MgmtPalResult<()> {
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
    pub fn read_aqa_reg(&self, ctrl_id: CtrlId) -> MgmtPalResult<CtrlAqaReg> {
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
    pub fn write_aqa_reg(&mut self, ctrl_id: CtrlId, reg: CtrlAqaReg) -> MgmtPalResult<()> {
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
    pub fn read_asq_reg(&self, ctrl_id: CtrlId) -> MgmtPalResult<CtrlAsqReg> {
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
    pub fn write_asq_reg(&mut self, ctrl_id: CtrlId, reg: CtrlAsqReg) -> MgmtPalResult<()> {
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
    pub fn read_acq_reg(&self, ctrl_id: CtrlId) -> MgmtPalResult<CtrlAcqReg> {
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
    pub fn write_acq_reg(&mut self, ctrl_id: CtrlId, reg: CtrlAcqReg) -> MgmtPalResult<()> {
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

    /// Retrieves the Admin Submission Queue (SQ) information for the specified controller.
    fn asq_info(&self, ctrl_id: CtrlId) -> MgmtPalResult<SqInfo> {
        let inner = self.inner.lock();
        let aqa = inner.ctrl_mgr.read_aqa_reg(ctrl_id)?;
        let asq = inner.ctrl_mgr.read_asq_reg(ctrl_id)?;
        Ok(SqInfo {
            id: 0, // Admin SQ always has ID 0
            size: aqa.asqs(),
            addr: asq.asqb(),
        })
    }

    /// Retrieves the Admin Completion Queue (CQ) information for the specified controller.
    fn acq_info(&self, ctrl_id: CtrlId) -> MgmtPalResult<CqInfo> {
        let inner = self.inner.lock();
        let aqa = inner.ctrl_mgr.read_aqa_reg(ctrl_id)?;
        let acq = inner.ctrl_mgr.read_acq_reg(ctrl_id)?;
        Ok(CqInfo {
            id: 0, // Admin CQ always has ID 0
            size: aqa.acqs(),
            addr: acq.acqb(),
            vec: 0, // Admin CQ always has vector 0
        })
    }

    /// Enables the specified controller.
    fn set_ctrl_enable(&self, ctrl_id: CtrlId) -> MgmtPalResult<()> {
        self.with_ctrl_mgr(|mgr| {
            let mut csts = mgr.read_csts_reg(ctrl_id)?;
            csts.set_rdy(true);
            csts.set_cfs(false);
            mgr.write_csts_reg(ctrl_id, csts)
        })?;
        Ok(())
    }

    /// Disables the specified controller.
    fn set_ctrl_disable(&self, ctrl_id: CtrlId) -> MgmtPalResult<()> {
        self.with_ctrl_mgr(|mgr| {
            let mut csts = mgr.read_csts_reg(ctrl_id)?;
            csts.set_rdy(false);
            csts.set_cfs(false);
            mgr.write_csts_reg(ctrl_id, csts)
        })?;
        Ok(())
    }

    /// Sets the fatal status for the specified controller.
    fn set_ctrl_fatal_status(&self, ctrl_id: CtrlId) {
        let _ = self.with_ctrl_mgr(|mgr| {
            let mut csts = mgr.read_csts_reg(ctrl_id)?;
            csts.set_cfs(true);
            csts.set_rdy(false);
            mgr.write_csts_reg(ctrl_id, csts)
        });
    }
}

/// Controller Capability Register.
///
/// Contains the controller's capabilities and configuration limits.
#[bitfield(u64)]
pub struct CtrlCapReg {
    /// Maximum queue entries supported
    pub mqes: u16,

    /// Contiguous queue required
    pub cqr: bool,

    /// Reserved
    #[bits(7)]
    _rsvd1: u8,

    /// Timeout
    pub to: u8,

    /// Doorbell stride
    #[bits(4)]
    pub dstrd: u8,

    /// Manticore subsystem reset supported
    pub mssrs: bool,

    /// Reserved
    #[bits(11)]
    _rsvd2: u16,

    /// Memory page size minimum
    #[bits(4)]
    pub mpsmin: u8,

    /// Memory page size maximum
    #[bits(4)]
    pub mpsmax: u8,

    /// Reserved
    _rsvd3: u8,
}

/// Controller Version Register
#[bitfield(u32)]
pub struct CtrlVsReg {
    /// Tertiary version number
    pub ter: u8,

    /// Minor version number
    pub min: u8,

    /// Major version number
    pub maj: u16,
}

/// Controller Configuration Register
#[bitfield(u32)]
//#[derive(Default)]
pub struct CtrlCcReg {
    /// Enable controller
    pub en: bool,

    /// Reserved
    #[bits(6)]
    _rsvd1: u8,

    /// Memory page size
    #[bits(4)]
    pub mps: u8,

    /// Reserved
    #[bits(5)]
    _rsvd2: u8,

    /// IO submission queue entry size
    #[bits(4)]
    pub iosqes: u8,

    /// IO completion queue entry size
    #[bits(4)]
    pub iocqes: u8,

    /// Reserved
    _rsvd3: u8,
}

/// Controller Status Register
#[bitfield(u32)]
//#[derive(Default)]
pub struct CtrlCstsReg {
    /// Controller ready
    pub rdy: bool,

    /// Controller fatal status
    pub cfs: bool,

    /// Reserved
    #[bits(2)]
    _rsvd1: u8,

    /// Manticore subsystem reset occurred
    pub mssro: bool,

    /// Processing paused
    pub pp: bool,

    /// Reserved
    #[bits(26)]
    _rsvd2: u32,
}

/// Controller Admin Queue Attribute Register
#[bitfield(u32)]
//#[derive(Default)]
pub struct CtrlAqaReg {
    /// Admin submission queue size
    #[bits(12)]
    pub asqs: u16,

    /// Reserved
    #[bits(4)]
    _rsvd1: u8,

    /// Admin completion queue size
    #[bits(12)]
    pub acqs: u16,

    /// Reserved
    #[bits(4)]
    _rsvd2: u8,
}

/// Admin Submission Queue Base Address Register
#[bitfield(u64)]
//#[derive(Default)]
pub struct CtrlAsqReg {
    /// Reserved
    #[bits(12)]
    _rsvd1: u16,

    /// Admin submission queue base
    #[bits(52)]
    pub asqb: u64,
}

/// Admin Completion Queue Base Address Register
#[bitfield(u64)]
//#[derive(Default)]
pub struct CtrlAcqReg {
    /// Reserved
    #[bits(12)]
    _rsvd1: u16,

    /// Admin completion queue base
    #[bits(52)]
    pub acqb: u64,
}
