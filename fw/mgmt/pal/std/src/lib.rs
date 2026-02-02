// Copyright (C) Microsoft Corporation. All rights reserved.

//! Standard Platform Abstraction Layer implementation.
//!
//! This crate provides a standard library-based implementation of the PAL traits,
//! suitable for non-embedded environments such as testing, simulation, and development.
//! It uses standard synchronization primitives and Embassy for async timing.

mod ctrl;
mod pcie;

use std::future::*;
use std::task::*;

pub use azihsm_fw_mgmt_pal_traits::*;
use ctrl::*;
use parking_lot::Mutex;
use pcie::*;
use tracing::*;

/// Standard library-based Platform Abstraction Layer implementation.
///
/// This PAL implementation is designed for environments with standard library
/// support, providing thread-safe access to platform components through interior
/// mutability with `parking_lot::Mutex`.
pub struct StdPal {
    /// The mutex-protected inner state containing platform managers.
    inner: Mutex<Inner>,
}

impl Default for StdPal {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
        }
    }
}

impl Pal for StdPal {
    /// Initializes the standard PAL.
    ///
    /// Currently performs no initialization and always succeeds.
    #[instrument(skip(self), ret)]
    fn init(&self) -> PalMgmtResult<()> {
        Ok(())
    }

    /// Runs the main event loop.
    ///
    /// Executes an infinite loop that logs a tick message every second.
    /// This serves as a placeholder for actual event processing logic.
    #[instrument("event_loop", skip(self))]
    async fn run(&self) {
        loop {
            embassy_futures::yield_now().await;
            self.with_pcie_mgr(|mgr| mgr.wake());
            self.with_ctrl_mgr(|mgr| mgr.wake());
            embassy_futures::yield_now().await;
        }
    }

    /// Deinitializes the standard PAL.
    ///
    /// Currently performs no cleanup and always succeeds.
    #[instrument(skip(self), ret)]
    fn deinit(&self) -> PalMgmtResult<()> {
        Ok(())
    }
}

impl StdPal {
    /// Triggers a PERST up event and waits for completion.
    ///
    /// Sets the PERST up signal and blocks until the event has been
    /// fully processed by the PCIe manager.
    pub fn do_perst_up(&self) {
        self.with_pcie_mgr(|mgr| {
            mgr.set_perst_up();
        });

        loop {
            let pending = self.with_pcie_mgr(|mgr| mgr.perst_up_pending());
            if !pending {
                break;
            }
        }
    }

    /// Triggers a PERST down event and waits for completion.
    ///
    /// Sets the PERST down signal and blocks until the event has been
    /// fully processed by the PCIe manager.
    pub fn do_perst_down(&self) {
        self.with_pcie_mgr(|mgr| {
            mgr.set_perst_down();
        });

        loop {
            let pending = self.with_pcie_mgr(|mgr| mgr.perst_down_pending());
            if !pending {
                break;
            }
        }
    }

    /// Triggers a Function Level Reset (FLR) and waits for completion.
    ///
    /// Sets the FLR signal and blocks until the reset has been
    /// fully processed by the PCIe manager.
    pub fn do_flr(&self) {
        self.with_pcie_mgr(|mgr| {
            mgr.set_flr();
        });

        loop {
            let pending = self.with_pcie_mgr(|mgr| mgr.flr_pending());
            if !pending {
                break;
            }
        }
    }

    /// Triggers a Virtual Function Level Reset (VFLR) and waits for completion.
    ///
    /// Sets the VFLR signal for the specified controller and blocks until
    /// the reset has been fully processed by the PCIe manager.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the virtual function's controller to reset.
    pub fn do_vflr(&self, ctrl_id: CtrlId) {
        self.with_pcie_mgr(|mgr| {
            mgr.set_vflr(ctrl_id);
        });

        loop {
            let pending = self.with_pcie_mgr(|mgr| mgr.vflr_pending(ctrl_id));
            if !pending {
                break;
            }
        }
    }

    /// Reads the controller capability register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn ctrl_read_cap_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlCapReg> {
        self.with_ctrl_mgr(|mgr| mgr.read_cap_reg(ctrl_id))
    }

    /// Reads the controller version register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn ctrl_read_vs_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlVsReg> {
        self.with_ctrl_mgr(|mgr| mgr.read_vs_reg(ctrl_id))
    }

    /// Reads the controller configuration register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn ctrl_read_cc_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlCcReg> {
        self.with_ctrl_mgr(|mgr| mgr.read_cc_reg(ctrl_id))
    }

    /// Writes to the controller configuration register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The configuration register value to write.
    pub fn ctrl_write_cc_reg(&self, ctrl_id: CtrlId, reg: CtrlCcReg) -> PalMgmtResult<()> {
        self.with_ctrl_mgr(|mgr| mgr.write_cc_reg(ctrl_id, reg))
    }

    /// Reads the controller status register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn ctrl_read_csts_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlCstsReg> {
        self.with_ctrl_mgr(|mgr| mgr.read_csts_reg(ctrl_id))
    }

    /// Reads the controller admin queue attribute register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn ctrl_read_aqa_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlAqaReg> {
        self.with_ctrl_mgr(|mgr| mgr.read_aqa_reg(ctrl_id))
    }

    /// Writes to the controller admin queue attribute register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The admin queue attribute register value to write.
    pub fn ctrl_write_aqa_reg(&self, ctrl_id: CtrlId, reg: CtrlAqaReg) -> PalMgmtResult<()> {
        self.with_ctrl_mgr(|mgr| mgr.write_aqa_reg(ctrl_id, reg))
    }

    /// Reads the admin submission queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn ctrl_read_asq_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlAsqReg> {
        self.with_ctrl_mgr(|mgr| mgr.read_asq_reg(ctrl_id))
    }

    /// Writes to the admin submission queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The admin submission queue base address register value to write.
    pub fn ctrl_write_asq_reg(&self, ctrl_id: CtrlId, reg: CtrlAsqReg) -> PalMgmtResult<()> {
        self.with_ctrl_mgr(|mgr| mgr.write_asq_reg(ctrl_id, reg))
    }

    /// Reads the admin completion queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn ctrl_read_acq_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlAcqReg> {
        self.with_ctrl_mgr(|mgr| mgr.read_acq_reg(ctrl_id))
    }

    /// Writes to the admin completion queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The admin completion queue base address register value to write.
    pub fn ctrl_write_acq_reg(&self, ctrl_id: CtrlId, reg: CtrlAcqReg) -> PalMgmtResult<()> {
        self.with_ctrl_mgr(|mgr| mgr.write_acq_reg(ctrl_id, reg))
    }

    /// Executes a closure with exclusive access to the inner state.
    ///
    /// # Parameters
    /// - `f`: A closure that receives a mutable reference to the inner state.
    fn with_lock<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Inner) -> R,
    {
        let mut inner = self.inner.lock();
        f(&mut inner)
    }

    /// Executes a closure with exclusive access to the PCIe manager.
    ///
    /// # Parameters
    /// - `f`: A closure that receives a mutable reference to the PCIe manager.
    fn with_pcie_mgr<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut StdPcieMgr) -> R,
    {
        self.with_lock(|inner| f(&mut inner.pcie_mgr))
    }

    /// Executes a closure with exclusive access to the controller manager.
    ///
    /// # Parameters
    /// - `f`: A closure that receives a mutable reference to the controller manager.
    fn with_ctrl_mgr<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut StdCtrlMgr) -> R,
    {
        self.with_lock(|inner| f(&mut inner.ctrl_mgr))
    }
}

/// Internal state container for the standard PAL.
///
/// Holds all platform manager instances that require mutable access.
struct Inner {
    /// The PCIe event manager.
    pcie_mgr: StdPcieMgr,

    /// The controller manager.
    ctrl_mgr: StdCtrlMgr,
}

impl Default for Inner {
    /// Creates a default instance of the inner state.
    fn default() -> Self {
        Self {
            pcie_mgr: StdPcieMgr::new(),
            ctrl_mgr: StdCtrlMgr::new(),
        }
    }
}
