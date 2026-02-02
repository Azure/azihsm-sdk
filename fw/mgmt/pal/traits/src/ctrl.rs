// Copyright (C) Microsoft Corporation. All rights reserved.

//! Controller management types and traits for the Platform Abstraction Layer (PAL).
//!
//! This module provides abstractions for managing hardware controllers, including
//! handling reset events, enable/disable operations, and queue information retrieval.

use bitfield_struct::bitfield;

use super::*;

/// Represents events that can occur on a controller.
///
/// Controller events are used to notify the management layer about
/// state changes in hardware controllers.
pub enum CtrlEvent {
    /// The controller has been enabled.
    Enable {
        /// The identifier of the enabled controller.
        ctrl_id: CtrlId,
    },
    /// The controller has been disabled.
    Disable {
        /// The identifier of the disabled controller.
        ctrl_id: CtrlId,
    },
}

/// Trait for managing hardware controllers.
///
/// Provides methods for polling controller events, enabling/disabling controllers,
/// setting fatal status, and retrieving queue information.
pub trait CtrlMgr {
    /// Polls for the next controller event.
    ///
    /// This is an asynchronous operation that waits for and returns the next
    /// controller event (reset, enable, or disable).
    fn poll_ctrl_event(&self) -> impl Future<Output = CtrlEvent> + Send;

    /// Reads the controller capability register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn read_cap_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlCapReg>;

    /// Writes to the controller capability register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The capability register value to write.
    fn write_cap_reg(&self, ctrl_id: CtrlId, reg: CtrlCapReg) -> PalMgmtResult<()>;

    /// Reads the controller version register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn read_vs_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlVsReg>;

    /// Writes to the controller version register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The version register value to write.
    fn write_vs_reg(&self, ctrl_id: CtrlId, reg: CtrlVsReg) -> PalMgmtResult<()>;

    /// Reads the controller configuration register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn read_cc_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlCcReg>;

    /// Reads the controller status register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn read_csts_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlCstsReg>;

    /// Writes to the controller status register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The status register value to write.
    fn write_csts_reg(&self, ctrl_id: CtrlId, reg: CtrlCstsReg) -> PalMgmtResult<()>;

    /// Reads the controller admin queue attribute register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn read_aqa_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlAqaReg>;

    /// Reads the admin submission queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn read_asq_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlAsqReg>;

    /// Reads the admin completion queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn read_acq_reg(&self, ctrl_id: CtrlId) -> PalMgmtResult<CtrlAcqReg>;
}

azihsm_define_pal_error! {
    CtrlMgr,
    pub CtrlMgrError {
        InvalidCtrlId = 0x0001,
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
