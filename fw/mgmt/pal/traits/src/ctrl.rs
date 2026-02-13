// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Controller management types and traits for the Platform Abstraction Layer (PAL).
//!
//! This module provides abstractions for managing hardware controllers, including
//! handling reset events, enable/disable operations, and queue information retrieval.

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

    /// Retrieves the Admin Submission Queue (SQ) information for the specified controller.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to query.
    ///
    /// # Returns
    /// A result containing the SQ information or an error if the controller ID is invalid.
    fn asq_info(&self, ctrl_id: CtrlId) -> MgmtPalResult<SqInfo>;

    /// Retrieves the Admin Completion Queue (CQ) information for the specified controller.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to query.
    ///
    /// # Returns
    ///
    fn acq_info(&self, ctrl_id: CtrlId) -> MgmtPalResult<CqInfo>;

    /// Enables the specified controller.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to enable.
    ///
    /// # Returns
    /// A result indicating success or failure of the operation.
    fn set_ctrl_enable(&self, ctrl_id: CtrlId) -> MgmtPalResult<()>;

    /// Disables the specified controller.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to disable.
    ///
    /// # Returns
    /// A result indicating success or failure of the operation.
    fn set_ctrl_disable(&self, ctrl_id: CtrlId) -> MgmtPalResult<()>;

    /// Sets the fatal status for the specified controller.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to set the fatal status for.
    fn set_ctrl_fatal_status(&self, ctrl_id: CtrlId);
}

azihsm_define_pal_error! {
    CtrlMgr,
    pub CtrlMgrError {
        InvalidCtrlId = 0x0001,
    }
}
