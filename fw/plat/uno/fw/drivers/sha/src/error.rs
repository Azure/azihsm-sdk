// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SHA driver error definitions.

use azihsm_fw_uno_error::make_component_error;
use azihsm_fw_uno_error::ComponentId;
use azihsm_fw_uno_error::HsmError;

/// SHA driver errors.
///
/// Each constant is an [`HsmError`] with facility=0x08F, component=SHA.
#[derive(Debug)]
pub struct ShaError;

impl ShaError {
    /// Invalid SHA mode selector.
    pub const INVALID_MODE: HsmError = make_component_error(ComponentId::SHA, 1);

    /// Invalid message length or byte-count configuration.
    pub const INVALID_MSG_LEN: HsmError = make_component_error(ComponentId::SHA, 2);

    /// All waiter queue slots are occupied.
    pub const QUEUE_FULL: HsmError = make_component_error(ComponentId::SHA, 3);

    /// SHA engine reported a command error.
    pub const CMD_ERROR: HsmError = make_component_error(ComponentId::SHA, 4);

    /// SHA engine reported a bus error.
    pub const BUS_ERROR: HsmError = make_component_error(ComponentId::SHA, 5);

    /// SHA engine reported a fault error.
    pub const FAULT_ERROR: HsmError = make_component_error(ComponentId::SHA, 6);
}
