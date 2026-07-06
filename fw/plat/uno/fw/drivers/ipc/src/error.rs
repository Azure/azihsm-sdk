// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IPC driver error definitions.

use azihsm_fw_uno_error::make_component_error;
use azihsm_fw_uno_error::ComponentId;
use azihsm_fw_uno_error::HsmError;

/// IPC driver errors.
pub struct IpcError;

impl IpcError {
    /// Pair index out of range.
    pub const INVALID_PAIR: HsmError = make_component_error(ComponentId::IPC, 1);

    /// Wrong pair kind for the requested operation.
    pub const WRONG_PAIR_KIND: HsmError = make_component_error(ComponentId::IPC, 2);

    /// TX ring is full.
    pub const TX_RING_FULL: HsmError = make_component_error(ComponentId::IPC, 3);

    /// No free send slots available.
    pub const NO_FREE_SLOTS: HsmError = make_component_error(ComponentId::IPC, 4);
}
