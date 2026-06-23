// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IIC driver error definitions.

use azihsm_fw_uno_error::make_component_error;
use azihsm_fw_uno_error::ComponentId;
use azihsm_fw_uno_error::HsmError;

/// IIC driver errors.
///
/// Each constant is an [`HsmError`] with facility=0x08F, component=IIC.
#[derive(Debug)]
pub struct IicError;

impl IicError {
    /// ISQ empty — no receive buffers available.
    pub const ISQ_EMPTY: HsmError = make_component_error(ComponentId::IIC, 1);

    /// ICQ full — firmware has not consumed entries.
    pub const ICQ_FULL: HsmError = make_component_error(ComponentId::IIC, 2);
}
