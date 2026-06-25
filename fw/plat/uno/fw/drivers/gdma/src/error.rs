// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GDMA driver error definitions.

use azihsm_fw_uno_error::make_component_error;
use azihsm_fw_uno_error::make_pal_error;
use azihsm_fw_uno_error::ComponentId;
use azihsm_fw_uno_error::HsmError;

/// GDMA driver errors.
///
/// Each constant is an [`HsmError`] with facility=0x08F, component=GDMA.
#[derive(Debug)]
pub struct GdmaError;

impl GdmaError {
    /// All tag slots are in use — too many concurrent DMA requests.
    pub const NO_FREE_TAGS: HsmError = make_component_error(ComponentId::GDMA, 1);

    /// SQ ring is full — hardware has not consumed prior entries.
    pub const SQ_FULL: HsmError = make_component_error(ComponentId::GDMA, 2);

    /// Transfer length is zero.
    pub const ZERO_LENGTH: HsmError = make_component_error(ComponentId::GDMA, 3);

    /// `Host { ctrl_id: 0 }` is invalid — use `Device` for device memory.
    pub const INVALID_HOST_IFC: HsmError = make_component_error(ComponentId::GDMA, 4);

    /// Hardware reported a DMA error. Status byte encoded in lower bits.
    pub const fn dma_error(status: u8) -> HsmError {
        make_pal_error(ComponentId::GDMA.0, 0x100 | status as u16)
    }
}
