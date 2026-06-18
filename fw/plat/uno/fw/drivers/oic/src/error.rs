// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OIC driver error definitions.

use azihsm_fw_uno_error::make_component_error;
use azihsm_fw_uno_error::make_pal_error;
use azihsm_fw_uno_error::ComponentId;
use azihsm_fw_uno_error::HsmError;

/// OIC driver errors.
///
/// Each constant is an [`HsmError`] with facility=0x08F, component=OIC.
#[derive(Debug)]
pub struct OicError;

impl OicError {
    /// All tag slots are in use — too many concurrent sends.
    pub const NO_FREE_TAGS: HsmError = make_component_error(ComponentId::OIC, 1);

    /// OSQ ring is full — hardware has not consumed prior entries.
    pub const OSQ_FULL: HsmError = make_component_error(ComponentId::OIC, 2);

    /// Hardware reported a DMA error. Status byte encoded in lower bits.
    pub const fn dma_error(status: u8) -> HsmError {
        make_pal_error(ComponentId::OIC.0, 0x100 | status as u16)
    }

    pub const X: HsmError = Self::dma_error(0x42);
}
