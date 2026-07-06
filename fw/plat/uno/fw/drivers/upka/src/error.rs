// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! PKA driver error definitions.

use azihsm_fw_uno_error::make_component_error;
use azihsm_fw_uno_error::ComponentId;
use azihsm_fw_uno_error::HsmError;

/// PKA driver errors.
#[derive(Debug)]
pub struct UpkaError;

impl UpkaError {
    /// All waiter queue slots are occupied.
    pub const QUEUE_FULL: HsmError = make_component_error(ComponentId::UPKA, 1);

    /// The PKA engine reported a command decode failure.
    pub const CMD_ERROR: HsmError = make_component_error(ComponentId::UPKA, 2);

    /// The PKA engine reported an AXI bus failure.
    pub const BUS_ERROR: HsmError = make_component_error(ComponentId::UPKA, 3);

    /// The PKA engine reported an internal fault.
    pub const FAULT_ERROR: HsmError = make_component_error(ComponentId::UPKA, 4);

    /// Unsupported ECC curve selector.
    pub const INVALID_CURVE: HsmError = make_component_error(ComponentId::UPKA, 5);

    /// Unsupported RSA key size or modulus length.
    pub const INVALID_KEY_SIZE: HsmError = make_component_error(ComponentId::UPKA, 6);

    /// Engine wipe failed during release.
    pub const WIPE_FAILED: HsmError = make_component_error(ComponentId::UPKA, 7);
}
