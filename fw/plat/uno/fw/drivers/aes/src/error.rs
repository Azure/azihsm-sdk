// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES driver error definitions.

use azihsm_fw_uno_error::make_component_error;
use azihsm_fw_uno_error::ComponentId;
use azihsm_fw_uno_error::HsmError;

/// AES driver errors.
///
/// Each constant is an [`HsmError`] with facility=0x08F, component=AES.
#[derive(Debug)]
pub struct AesError;

impl AesError {
    /// Invalid AES key length (must be 16, 24, or 32 bytes).
    pub const INVALID_KEY_LEN: HsmError = make_component_error(ComponentId::AES, 1);

    /// Invalid message length (must be non-zero, multiple of 16 bytes).
    pub const INVALID_MSG_LEN: HsmError = make_component_error(ComponentId::AES, 2);

    /// Result buffer smaller than message.
    pub const RESULT_BUF_TOO_SMALL: HsmError = make_component_error(ComponentId::AES, 3);

    /// CBC mode requires an IV of exactly 16 bytes.
    pub const INVALID_IV: HsmError = make_component_error(ComponentId::AES, 4);

    /// AES engine reported a command error.
    pub const CMD_ERROR: HsmError = make_component_error(ComponentId::AES, 5);

    /// AES engine reported a bus error.
    pub const BUS_ERROR: HsmError = make_component_error(ComponentId::AES, 6);

    /// AES engine reported a fault error.
    pub const FAULT_ERROR: HsmError = make_component_error(ComponentId::AES, 7);

    /// All waiter queue slots are occupied.
    pub const QUEUE_FULL: HsmError = make_component_error(ComponentId::AES, 8);
}
