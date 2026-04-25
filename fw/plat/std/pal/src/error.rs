// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error codes for the std PAL.

#![allow(dead_code)]

use azihsm_fw_hsm_pal_traits::HsmError;

const ID: u16 = 0x100;

/// Submit channel closed — Embassy thread stopped.
pub const CHANNEL_CLOSED: HsmError = HsmError::make_pal(ID, 1);

/// Host DMA copy from host not supported in std PAL.
pub const HOST_COPY_NOT_SUPPORTED: HsmError = HsmError::make_pal(ID, 2);
