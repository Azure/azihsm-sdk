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

/// Random number generator failure in std PAL.
pub const RNG_FAILURE: HsmError = HsmError::make_pal(ID, 3);

/// Partition index out of range (pid ≥ [`NUM_PARTITIONS`]).
pub const PART_INVALID_PID: HsmError = HsmError::make_pal(ID, 10);

/// Partition is not in [`Disabled`] state — cannot allocate.
pub const PART_ALREADY_ALLOCATED: HsmError = HsmError::make_pal(ID, 11);

/// Partition is in [`Disabled`] state — cannot free or query identity.
pub const PART_NOT_ALLOCATED: HsmError = HsmError::make_pal(ID, 12);

/// Total resource count across all partitions would exceed the maximum.
pub const PART_RESOURCE_EXHAUSTED: HsmError = HsmError::make_pal(ID, 13);

/// ECC-384 key pair generation failed.
pub const PART_KEY_GEN_FAILURE: HsmError = HsmError::make_pal(ID, 14);
