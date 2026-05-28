// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side TBOR codec — re-exports the firmware TBOR primitives
//! ([`azihsm_fw_ddi_tbor`]) so that host code can speak the same wire
//! format as the firmware without duplicating the codec implementation.

#![no_std]

pub use azihsm_fw_ddi_tbor::*;
