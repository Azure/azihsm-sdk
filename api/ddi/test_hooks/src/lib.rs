// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side definitions for the DDI test-hook commands.
//!
//! These wire types mirror the requests served by the platform test-hook
//! handlers below the PAL (`fw/plat/uno/fw/pal/src/test_hooks`). A build
//! of the firmware without `mcr_test_hooks` answers every test-hook
//! opcode with `UnsupportedCmd`, so tests that drive these commands
//! degrade to a graceful skip rather than a failure.

#![cfg_attr(not(any(feature = "fuzzing", feature = "helpers")), no_std)]

mod test_ops;

#[cfg(feature = "helpers")]
mod helpers;

use azihsm_ddi_mbor_codec::*;
use azihsm_ddi_mbor_derive::Ddi;
use azihsm_ddi_mbor_types::*;
#[cfg(feature = "helpers")]
pub use helpers::*;
use open_enum::open_enum;
pub use test_ops::*;
