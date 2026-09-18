// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side definitions for the DDI test-hook commands.
//!
//! These wire types mirror the requests served by the platform test-hook
//! handlers below the PAL (`fw/plat/uno/fw/pal/src/test_hooks`). Firmware
//! feature selection is owned by the Uno firmware; host helpers are enabled
//! uniformly through this crate's `helpers` feature.

#![cfg_attr(not(any(feature = "fuzzing", feature = "helpers")), no_std)]

mod get_priv_key;
mod raw_key_import;
mod test_action;

pub use get_priv_key::*;
pub use raw_key_import::*;
pub use test_action::*;
