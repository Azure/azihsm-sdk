// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side definitions for the DDI test-hook commands.
//!
//! These wire types mirror the requests served by the platform test-hook
//! handlers below the PAL (`fw/plat/uno/fw/pal/src/test_hooks`). Firmware
//! feature selection is owned independently by the Uno firmware.
//!
//! The refactored host package and Uno firmware use `TestAction` opcode 2004
//! for every hook. `GetPrivKey`, `RawKeyImport`, and `GetRng` are actions 25,
//! 26, and 27; legacy standalone opcodes 2005, 2008, and 2007 are not supported.
//!
//! Shared TestAction definitions are under `common`: `test_action_types` owns
//! action selectors and action-specific payload schemas, while `test_ops`
//! owns all DDI request, response, and command-envelope wire structures.
//! The outer modules contain semantic conversion and execution helpers only.

mod common;
mod get_priv_key;
mod get_rng;
mod raw_key_import;
mod test_action;

pub use common::*;
pub use get_priv_key::*;
pub use get_rng::*;
pub use raw_key_import::*;
pub use test_action::*;
