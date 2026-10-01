// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side definitions for the DDI test-hook commands.
//!
//! These wire types mirror the requests served by the platform test-hook
//! handlers below the PAL (`fw/plat/uno/fw/pal/src/test_hooks`). Firmware
//! feature selection is owned independently by the Uno firmware.
//!
//! The refactored host package and Uno firmware use `TestAction` opcode 2004
//! for every hook. `GetPrivKey` and `RawKeyImport` are actions 25 and 26;
//! legacy standalone opcodes 2005 and 2008 are not supported by this package.

mod get_priv_key;
mod raw_key_import;
mod test_action;

pub use get_priv_key::*;
pub use raw_key_import::*;
pub use test_action::*;
