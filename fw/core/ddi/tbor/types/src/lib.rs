// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI request/response schema types with TBOR-encoded wire format.
//!
//! Each module defines the on-the-wire schema for a single DDI command,
//! using the `#[tbor]` derive macro. The generated `decode` / `encode`
//! entry points are consumed both by the firmware command handlers
//! (`fw/core/lib/src/ddi/tbor/`) and — via re-export through
//! `azihsm_ddi_tbor_types` — by the host driver. Sharing the schema
//! between both sides means changes to wire layout propagate
//! automatically and the derive's validation is exercised by both ends.

#![no_std]

pub use azihsm_fw_ddi_tbor_api::*;

pub mod change_psk;
pub mod close_session;
pub mod get_api_rev;
pub mod open_session_finish;
pub mod open_session_init;
pub mod part_info;
pub mod part_init;
pub mod policy;

pub use change_psk::*;
pub use close_session::*;
pub use get_api_rev::*;
pub use open_session_finish::*;
pub use open_session_init::*;
pub use part_info::*;
pub use part_init::*;
pub use policy::*;
