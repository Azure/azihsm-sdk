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

/// Little-endian, alignment-1 integer aliases for TBOR POD fields.
///
/// Wire-facing structs that are borrowed zero-copy from the data
/// section (e.g. typed-slice elements like
/// [`evidence::CertDescriptor`]) must be `Unaligned` so the cast is
/// sound at any byte offset.  Use these [`zerocopy`] little-endian types
/// instead of the native `u16`/`u32`/`u64` (which carry alignment 2/4/8)
/// to keep such structs alignment-1 and fixed little-endian on the wire.
pub mod tbor_int {
    /// 8-bit field. A single byte has no endianness and is already
    /// alignment-1, so this aliases the native `u8` for naming
    /// consistency with the multi-byte little-endian wire types.
    pub use core::primitive::u8 as U8;

    pub use zerocopy::little_endian::U16;
    pub use zerocopy::little_endian::U32;
    pub use zerocopy::little_endian::U64;
}

pub mod api_rev;
pub mod evidence;
pub mod key_props;
pub mod part_final;
pub mod part_info;
pub mod part_init;
pub mod policy;
pub mod psk_change;
pub mod sd_sealing_key_gen;
pub mod session_close;
pub mod session_open_finish;
pub mod session_open_init;

pub use api_rev::*;
pub use evidence::*;
pub use key_props::*;
pub use part_final::*;
pub use part_info::*;
pub use part_init::*;
pub use policy::*;
pub use psk_change::*;
pub use sd_sealing_key_gen::*;
pub use session_close::*;
pub use session_open_finish::*;
pub use session_open_init::*;
