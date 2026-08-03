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

pub mod aes_encrypt_decrypt;
pub mod aes_generate_key;
pub mod api_rev;
pub mod ecc_generate_key;
pub mod ecc_sign;
pub mod ecdh_derive;
pub mod evidence;
pub mod get_unwrapping_key;
pub mod hmac;
pub mod hmac_generate_key;
pub mod key_props;
pub mod key_report;
pub mod part_final;
pub mod part_info;
pub mod part_init;
pub mod policy;
pub mod psk_change;
pub mod rsa_mod_exp;
pub mod sd_create_peer_backup;
pub mod sd_create_remote_backup;
pub mod sd_reseal_remote_backup;
pub mod sd_restore_local_backup;
pub mod sd_restore_peer_backup;
pub mod sd_restore_remote_backup;
pub mod sd_sealing_key_gen;
pub mod session_close;
pub mod session_open_finish;
pub mod session_open_init;
pub mod unwrap_key;

pub use aes_encrypt_decrypt::*;
pub use aes_generate_key::*;
pub use api_rev::*;
pub use ecc_generate_key::*;
pub use ecc_sign::*;
pub use ecdh_derive::*;
pub use evidence::*;
pub use get_unwrapping_key::*;
pub use hmac::*;
pub use hmac_generate_key::*;
pub use key_props::*;
pub use key_report::*;
pub use part_final::*;
pub use part_info::*;
pub use part_init::*;
pub use policy::*;
pub use psk_change::*;
pub use rsa_mod_exp::*;
pub use sd_create_peer_backup::*;
pub use sd_create_remote_backup::*;
pub use sd_reseal_remote_backup::*;
pub use sd_restore_local_backup::*;
pub use sd_restore_peer_backup::*;
pub use sd_restore_remote_backup::*;
pub use sd_sealing_key_gen::*;
pub use session_close::*;
pub use session_open_finish::*;
pub use session_open_init::*;
pub use unwrap_key::*;
