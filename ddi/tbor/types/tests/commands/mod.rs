// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-command compliance test modules. Each file is gated on the
//! backend feature(s) that can satisfy it (e.g., TBOR commands require
//! `emu` for a real round-trip).

pub mod api_rev;
pub mod concat_kdf_derive;
pub mod default_psk_gate;
pub mod ecc_generate_key;
pub mod ecc_sign;
pub mod ecdh_derive;
pub mod forward_compat;
pub mod fw_error_decode;
pub mod get_unwrapping_key;
pub mod hkdf_derive;
pub mod hmac;
pub mod hmac_generate_key;
pub mod key_report;
pub mod open_session;
pub mod part_final;
pub mod part_info;
pub mod part_init;
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
pub mod unexpected_toc_type;
pub mod unwrap_key;
