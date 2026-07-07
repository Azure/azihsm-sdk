// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-command compliance test modules. Each file is gated on the
//! backend feature(s) that can satisfy it (e.g., TBOR commands require
//! `emu` for a real round-trip).

pub mod api_rev;
pub mod default_psk_gate;
pub mod forward_compat;
pub mod fw_error_decode;
pub mod open_session;
pub mod part_info;
pub mod part_init;
pub mod psk_change;
pub mod session_close;
pub mod unexpected_toc_type;
