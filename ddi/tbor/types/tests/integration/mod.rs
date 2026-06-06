// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration test modules. Each per-command file is gated on the
//! backend feature(s) that can satisfy it (e.g., TBOR commands require
//! `emu` for a real round-trip).

pub mod change_psk;
pub mod close_session;
pub mod common;
pub mod default_psk_gate;
pub mod fw_error_decode;
pub mod get_api_rev;
pub mod open_session;
pub mod session_smoke;
