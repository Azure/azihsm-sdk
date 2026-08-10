// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR session helpers.
//!
//! The [`open_close`] submodule holds the paired [`session_open`] and
//! [`session_close`] lifecycle helpers. Lower-level [`session_open_init`]
//! and [`session_open_finish`] primitives live in [`init`] and [`finish`]
//! so negative-path tests can intercept the handshake — e.g., tamper with
//! `mac_fin` to drive the Phase-2 MAC mismatch arm in the FW.

mod crypto;
pub mod finish;
pub mod init;
pub mod open_close;
pub mod part_final;
pub mod part_init;
pub mod psk_change;

pub(crate) use finish::build_mac_fin;
pub(crate) use finish::session_open_finish;
pub(crate) use finish::session_open_finish_with_mac;
pub(crate) use finish::SessionHandshake;
pub(crate) use init::session_open_init;
pub(crate) use init::session_open_init_with_options;
pub(crate) use init::PendingHandshake;
pub(crate) use init::SessionOpenInitOptions;
pub(crate) use open_close::session_close;
pub(crate) use open_close::session_open;
pub(crate) use part_final::part_final;
pub(crate) use part_init::build_part_init_mach_seed_aad;
pub(crate) use part_init::encrypt_mach_seed_envelope;
pub(crate) use part_init::part_init;
pub(crate) use psk_change::encrypt_psk_envelope;
pub(crate) use psk_change::psk_change;
