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

pub use finish::build_mac_fin;
pub use finish::session_open_finish;
pub use finish::session_open_finish_with_mac;
pub use finish::SessionHandshake;
pub use init::session_open_init;
pub use init::session_open_init_with_options;
pub use init::PendingHandshake;
pub use init::SessionOpenInitOptions;
pub use open_close::session_close;
pub use open_close::session_open;
pub use part_final::part_final;
pub use part_init::build_part_init_mach_seed_aad;
pub use part_init::encrypt_mach_seed_envelope;
pub use part_init::part_init;
pub use psk_change::encrypt_psk_envelope;
pub use psk_change::psk_change;
