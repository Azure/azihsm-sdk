// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR session-establishment helpers.
//!
//! [`open_session`] runs the full happy-path two-phase handshake
//! (`SessionOpenInit` + `SessionOpenFinish`) against a [`DdiDev`] and
//! returns a [`SessionHandshake`] carrier whose fields are everything
//! a per-command test needs to drive subsequent in-session commands
//! (param_key for the AEAD-GCM envelope, session_id, session_type,
//! bmk_session for later resume tests).
//!
//! The lower-level [`session_open_init`] and [`session_open_finish`]
//! helpers are also exposed so negative-path tests can intercept the
//! handshake — e.g., tamper with `mac_fin` to drive the Phase-2 MAC
//! mismatch arm in the FW.

mod crypto;
pub mod finish;
pub mod init;
pub mod part_init;
pub mod psk_change;
pub mod session_close;

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::SessionType;
pub use finish::build_mac_fin;
pub use finish::session_open_finish;
pub use finish::session_open_finish_with_mac;
pub use finish::SessionHandshake;
pub use init::session_open_init;
pub use init::session_open_init_with_options;
pub use init::PendingHandshake;
pub use init::SessionOpenInitOptions;
pub use part_init::build_part_init_mach_seed_aad;
pub use part_init::encrypt_mach_seed_envelope;
pub use part_init::part_init;
pub use psk_change::encrypt_psk_envelope;
pub use psk_change::psk_change;
pub use session_close::session_close;

/// One-shot helper: run both phases of the session handshake against
/// `dev`. Equivalent to `session_open_init(...)? → session_open_finish(...)`.
pub fn open_session(
    dev: &<AzihsmDdi as Ddi>::Dev,
    psk_id: u8,
    session_type: SessionType,
) -> Result<SessionHandshake, DdiError> {
    let pending = session_open_init(dev, psk_id, session_type)?;
    session_open_finish(dev, pending)
}
