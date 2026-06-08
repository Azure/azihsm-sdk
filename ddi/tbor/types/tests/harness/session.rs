// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR session-establishment helpers.
//!
//! [`open_session`] runs the full happy-path two-phase handshake
//! (`OpenSessionInit` + `OpenSessionFinish`) against a [`DdiDev`] and
//! returns a [`SessionHandshake`] carrier whose fields are everything
//! a per-command test needs to drive subsequent in-session commands
//! (param_key for the AEAD-GCM envelope, session_id, session_type,
//! bmk_session for later resume tests).
//!
//! The lower-level [`open_session_init`] and [`open_session_finish`]
//! helpers are also exposed so negative-path tests can intercept the
//! handshake — e.g., tamper with `mac_fin` to drive the Phase-2 MAC
//! mismatch arm in the FW.

pub mod change_psk;
pub mod close_session;
mod crypto;
pub mod finish;
pub mod init;
pub mod part_init;

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::SessionType;
pub use change_psk::change_psk;
pub use change_psk::encrypt_psk_envelope;
pub use close_session::close_session;
pub use finish::build_mac_fin;
pub use finish::open_session_finish;
pub use finish::open_session_finish_with_mac;
pub use finish::SessionHandshake;
pub use init::open_session_init;
pub use init::open_session_init_with_options;
pub use init::OpenSessionInitOptions;
pub use init::PendingHandshake;
pub use part_init::build_part_init_mach_seed_aad;
pub use part_init::encrypt_mach_seed_envelope;
pub use part_init::part_init;

/// One-shot helper: run both phases of the session handshake against
/// `dev`. Equivalent to `open_session_init(...)? → open_session_finish(...)`.
pub fn open_session(
    dev: &<AzihsmDdi as Ddi>::Dev,
    psk_id: u8,
    session_type: SessionType,
) -> Result<SessionHandshake, DdiError> {
    let pending = open_session_init(dev, psk_id, session_type)?;
    open_session_finish(dev, pending)
}
