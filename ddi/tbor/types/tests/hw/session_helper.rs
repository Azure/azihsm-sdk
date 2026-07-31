// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Session-establishment helpers for hardware smoke tests.
//!
//! Re-uses the same crypto/plumbing modules that back the emu harness'
//! session helpers by pulling them in via `#[path]` — the files live
//! under `../harness/session/` but the harness module tree itself is
//! `#[cfg]`'d off in the hardware build (see
//! `azihsm_ddi_tbor_tests.rs`), so we can't `use crate::harness::…`
//! from here. Everything below is a thin surface over those shared
//! files plus the one-shot [`open_session`] convenience wrapper.
//!
//! Only compiled in hardware mode (`hw::` is itself gated on the
//! no-backend-feature build).

#[path = "../harness/session/crypto.rs"]
mod crypto;
#[path = "../harness/session/finish.rs"]
pub mod finish;
#[path = "../harness/session/init.rs"]
pub mod init;
#[path = "../harness/session/part_init.rs"]
pub mod part_init;
#[path = "../harness/session/psk_change.rs"]
pub mod psk_change;
#[path = "../harness/session/session_close.rs"]
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

/// One-shot happy-path handshake: `SessionOpenInit` +
/// `SessionOpenFinish`. Mirrors `crate::harness::session::open_session`
/// so hw tests and emu tests read the same at the call site.
pub fn open_session(
    dev: &<AzihsmDdi as Ddi>::Dev,
    psk_id: u8,
    session_type: SessionType,
) -> Result<SessionHandshake, DdiError> {
    let pending = session_open_init(dev, psk_id, session_type)?;
    session_open_finish(dev, pending)
}
