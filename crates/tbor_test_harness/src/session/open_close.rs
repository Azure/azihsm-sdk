// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Session lifecycle helpers — combined open + close.
//!
//! [`session_open`] runs the full happy-path two-phase handshake
//! (`SessionOpenInit` + `SessionOpenFinish`) against a [`DdiDev`] and
//! returns a [`SessionHandshake`] carrier whose fields are everything
//! a per-command test needs to drive subsequent in-session commands
//! (param_key for the AEAD-GCM envelope, session_id, session_type,
//! bmk_session for later resume tests).
//!
//! [`session_close`] is the matching teardown: a thin wrapper around
//! [`TborSessionCloseReq`] that closes the session identified by
//! `session_id`. The FW response is an empty ack ([`TborSessionCloseResp`]);
//! callers only care whether it succeeded.
//!
//! The lower-level [`session_open_init`] and [`session_open_finish`]
//! primitives live in their own modules ([`super::init`], [`super::finish`])
//! so negative-path tests can intercept the handshake — e.g., tamper with
//! `mac_fin` to drive the Phase-2 MAC mismatch arm in the FW.

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborSessionCloseReq;
use azihsm_ddi_tbor_types::TborSessionCloseResp;

use super::finish::session_open_finish;
use super::finish::SessionHandshake;
use super::init::session_open_init;

/// One-shot helper: run both phases of the session handshake against
/// `dev`. Equivalent to `session_open_init(...)? → session_open_finish(...)`.
pub fn session_open(
    dev: &<AzihsmDdi as Ddi>::Dev,
    psk_id: u8,
    session_type: SessionType,
) -> Result<SessionHandshake, DdiError> {
    let pending = session_open_init(dev, psk_id, session_type)?;
    session_open_finish(dev, pending)
}

/// Issue `SessionClose(session_id)` and return on success.
pub fn session_close(
    dev: &<AzihsmDdi as Ddi>::Dev,
    session_id: u16,
) -> Result<(), DdiError> {
    let req = TborSessionCloseReq { session_id };
    let mut cookie = None;
    let _resp: TborSessionCloseResp = dev.exec_op_tbor(&req, None, &mut cookie)?;
    Ok(())
}
