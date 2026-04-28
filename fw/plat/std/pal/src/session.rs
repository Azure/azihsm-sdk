// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stub [`HsmSessionManager`] implementation for the standard PAL.
//!
//! All methods return [`HsmError::InternalError`] or a safe default —
//! session management is not yet wired into the standard PAL.

use super::*;

impl HsmSessionManager for StdHsmPal {
    fn session_limit_reached(&self, _pid: HsmPartId) -> bool {
        true
    }

    fn session_create(&self, _pid: HsmPartId, _id: Option<HsmSessId>) -> HsmResult<HsmSessId> {
        Err(HsmError::InternalError)
    }

    fn session_delete(&self, _pid: HsmPartId, _id: HsmSessId) -> HsmResult<()> {
        Err(HsmError::InternalError)
    }

    fn session_state(&self, _pid: HsmPartId, _id: HsmSessId) -> HsmSessionState {
        HsmSessionState::Invalid
    }
}
