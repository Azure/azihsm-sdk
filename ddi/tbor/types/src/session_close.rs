// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SessionClose` command.

use crate::tbor;

/// TBOR opcode for `SessionClose`.
pub const TBOR_OP_SESSION_CLOSE: u8 = 0x05;

/// Host-facing TBOR `SessionClose` request.
#[tbor(opcode = TBOR_OP_SESSION_CLOSE, session_ctrl = close)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborSessionCloseReq {
    /// Session identifier to tear down.
    #[tbor(session_id)]
    pub session_id: u16,
}

/// Host-facing TBOR `SessionClose` response (empty ack).
#[tbor(response)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborSessionCloseResp;
