// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `CloseSession` command.

use crate::tbor;

/// TBOR opcode for `CloseSession`.
pub const TBOR_OP_CLOSE_SESSION: u8 = 0x12;

/// Host-facing TBOR `CloseSession` request.
#[tbor(opcode = TBOR_OP_CLOSE_SESSION, session_ctrl = close)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborCloseSessionReq {
    /// Session identifier to tear down.
    #[tbor(session_id)]
    pub session_id: u16,
}

/// Host-facing TBOR `CloseSession` response (empty ack).
#[tbor(response)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborCloseSessionResp;
