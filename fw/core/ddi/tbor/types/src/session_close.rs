// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SessionClose` wire schema.
//!
//! Sent inside the established session's AEAD framing — payload is
//! just the target slot index.  Authentication is implicit via the
//! framing layer (anyone able to wrap a valid frame already holds
//! `session_enc_key`).

use azihsm_fw_ddi_tbor_api::tbor;

/// `SessionClose` request schema.
#[tbor(opcode = 0x05)]
pub struct TborSessionCloseReq {
    /// Session identifier to tear down.  Typed
    /// [`SessionId`](azihsm_fw_ddi_tbor_api::SessionId); marked
    /// `#[tbor(session_id)]` to select the 16-bit session-id TOC encoding
    /// (parity with MBOR).
    #[tbor(session_id)]
    pub session_id: SessionId,
}

/// `SessionClose` response schema.
///
/// No semantic payload — the wire derive emits a `none` TOC entry to
/// satisfy the `toc_count >= 1` codec requirement.
#[tbor(response)]
pub struct TborSessionCloseResp;
