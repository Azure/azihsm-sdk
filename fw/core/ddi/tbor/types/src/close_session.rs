// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `CloseSession` wire schema.
//!
//! Sent inside the established session's AEAD framing — payload is
//! just the target slot index.  Authentication is implicit via the
//! framing layer (anyone able to wrap a valid frame already holds
//! `session_enc_key`).

use azihsm_fw_ddi_tbor_api::tbor;

/// `CloseSession` request schema.
#[tbor(opcode = 0x12)]
pub struct TborCloseSessionReq {
    /// Session identifier to tear down.  16-bit on the wire
    /// (`#[tbor(session_id)]`) for parity with MBOR.
    #[tbor(session_id)]
    pub session_id: u16,
}

/// `CloseSession` response schema.
///
/// No semantic payload — the wire derive emits a `none` TOC entry to
/// satisfy the `toc_count >= 1` codec requirement.
#[tbor(response)]
pub struct TborCloseSessionResp;
