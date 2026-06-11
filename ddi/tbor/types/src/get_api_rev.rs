// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `GetApiRev` command.
//!
//! Both the request and response wire schemas live in
//! `azihsm_fw_ddi_tbor_types::get_api_rev` (shared with the firmware
//! handler in `fw/core/lib/src/ddi/tbor/get_api_rev.rs`). This module
//! adds the host-facing value types so [`exec_op_tbor`] returns owned
//! response values rather than borrowing `View<'a>` accessors over the
//! driver's IO scratch buffer.
//!
//! [`exec_op_tbor`]: ../../azihsm_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use crate::tbor;

/// TBOR opcode for `GetApiRev`.
pub const TBOR_OP_GET_API_REV: u8 = 0x01;

/// Host-facing TBOR `GetApiRev` request. Carries no per-call data.
#[tbor(opcode = TBOR_OP_GET_API_REV, session_ctrl = no_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborGetApiRevReq;

impl TborGetApiRevReq {
    /// Construct a `GetApiRev` request.
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

/// Host-facing TBOR `GetApiRev` response.
///
/// Reports the inclusive range of TBOR wire-protocol versions the
/// firmware understands.
#[tbor(response)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborGetApiRevResp {
    /// Lowest TBOR wire-protocol version the firmware speaks.
    pub min_protocol_version: u8,

    /// Highest TBOR wire-protocol version the firmware speaks.
    pub max_protocol_version: u8,
}
