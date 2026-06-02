// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `GetApiRev` wire schema.
//!
//! `GetApiRev` is the bootstrap TBOR command. The host sends an empty
//! request; the firmware responds with the inclusive range of TBOR
//! wire-protocol versions it supports. The host then picks a compatible
//! version for subsequent commands.
//!
//! All firmware versions are required to be able to decode a v1 request
//! and encode a v1 response — `GetApiRev` is the well-known bootstrap,
//! and the host has no way to negotiate before sending it.
//!
//! The request body is empty: the derive emits a synthetic `none` TOC
//! placeholder to satisfy the codec's `toc_count >= 1` requirement.

use azihsm_fw_ddi_tbor_api::tbor;

/// TBOR opcode for `GetApiRev`.
pub const TBOR_OP_GET_API_REV: u8 = 0x01;

/// `GetApiRev` request schema.
///
/// The body carries no semantic data. On the wire the derive emits a
/// single `none` TOC placeholder to satisfy the TBOR codec's
/// `toc_count >= 1` requirement; the decoder verifies that placeholder
/// is present and the opcode matches.
#[tbor(opcode = 0x01)]
pub struct TborGetApiRevReq;

/// `GetApiRev` response schema.
///
/// Advertises the inclusive range of TBOR wire-protocol versions the
/// firmware supports.
#[tbor(response)]
pub struct TborGetApiRevResp {
    /// Lowest TBOR wire-protocol version the firmware speaks.
    pub min_protocol_version: u8,

    /// Highest TBOR wire-protocol version the firmware speaks.
    pub max_protocol_version: u8,
}
