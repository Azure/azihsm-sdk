// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `ApiRev` wire schema.
//!
//! `ApiRev` is the bootstrap TBOR command. The host sends an empty
//! request; the firmware responds with the inclusive range of TBOR
//! wire-protocol versions it supports. The host then picks a compatible
//! version for subsequent commands.
//!
//! All firmware versions are required to be able to decode a v1 request
//! and encode a v1 response — `ApiRev` is the well-known bootstrap,
//! and the host has no way to negotiate before sending it.
//!
//! The request body is empty: the derive emits a synthetic `none` TOC
//! placeholder to satisfy the codec's `toc_count >= 1` requirement.

use azihsm_fw_ddi_tbor_api::tbor;

use crate::tbor_int::U8;

/// TBOR opcode for `ApiRev`.
pub const TBOR_OP_API_REV: u8 = 0x01;

/// `ApiRev` request schema.
///
/// The body carries no semantic data. On the wire the derive emits a
/// single `none` TOC placeholder to satisfy the TBOR codec's
/// `toc_count >= 1` requirement; the decoder verifies that placeholder
/// is present and the opcode matches.
#[tbor(opcode = 0x01)]
pub struct TborApiRevReq;

/// `ApiRev` response schema.
///
/// Advertises the inclusive range of TBOR wire-protocol versions the
/// firmware supports.
#[tbor(response)]
pub struct TborApiRevResp {
    /// Lowest TBOR wire-protocol version the firmware speaks.
    pub min_ver: U8,

    /// Highest TBOR wire-protocol version the firmware speaks.
    pub max_ver: U8,
}
