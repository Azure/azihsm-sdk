// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `GetPartId` command.
//!
//! `GetPartId` is a CO-session query returning the partition's stable
//! identifier and its DER-encoded partition public key.
//!
//! Host-side mirror of the MBOR `GetPartId` command.  The opcode and
//! in-session semantics are pinned here pending the firmware TBOR schema.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `GetPartId`.
pub const TBOR_OP_GET_PART_ID: u8 = 0x32;

/// Length of the partition identifier (16 B).
pub const PART_ID_LEN: usize = 16;

/// Maximum on-the-wire length of a DER-encoded partition public key.
pub const PART_PUB_KEY_MAX_LEN: usize = 256;

/// Host-facing TBOR `GetPartId` request.
#[tbor(opcode = TBOR_OP_GET_PART_ID, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborGetPartIdReq {
    /// CO session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,
}

/// Host-facing TBOR `GetPartId` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborGetPartIdResp {
    /// Stable partition identifier.
    pub part_id: [u8; PART_ID_LEN],

    /// DER `SubjectPublicKeyInfo` of the partition public key.  The
    /// encoding self-describes the key algorithm.
    #[tbor(max_len = 256)]
    pub part_pub_key: Vec<u8>,
}
