// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `FinalizePart` command.
//!
//! `FinalizePart` is the CO-session command that completes partition
//! provisioning begun by [`crate::TborPartInitReq`].  The caller supplies the
//! PTA certificate chain rooted at the POTA the partition was initialized
//! under (and, on re-provisioning, the partition's previous local backup
//! masked key); the device returns the partition-local backup masked key.
//!
//! Host-side mirror of the MBOR `FinalizePart` command.  The opcode and
//! in-session semantics are pinned here pending the firmware TBOR schema.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `FinalizePart`.
pub const TBOR_OP_FINALIZE_PART: u8 = 0x31;

/// Maximum on-the-wire length of the PTA certificate chain.
pub const PTA_CERT_CHAIN_MAX_LEN: usize = 2048;

/// Maximum on-the-wire length of a partition-local backup masked key.
pub const PART_LOCAL_BMK_MAX_LEN: usize = 3072;

/// Host-facing TBOR `FinalizePart` request.
#[tbor(opcode = TBOR_OP_FINALIZE_PART, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborFinalizePartReq {
    /// CO session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// DER PTA certificate chain rooted at the provisioning POTA.
    #[tbor(max_len = 2048)]
    pub pta_cert_chain: Vec<u8>,

    /// Previous partition-local backup masked key, present only when
    /// re-provisioning an already-finalized partition.
    #[tbor(max_len = 3072)]
    pub prev_part_local_bmk: Option<Vec<u8>>,
}

/// Host-facing TBOR `FinalizePart` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborFinalizePartResp {
    /// Partition-local backup masked key produced by finalization.
    #[tbor(max_len = 3072)]
    pub part_local_bmk: Vec<u8>,
}
