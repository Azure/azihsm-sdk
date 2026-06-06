// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `OpenSessionFinish` command
//! (session-establishment Phase 2).

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `OpenSessionFinish`.
pub const TBOR_OP_OPEN_SESSION_FINISH: u8 = 0x11;

/// Length of the Phase-2 confirmation MAC (HMAC-SHA-384).
pub const MAC_FIN_LEN: usize = 48;

/// Length of the host-supplied `seed`, encrypted inside
/// `seed_envelope` and used by the FW as the KBKDF context that
/// produces `BK_SESSION`.
pub const SEED_LEN: usize = 32;

/// Length of the AEAD `seed_envelope` on the wire.
///
/// `"AEAD"(4) ‖ alg=AesGcm256(1) ‖ rsv=0(1) ‖ aad_len_be=0(2) ‖
///  IV(12) ‖ seed(32) ‖ TAG(16)` = 68 B.
pub const SEED_ENVELOPE_LEN: usize = 8 + 12 + SEED_LEN + 16;

/// Host-facing TBOR `OpenSessionFinish` request.
#[tbor]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TborOpenSessionFinishReq {
    /// Pending session identifier reserved in Phase 1.
    #[tbor(session_id)]
    pub session_id: u16,
    /// Phase-2 confirmation MAC (HMAC-SHA-384, 48 B).
    pub mac_fin: [u8; MAC_FIN_LEN],
    /// AEAD `seed_envelope` wrapping the 32-byte session seed under
    /// the session's `param_key`.  See [`SEED_ENVELOPE_LEN`] for the
    /// fixed wire layout.
    pub seed_envelope: [u8; SEED_ENVELOPE_LEN],
}

impl Default for TborOpenSessionFinishReq {
    fn default() -> Self {
        Self {
            session_id: 0,
            mac_fin: [0u8; MAC_FIN_LEN],
            seed_envelope: [0u8; SEED_ENVELOPE_LEN],
        }
    }
}

/// Host-facing TBOR `OpenSessionFinish` response.
///
/// `bmk_session` is owned and right-sized — the host has `alloc`
/// available, so we avoid carrying a fixed-size padding buffer and
/// a separate length field.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborOpenSessionFinishResp {
    /// Wrapped session-key blob (AEAD-GCM envelope of `masking_key`).
    pub bmk_session: Vec<u8>,
}
