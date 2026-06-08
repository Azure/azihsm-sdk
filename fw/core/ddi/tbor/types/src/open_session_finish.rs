// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `OpenSessionFinish` wire schema (session-establishment Phase 2).

use azihsm_fw_ddi_tbor_api::tbor;

/// Length of the Phase-2 confirmation MAC (HMAC-SHA-384).
pub const MAC_FIN_LEN: usize = 48;

/// Length of the host-supplied `seed`, encrypted inside
/// `seed_envelope`.
pub const SEED_LEN: usize = 32;

/// Length of the AEAD `seed_envelope` on the wire.
///
/// Layout (see [`azihsm_fw_core_crypto_aead_envelope`]):
/// `"AEAD"(4) ‖ alg=AesGcm256(1) ‖ rsv=0(1) ‖ aad_len_be=0(2) ‖
///  IV(12) ‖ seed(32) ‖ TAG(16)` = 68 B.  No AAD: `param_key` is
/// HPKE-derived per session, so the envelope is structurally bound
/// to the active session by key uniqueness.
pub const SEED_ENVELOPE_LEN: usize = 8 + 12 + SEED_LEN + 16;

/// Upper bound on the `bmk_session` envelope length on the wire.
///
/// Today's tight layout (AEAD-GCM with 32-byte AAD wrapping the
/// 80-byte `masking_key`): `8 + 12 + 32 + 80 + 16` = 148 B.  The
/// declared cap is kept generous to accommodate future AAD growth
/// without breaking the schema.
pub const BMK_SESSION_MAX_LEN: usize = 512;

/// `OpenSessionFinish` request schema.
#[tbor(opcode = 0x11)]
pub struct TborOpenSessionFinishReq<'a> {
    /// Pending session identifier the handshake reserved in Phase 1.
    /// 16-bit on the wire (`#[tbor(session_id)]`) for parity with
    /// MBOR.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Phase-2 confirmation MAC.
    #[tbor(len = 48)]
    pub mac_fin: &'a [u8],

    /// AEAD-GCM `seed_envelope` (`SEED_ENVELOPE_LEN` B fixed) wrapping
    /// the 32-byte host seed under the session's `param_key`.  See
    /// [`SEED_ENVELOPE_LEN`] for the exact layout.  The FW recovers
    /// the seed and uses it as the KBKDF context that produces
    /// `BK_SESSION` (the wrap key for the response `bmk_session`).
    ///
    /// Marked `#[tbor(mutable)]` so the FW handler can AEAD-open the
    /// envelope in place — the field is exposed as the
    /// `seed_envelope` member of the generated
    /// `TborOpenSessionFinishReqViewMut` destructured view.
    #[tbor(len = 68, mutable)]
    pub seed_envelope: &'a [u8],
}

/// `OpenSessionFinish` response schema.
///
/// Carries the `bmk_session` blob: an AEAD-GCM envelope of the
/// 80-byte session `masking_key`, wrapped under
/// `BK_SESSION = KBKDF-SHA384(BK_BOOT, "SESSION_BK", seed)`.  The
/// host persists this blob and replays it through the MBOR
/// `ReopenSession` command to recover masked-key compatibility
/// after the device resets or the slot is destroyed.
#[tbor(response)]
pub struct TborOpenSessionFinishResp<'a> {
    /// Wrapped session-key blob.  Variable length up to
    /// [`BMK_SESSION_MAX_LEN`].
    #[tbor(max_len = 512)]
    pub bmk_session: &'a [u8],
}
