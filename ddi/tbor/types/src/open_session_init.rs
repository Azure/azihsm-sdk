// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `OpenSessionInit` command.

use crate::tbor;

/// TBOR opcode for `OpenSessionInit`.
pub const TBOR_OP_OPEN_SESSION_INIT: u8 = 0x10;

/// Length of the VM's per-handshake ephemeral public key
/// (HPKE `Npk` for the P-384 KEM: SEC1 uncompressed `0x04 ‖ X ‖ Y`
/// per RFC 9180 §7.1.1, big-endian coordinates).
pub const PK_INIT_LEN: usize = 97;

/// Length of the HSM's HPKE response ephemeral.
pub const PK_RESP_LEN: usize = 97;

/// Length of the Phase-1 confirmation MAC (HMAC-SHA-384).
pub const MAC_RESP_LEN: usize = 48;

/// Wire identifier for the only `SessionSuite` currently implemented
/// — HPKE `DHKEM(P-384, HKDF-SHA-384) + HKDF-SHA-384 + AES-256-GCM`.
///
/// Mirrors the FW-side `SessionSuite::P384HkdfSha384AesGcm256`
/// discriminant.
pub const SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256: u8 = 0x01;

/// HPKE `info` string for the session-establishment handshake.
///
/// Mirror of `azihsm_fw_hsm_pal_traits::SESSION_HPKE_INFO`.  Mixed
/// into the HPKE key schedule on both sides; ensures the derived
/// `exported` value is domain-separated from any other HPKE usage.
pub const SESSION_HPKE_INFO: &[u8] = b"azihsm-session-v2";

/// HPKE exporter context for the session-establishment handshake.
///
/// Mirror of `azihsm_fw_hsm_pal_traits::SESSION_HPKE_EXPORTER_CONTEXT`.
pub const SESSION_HPKE_EXPORTER_CONTEXT: &[u8] = b"session-exporter";

/// HMAC label binding the Phase-1 (server-auth) confirm signature.
///
/// Mirror of `azihsm_fw_hsm_pal_traits::SESSION_PHASE1_LABEL`.
pub const SESSION_PHASE1_LABEL: &[u8] = b"phase1-confirm";

/// Channel-level integrity profile for a TBOR session.
///
/// Host-side mirror of `azihsm_fw_hsm_pal_traits::SessionType` —
/// kept here as an independent definition so the host crate does not
/// have to pull in the firmware PAL traits.  The on-wire `u8`
/// encoding matches the FW enum so both sides populate the same SQE
/// field with the same byte values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionType {
    /// Channel transports MBOR bodies without per-message MAC.
    PlainText = 0,

    /// Channel transports MBOR bodies wrapped in an outer per-message
    /// HMAC envelope.
    Authenticated = 1,
}

impl SessionType {
    /// Wire-encode this `SessionType` to its `u8` discriminant.
    #[inline]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// `true` for [`Authenticated`](Self::Authenticated).
    #[inline]
    pub const fn is_authenticated(self) -> bool {
        matches!(self, Self::Authenticated)
    }
}

/// Host-facing TBOR `OpenSessionInit` request.
///
/// Always starts a fresh HPKE handshake.  The 32-byte session seed
/// is now generated client-side in
/// [`TborOpenSessionFinishReq`](crate::TborOpenSessionFinishReq) and
/// shipped AEAD-encrypted in Phase 2.  Resume is handled by the MBOR
/// `ReopenSession` command, not by this opcode.
#[tbor(opcode = TBOR_OP_OPEN_SESSION_INIT, session_ctrl = open)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TborOpenSessionInitReq {
    /// PSK identifier asserting the caller role.
    pub psk_id: u8,

    /// Channel-level integrity profile (0 = PlainText, 1 = Authenticated).
    ///
    /// CO (`psk_id = 0`) must use `Authenticated (1)`; CU (`psk_id = 1`)
    /// must use `PlainText (0)`.  Any other pairing is rejected by
    /// the HSM with `InvalidSessionType`.
    pub session_type: u8,

    /// Cryptographic suite identifier.  See `SessionSuite` in the PAL
    /// traits crate for the registered values.  Today only `0x01`
    /// (`P384HkdfSha384AesGcm256`) is accepted; any other value is
    /// rejected by the HSM with `UnsupportedSessionSuite`.
    pub suite_id: u8,

    /// Per-handshake ephemeral public key supplied by the VM.  The
    /// encoding and length are dictated by `suite_id`; for `0x01`
    /// this is the HPKE `Npk` SEC1 uncompressed `0x04 ‖ X ‖ Y` for
    /// the P-384 KEM (97 B).
    pub pk_init: [u8; PK_INIT_LEN],
}

impl Default for TborOpenSessionInitReq {
    fn default() -> Self {
        // Default to a valid CO/Authenticated pairing: CO sessions
        // (psk_id=0) must use the Authenticated session type
        // (session_type=1) per the role/type compatibility matrix.
        Self {
            psk_id: 0,
            session_type: 1,
            suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
            pk_init: [0u8; PK_INIT_LEN],
        }
    }
}

/// Host-facing TBOR `OpenSessionInit` response.
#[tbor(response)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TborOpenSessionInitResp {
    /// Reserved session identifier.
    #[tbor(session_id)]
    pub session_id: u16,
    /// HSM's HPKE response ephemeral.
    pub pk_resp: [u8; PK_RESP_LEN],
    /// Phase-1 confirmation MAC.
    pub mac_resp: [u8; MAC_RESP_LEN],
}
