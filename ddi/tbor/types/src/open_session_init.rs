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
/// Mirrors `azihsm_fw_hsm_pal_traits::SessionSuite::P384HkdfSha384AesGcm256`
/// — kept here as a plain `u8` constant so this host crate does not
/// have to pull in the firmware PAL traits.
pub const SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256: u8 = 0x01;

/// Host-facing TBOR `OpenSessionInit` request.
///
/// Always starts a fresh HPKE handshake.  The 32-byte session seed
/// is now generated client-side in
/// [`TborOpenSessionFinishReq`](crate::TborOpenSessionFinishReq) and
/// shipped AEAD-encrypted in Phase 2.  Resume is handled by the MBOR
/// `ReopenSession` command, not by this opcode.
#[tbor]
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use azihsm_fw_ddi_tbor_types::TborOpenSessionInitReq as ReqSchema;

    use super::*;
    use crate::TborOpReq;

    fn sample_req(psk_id: u8, session_type: u8) -> TborOpenSessionInitReq {
        let mut pk_init = [0u8; PK_INIT_LEN];
        for (i, b) in pk_init.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        TborOpenSessionInitReq {
            psk_id,
            session_type,
            suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
            pk_init,
        }
    }

    #[test]
    fn encode_decode_round_trip_plaintext() {
        let req = sample_req(1, 0);
        let mut buf = [0u8; 512];
        let wire = req.encode_request(&mut buf).expect("encode");
        let view = ReqSchema::decode(wire).expect("schema decode");
        assert_eq!(view.psk_id(), 1);
        assert_eq!(view.session_type(), 0);
        assert_eq!(view.suite_id(), SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256);
        assert_eq!(view.pk_init(), &req.pk_init);
    }

    #[test]
    fn encode_decode_round_trip_authenticated() {
        let req = sample_req(0, 1);
        let mut buf = [0u8; 512];
        let wire = req.encode_request(&mut buf).expect("encode");
        let view = ReqSchema::decode(wire).expect("schema decode");
        assert_eq!(view.psk_id(), 0);
        assert_eq!(view.session_type(), 1);
        assert_eq!(view.suite_id(), SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256);
        assert_eq!(view.pk_init(), &req.pk_init);
    }

    #[test]
    fn default_uses_authenticated_session_type_for_co() {
        let req = TborOpenSessionInitReq::default();
        assert_eq!(req.psk_id, 0);
        assert_eq!(req.session_type, 1);
        assert_eq!(req.suite_id, SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256);
    }

    #[test]
    fn session_type_byte_persists_unknown_values_on_the_wire() {
        let req = sample_req(0, 0xff);
        let mut buf = [0u8; 512];
        let wire = req.encode_request(&mut buf).expect("encode");
        let view = ReqSchema::decode(wire).expect("schema decode");
        assert_eq!(view.session_type(), 0xff);
    }

    #[test]
    fn suite_id_byte_persists_unknown_values_on_the_wire() {
        let mut req = sample_req(0, 1);
        req.suite_id = 0xab;
        let mut buf = [0u8; 512];
        let wire = req.encode_request(&mut buf).expect("encode");
        let view = ReqSchema::decode(wire).expect("schema decode");
        assert_eq!(view.suite_id(), 0xab);
    }
}
