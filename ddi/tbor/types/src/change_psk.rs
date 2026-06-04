// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `ChangePsk` command.
//!
//! Construction of the inner AEAD-GCM envelope is the caller's
//! responsibility: pass the wire-ready envelope bytes (already wrapped
//! under the active session's `param_key`, with the
//! `"psk-change-v1" ‖ session_id` AAD) in `psk_envelope`.  See the FW
//! schema docs at [`azihsm_fw_ddi_tbor_types::change_psk`] for the
//! AAD layout and the implicit (session-role-driven) target selection.

use alloc::vec::Vec;

pub use azihsm_fw_ddi_tbor_types::build_psk_change_aad;
pub use azihsm_fw_ddi_tbor_types::PSK_CHANGE_AAD_LABEL;
pub use azihsm_fw_ddi_tbor_types::PSK_CHANGE_AAD_LEN;
pub use azihsm_fw_ddi_tbor_types::PSK_CHANGE_ENVELOPE_MAX_LEN;
pub use azihsm_fw_ddi_tbor_types::TBOR_OP_CHANGE_PSK;

use crate::tbor;

/// Host-facing TBOR `ChangePsk` request.
///
/// The target PSK slot is derived HSM-side from the session role
/// (CO session → CO slot, CU session → CU slot); the request does
/// not carry a slot-selection field.
#[tbor]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborChangePskReq {
    /// Logical session id the request is bound to.  Same value must
    /// appear in the AEAD-GCM envelope's AAD; see
    /// [`build_psk_change_aad`].
    #[tbor(session_id)]
    pub session_id: u16,

    /// AEAD-GCM envelope wrapping the 32-byte new PSK under the active
    /// session's `param_key`.
    #[tbor(max_len = 160)]
    pub psk_envelope: Vec<u8>,
}

/// Host-facing TBOR `ChangePsk` response (empty ack).
#[tbor(response)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborChangePskResp;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use azihsm_fw_ddi_tbor_types::TborChangePskReq as ReqSchema;

    use super::*;
    use crate::TborOpReq;

    #[test]
    fn aad_layout_matches_spec() {
        let aad = build_psk_change_aad(0x1234);
        assert_eq!(&aad[..13], PSK_CHANGE_AAD_LABEL);
        assert_eq!(&aad[13..15], &[0x34, 0x12]); // little-endian
        assert_eq!(aad.len(), PSK_CHANGE_AAD_LEN);
    }

    #[test]
    fn encode_decode_round_trip() {
        let req = TborChangePskReq {
            session_id: 0x0042,
            psk_envelope: (0u8..128).collect(),
        };
        let mut buf = [0u8; 256];
        let wire = req.encode_request(&mut buf).expect("encode");
        let view = ReqSchema::decode(wire).expect("schema decode");
        assert_eq!(u16::from(view.session_id()), 0x0042);
        assert_eq!(view.psk_envelope(), req.psk_envelope.as_slice());
    }

    #[test]
    fn opcode_matches_schema() {
        assert_eq!(<TborChangePskReq as TborOpReq>::OPCODE, TBOR_OP_CHANGE_PSK,);
    }
}
