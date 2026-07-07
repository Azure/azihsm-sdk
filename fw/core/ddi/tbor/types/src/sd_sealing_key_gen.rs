// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdSealingKeyGen` wire schema.
//!
//! `SdSealingKeyGen` is an in-session command that generates a new
//! security-domain sealing key in the partition's vault and returns its
//! [`KeyId`](azihsm_fw_ddi_tbor_api::KeyId) handle.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher (parity with the other
//!   in-session commands).
//! * `scope` — the requested key [`KeyScope`] (lifecycle / visibility
//!   domain), carried as its 1-byte [`open_enum`](open_enum::open_enum)
//!   discriminant.  Mirrors the firmware
//!   [`HsmKeyScope`](azihsm_fw_hsm_pal_traits::HsmKeyScope).
//!
//! Output:
//!
//! * `key_handle` — the new key's vault id
//!   ([`HsmKeyId`](azihsm_fw_hsm_pal_traits::HsmKeyId) value), carried
//!   as a [`KeyId`](azihsm_fw_ddi_tbor_api::KeyId) (TOC entry type 1).

use azihsm_fw_ddi_tbor_api::tbor;

use crate::key_props::KeyScope;

/// TBOR opcode for `SdSealingKeyGen`.
pub const TBOR_OP_SD_SEALING_KEY_GEN: u8 = 0x09;

/// `SdSealingKeyGen` request schema.
///
/// Generates a security-domain sealing key under the active session's
/// partition with the caller-supplied [`KeyScope`].
#[tbor(opcode = 0x09)]
pub struct TborSdSealingKeyGenReq {
    /// CO/CU session id this request is bound to.  The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (lifecycle / visibility domain). Carried as
    /// the 1-byte [`KeyScope`] discriminant.
    #[tbor(U8)]
    pub scope: KeyScope,
}

/// `SdSealingKeyGen` response schema.
#[tbor(response)]
pub struct TborSdSealingKeyGenResp {
    /// Vault id (`HsmKeyId`) of the newly generated sealing key. Carried
    /// as a [`KeyId`](azihsm_fw_ddi_tbor_api::KeyId) (inline 16-bit, TOC
    /// entry type 1).
    #[tbor(key_id)]
    pub key_handle: KeyId,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::KeyId;
    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_scope() {
        let mut buf = [0u8; 256];
        let frame = TborSdSealingKeyGenReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(9))
            .unwrap()
            .scope(KeyScope::SecurityDomain)
            .unwrap()
            .finish();

        // The wire carries the 1-byte scope discriminant.
        assert_eq!(frame.scope(), KeyScope::SecurityDomain);
    }

    #[test]
    fn response_round_trips_key_handle() {
        let mut buf = [0u8; 256];
        let frame = TborSdSealingKeyGenResp::encode(&mut buf, 0, true)
            .unwrap()
            .key_handle(KeyId(0x1234))
            .unwrap()
            .finish();
        assert_eq!(frame.key_handle(), KeyId(0x1234));
    }
}
