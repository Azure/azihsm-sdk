// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `GetUnwrappingKey` wire schema.
//!
//! `GetUnwrappingKey` is an in-session command that returns the
//! partition's RSA-2048 **unwrapping** public key, which the host uses to
//! RSA-AES key-wrap a payload for [`UnwrapKey`](crate::hmac).  The
//! unwrapping key is a device-provisioned partition-internal key; only its
//! public half is returned (the private half never leaves the device and
//! is resolved internally by `UnwrapKey`), so — unlike the other
//! key-producing commands — there is no masked blob.
//!
//! RSA key generation is expensive, so the key is materialised lazily; an
//! absent key surfaces as `PendingKeyGeneration` so the host retries.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher.
//!
//! Outputs:
//!
//! * `pub_key` — the RSA-2048 unwrapping public key in HSM wire format:
//!   `n_le(256) ‖ e_le(4)` = [`UNWRAPPING_PUB_KEY_LEN`] (260) bytes.

use azihsm_fw_ddi_tbor_api::tbor;

/// TBOR opcode for `GetUnwrappingKey`.
pub const TBOR_OP_GET_UNWRAPPING_KEY: u8 = 0x13;

/// Wire length of the RSA-2048 unwrapping public key in HSM format:
/// `n_le(256) ‖ e_le(4)`.  Pinned into the `#[tbor(buffer, len = 260)]`
/// literal on [`TborGetUnwrappingKeyResp::pub_key`].
pub const UNWRAPPING_PUB_KEY_LEN: usize = 256 + 4;

/// `GetUnwrappingKey` request schema.
#[tbor(opcode = 0x13)]
pub struct TborGetUnwrappingKeyReq {
    /// CO/CU session id this request is bound to.  The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,
}

/// `GetUnwrappingKey` response schema.
#[tbor(response)]
pub struct TborGetUnwrappingKeyResp<'a> {
    /// The RSA-2048 unwrapping public key in HSM wire format
    /// (`n_le(256) ‖ e_le(4)`), exactly [`UNWRAPPING_PUB_KEY_LEN`] (260)
    /// bytes.
    #[tbor(buffer, len = 260)]
    pub pub_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_session_id() {
        let mut buf = [0u8; 128];
        let frame = TborGetUnwrappingKeyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(11))
            .unwrap()
            .finish();
        assert_eq!(u16::from(frame.session_id()), 11);
    }

    #[test]
    fn response_round_trips_pub_key() {
        let mut buf = [0u8; 512];
        let pub_key = [0xA5u8; UNWRAPPING_PUB_KEY_LEN];
        let frame = TborGetUnwrappingKeyResp::encode(&mut buf, 0, true)
            .unwrap()
            .pub_key(&pub_key)
            .unwrap()
            .finish();
        assert_eq!(frame.pub_key(), &pub_key[..]);
    }

    #[test]
    fn pub_key_len_matches_pinned_value() {
        const _: () = assert!(260 == UNWRAPPING_PUB_KEY_LEN);
        assert_eq!(UNWRAPPING_PUB_KEY_LEN, 260);
    }
}
