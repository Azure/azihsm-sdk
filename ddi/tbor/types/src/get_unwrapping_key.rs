// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `GetUnwrappingKey` command.
//!
//! `GetUnwrappingKey` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that returns the partition's RSA-2048 **unwrapping**
//! public key, which the host uses to RSA-AES key-wrap a payload for a
//! future `UnwrapKey` import.  The unwrapping key is a device-provisioned
//! partition-internal key; only its public half is returned.
//!
//! RSA key generation is expensive, so the key is materialised lazily; an
//! absent key surfaces as `PendingKeyGeneration` (the host retries).

use crate::tbor;

/// TBOR opcode for `GetUnwrappingKey`.
pub const TBOR_OP_GET_UNWRAPPING_KEY: u8 = 0x13;

/// Wire length of the RSA-2048 unwrapping public key in HSM format:
/// `n_le(256) ‖ e_le(4)`.
pub const UNWRAPPING_PUB_KEY_LEN: usize = 256 + 4;

/// Host-facing TBOR `GetUnwrappingKey` request.
#[tbor(opcode = TBOR_OP_GET_UNWRAPPING_KEY, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborGetUnwrappingKeyReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,
}

/// Host-facing TBOR `GetUnwrappingKey` response.
#[tbor(response)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TborGetUnwrappingKeyResp {
    /// The RSA-2048 unwrapping public key in HSM wire format
    /// (`n_le(256) ‖ e_le(4)`), exactly [`UNWRAPPING_PUB_KEY_LEN`] (260)
    /// bytes.
    pub pub_key: [u8; UNWRAPPING_PUB_KEY_LEN],
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_session_id() {
        let req = TborGetUnwrappingKeyReq { session_id: 11 };
        let mut buf = [0u8; 128];
        let frame = req.encode_request(&mut buf).expect("encode");
        // The session id (11) must appear in the encoded frame.
        assert!(
            frame.contains(&11),
            "encoded frame must carry the session id"
        );
    }
}
