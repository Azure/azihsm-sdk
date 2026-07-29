// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `Hmac` command.
//!
//! `Hmac` is an **in-session** command (Crypto-Officer or Crypto-User)
//! that computes an HMAC tag over `msg` using a caller-held **masked**
//! HMAC key (the `masked_key` returned by
//! [`HmacGenerateKey`](crate::hmac_generate_key) or imported via unwrap).
//! The device unmasks the key on-device, computes the MAC, and returns the
//! tag; nothing is persisted.

use alloc::vec::Vec;

pub use crate::hmac_generate_key::MASKED_HMAC_KEY_MAX_LEN;
pub use crate::hmac_generate_key::MASKED_HMAC_KEY_MIN_LEN;
use crate::tbor;

/// TBOR opcode for `Hmac`.
pub const TBOR_OP_HMAC: u8 = 0x12;

/// Maximum message length (bytes) accepted by `Hmac`.
///
/// `1024`, matching the MBOR `Hmac` command's message bound
/// (`DdiHmacReq::msg`), which is itself sized to the AES-CBC
/// single-shot message cap (`MAX_MSG_SIZE`) so the two symmetric
/// primitives share one host-visible limit.  Larger inputs are hashed
/// host-side or chunked by the caller.
pub const HMAC_MSG_MAX_LEN: usize = 1024;

/// Maximum HMAC tag length (bytes): the SHA-512 digest.
pub const HMAC_TAG_MAX_LEN: usize = 64;

/// Host-facing TBOR `Hmac` request.
#[tbor(opcode = TBOR_OP_HMAC, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborHmacReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The masked HMAC key (from `HmacGenerateKey` / unwrap), an
    /// AEAD-GCM-256 envelope of 164..=260 B.
    #[tbor(min_len = 164, max_len = 260)]
    pub masked_key: Vec<u8>,

    /// The message to MAC, up to [`HMAC_MSG_MAX_LEN`] (1024) bytes.
    #[tbor(max_len = 1024)]
    pub msg: Vec<u8>,
}

/// Host-facing TBOR `Hmac` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborHmacResp {
    /// The HMAC tag over `msg`: 32 / 48 / 64 B for SHA-256 / 384 / 512.
    #[tbor(max_len = 64)]
    pub tag: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_masked_key_and_msg() {
        let req = TborHmacReq {
            session_id: 7,
            masked_key: alloc::vec![0x11u8; MASKED_HMAC_KEY_MIN_LEN],
            msg: alloc::vec![0x22u8; 40],
        };

        let mut buf = [0u8; 1536];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The message bytes must appear in the encoded frame.
        assert!(
            frame.windows(4).any(|w| w == [0x22u8; 4]),
            "encoded frame must carry the message bytes",
        );
    }
}
