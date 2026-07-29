// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `HmacGenerateKey` command.
//!
//! `HmacGenerateKey` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that generates a fresh random HMAC key of the requested
//! SHA variant and returns it as a **masked** blob.  The key is not stored
//! on-device; the caller holds the masked blob and passes it back to
//! [`Hmac`](crate::hmac) to compute a MAC (unmask-on-use).
//!
//! The request carries the requested key `scope` (lifecycle / visibility
//! domain) and `hash_algo` (SHA variant) as raw 1-byte discriminants — the
//! firmware types them as the `KeyScope` / `HashAlgo` open-enums, but this
//! host crate is firewalled from the firmware PAL types so it carries the
//! same bytes as raw `u8`.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `HmacGenerateKey`.
pub const TBOR_OP_HMAC_GENERATE_KEY: u8 = 0x11;

/// Minimum masked HMAC-key envelope length (SHA-256, 32-byte key): an
/// AEAD-GCM-256 masked-key envelope `header(8) ‖ iv(12) ‖ aad(96) ‖
/// pt(32) ‖ tag(16)`.
pub const MASKED_HMAC_KEY_MIN_LEN: usize = 8 + 12 + 96 + 32 + 16;

/// Maximum masked HMAC-key envelope length (128-byte key): an AEAD-GCM-256
/// masked-key envelope `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(128) ‖ tag(16)`.
pub const MASKED_HMAC_KEY_MAX_LEN: usize = 8 + 12 + 96 + 128 + 16;

/// `HashAlgo` discriminant for HMAC-SHA-256 (mirror of the firmware
/// `HsmHashAlgo` / TBOR `HashAlgo` value).
pub const HMAC_HASH_SHA256: u8 = 1;
/// `HashAlgo` discriminant for HMAC-SHA-384.
pub const HMAC_HASH_SHA384: u8 = 2;
/// `HashAlgo` discriminant for HMAC-SHA-512.
pub const HMAC_HASH_SHA512: u8 = 3;

/// Host-facing TBOR `HmacGenerateKey` request.
#[tbor(opcode = TBOR_OP_HMAC_GENERATE_KEY, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborHmacGenerateKeyReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope as the 1-byte `KeyScope` discriminant.
    pub scope: u8,

    /// Hash algorithm as the 1-byte `HashAlgo` discriminant (see
    /// [`HMAC_HASH_SHA256`] / [`HMAC_HASH_SHA384`] / [`HMAC_HASH_SHA512`]).
    /// Selects the HMAC SHA variant and the valid `key_length` range.
    pub hash_algo: u8,

    /// Requested key length in bytes.  HMAC keys are variable-length; the
    /// value must be in the SHA variant's range (SHA-256: 32–64,
    /// SHA-384: 48–128, SHA-512: 64–128), else the device returns
    /// `InvalidKeyLength`.
    pub key_length: u8,
}

/// Host-facing TBOR `HmacGenerateKey` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborHmacGenerateKeyResp {
    /// The freshly generated HMAC key, masked (AEAD-GCM-256) under the
    /// requested scope's masking key.  `132 + key_length` B (164 … 260 B
    /// for a 32 … 128-byte key); not stored on-device.
    #[tbor(max_len = 260)]
    pub masked_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_scope_and_hash() {
        let req = TborHmacGenerateKeyReq {
            session_id: 5,
            // KeyScope::Session discriminant (0b001).
            scope: 0b001,
            hash_algo: HMAC_HASH_SHA384,
            key_length: 96,
        };

        let mut buf = [0u8; 256];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The 1-byte hash-algo discriminant must appear in the encoded frame.
        assert!(
            frame.contains(&HMAC_HASH_SHA384),
            "encoded frame must carry the hash-algo discriminant",
        );
    }
}
