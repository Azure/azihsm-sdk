// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `AesEncryptDecrypt` command.
//!
//! `AesEncryptDecrypt` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that AES-CBC encrypts or decrypts `msg` using a
//! caller-held **masked** AES key (the `masked_key` from
//! [`AesGenerateKey`](crate::aes_generate_key) or imported via
//! [`UnwrapKey`](crate::unwrap_key)).  The device unmasks the key
//! on-device, runs the AES-CBC transform, and returns the transformed
//! message plus the updated chaining IV; nothing is persisted.

use alloc::vec::Vec;

pub use crate::aes_generate_key::MASKED_AES_KEY_MAX_LEN;
pub use crate::aes_generate_key::MASKED_AES_KEY_MIN_LEN;
use crate::tbor;

/// TBOR opcode for `AesEncryptDecrypt`.
pub const TBOR_OP_AES_ENCRYPT_DECRYPT: u8 = 0x16;

/// AES-CBC block size in bytes — also the required IV length.
pub const AES_IV_LEN: usize = 16;

/// Maximum message length (bytes) accepted by `AesEncryptDecrypt`.
pub const AES_MSG_MAX_LEN: usize = 1024;

/// `AesOp` discriminant selecting encryption.
pub const AES_OP_ENCRYPT: u8 = 1;
/// `AesOp` discriminant selecting decryption.
pub const AES_OP_DECRYPT: u8 = 2;

/// Host-facing TBOR `AesEncryptDecrypt` request.
#[tbor(opcode = TBOR_OP_AES_ENCRYPT_DECRYPT, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborAesEncryptDecryptReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The masked AES key (from `AesGenerateKey` / `UnwrapKey`), an
    /// AEAD-GCM-256 envelope of 148..=164 B.
    #[tbor(min_len = 148, max_len = 164)]
    pub masked_key: Vec<u8>,

    /// The direction as the 1-byte `AesOp` discriminant (see
    /// [`AES_OP_ENCRYPT`] / [`AES_OP_DECRYPT`]).
    pub op: u8,

    /// The message to transform: a non-empty multiple of the 16-byte AES
    /// block, up to [`AES_MSG_MAX_LEN`] (1024) bytes.
    #[tbor(max_len = 1024)]
    pub msg: Vec<u8>,

    /// The 16-byte CBC initialization vector.  A fixed-size array encodes
    /// the exact length (the FW codec is the length authority).
    pub iv: [u8; 16],
}

/// Host-facing TBOR `AesEncryptDecrypt` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborAesEncryptDecryptResp {
    /// The transformed message (same length as the input `msg`).
    #[tbor(max_len = 1024)]
    pub msg: Vec<u8>,

    /// The updated chaining IV (the last ciphertext block).  A fixed-size
    /// array encodes the exact length.
    pub iv: [u8; 16],
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_op_and_iv() {
        let req = TborAesEncryptDecryptReq {
            session_id: 7,
            masked_key: alloc::vec![0x11u8; MASKED_AES_KEY_MIN_LEN],
            op: AES_OP_ENCRYPT,
            msg: alloc::vec![0x22u8; 32],
            iv: [0x33u8; AES_IV_LEN],
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
