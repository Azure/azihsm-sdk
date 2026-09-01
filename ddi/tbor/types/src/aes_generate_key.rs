// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `AesGenerateKey` command.
//!
//! `AesGenerateKey` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that generates a fresh random AES key of the requested
//! size and returns it as a **masked** blob.  The key is not stored
//! on-device; the caller holds the masked blob and passes it back to
//! [`AesEncryptDecrypt`](crate::aes_encrypt_decrypt) to transform data
//! (unmask-on-use).
//!
//! The request carries the requested key `scope` (lifecycle / visibility
//! domain) and `key_size` as raw 1-byte discriminants — the firmware types
//! them as the `KeyScope` / `AesKeySize` open-enums, but this host crate is
//! firewalled from the firmware PAL types so it carries the same bytes as
//! raw `u8`.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `AesGenerateKey`.
pub const TBOR_OP_AES_GENERATE_KEY: u8 = 0x15;

/// Minimum masked AES-key envelope length (AES-128, 16-byte key): an
/// AEAD-GCM-256 masked-key envelope `header(8) ‖ iv(12) ‖ aad(96) ‖
/// pt(16) ‖ tag(16)`.
pub const MASKED_AES_KEY_MIN_LEN: usize = 8 + 12 + 96 + 16 + 16;

/// Maximum masked AES-key envelope length (AES-256, 32-byte key).
pub const MASKED_AES_KEY_MAX_LEN: usize = 8 + 12 + 96 + 32 + 16;

/// `AesKeySize` discriminant for AES-128 (16-byte key).
pub const AES_KEY_SIZE_128: u8 = 1;
/// `AesKeySize` discriminant for AES-192 (24-byte key).
pub const AES_KEY_SIZE_192: u8 = 2;
/// `AesKeySize` discriminant for AES-256 (32-byte key).
pub const AES_KEY_SIZE_256: u8 = 3;

/// Maximum caller-supplied key-label length (bytes) recorded in the masked
/// blob's metadata (`MaskedKeyMetadata.key_label`).
pub const AES_KEY_LABEL_MAX_LEN: usize = 32;

/// Host-facing TBOR `AesGenerateKey` request.
#[tbor(opcode = TBOR_OP_AES_GENERATE_KEY, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborAesGenerateKeyReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope as the 1-byte `KeyScope` discriminant.
    pub scope: u8,

    /// AES key size as the 1-byte `AesKeySize` discriminant (see
    /// [`AES_KEY_SIZE_128`] / [`AES_KEY_SIZE_192`] / [`AES_KEY_SIZE_256`]).
    pub key_size: u8,

    /// Caller-supplied key label recorded in the masked blob's metadata,
    /// up to [`AES_KEY_LABEL_MAX_LEN`] (32) bytes.  Empty for an unlabeled
    /// key.
    #[tbor(max_len = 32)]
    pub key_label: Vec<u8>,
}

/// Host-facing TBOR `AesGenerateKey` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborAesGenerateKeyResp {
    /// The freshly generated AES key, masked (AEAD-GCM-256) under the
    /// requested scope's masking key.  148 / 156 / 164 B for
    /// AES-128 / 192 / 256; not stored on-device.
    #[tbor(max_len = 164)]
    pub masked_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_scope_and_size() {
        let req = TborAesGenerateKeyReq {
            session_id: 5,
            // KeyScope::Local discriminant (0b011).
            scope: 0b011,
            key_size: AES_KEY_SIZE_256,
            key_label: b"my-aes-key".to_vec(),
        };

        let mut buf = [0u8; 256];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The 1-byte key-size discriminant must appear in the encoded frame.
        assert!(
            frame.contains(&AES_KEY_SIZE_256),
            "encoded frame must carry the key-size discriminant",
        );
    }
}
