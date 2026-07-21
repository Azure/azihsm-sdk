// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `UnwrapKey` command.
//!
//! `UnwrapKey` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that RSA-AES-unwraps a host-supplied wrapped key
//! (AES / RSA / ECC / HMAC) with the partition's unwrapping key (see
//! [`GetUnwrappingKey`](crate::get_unwrapping_key)) and returns it as a
//! **masked** blob under the requested scope's masking key — plus the
//! re-derived wire public key for RSA / ECC.
//!
//! The `scope`, `key_class`, and `oaep_hash_algo` are raw 1-byte discriminants
//! (the firmware types them as the `KeyScope` / `KeyClass` / `HashAlgo`
//! open-enums; this host crate is firewalled from the firmware PAL types).

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `UnwrapKey`.
pub const TBOR_OP_UNWRAP_KEY: u8 = 0x14;

/// Max wrapped-blob length (`RSA-OAEP(KEK) ‖ AES-KWP(key)`).
pub const UNWRAP_WRAPPED_BLOB_MAX_LEN: usize = 3072;
/// Max masked recovered-key envelope length.
pub const UNWRAP_MASKED_KEY_MAX_LEN: usize = 3072;
/// Max recovered public-key length.
pub const UNWRAP_PUB_KEY_MAX_LEN: usize = 520;

/// `KeyClass` discriminant for a raw AES key.
pub const KEY_CLASS_AES: u8 = 0;
/// `KeyClass` discriminant for a DER RSA private key (non-CRT).
pub const KEY_CLASS_RSA: u8 = 1;
/// `KeyClass` discriminant for a DER RSA private key (CRT).
pub const KEY_CLASS_RSA_CRT: u8 = 2;
/// `KeyClass` discriminant for a PKCS#8 DER ECC private key.
pub const KEY_CLASS_ECC: u8 = 3;
/// `KeyClass` discriminant for a variable-length HMAC-SHA-256 key.
pub const KEY_CLASS_HMAC_SHA256: u8 = 4;
/// `KeyClass` discriminant for a variable-length HMAC-SHA-384 key.
pub const KEY_CLASS_HMAC_SHA384: u8 = 5;
/// `KeyClass` discriminant for a variable-length HMAC-SHA-512 key.
pub const KEY_CLASS_HMAC_SHA512: u8 = 6;

/// Host-facing TBOR `UnwrapKey` request.
#[tbor(opcode = TBOR_OP_UNWRAP_KEY, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborUnwrapKeyReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope (masks the recovered key), 1-byte `KeyScope`.
    pub scope: u8,

    /// Class of the wrapped key, 1-byte `KeyClass` (see `KEY_CLASS_*`).
    pub key_class: u8,

    /// OAEP hash used to wrap the KEK, 1-byte `HashAlgo`.
    pub oaep_hash_algo: u8,

    /// The RSA-AES-wrapped key (`RSA-OAEP(KEK) ‖ AES-KWP(key)`).
    #[tbor(max_len = 3072)]
    pub wrapped_blob: Vec<u8>,
}

/// Host-facing TBOR `UnwrapKey` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborUnwrapKeyResp {
    /// The recovered key's vault-kind discriminant.
    pub key_kind: u8,

    /// The recovered key, masked under the scope's masking key.
    #[tbor(max_len = 3072)]
    pub masked_key: Vec<u8>,

    /// The recovered key's wire public key for RSA / ECC; empty for
    /// symmetric (AES / HMAC) keys.
    #[tbor(max_len = 520)]
    pub pub_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_fields() {
        let req = TborUnwrapKeyReq {
            session_id: 7,
            scope: 0b011,
            key_class: KEY_CLASS_HMAC_SHA256,
            oaep_hash_algo: 1,
            wrapped_blob: alloc::vec![0x5Au8; 300],
        };
        let mut buf = [0u8; 4096];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.contains(&KEY_CLASS_HMAC_SHA256),
            "encoded frame must carry the key-class discriminant",
        );
    }
}
