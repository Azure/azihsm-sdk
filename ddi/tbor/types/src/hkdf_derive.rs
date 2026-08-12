// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `HkdfDerive` command.
//!
//! `HkdfDerive` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that derives key material from a caller-held **masked**
//! ECDH shared secret (from [`EcdhDerive`](crate::TborEcdhDeriveReq)) via
//! HKDF (RFC 5869), and returns the derived key as a **masked** blob under
//! the requested scope's masking key.
//!
//! `scope`, `hash_algo`, and `key_type` are raw 1-byte discriminants (the
//! firmware types them as `KeyScope` / `HashAlgo` / `KdfKeyType`
//! open-enums; this host crate is firewalled from the firmware PAL types).

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `HkdfDerive`.
pub const TBOR_OP_HKDF_DERIVE: u8 = 0x1C;

/// Maximum HKDF salt length (bytes).
pub const HKDF_SALT_MAX_LEN: usize = 256;
/// Maximum HKDF info length (bytes).
pub const HKDF_INFO_MAX_LEN: usize = 256;
/// Minimum masked ECDH-secret IKM envelope length (P-256).
pub const HKDF_MASKED_SECRET_MIN_LEN: usize = 8 + 12 + 96 + 32 + 16;
/// Maximum masked ECDH-secret IKM envelope length (P-521).
pub const HKDF_MASKED_SECRET_MAX_LEN: usize = 8 + 12 + 96 + 66 + 16;
/// Maximum masked derived-key envelope length (128-byte var HMAC key).
pub const HKDF_MASKED_KEY_MAX_LEN: usize = 8 + 12 + 96 + 128 + 16;

/// `KdfKeyType` discriminant for an AES-128 (16-byte) derived key.
pub const KDF_KEY_TYPE_AES128: u8 = 10;
/// `KdfKeyType` discriminant for an AES-192 (24-byte) derived key.
pub const KDF_KEY_TYPE_AES192: u8 = 11;
/// `KdfKeyType` discriminant for an AES-256 (32-byte) derived key.
pub const KDF_KEY_TYPE_AES256: u8 = 12;
/// `KdfKeyType` discriminant for a fixed HMAC-SHA-256 (32-byte) key.
pub const KDF_KEY_TYPE_HMAC_SHA256: u8 = 25;
/// `KdfKeyType` discriminant for a fixed HMAC-SHA-384 (48-byte) key.
pub const KDF_KEY_TYPE_HMAC_SHA384: u8 = 26;
/// `KdfKeyType` discriminant for a fixed HMAC-SHA-512 (64-byte) key.
pub const KDF_KEY_TYPE_HMAC_SHA512: u8 = 27;
/// `KdfKeyType` discriminant for a variable-length HMAC-SHA-256 key.
pub const KDF_KEY_TYPE_VAR_HMAC256: u8 = 30;
/// `KdfKeyType` discriminant for a variable-length HMAC-SHA-384 key.
pub const KDF_KEY_TYPE_VAR_HMAC384: u8 = 31;
/// `KdfKeyType` discriminant for a variable-length HMAC-SHA-512 key.
pub const KDF_KEY_TYPE_VAR_HMAC512: u8 = 32;

/// Host-facing TBOR `HkdfDerive` request.
#[tbor(opcode = TBOR_OP_HKDF_DERIVE, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborHkdfDeriveReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope (masks the derived key), 1-byte `KeyScope`.
    pub scope: u8,

    /// HKDF hash / HMAC PRF, 1-byte `HashAlgo`.
    pub hash_algo: u8,

    /// Derived-key type, 1-byte `KdfKeyType` (see `KDF_KEY_TYPE_*`).
    pub key_type: u8,

    /// Output length in bytes for the variable-length HMAC types; `0`
    /// means absent (required for `VarHmac*`, ignored otherwise).
    pub key_length: u8,

    /// The masked ECDH shared secret IKM (from `EcdhDerive`).
    #[tbor(min_len = 164, max_len = 198)]
    pub masked_secret: Vec<u8>,

    /// Optional HKDF-Extract salt; an **empty** buffer selects the RFC
    /// 5869 default (all-zero) salt.
    #[tbor(max_len = 256)]
    pub salt: Vec<u8>,

    /// Optional HKDF-Expand context/application info; an **empty** buffer
    /// means none.
    #[tbor(max_len = 256)]
    pub info: Vec<u8>,
}

/// Host-facing TBOR `HkdfDerive` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborHkdfDeriveResp {
    /// The derived key, masked (AEAD-GCM-256) under the scope's masking
    /// key.
    #[tbor(max_len = 260)]
    pub masked_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_fields() {
        let req = TborHkdfDeriveReq {
            session_id: 7,
            scope: 0b011,
            hash_algo: 2,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret: alloc::vec![0x11u8; HKDF_MASKED_SECRET_MIN_LEN],
            salt: alloc::vec![0x22u8; 16],
            info: alloc::vec![0x33u8; 8],
        };
        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.contains(&KDF_KEY_TYPE_AES256),
            "encoded frame must carry the key-type discriminant",
        );
    }
}
