// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `ConcatKdfDerive` command.
//!
//! `ConcatKdfDerive` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that derives key material from a caller-held **masked**
//! ECDH shared secret (from [`EcdhDerive`](crate::TborEcdhDeriveReq)) via a
//! single-step "concatenation" KDF — ANSI X9.63 or NIST SP 800-56A r3
//! one-step — and returns the derived key as a **masked** blob under the
//! requested scope's masking key.
//!
//! `scope`, `hash_algo`, `kdf_alg`, and `key_type` are raw 1-byte
//! discriminants (the firmware types them as `KeyScope` / `HashAlgo` /
//! `ConcatKdfAlg` / `KdfKeyType` open-enums; this host crate is firewalled
//! from the firmware PAL types).  The `KDF_KEY_TYPE_*` discriminants are
//! shared with [`HkdfDerive`](crate::TborHkdfDeriveReq).

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `ConcatKdfDerive`.
pub const TBOR_OP_CONCAT_KDF_DERIVE: u8 = 0x1D;

/// Maximum info (`SharedInfo` / `OtherInfo`) length (bytes).
pub const CONCAT_INFO_MAX_LEN: usize = 256;
/// Minimum masked ECDH-secret IKM envelope length (P-256).
pub const CONCAT_MASKED_SECRET_MIN_LEN: usize = 8 + 12 + 96 + 32 + 16;
/// Maximum masked ECDH-secret IKM envelope length (P-521).
pub const CONCAT_MASKED_SECRET_MAX_LEN: usize = 8 + 12 + 96 + 66 + 16;
/// Maximum masked derived-key envelope length (128-byte var HMAC key).
pub const CONCAT_MASKED_KEY_MAX_LEN: usize = 8 + 12 + 96 + 128 + 16;

/// `ConcatKdfAlg` discriminant for the ANSI X9.63 single-step KDF.
pub const CONCAT_KDF_ALG_X963: u8 = 1;
/// `ConcatKdfAlg` discriminant for the NIST SP 800-56A one-step KDF.
pub const CONCAT_KDF_ALG_SP800_56A: u8 = 2;

/// Host-facing TBOR `ConcatKdfDerive` request.
#[tbor(opcode = TBOR_OP_CONCAT_KDF_DERIVE, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborConcatKdfDeriveReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope (masks the derived key), 1-byte `KeyScope`.
    pub scope: u8,

    /// KDF hash, 1-byte `HashAlgo`.
    pub hash_algo: u8,

    /// Single-step KDF variant, 1-byte `ConcatKdfAlg` (see
    /// `CONCAT_KDF_ALG_*`).
    pub kdf_alg: u8,

    /// Derived-key type, 1-byte `KdfKeyType` (see `KDF_KEY_TYPE_*`).
    pub key_type: u8,

    /// Output length in bytes for the variable-length HMAC types; `0`
    /// means absent (required for `VarHmac*`, ignored otherwise).
    pub key_length: u8,

    /// The masked ECDH shared secret IKM (from `EcdhDerive`).
    #[tbor(min_len = 164, max_len = 198)]
    pub masked_secret: Vec<u8>,

    /// Optional `SharedInfo` / `OtherInfo`; an **empty** buffer means none.
    #[tbor(max_len = 256)]
    pub info: Vec<u8>,
}

/// Host-facing TBOR `ConcatKdfDerive` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborConcatKdfDeriveResp {
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
        let req = TborConcatKdfDeriveReq {
            session_id: 7,
            scope: 0b011,
            hash_algo: 2,
            kdf_alg: CONCAT_KDF_ALG_SP800_56A,
            key_type: 12,
            key_length: 0,
            masked_secret: alloc::vec![0x11u8; CONCAT_MASKED_SECRET_MIN_LEN],
            info: alloc::vec![0x22u8; 16],
        };
        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.contains(&CONCAT_KDF_ALG_SP800_56A),
            "encoded frame must carry the kdf-alg discriminant",
        );
    }
}
