// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `Hash` command.
//!
//! `Hash` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that computes a SHA-256 / 384 / 512 digest of a
//! host-supplied message and returns it.  It carries no key and touches no
//! partition state — a pure hashing utility.
//!
//! `algo` is a raw 1-byte discriminant (the firmware types it as the
//! `HashAlgo` open-enum; this host crate is firewalled from the firmware
//! PAL types).

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `Hash`.
pub const TBOR_OP_HASH: u8 = 0x1B;

/// Maximum message length (bytes) accepted by `Hash`.
pub const HASH_MSG_MAX_LEN: usize = 2048;
/// Maximum digest length (bytes) — the SHA-512 digest.
pub const HASH_DIGEST_MAX_LEN: usize = 64;

/// `HashAlgo` discriminant for SHA-256 (32-byte digest).
pub const HASH_ALGO_SHA256: u8 = 1;
/// `HashAlgo` discriminant for SHA-384 (48-byte digest).
pub const HASH_ALGO_SHA384: u8 = 2;
/// `HashAlgo` discriminant for SHA-512 (64-byte digest).
pub const HASH_ALGO_SHA512: u8 = 3;

/// Host-facing TBOR `Hash` request.
#[tbor(opcode = TBOR_OP_HASH, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborHashReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Digest algorithm, 1-byte `HashAlgo` (see `HASH_ALGO_*`).
    pub algo: u8,

    /// The message to hash, up to `HASH_MSG_MAX_LEN` bytes.
    #[tbor(max_len = 2048)]
    pub msg: Vec<u8>,
}

/// Host-facing TBOR `Hash` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborHashResp {
    /// The natural (big-endian) digest, exactly the algorithm's length
    /// (32 / 48 / 64 B for SHA-256 / 384 / 512).
    #[tbor(max_len = 64)]
    pub digest: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_fields() {
        let req = TborHashReq {
            session_id: 9,
            algo: HASH_ALGO_SHA384,
            msg: alloc::vec![0x61u8; 64],
        };
        let mut buf = [0u8; 512];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.contains(&HASH_ALGO_SHA384),
            "encoded frame must carry the sha-mode discriminant",
        );
    }
}
