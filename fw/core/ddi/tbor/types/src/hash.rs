// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `Hash` wire schema.
//!
//! `Hash` is an in-session command that computes a cryptographic hash
//! (SHA-256 / 384 / 512) of a host-supplied message and returns the
//! digest.  It carries no key and touches no partition state — it is a
//! pure hashing utility, the TBOR analogue of MBOR `ShaDigest`.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked by the dispatcher.
//! * `algo` — the [`HashAlgo`] selecting the digest algorithm.
//! * `msg` — the message to hash, up to [`HASH_MSG_MAX_LEN`] bytes.
//!
//! Outputs:
//!
//! * `digest` — the natural (big-endian) digest, exactly the algorithm's
//!   length (32 / 48 / 64 B for SHA-256 / 384 / 512).

use azihsm_fw_ddi_tbor_api::tbor;

use crate::key_props::HashAlgo;

/// TBOR opcode for `Hash`.
pub const TBOR_OP_HASH: u8 = 0x1B;

/// Maximum message length (bytes) accepted by `Hash`.  Pinned into
/// the `#[tbor(buffer, max_len = 2048)]` literal on
/// [`TborHashReq::msg`].
pub const HASH_MSG_MAX_LEN: usize = 2048;

/// Maximum digest length (bytes) — the SHA-512 digest.  Pinned into the
/// `#[tbor(buffer, max_len = 64)]` literal on
/// [`TborHashResp::digest`].
pub const HASH_DIGEST_MAX_LEN: usize = 64;

/// `Hash` request schema.
#[tbor(opcode = 0x1B)]
pub struct TborHashReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Digest algorithm, 1-byte [`HashAlgo`].
    #[tbor(U8)]
    pub algo: HashAlgo,

    /// The message to hash, up to [`HASH_MSG_MAX_LEN`] bytes.
    #[tbor(buffer, max_len = 2048)]
    pub msg: &'a [u8],
}

/// `Hash` response schema.
///
/// `digest` is `#[tbor(mutable)]` so the handler can reserve the slot and
/// have the PAL write the digest straight into it (`decode_mut`) — no
/// scratch buffer, no copy.
#[tbor(response)]
pub struct TborHashResp<'a> {
    /// The natural (big-endian) digest, exactly the algorithm's length
    /// (32 / 48 / 64 B for SHA-256 / 384 / 512).
    #[tbor(buffer, max_len = 64, mutable)]
    pub digest: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 512];
        let msg = [0x61u8; 64];
        let frame = TborHashReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(9))
            .unwrap()
            .algo(HashAlgo::Sha384)
            .unwrap()
            .msg(&msg)
            .unwrap()
            .finish();
        assert_eq!(frame.algo(), HashAlgo::Sha384);
        assert_eq!(frame.msg(), &msg[..]);
    }

    #[test]
    fn response_round_trips_digest() {
        let mut buf = [0u8; 256];
        let digest = [0x5Au8; HASH_DIGEST_MAX_LEN];
        let frame = TborHashResp::encode(&mut buf, 0, false)
            .unwrap()
            .digest(&digest)
            .unwrap()
            .finish();
        assert_eq!(frame.digest(), &digest[..]);
    }

    #[test]
    fn lengths_match_pinned_values() {
        assert_eq!(HASH_MSG_MAX_LEN, 2048);
        assert_eq!(HASH_DIGEST_MAX_LEN, 64);
    }
}
