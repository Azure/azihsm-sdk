// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `AesEncryptDecrypt` wire schema.
//!
//! `AesEncryptDecrypt` is an in-session command that AES-CBC encrypts or
//! decrypts a host-supplied message using a caller-held **masked** AES key
//! (the `masked_key` from [`AesGenerateKey`](crate::aes_generate_key) or
//! imported via [`UnwrapKey`](crate::unwrap_key)).  The device unmasks the
//! key on-device (verifying the AEAD tag), runs the AES-CBC transform, and
//! returns the transformed message plus the updated chaining IV so the
//! host can chain subsequent CBC blocks — the TBOR analogue of MBOR
//! `AesEncryptDecrypt`, but keyed by a masked blob rather than a vault
//! `key_id`.  Nothing is persisted.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher.
//! * `masked_key` — the masked AES key (an AEAD-GCM-256 envelope,
//!   [`MASKED_AES_KEY_MIN_LEN`]..=[`MASKED_AES_KEY_MAX_LEN`] B).  Its
//!   scope (read from the cleartext, tag-bound metadata) selects the
//!   masking key; the key kind confirms it is an AES key.
//! * `op` — the [`AesOp`] selecting encrypt or decrypt.
//! * `msg` — the message to transform: a non-empty multiple of the 16-byte
//!   AES block, up to [`AES_MSG_MAX_LEN`] bytes.
//! * `iv` — the 16-byte ([`AES_IV_LEN`]) CBC initialization vector.
//!
//! Outputs:
//!
//! * `msg` — the transformed message (same length as the input).
//! * `iv` — the updated chaining IV (the last ciphertext block), for
//!   chaining subsequent CBC calls.

use azihsm_fw_ddi_tbor_api::tbor;
use open_enum::open_enum;

pub use crate::aes_generate_key::MASKED_AES_KEY_MAX_LEN;
pub use crate::aes_generate_key::MASKED_AES_KEY_MIN_LEN;

/// TBOR opcode for `AesEncryptDecrypt`.
pub const TBOR_OP_AES_ENCRYPT_DECRYPT: u8 = 0x16;

/// AES-CBC block size in bytes — also the required IV length.
pub const AES_IV_LEN: usize = 16;

/// Maximum message length (bytes) accepted by `AesEncryptDecrypt`,
/// matching the MBOR `AesEncryptDecrypt` command's message bound.  Pinned
/// into the `#[tbor(buffer, max_len = 1024)]` literals on
/// [`TborAesEncryptDecryptReq::msg`] / [`TborAesEncryptDecryptResp::msg`].
pub const AES_MSG_MAX_LEN: usize = 1024;

/// AES encrypt / decrypt operation selector on the TBOR wire.
///
/// The 1-byte discriminants mirror the MBOR `DdiAesOp` values
/// (`Encrypt = 1`, `Decrypt = 2`).  Kept as an [`open_enum`] so an
/// unrecognized discriminant round-trips as `AesOp(x)` and is rejected
/// on-device rather than failing to decode.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesOp {
    /// Encrypt the message.
    Encrypt = 1,

    /// Decrypt the message.
    Decrypt = 2,
}

/// `AesEncryptDecrypt` request schema.
///
/// AES-CBC encrypts or decrypts `msg` under the masked AES key and `iv`.
#[tbor(opcode = 0x16)]
pub struct TborAesEncryptDecryptReq<'a> {
    /// CO/CU session id this request is bound to.  The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The masked AES key (from `AesGenerateKey` / `UnwrapKey`), an
    /// AEAD-GCM-256 envelope of 148..=164 B.  Unmasked on-device to
    /// recover the key and confirm its AES kind and direction permission.
    ///
    /// Marked `#[tbor(mutable)]` so the handler can `unmask` it **in place**
    /// in the request buffer (via `decode_mut`) — no scratch copy of the
    /// blob, and the recovered key is used straight from `target_key`.
    #[tbor(buffer, min_len = 148, max_len = 164, mutable)]
    pub masked_key: &'a [u8],

    /// The direction, carried as the 1-byte [`AesOp`] discriminant.
    #[tbor(U8)]
    pub op: AesOp,

    /// The message to transform: a non-empty multiple of the 16-byte AES
    /// block, up to [`AES_MSG_MAX_LEN`] (1024) bytes.
    #[tbor(buffer, max_len = 1024)]
    pub msg: &'a [u8],

    /// The 16-byte CBC initialization vector.
    #[tbor(buffer, len = 16)]
    pub iv: &'a [u8],
}

/// `AesEncryptDecrypt` response schema.
///
/// The `msg` / `iv` fields are `#[tbor(mutable)]` so the handler can build
/// the response with the two slots **reserved** (via `msg_reserve` /
/// `iv_reserve`) and then have the AES engine write the ciphertext and
/// chaining IV straight into them (`decode_mut`) — no scratch buffer and
/// no copy of the message.
#[tbor(response)]
pub struct TborAesEncryptDecryptResp<'a> {
    /// The transformed message (same length as the input `msg`).
    #[tbor(buffer, max_len = 1024, mutable)]
    pub msg: &'a [u8],

    /// The updated chaining IV (the last ciphertext block), for chaining
    /// subsequent CBC calls.
    #[tbor(buffer, len = 16, mutable)]
    pub iv: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 1536];
        let masked = [0x11u8; MASKED_AES_KEY_MIN_LEN];
        let msg = [0x22u8; 64];
        let iv = [0x33u8; AES_IV_LEN];
        let frame = TborAesEncryptDecryptReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .op(AesOp::Encrypt)
            .unwrap()
            .msg(&msg)
            .unwrap()
            .iv(&iv)
            .unwrap()
            .finish();

        assert_eq!(frame.op(), AesOp::Encrypt);
        assert_eq!(frame.msg(), &msg[..]);
        assert_eq!(frame.iv(), &iv[..]);
    }

    #[test]
    fn response_round_trips_msg_and_iv() {
        let mut buf = [0u8; 1536];
        let msg = [0x44u8; 48];
        let iv = [0x55u8; AES_IV_LEN];
        let frame = TborAesEncryptDecryptResp::encode(&mut buf, 0, true)
            .unwrap()
            .msg(&msg)
            .unwrap()
            .iv(&iv)
            .unwrap()
            .finish();
        assert_eq!(frame.msg(), &msg[..]);
        assert_eq!(frame.iv(), &iv[..]);
    }

    #[test]
    fn response_reserve_matches_value_layout() {
        // A frame built with the `*_reserve` setters must have the same
        // wire layout (header + TOC + total length) as one built with the
        // value setters; only the data bytes are left for fill-later.
        let mut buf_v = [0u8; 1536];
        let msg = [0x44u8; 48];
        let iv = [0x55u8; AES_IV_LEN];
        let frame_v = TborAesEncryptDecryptResp::encode(&mut buf_v, 0, true)
            .unwrap()
            .msg(&msg)
            .unwrap()
            .iv(&iv)
            .unwrap()
            .finish();
        let len_v = frame_v.as_bytes().len();

        let mut buf_r = [0u8; 1536];
        let frame_r = TborAesEncryptDecryptResp::encode(&mut buf_r, 0, true)
            .unwrap()
            .msg_reserve(48)
            .unwrap()
            .iv_reserve(AES_IV_LEN)
            .unwrap()
            .finish();

        // Identical total length, and the reserved slots report the
        // reserved sizes (their bytes are whatever was in the buffer — the
        // zero-initialized `buf_r` here).
        assert_eq!(frame_r.as_bytes().len(), len_v, "reserve length == value");
        assert_eq!(frame_r.msg().len(), 48);
        assert_eq!(frame_r.iv().len(), AES_IV_LEN);
        assert!(
            frame_r.msg().iter().all(|&b| b == 0),
            "reserved region is left untouched for fill-later",
        );
    }

    #[test]
    fn response_reserve_rejects_oversize() {
        // The reserve setter enforces the same length bound as the value
        // setter: the IV slot is fixed at 16 bytes.
        let mut buf = [0u8; 1536];
        let err = TborAesEncryptDecryptResp::encode(&mut buf, 0, true)
            .unwrap()
            .msg_reserve(48)
            .unwrap()
            .iv_reserve(17);
        assert!(err.is_err(), "IV reserve must reject a non-16-byte length");
    }

    #[test]
    fn lengths_match_pinned_values() {
        // The `#[tbor(buffer, ... = N)]` attributes must remain numeric
        // literals; pin them against the exported consts.
        const _: () = assert!(1024 == AES_MSG_MAX_LEN);
        const _: () = assert!(16 == AES_IV_LEN);
        const _: () = assert!(148 == MASKED_AES_KEY_MIN_LEN);
        const _: () = assert!(164 == MASKED_AES_KEY_MAX_LEN);
        assert_eq!(AES_MSG_MAX_LEN, 1024);
        assert_eq!(AES_IV_LEN, 16);
    }
}
