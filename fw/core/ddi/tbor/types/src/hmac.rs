// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `Hmac` wire schema.
//!
//! `Hmac` is an in-session command that computes an HMAC tag over a
//! host-supplied message using a caller-held **masked** HMAC key (the
//! `masked_key` returned by [`HmacGenerateKey`](crate::hmac_generate_key)
//! or imported via unwrap).  The device unmasks the key on-device,
//! computes the MAC, and returns the tag — nothing is persisted.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher.
//! * `masked_key` — the masked HMAC key (an AEAD-GCM-256 envelope,
//!   [`MASKED_HMAC_KEY_MIN_LEN`]..=[`MASKED_HMAC_KEY_MAX_LEN`] B).  Its
//!   scope (read from the cleartext, tag-bound metadata) selects the
//!   masking key; the key kind selects the SHA variant / tag length.
//! * `msg` — the message to MAC, up to [`HMAC_MSG_MAX_LEN`] bytes.
//!
//! Outputs:
//!
//! * `tag` — the HMAC tag: 32 / 48 / 64 B for SHA-256 / 384 / 512.

use azihsm_fw_ddi_tbor_api::tbor;

pub use crate::hmac_generate_key::MASKED_HMAC_KEY_MAX_LEN;
pub use crate::hmac_generate_key::MASKED_HMAC_KEY_MIN_LEN;

/// TBOR opcode for `Hmac`.
pub const TBOR_OP_HMAC: u8 = 0x12;

/// Maximum message length (bytes) accepted by `Hmac`, matching the MBOR
/// `Hmac` command's message bound (`DdiHmacReq::msg`), which is itself
/// sized to the AES-CBC single-shot message cap (`MAX_MSG_SIZE`) so the
/// two symmetric primitives share one host-visible limit.  Pinned into
/// the `#[tbor(buffer, max_len = 1024)]` literal on [`TborHmacReq::msg`].
pub const HMAC_MSG_MAX_LEN: usize = 1024;

/// Maximum HMAC tag length (bytes): the SHA-512 digest.  Pinned into the
/// `#[tbor(buffer, max_len = 64)]` literal on [`TborHmacResp::tag`].
pub const HMAC_TAG_MAX_LEN: usize = 64;

/// `Hmac` request schema.
///
/// Computes an HMAC tag over `msg` using the masked HMAC key.
#[tbor(opcode = 0x12)]
pub struct TborHmacReq<'a> {
    /// CO/CU session id this request is bound to.  The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The masked HMAC key (from `HmacGenerateKey` / unwrap), an
    /// AEAD-GCM-256 envelope of 164..=260 B.  Unmasked on-device to
    /// recover the key, its kind (SHA variant), and its `sign` attribute.
    ///
    /// Marked `#[tbor(mutable)]` so the handler can `unmask` it **in place**
    /// in the request buffer (via `decode_mut`) — no scratch copy of the
    /// blob, and the recovered key is used straight from `target_key`.
    #[tbor(buffer, min_len = 164, max_len = 260, mutable)]
    pub masked_key: &'a [u8],

    /// The message to MAC, up to [`HMAC_MSG_MAX_LEN`] (1024) bytes.
    #[tbor(buffer, max_len = 1024)]
    pub msg: &'a [u8],
}

/// `Hmac` response schema.
#[tbor(response)]
pub struct TborHmacResp<'a> {
    /// The HMAC tag over `msg`: 32 / 48 / 64 B for SHA-256 / 384 / 512.
    #[tbor(buffer, max_len = 64)]
    pub tag: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_masked_key_and_msg() {
        let mut buf = [0u8; 1536];
        let masked = [0x11u8; MASKED_HMAC_KEY_MIN_LEN];
        let msg = [0x22u8; 300];
        let frame = TborHmacReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .msg(&msg)
            .unwrap()
            .finish();

        assert_eq!(frame.masked_key(), &masked[..]);
        assert_eq!(frame.msg(), &msg[..]);
    }

    #[test]
    fn response_round_trips_tag() {
        let mut buf = [0u8; 256];
        let tag = [0x33u8; HMAC_TAG_MAX_LEN];
        let frame = TborHmacResp::encode(&mut buf, 0, true)
            .unwrap()
            .tag(&tag)
            .unwrap()
            .finish();
        assert_eq!(frame.tag(), &tag[..]);
    }

    #[test]
    fn lengths_match_pinned_values() {
        // The `#[tbor(buffer, ... = N)]` attributes must remain numeric
        // literals; pin them against the exported consts.
        const _: () = assert!(1024 == HMAC_MSG_MAX_LEN);
        const _: () = assert!(64 == HMAC_TAG_MAX_LEN);
        const _: () = assert!(164 == MASKED_HMAC_KEY_MIN_LEN);
        const _: () = assert!(260 == MASKED_HMAC_KEY_MAX_LEN);
        assert_eq!(HMAC_MSG_MAX_LEN, 1024);
        assert_eq!(HMAC_TAG_MAX_LEN, 64);
    }
}
