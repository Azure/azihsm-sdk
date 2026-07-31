// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `EccSign` wire schema.
//!
//! `EccSign` is an in-session command that produces a raw ECDSA `r ‖ s`
//! signature over a host-supplied **pre-computed digest** using a
//! caller-held **masked** ECC private key (from
//! [`EccGenerateKey`](crate::ecc_generate_key) or imported via
//! [`UnwrapKey`](crate::unwrap_key)).  The device unmasks the key
//! on-device (recovering its curve from the key kind), signs, and returns
//! the signature.  Firmware does **no** hashing — the caller supplies the
//! digest.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked by the dispatcher.
//! * `masked_key` — the masked ECC private key (unmasked in place).
//! * `digest` — the pre-computed message digest in wire little-endian
//!   order. Its length must be a supported SHA-2 digest length
//!   (32 / 48 / 64 B); the hash algorithm is inferred from that length, so
//!   no separate algorithm selector is carried on the wire.
//!
//! Outputs:
//!
//! * `signature` — raw `r ‖ s`, each component little-endian and padded to
//!   the curve's wire coordinate length (64 / 96 / 136 B for
//!   P-256 / P-384 / P-521).

use azihsm_fw_ddi_tbor_api::tbor;

pub use crate::ecc_generate_key::MASKED_ECC_KEY_MAX_LEN;
pub use crate::ecc_generate_key::MASKED_ECC_KEY_MIN_LEN;

/// TBOR opcode for `EccSign`.
pub const TBOR_OP_ECC_SIGN: u8 = 0x18;

/// Maximum digest length (bytes) accepted by `EccSign` — the SHA-512
/// digest.  Pinned into the `#[tbor(buffer, max_len = 64)]` literal on
/// [`TborEccSignReq::digest`].
pub const ECC_DIGEST_MAX_LEN: usize = 64;

/// Maximum wire ECDSA signature length (`r ‖ s`, P-521 padded).  Pinned
/// into the `#[tbor(buffer, max_len = 136)]` literal on
/// [`TborEccSignResp::signature`].
pub const ECC_SIG_MAX_LEN: usize = 136;

/// `EccSign` request schema.
///
/// `masked_key` is `#[tbor(mutable)]` so the handler can `unmask` it **in
/// place** in the request buffer (via `decode_mut`) — no scratch copy — and
/// sign directly from the recovered key.
#[tbor(opcode = 0x18)]
pub struct TborEccSignReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The masked ECC private key (from `EccGenerateKey` / `UnwrapKey`), an
    /// AEAD-GCM-256 envelope of 164..=200 B.  Its kind recovers the curve.
    #[tbor(buffer, min_len = 164, max_len = 200, mutable)]
    pub masked_key: &'a [u8],

    /// The pre-computed message digest in wire little-endian order. Its
    /// length must be a supported SHA-2 digest length (32 / 48 / 64 B); the
    /// hash algorithm is inferred from that length.
    #[tbor(buffer, max_len = 64)]
    pub digest: &'a [u8],
}

/// `EccSign` response schema.
#[tbor(response)]
pub struct TborEccSignResp<'a> {
    /// Raw ECDSA `r ‖ s`, each component little-endian and padded to the
    /// curve wire coordinate length: 64 / 96 / 136 B for
    /// P-256 / P-384 / P-521.
    #[tbor(buffer, max_len = 136, mutable)]
    pub signature: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 512];
        let masked = [0x11u8; MASKED_ECC_KEY_MIN_LEN];
        let digest = [0x22u8; 32];
        let frame = TborEccSignReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .digest(&digest)
            .unwrap()
            .finish();
        assert_eq!(frame.digest(), &digest[..]);
    }

    #[test]
    fn response_round_trips_signature() {
        let mut buf = [0u8; 256];
        let sig = [0x33u8; ECC_SIG_MAX_LEN];
        let frame = TborEccSignResp::encode(&mut buf, 0, true)
            .unwrap()
            .signature(&sig)
            .unwrap()
            .finish();
        assert_eq!(frame.signature(), &sig[..]);
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(64 == ECC_DIGEST_MAX_LEN);
        const _: () = assert!(136 == ECC_SIG_MAX_LEN);
        assert_eq!(ECC_DIGEST_MAX_LEN, 64);
        assert_eq!(ECC_SIG_MAX_LEN, 136);
    }
}
