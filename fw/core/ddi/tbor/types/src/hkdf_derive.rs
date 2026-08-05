// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `HkdfDerive` wire schema.
//!
//! `HkdfDerive` is an in-session command that derives key material from a
//! caller-held **masked** ECDH shared secret (from
//! [`EcdhDerive`](crate::ecdh_derive)) via HKDF (RFC 5869:
//! Extract-then-Expand), and returns the derived key as a **masked** blob
//! under the requested scope's masking key.  This is the TBOR analogue of
//! MBOR `HkdfDerive`, re-masking the derived key instead of vaulting it.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked by the dispatcher.
//! * `scope` — the [`KeyScope`] whose masking key wraps the derived key.
//! * `hash_algo` — the [`HashAlgo`] selecting the HKDF hash / HMAC PRF.
//! * `key_type` — the [`KdfKeyType`] selecting the derived key's type
//!   (AES / HMAC / variable-length HMAC) and thus its length.
//! * `key_length` — for the variable-length HMAC types, the requested
//!   output length in bytes; `0` means absent (required for `VarHmac*`,
//!   ignored otherwise).
//! * `masked_secret` — the masked ECDH shared secret IKM (unmasked in
//!   place; its kind confirms it is an ECDH secret).
//! * `salt` — optional HKDF-Extract salt; an **empty** buffer selects the
//!   RFC 5869 default (all-zero) salt.
//! * `info` — optional HKDF-Expand context/application info; an **empty**
//!   buffer means none.
//!
//! Outputs:
//!
//! * `masked_key` — the derived key, masked (AEAD-GCM-256) under the
//!   scope's masking key.

use azihsm_fw_ddi_tbor_api::tbor;

use crate::key_props::HashAlgo;
use crate::key_props::KdfKeyType;
use crate::key_props::KeyScope;

/// TBOR opcode for `HkdfDerive`.
pub const TBOR_OP_HKDF_DERIVE: u8 = 0x1C;

/// Maximum HKDF salt length (bytes).  Pinned into the `#[tbor(buffer,
/// max_len = 256)]` literal on [`TborHkdfDeriveReq::salt`].
pub const HKDF_SALT_MAX_LEN: usize = 256;

/// Maximum HKDF info length (bytes).  Pinned into the `#[tbor(buffer,
/// max_len = 256)]` literal on [`TborHkdfDeriveReq::info`].
pub const HKDF_INFO_MAX_LEN: usize = 256;

/// Minimum masked ECDH-secret IKM envelope length (P-256, 32-byte
/// secret): `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(32) ‖ tag(16)`.  Pinned
/// into the `#[tbor(buffer, min_len = 164)]` literal on
/// [`TborHkdfDeriveReq::masked_secret`].
pub const HKDF_MASKED_SECRET_MIN_LEN: usize = 8 + 12 + 96 + 32 + 16;

/// Maximum masked ECDH-secret IKM envelope length (P-521, 66-byte
/// secret).  Pinned into the `#[tbor(buffer, max_len = 198)]` literal on
/// [`TborHkdfDeriveReq::masked_secret`].
pub const HKDF_MASKED_SECRET_MAX_LEN: usize = 8 + 12 + 96 + 66 + 16;

/// Minimum masked derived-key envelope length (AES-128 / 16-byte key):
/// `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(16) ‖ tag(16)`.
pub const HKDF_MASKED_KEY_MIN_LEN: usize = 8 + 12 + 96 + 16 + 16;

/// Maximum masked derived-key envelope length (128-byte variable-length
/// HMAC key).  Pinned into the `#[tbor(buffer, max_len = 260)]` literal on
/// [`TborHkdfDeriveResp::masked_key`].
pub const HKDF_MASKED_KEY_MAX_LEN: usize = 8 + 12 + 96 + 128 + 16;

/// `HkdfDerive` request schema.
///
/// `masked_secret` is `#[tbor(mutable)]` so the handler can `unmask` the
/// IKM **in place** in the request buffer (via `decode_mut`) — no scratch
/// copy — and derive directly from the recovered secret.  `salt` and
/// `info` are optional-by-emptiness: a zero-length buffer selects the RFC
/// 5869 default salt / omits the info, which is cryptographically exact
/// (HMAC pads a shorter-than-block key with zeros).
#[tbor(opcode = 0x1C)]
pub struct TborHkdfDeriveReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (masks the derived key), 1-byte [`KeyScope`].
    #[tbor(U8)]
    pub scope: KeyScope,

    /// HKDF hash / HMAC PRF, 1-byte [`HashAlgo`].
    #[tbor(U8)]
    pub hash_algo: HashAlgo,

    /// Derived-key type, 1-byte [`KdfKeyType`].
    #[tbor(U8)]
    pub key_type: KdfKeyType,

    /// Output length in bytes for the variable-length HMAC types; `0`
    /// means absent (required for `VarHmac*`, ignored otherwise).
    #[tbor(U8)]
    pub key_length: u8,

    /// The masked ECDH shared secret IKM (from `EcdhDerive`), an
    /// AEAD-GCM-256 envelope of 164..=198 B; unmasked in place.
    #[tbor(buffer, min_len = 164, max_len = 198, mutable)]
    pub masked_secret: &'a [u8],

    /// Optional HKDF-Extract salt (≤ 256 B); an **empty** buffer selects
    /// the RFC 5869 default (all-zero) salt.
    #[tbor(buffer, max_len = 256)]
    pub salt: &'a [u8],

    /// Optional HKDF-Expand context/application info (≤ 256 B); an
    /// **empty** buffer means none.
    #[tbor(buffer, max_len = 256)]
    pub info: &'a [u8],
}

/// `HkdfDerive` response schema.
///
/// `masked_key` is `#[tbor(mutable)]` so the handler can reserve the slot
/// and mask the derived key straight into it (`decode_mut`).
#[tbor(response)]
pub struct TborHkdfDeriveResp<'a> {
    /// The derived key, masked (AEAD-GCM-256) under the scope's masking
    /// key.  148..=260 B depending on the derived key length.
    #[tbor(buffer, max_len = 260, mutable)]
    pub masked_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 1024];
        let secret = [0x11u8; HKDF_MASKED_SECRET_MIN_LEN];
        let salt = [0x22u8; 16];
        let info = [0x33u8; 8];
        let frame = TborHkdfDeriveReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .scope(KeyScope::Local)
            .unwrap()
            .hash_algo(HashAlgo::Sha384)
            .unwrap()
            .key_type(KdfKeyType::Aes256)
            .unwrap()
            .key_length(0)
            .unwrap()
            .masked_secret(&secret)
            .unwrap()
            .salt(&salt)
            .unwrap()
            .info(&info)
            .unwrap()
            .finish();
        assert_eq!(frame.scope(), KeyScope::Local);
        assert_eq!(frame.hash_algo(), HashAlgo::Sha384);
        assert_eq!(frame.key_type(), KdfKeyType::Aes256);
        assert_eq!(frame.salt(), &salt[..]);
        assert_eq!(frame.info(), &info[..]);
    }

    #[test]
    fn response_round_trips_masked_key() {
        let mut buf = [0u8; 512];
        let masked = [0x44u8; HKDF_MASKED_KEY_MAX_LEN];
        let frame = TborHkdfDeriveResp::encode(&mut buf, 0, false)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_key(), &masked[..]);
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(164 == HKDF_MASKED_SECRET_MIN_LEN);
        const _: () = assert!(198 == HKDF_MASKED_SECRET_MAX_LEN);
        const _: () = assert!(260 == HKDF_MASKED_KEY_MAX_LEN);
        assert_eq!(HKDF_SALT_MAX_LEN, 256);
        assert_eq!(HKDF_INFO_MAX_LEN, 256);
        assert_eq!(HKDF_MASKED_KEY_MIN_LEN, 148);
    }
}
