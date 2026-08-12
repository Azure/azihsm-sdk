// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `ConcatKdfDerive` wire schema.
//!
//! `ConcatKdfDerive` is an in-session command that derives key material
//! from a caller-held **masked** ECDH shared secret (from
//! [`EcdhDerive`](crate::ecdh_derive)) via a single-step "concatenation"
//! KDF — either ANSI X9.63 (SEC 1 §3.6.1) or NIST SP 800-56A r3 one-step
//! (§5.8.2.1) — and returns the derived key as a **masked** blob under the
//! requested scope's masking key.  Both variants hash the shared secret, a
//! block counter, and a single info octet string; they differ only in the
//! counter/secret ordering, selected by [`ConcatKdfAlg`].
//!
//! Unlike [`HkdfDerive`](crate::hkdf_derive) (which has a salt and an
//! info), a single-step KDF takes only one info string (`SharedInfo` for
//! X9.63, `OtherInfo` for SP 800-56A).
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked by the dispatcher.
//! * `scope` — the [`KeyScope`] whose masking key wraps the derived key.
//! * `hash_algo` — the [`HashAlgo`] driving the KDF.
//! * `kdf_alg` — the [`ConcatKdfAlg`] variant (X9.63 vs SP 800-56A).
//! * `key_type` — the [`KdfKeyType`] selecting the derived key's type/length.
//! * `key_length` — for the variable-length HMAC types, the requested
//!   output length in bytes; `0` means absent.
//! * `masked_secret` — the masked ECDH shared secret IKM (unmasked in place).
//! * `info` — optional `SharedInfo` / `OtherInfo`; an **empty** buffer
//!   means none.
//!
//! Outputs:
//!
//! * `masked_key` — the derived key, masked (AEAD-GCM-256) under the
//!   scope's masking key.

use azihsm_fw_ddi_tbor_api::tbor;
use open_enum::open_enum;

use crate::key_props::HashAlgo;
use crate::key_props::KdfKeyType;
use crate::key_props::KeyScope;

/// TBOR opcode for `ConcatKdfDerive`.
pub const TBOR_OP_CONCAT_KDF_DERIVE: u8 = 0x1D;

/// Maximum info (`SharedInfo` / `OtherInfo`) length (bytes).  Pinned into
/// the `#[tbor(buffer, max_len = 256)]` literal on
/// [`TborConcatKdfDeriveReq::info`].
pub const CONCAT_INFO_MAX_LEN: usize = 256;

/// Minimum masked ECDH-secret IKM envelope length (P-256, 32-byte
/// secret): `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(32) ‖ tag(16)`.  Pinned
/// into the `#[tbor(buffer, min_len = 164)]` literal on
/// [`TborConcatKdfDeriveReq::masked_secret`].
pub const CONCAT_MASKED_SECRET_MIN_LEN: usize = 8 + 12 + 96 + 32 + 16;

/// Maximum masked ECDH-secret IKM envelope length (P-521, 66-byte
/// secret).  Pinned into the `#[tbor(buffer, max_len = 198)]` literal on
/// [`TborConcatKdfDeriveReq::masked_secret`].
pub const CONCAT_MASKED_SECRET_MAX_LEN: usize = 8 + 12 + 96 + 66 + 16;

/// Minimum masked derived-key envelope length (AES-128 / 16-byte key).
pub const CONCAT_MASKED_KEY_MIN_LEN: usize = 8 + 12 + 96 + 16 + 16;

/// Maximum masked derived-key envelope length (128-byte variable-length
/// HMAC key).  Pinned into the `#[tbor(buffer, max_len = 260)]` literal on
/// [`TborConcatKdfDeriveResp::masked_key`].
pub const CONCAT_MASKED_KEY_MAX_LEN: usize = 8 + 12 + 96 + 128 + 16;

/// Which single-step concatenation KDF to run on the TBOR wire.
///
/// Kept as an [`open_enum`] so an unrecognized discriminant round-trips as
/// `ConcatKdfAlg(x)` and is rejected on-device rather than failing to
/// decode.  Both variants hash the shared secret, a 4-byte big-endian
/// block counter, and the info string; they differ only in field order.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcatKdfAlg {
    /// ANSI X9.63 / SEC 1 §3.6.1: `Hash(Z || counter || SharedInfo)`.
    X963 = 1,
    /// NIST SP 800-56A r3 §5.8.2.1 one-step: `Hash(counter || Z || OtherInfo)`.
    Sp800_56a = 2,
}

/// `ConcatKdfDerive` request schema.
///
/// `masked_secret` is `#[tbor(mutable)]` so the handler can `unmask` the
/// IKM **in place** in the request buffer (via `decode_mut`) — no scratch
/// copy — and derive directly from the recovered secret.  `info` is
/// optional-by-emptiness: a zero-length buffer omits the info string.
#[tbor(opcode = 0x1D)]
pub struct TborConcatKdfDeriveReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (masks the derived key), 1-byte [`KeyScope`].
    #[tbor(U8)]
    pub scope: KeyScope,

    /// KDF hash, 1-byte [`HashAlgo`].
    #[tbor(U8)]
    pub hash_algo: HashAlgo,

    /// Single-step KDF variant, 1-byte [`ConcatKdfAlg`].
    #[tbor(U8)]
    pub kdf_alg: ConcatKdfAlg,

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

    /// Optional `SharedInfo` (X9.63) / `OtherInfo` (SP 800-56A), ≤ 256 B;
    /// an **empty** buffer means none.
    #[tbor(buffer, max_len = 256)]
    pub info: &'a [u8],
}

/// `ConcatKdfDerive` response schema.
///
/// `masked_key` is `#[tbor(mutable)]` so the handler can reserve the slot
/// and mask the derived key straight into it (`decode_mut`).
#[tbor(response)]
pub struct TborConcatKdfDeriveResp<'a> {
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
        let secret = [0x11u8; CONCAT_MASKED_SECRET_MIN_LEN];
        let info = [0x22u8; 16];
        let frame = TborConcatKdfDeriveReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .scope(KeyScope::Local)
            .unwrap()
            .hash_algo(HashAlgo::Sha384)
            .unwrap()
            .kdf_alg(ConcatKdfAlg::Sp800_56a)
            .unwrap()
            .key_type(KdfKeyType::Aes256)
            .unwrap()
            .key_length(0)
            .unwrap()
            .masked_secret(&secret)
            .unwrap()
            .info(&info)
            .unwrap()
            .finish();
        assert_eq!(frame.scope(), KeyScope::Local);
        assert_eq!(frame.kdf_alg(), ConcatKdfAlg::Sp800_56a);
        assert_eq!(frame.key_type(), KdfKeyType::Aes256);
        assert_eq!(frame.info(), &info[..]);
    }

    #[test]
    fn response_round_trips_masked_key() {
        let mut buf = [0u8; 512];
        let masked = [0x44u8; CONCAT_MASKED_KEY_MAX_LEN];
        let frame = TborConcatKdfDeriveResp::encode(&mut buf, 0, false)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_key(), &masked[..]);
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(164 == CONCAT_MASKED_SECRET_MIN_LEN);
        const _: () = assert!(198 == CONCAT_MASKED_SECRET_MAX_LEN);
        const _: () = assert!(260 == CONCAT_MASKED_KEY_MAX_LEN);
        assert_eq!(CONCAT_INFO_MAX_LEN, 256);
        assert_eq!(CONCAT_MASKED_KEY_MIN_LEN, 148);
    }
}
