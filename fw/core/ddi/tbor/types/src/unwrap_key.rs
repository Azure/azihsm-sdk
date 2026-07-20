// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `UnwrapKey` wire schema.
//!
//! `UnwrapKey` implements the firmware side of `CKM_RSA_AES_KEY_WRAP` for
//! the TBOR transport: within an open session, unwrap a host-supplied
//! wrapped-key blob with the partition's RSA-2048 unwrapping key (see
//! [`GetUnwrappingKey`](crate::get_unwrapping_key)) and return the
//! recovered key as a **masked** blob under the requested scope's masking
//! key — the TBOR analogue of MBOR `RsaUnwrap`, but re-masking the
//! recovered key instead of vaulting it.
//!
//! The AES, RSA (plain / CRT), ECC, and HMAC key classes are supported.
//! The recovered key is re-derived to wire public form for the asymmetric
//! (RSA / ECC) classes and returned alongside the masked blob.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked by the dispatcher.
//! * `scope` — the [`KeyScope`] whose masking key wraps the recovered key.
//! * `key_class` — the [`KeyClass`] of the wrapped key.
//! * `oaep_hash` — the OAEP [`HashAlgo`] used to wrap the KEK.
//! * `wrapped_blob` — the RSA-AES-wrapped key
//!   (`RSA-OAEP(KEK) ‖ AES-KWP(key)`), up to [`UNWRAP_WRAPPED_BLOB_MAX_LEN`].
//!
//! Outputs:
//!
//! * `key_kind` — the recovered key's [`HsmVaultKeyKind`](azihsm_fw_hsm_pal_traits::HsmVaultKeyKind)
//!   discriminant.
//! * `masked_key` — the recovered key, masked (AEAD-GCM-256) under the
//!   scope's masking key.
//! * `pub_key` — the recovered key's wire public key for RSA / ECC
//!   (`n_le ‖ e_le` / `x ‖ y`); empty for symmetric (AES / HMAC) keys.

use azihsm_fw_ddi_tbor_api::tbor;
use open_enum::open_enum;

use crate::key_props::HashAlgo;
use crate::key_props::KeyScope;

/// TBOR opcode for `UnwrapKey`.
pub const TBOR_OP_UNWRAP_KEY: u8 = 0x14;

/// Max wrapped-blob length (`RSA-OAEP(KEK) ‖ AES-KWP(key)`), sized for the
/// largest supported key (RSA-4096-CRT).  Pinned into the `#[tbor(buffer,
/// max_len = 3072)]` literal on [`TborUnwrapKeyReq::wrapped_blob`].
pub const UNWRAP_WRAPPED_BLOB_MAX_LEN: usize = 3072;

/// Max masked recovered-key envelope length.  Pinned into the
/// `#[tbor(buffer, max_len = 3072)]` literal on
/// [`TborUnwrapKeyResp::masked_key`].
pub const UNWRAP_MASKED_KEY_MAX_LEN: usize = 3072;

/// Max recovered public-key length (RSA-4096 `n_le(512) ‖ e_le(4)`).
/// Pinned into the `#[tbor(buffer, max_len = 520)]` literal on
/// [`TborUnwrapKeyResp::pub_key`].
pub const UNWRAP_PUB_KEY_MAX_LEN: usize = 520;

// Tripwires: keep the public length constants in lock-step with the
// `#[tbor(buffer, max_len = ...)]` literals below (the derive requires
// integer literals, so the two cannot share a symbol).
const _: () = assert!(UNWRAP_WRAPPED_BLOB_MAX_LEN == 3072);
const _: () = assert!(UNWRAP_MASKED_KEY_MAX_LEN == 3072);
const _: () = assert!(UNWRAP_PUB_KEY_MAX_LEN == 520);

/// Class of the wrapped key on the TBOR wire — selects the decode path.
///
/// Kept as an [`open_enum`] so an unrecognized discriminant round-trips
/// and is rejected on-device rather than failing to decode.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    /// A raw 16 / 24 / 32-byte AES key.
    Aes = 0,
    /// A DER-encoded RSA private key (non-CRT vault kind).
    Rsa = 1,
    /// A DER-encoded RSA private key (CRT vault kind).
    RsaCrt = 2,
    /// A PKCS#8 DER-encoded ECC private key.
    Ecc = 3,
    /// A raw variable-length HMAC-SHA-256 key (`VarLenHmacSha256`).
    HmacSha256 = 4,
    /// A raw variable-length HMAC-SHA-384 key (`VarLenHmacSha384`).
    HmacSha384 = 5,
    /// A raw variable-length HMAC-SHA-512 key (`VarLenHmacSha512`).
    HmacSha512 = 6,
}

/// `UnwrapKey` request schema.
#[tbor(opcode = 0x14)]
pub struct TborUnwrapKeyReq<'a> {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (masks the recovered key), 1-byte [`KeyScope`].
    #[tbor(U8)]
    pub scope: KeyScope,

    /// Class of the wrapped key, 1-byte [`KeyClass`].
    #[tbor(U8)]
    pub key_class: KeyClass,

    /// OAEP hash used to wrap the KEK, 1-byte [`HashAlgo`].
    #[tbor(U8)]
    pub oaep_hash: HashAlgo,

    /// The RSA-AES-wrapped key (`RSA-OAEP(KEK) ‖ AES-KWP(key)`), up to
    /// [`UNWRAP_WRAPPED_BLOB_MAX_LEN`] bytes.
    #[tbor(buffer, max_len = 3072)]
    pub wrapped_blob: &'a [u8],
}

/// `UnwrapKey` response schema.
#[tbor(response)]
pub struct TborUnwrapKeyResp<'a> {
    /// The recovered key's vault-kind discriminant (`HsmVaultKeyKind`).
    #[tbor(U8)]
    pub key_kind: u8,

    /// The recovered key, masked (AEAD-GCM-256) under the scope's masking
    /// key.
    ///
    /// `#[tbor(mutable)]` so the handler can reserve the slot and mask the
    /// recovered key straight into it (`decode_mut`) — avoiding a separate
    /// MAX-sized scratch buffer that would otherwise coexist with the
    /// (multi-KB, for RSA) unwrap material and blow the per-IO DMA budget.
    #[tbor(buffer, max_len = 3072, mutable)]
    pub masked_key: &'a [u8],

    /// The recovered key's wire public key for RSA / ECC; empty for
    /// symmetric (AES / HMAC) keys.
    ///
    /// `#[tbor(mutable)]` so the handler can reserve the slot and derive the
    /// wire public key straight into it (`decode_mut`) — no scratch buffer,
    /// no copy.
    #[tbor(buffer, max_len = 520, mutable)]
    pub pub_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 4096];
        let wrapped = [0x5Au8; 300];
        let frame = TborUnwrapKeyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .scope(KeyScope::Local)
            .unwrap()
            .key_class(KeyClass::HmacSha256)
            .unwrap()
            .oaep_hash(HashAlgo::Sha256)
            .unwrap()
            .wrapped_blob(&wrapped)
            .unwrap()
            .finish();

        assert_eq!(frame.key_class(), KeyClass::HmacSha256);
        assert_eq!(frame.oaep_hash(), HashAlgo::Sha256);
        assert_eq!(frame.wrapped_blob(), &wrapped[..]);
    }

    #[test]
    fn response_round_trips_fields() {
        let mut buf = [0u8; 4096];
        let masked = [0xABu8; 196];
        let pub_key = [0xCDu8; 96];
        let frame = TborUnwrapKeyResp::encode(&mut buf, 0, true)
            .unwrap()
            .key_kind(28)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .pub_key(&pub_key)
            .unwrap()
            .finish();
        assert_eq!(frame.key_kind(), 28);
        assert_eq!(frame.masked_key(), &masked[..]);
        assert_eq!(frame.pub_key(), &pub_key[..]);
    }
}
