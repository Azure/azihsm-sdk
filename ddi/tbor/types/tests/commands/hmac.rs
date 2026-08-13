// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `Hmac` command.
//!
//! `Hmac` computes an HMAC tag over a host message using a caller-held
//! **masked** HMAC key (from `HmacGenerateKey`).  The device unmasks the
//! key on-device, computes the MAC, and returns the tag.
//!
//! Coverage:
//! * Generate → MAC round-trip per hash variant (SHA-256/384/512): the tag
//!   has the digest length, is non-zero and deterministic, and a different
//!   message yields a different tag.
//! * Session-scoped key round-trip (masked under the per-session key).
//! * Unwrapped-key → MAC round-trip: an HMAC key imported via `UnwrapKey`
//!   computes a valid MAC, and a second independent import reproduces the
//!   tag (proving the key material survives wrap/unwrap).
//! * Tampered masked key → `AesGcmDecryptTagDoesNotMatch`.
//! * Empty message is accepted.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::TborHmacGenerateKeyReq;
use azihsm_ddi_tbor_types::TborHmacReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::HMAC_HASH_SHA256;
use azihsm_ddi_tbor_types::HMAC_HASH_SHA384;
use azihsm_ddi_tbor_types::HMAC_HASH_SHA512;
use azihsm_ddi_tbor_types::KEY_CLASS_HMAC_SHA256;

use crate::commands::hmac_generate_key::SCOPE_EPHEMERAL;
use crate::commands::hmac_generate_key::SCOPE_SESSION;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap;
use azihsm_ddi_tbor_test_harness::TestCtx;

/// Expected tag length (bytes) for a wire hash discriminant.
fn tag_len_for_hash(hash: u8) -> usize {
    match hash {
        HMAC_HASH_SHA256 => 32,
        HMAC_HASH_SHA384 => 48,
        HMAC_HASH_SHA512 => 64,
        other => panic!("unexpected hash discriminant {other}"),
    }
}

/// Generate a masked HMAC key of `(scope, hash)` on `session_id`.  Uses
/// the digest-size key length (a valid in-range `VarLenHmac` length) — the
/// MAC tests exercise MAC behaviour, not the key-length range.
fn generate_key(ctx: &TestCtx, session_id: u16, scope: u8, hash: u8) -> Vec<u8> {
    let req = TborHmacGenerateKeyReq {
        session_id,
        scope,
        hash_algo: hash,
        key_length: tag_len_for_hash(hash) as u8,
    };
    ctx.tbor(&req).expect("HmacGenerateKey").masked_key
}

/// Compute a MAC tag over `msg` with the masked key.
fn mac(ctx: &TestCtx, session_id: u16, masked_key: &[u8], msg: &[u8]) -> Vec<u8> {
    let req = TborHmacReq {
        session_id,
        masked_key: masked_key.to_vec(),
        msg: msg.to_vec(),
    };
    ctx.tbor(&req).expect("Hmac").tag
}

#[test]
fn hmac_roundtrip_all_hashes_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let msg = b"the quick brown fox";

    for hash in [HMAC_HASH_SHA256, HMAC_HASH_SHA384, HMAC_HASH_SHA512] {
        let masked = generate_key(&ctx, session.session_id, SCOPE_EPHEMERAL, hash);
        let tag = mac(&ctx, session.session_id, &masked, msg);

        // Tag length matches the hash digest length, and is non-zero.
        assert_eq!(tag.len(), tag_len_for_hash(hash), "tag length");
        assert!(tag.iter().any(|&b| b != 0), "tag must not be all-zero");

        // HMAC is deterministic: the same key + message reproduce the tag.
        let tag_again = mac(&ctx, session.session_id, &masked, msg);
        assert_eq!(tag, tag_again, "HMAC must be deterministic");

        // A different message yields a different tag.
        let tag_other = mac(&ctx, session.session_id, &masked, b"a different message");
        assert_ne!(tag, tag_other, "distinct messages must yield distinct tags");
    }
}

#[test]
fn hmac_session_scope_roundtrip_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let masked = generate_key(&ctx, session.session_id, SCOPE_SESSION, HMAC_HASH_SHA256);
    let tag = mac(&ctx, session.session_id, &masked, b"session-scoped mac");
    assert_eq!(tag.len(), 32);
    assert!(tag.iter().any(|&b| b != 0));
}

/// Unwrap an HMAC key (RSA-AES key import) and use it via `Hmac`.
///
/// Exercises the cross-command integration between `UnwrapKey` (imports a
/// host-wrapped HMAC key as a masked blob) and `Hmac` (MACs with the
/// recovered key).  A second independent unwrap of the same key must
/// reproduce the tag, proving the key material survives wrap → unwrap →
/// mask → unmask intact.
#[test]
fn hmac_unwrapped_key_roundtrip_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let hmac_key = [0x37u8; 32];
    let msg = b"unwrap then mac";

    let masked = unwrap(&ctx, session.session_id, KEY_CLASS_HMAC_SHA256, &hmac_key).masked_key;
    let tag = mac(&ctx, session.session_id, &masked, msg);
    assert_eq!(tag.len(), 32, "HMAC-SHA-256 tag length");
    assert!(tag.iter().any(|&b| b != 0), "tag must not be all-zero");

    // A second independent unwrap of the same key recovers the same key
    // material, so MAC-ing the same message reproduces the tag.
    let masked2 = unwrap(&ctx, session.session_id, KEY_CLASS_HMAC_SHA256, &hmac_key).masked_key;
    let tag2 = mac(&ctx, session.session_id, &masked2, msg);
    assert_eq!(tag, tag2, "same unwrapped key must reproduce the MAC");
}

#[test]
fn hmac_empty_message_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let masked = generate_key(&ctx, session.session_id, SCOPE_EPHEMERAL, HMAC_HASH_SHA256);
    let tag = mac(&ctx, session.session_id, &masked, b"");
    assert_eq!(tag.len(), 32);
    assert!(
        tag.iter().any(|&b| b != 0),
        "HMAC of empty message is non-zero"
    );
}

#[test]
fn hmac_rejects_tampered_key_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let mut masked = generate_key(&ctx, session.session_id, SCOPE_EPHEMERAL, HMAC_HASH_SHA256);

    // Flip a byte in the AEAD tag region (last 16 bytes) so the unmask tag
    // check fails without changing the cleartext scope metadata.
    let last = masked.len() - 1;
    masked[last] ^= 0x01;

    let req = TborHmacReq {
        session_id: session.session_id,
        masked_key: masked,
        msg: b"whatever".to_vec(),
    };
    ctx.expect_fw_reject(&req, TborStatus::AesGcmDecryptTagDoesNotMatch);
}
