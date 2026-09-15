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
//! * Imported keys match host HMACs for every hash at padding/block
//!   boundaries and the maximum message length, including binary data.
//! * Session-scoped MAC before partition finalization.
//! * Crypto-User MACs for every hash and provisioned scope; distinct keys
//!   produce distinct tags for the same message.
//! * Variable key lengths under Session / Ephemeral / Local scopes.
//! * Non-HMAC keys and invalid sessions are rejected.
//! * Session keys are isolated; Local / Ephemeral keys work across sessions.
//! * Oversized messages and out-of-range masked-key lengths are rejected.
//! * IV and ciphertext tampering fail authentication without damaging the key.

#![cfg(feature = "emu")]

use azihsm_crypto::HashAlgo;
use azihsm_crypto::HmacAlgo;
use azihsm_crypto::HmacKey;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::Signer;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborHmacGenerateKeyReq;
use azihsm_ddi_tbor_types::TborHmacReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::HMAC_HASH_SHA256;
use azihsm_ddi_tbor_types::HMAC_HASH_SHA384;
use azihsm_ddi_tbor_types::HMAC_HASH_SHA512;
use azihsm_ddi_tbor_types::HMAC_MSG_MAX_LEN;
use azihsm_ddi_tbor_types::KEY_CLASS_AES;
use azihsm_ddi_tbor_types::KEY_CLASS_HMAC_SHA256;
use azihsm_ddi_tbor_types::KEY_CLASS_HMAC_SHA384;
use azihsm_ddi_tbor_types::KEY_CLASS_HMAC_SHA512;
use azihsm_ddi_tbor_types::MASKED_HMAC_KEY_MAX_LEN;
use azihsm_ddi_tbor_types::MASKED_HMAC_KEY_MIN_LEN;

use crate::commands::hmac_generate_key::SCOPE_EPHEMERAL;
use crate::commands::hmac_generate_key::SCOPE_LOCAL;
use crate::commands::hmac_generate_key::SCOPE_SESSION;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap;
use crate::harness::bootstrap_rotated_co;
use crate::harness::bootstrap_rotated_cu;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;
use crate::harness::CO_PSK_ID;
use crate::harness::ROTATED_CO_PSK;
use crate::harness::ROTATED_CU_PSK;

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
fn hmac_roundtrip_all_hashes() {
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
fn hmac_session_scope_roundtrip() {
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
fn hmac_unwrapped_key_roundtrip() {
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
fn hmac_empty_message() {
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
fn hmac_rejects_tampered_key() {
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

/// Compare full tags with a host computation, including the
/// SHA-2 padding transitions, block boundaries, and the wire message cap.
#[test]
fn hmac_matches_host_at_message_boundaries() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for (class, hash, key_len) in [
        (KEY_CLASS_HMAC_SHA256, HashAlgo::sha256(), 32),
        (KEY_CLASS_HMAC_SHA384, HashAlgo::sha384(), 48),
        (KEY_CLASS_HMAC_SHA512, HashAlgo::sha512(), 64),
    ] {
        let key_bytes: Vec<u8> = (0..key_len).map(|i| i as u8).collect();
        let masked = unwrap(&ctx, session.session_id, class, &key_bytes).masked_key;
        let key = HmacKey::from_bytes(&key_bytes).expect("host HMAC key");
        let mut algo = HmacAlgo::new(hash);
        for len in [
            0,
            1,
            55,
            56,
            63,
            64,
            65,
            111,
            112,
            127,
            128,
            129,
            HMAC_MSG_MAX_LEN,
        ] {
            let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let expected = Signer::sign_vec(&mut algo, &key, &msg).expect("host HMAC");
            assert_eq!(
                mac(&ctx, session.session_id, &masked, &msg),
                expected,
                "key class {class}, message length {len}",
            );
        }
    }
}

#[test]
fn hmac_session_scope_before_finalize() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    for hash in [HMAC_HASH_SHA256, HMAC_HASH_SHA384, HMAC_HASH_SHA512] {
        let masked = generate_key(&ctx, session.session_id, SCOPE_SESSION, hash);
        let tag = mac(&ctx, session.session_id, &masked, b"before finalize");
        assert_eq!(tag.len(), tag_len_for_hash(hash));
        assert_eq!(
            tag,
            mac(&ctx, session.session_id, &masked, b"before finalize")
        );
    }
}

#[test]
fn hmac_rejects_non_hmac_key() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    // AES-256 has the same envelope length as HMAC-SHA-256, so this
    // reaches the key-kind check after successfully decoding and unmasking.
    let masked = unwrap(&ctx, session.session_id, KEY_CLASS_AES, &[0x37; 32]).masked_key;
    ctx.expect_fw_reject(
        &TborHmacReq {
            session_id: session.session_id,
            masked_key: masked,
            msg: b"wrong key type".to_vec(),
        },
        TborStatus::InvalidKeyType,
    );
}

#[test]
fn hmac_variable_key_lengths_all_scopes() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for (hash, lengths) in [
        (HMAC_HASH_SHA256, [32, 48, 64]),
        (HMAC_HASH_SHA384, [48, 96, 128]),
        (HMAC_HASH_SHA512, [64, 96, 128]),
    ] {
        for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
            for key_length in lengths {
                let masked = ctx
                    .tbor(&TborHmacGenerateKeyReq {
                        session_id: session.session_id,
                        scope,
                        hash_algo: hash,
                        key_length,
                    })
                    .expect("generate variable-length HMAC key")
                    .masked_key;
                let msg = b"variable-length key";
                let tag = mac(&ctx, session.session_id, &masked, msg);
                assert_eq!(
                    tag.len(),
                    tag_len_for_hash(hash),
                    "hash {hash}, scope {scope}, key length {key_length}"
                );
                assert_eq!(tag, mac(&ctx, session.session_id, &masked, msg));
            }
        }
    }
}

#[test]
fn hmac_rejects_invalid_session() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let masked = generate_key(&ctx, session.session_id, SCOPE_EPHEMERAL, HMAC_HASH_SHA256);
    ctx.expect_fw_reject(
        &TborHmacReq {
            session_id: u16::MAX,
            masked_key: masked,
            msg: b"invalid session".to_vec(),
        },
        TborStatus::FileHandleSessionIdDoesNotMatch,
    );
}

#[test]
fn hmac_scope_behavior_after_session_reopen() {
    let ctx = TestCtx::new();
    let first = finalized_co_session(&ctx);
    let msg = b"cross-session HMAC";
    let keys: Vec<_> = [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL]
        .into_iter()
        .map(|scope| {
            let masked = generate_key(&ctx, first.session_id, scope, HMAC_HASH_SHA256);
            let expected = mac(&ctx, first.session_id, &masked, msg);
            (scope, masked, expected)
        })
        .collect();
    // The transport permits one session per file handle. Reopening also
    // proves that Session keys expire while partition-scoped keys survive.
    ctx.session_close(first.session_id)
        .expect("close first session");
    let pending = ctx
        .session_open_init_with_options(
            SessionOpenInitOptions::new(CO_PSK_ID, SessionType::Authenticated)
                .with_psk(&ROTATED_CO_PSK),
        )
        .expect("open second session");
    let second = ctx
        .session_open_finish(pending)
        .expect("finish second session");
    for (scope, masked, expected) in keys {
        if scope == SCOPE_SESSION {
            ctx.expect_fw_reject(
                &TborHmacReq {
                    session_id: second.session_id,
                    masked_key: masked.clone(),
                    msg: msg.to_vec(),
                },
                TborStatus::AesGcmDecryptTagDoesNotMatch,
            );
        } else {
            assert_eq!(mac(&ctx, second.session_id, &masked, msg), expected);
        }
    }
    ctx.session_close(second.session_id)
        .expect("close second session");
}

#[test]
fn hmac_rejects_oversized_message() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let masked = generate_key(&ctx, session.session_id, SCOPE_EPHEMERAL, HMAC_HASH_SHA256);
    ctx.expect_fw_reject(
        &TborHmacReq {
            session_id: session.session_id,
            masked_key: masked,
            msg: vec![0xA5; HMAC_MSG_MAX_LEN + 1],
        },
        TborStatus::TborInvalidFixedLength,
    );
}

#[test]
fn hmac_rejects_out_of_range_masked_key_lengths() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for len in [0, MASKED_HMAC_KEY_MIN_LEN - 1, MASKED_HMAC_KEY_MAX_LEN + 1] {
        // Host encoding allows these lengths; the firmware schema rejects
        // them before interpreting the envelope contents.
        ctx.expect_fw_reject(
            &TborHmacReq {
                session_id: session.session_id,
                masked_key: vec![0; len],
                msg: b"invalid envelope length".to_vec(),
            },
            TborStatus::TborInvalidFixedLength,
        );
    }
}

/// Tampering with the masked-key IV must be rejected.
#[test]
fn hmac_rejects_tampered_iv() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let masked = generate_key(&ctx, session.session_id, SCOPE_EPHEMERAL, HMAC_HASH_SHA256);

    let msg = b"authenticated key envelope";
    let expected = mac(&ctx, session.session_id, &masked, msg);

    let mut tampered = masked.clone();

    // Envelope starts with header(8), followed by IV.
    tampered[8] ^= 1;

    ctx.expect_fw_reject(
        &TborHmacReq {
            session_id: session.session_id,
            masked_key: tampered,
            msg: msg.to_vec(),
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );

    // Rejected input must not affect the original masked key.
    assert_eq!(mac(&ctx, session.session_id, &masked, msg), expected);
}

/// Tampering with the masked-key ciphertext invalidates the authenticated envelope.
#[test]
fn hmac_rejects_tampered_ciphertext() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let masked = generate_key(&ctx, session.session_id, SCOPE_EPHEMERAL, HMAC_HASH_SHA256);

    let msg = b"authenticated key envelope";
    let expected = mac(&ctx, session.session_id, &masked, msg);

    let mut tampered = masked.clone();

    // Envelope: header(8) + IV(12) + metadata/AAD(192) + ciphertext.
    tampered[8 + 12 + 192] ^= 1;

    ctx.expect_fw_reject(
        &TborHmacReq {
            session_id: session.session_id,
            masked_key: tampered,
            msg: msg.to_vec(),
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );

    assert_eq!(mac(&ctx, session.session_id, &masked, msg), expected);
}

#[test]
fn hmac_crypto_user_all_hashes_and_scopes() {
    let ctx = TestCtx::new();
    let co = finalized_co_session(&ctx);
    ctx.session_close(co.session_id).expect("close CO session");
    let cu = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    let msg = b"Crypto-User HMAC";
    for hash in [HMAC_HASH_SHA256, HMAC_HASH_SHA384, HMAC_HASH_SHA512] {
        for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
            let first = generate_key(&ctx, cu.session_id, scope, hash);
            let second = generate_key(&ctx, cu.session_id, scope, hash);
            let first_tag = mac(&ctx, cu.session_id, &first, msg);
            let second_tag = mac(&ctx, cu.session_id, &second, msg);
            assert_eq!(first_tag.len(), tag_len_for_hash(hash));
            assert_eq!(second_tag.len(), tag_len_for_hash(hash));
            assert_ne!(
                first_tag, second_tag,
                "distinct keys must produce distinct tags: hash {hash}, scope {scope}"
            );
            // Alternating keys must not leave stale key material in use.
            assert_eq!(first_tag, mac(&ctx, cu.session_id, &first, msg));
        }
    }
    ctx.session_close(cu.session_id).expect("close CU session");
}

/// Hmac rejects use of a masked key after its owning session is closed.
#[test]
fn hmac_rejects_closed_session() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let masked = generate_key(&ctx, session.session_id, SCOPE_SESSION, HMAC_HASH_SHA256);

    let session_id = session.session_id;

    // Prove the key works before closing the session.
    let tag = mac(&ctx, session_id, &masked, b"before close");
    assert_eq!(tag.len(), 32);

    ctx.session_close(session_id).expect("close HMAC session");

    ctx.expect_fw_reject(
        &TborHmacReq {
            session_id,
            masked_key: masked,
            msg: b"after close".to_vec(),
        },
        TborStatus::SessionNotFound,
    );
}

/// Repeated Hmac calls do not consume or mutate the masked HMAC key.
#[test]
fn hmac_masked_key_reusable_after_multiple_calls() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let masked = generate_key(&ctx, session.session_id, SCOPE_EPHEMERAL, HMAC_HASH_SHA256);
    let original = masked.clone();

    let messages: [&[u8]; 5] = [b"one", b"two", b"three", b"", b"final message"];

    for msg in messages {
        let first = mac(&ctx, session.session_id, &masked, msg);
        let second = mac(&ctx, session.session_id, &masked, msg);

        assert_eq!(first, second, "masked key must remain reusable");
        assert_eq!(
            masked, original,
            "host-side masked key bytes must remain unchanged"
        );
    }
}

/// Hmac accepts arbitrary binary input containing every possible byte value.
#[test]
fn hmac_all_byte_values_matches_host() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key_bytes = [0x5Au8; 32];
    let masked = unwrap(&ctx, session.session_id, KEY_CLASS_HMAC_SHA256, &key_bytes).masked_key;

    let msg: Vec<u8> = (0u8..=u8::MAX).collect();

    let key = HmacKey::from_bytes(&key_bytes).expect("host HMAC key");
    let mut algo = HmacAlgo::new(HashAlgo::sha256());
    let expected = Signer::sign_vec(&mut algo, &key, &msg).expect("host HMAC");

    let actual = mac(&ctx, session.session_id, &masked, &msg);

    assert_eq!(actual, expected);
}

/// Corrupting the masked-key envelope header must never produce a valid MAC.
#[test]
fn hmac_rejects_corrupted_masked_key_header() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let masked = generate_key(&ctx, session.session_id, SCOPE_EPHEMERAL, HMAC_HASH_SHA256);

    // Exercise each byte in the cleartext envelope header independently.
    for offset in 0..8 {
        let mut corrupted = masked.clone();
        corrupted[offset] ^= 0x80;

        let req = TborHmacReq {
            session_id: session.session_id,
            masked_key: corrupted,
            msg: b"header corruption".to_vec(),
        };

        // Do not use mac(), because rejection is expected.
        assert!(
            ctx.tbor(&req).is_err(),
            "corrupted masked-key header byte {offset} unexpectedly succeeded"
        );
    }

    // Original key must still work after all rejected attempts.
    let tag = mac(&ctx, session.session_id, &masked, b"header corruption");
    assert_eq!(tag.len(), 32);
}

/// Alternating HMAC algorithms does not retain stale hash or key state.
#[test]
fn hmac_alternating_hashes_do_not_leak_state() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let msg = b"algorithm state isolation";

    let key256 = generate_key(&ctx, session.session_id, SCOPE_EPHEMERAL, HMAC_HASH_SHA256);
    let key384 = generate_key(&ctx, session.session_id, SCOPE_EPHEMERAL, HMAC_HASH_SHA384);
    let key512 = generate_key(&ctx, session.session_id, SCOPE_EPHEMERAL, HMAC_HASH_SHA512);

    let tag256 = mac(&ctx, session.session_id, &key256, msg);
    let tag384 = mac(&ctx, session.session_id, &key384, msg);
    let tag512 = mac(&ctx, session.session_id, &key512, msg);

    assert_eq!(tag256.len(), 32);
    assert_eq!(tag384.len(), 48);
    assert_eq!(tag512.len(), 64);

    // Go back to earlier algorithms after SHA-512.
    assert_eq!(mac(&ctx, session.session_id, &key256, msg), tag256);
    assert_eq!(mac(&ctx, session.session_id, &key384, msg), tag384);
    assert_eq!(mac(&ctx, session.session_id, &key512, msg), tag512);
}
