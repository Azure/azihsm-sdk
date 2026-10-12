// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//! Integration tests for the TBOR `HmacGenerateKey` command.
//!
//! The command generates a random HMAC key of the requested SHA variant
//! and returns it **masked** under the requested scope's masking key —
//! nothing is stored on-device.  Unlike the security-domain commands,
//! `HmacGenerateKey` is available to both Crypto-Officer and Crypto-User
//! sessions.
//!
//! Coverage:
//! * Happy path per hash variant (SHA-256/384/512) — the masked key has
//!   the expected length and is non-zero; a second call yields a distinct
//!   key.
//! * Variable key lengths across each variant's `[min, max]` range
//!   (SHA-256: 32–64, SHA-384: 48–128, SHA-512: 64–128), incl. the 128 B
//!   maximum → 356 B masked blob.
//! * Out-of-range `key_length` (below min / above max) → `InvalidKeyLength`.
//! * Every masking-key scope: `Session` (masked under the per-session
//!   key, works pre-finalize), `Ephemeral` / `Local` (provisioned by
//!   `PartFinal`).
//! * `SecurityDomain` scope before `CreateSD` → `UnsupportedKeyScope`.
//! * `Ephemeral` scope before `PartFinal` → `InvalidArg`.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::ROTATED_CU_PSK;

use azihsm_ddi_tbor_test_harness::{bootstrap_rotated_co, bootstrap_rotated_cu};
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborHmacGenerateKeyReq;
use azihsm_ddi_tbor_types::TborHmacReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::TBOR_KEY_LABEL_MAX_LEN;
use azihsm_ddi_tbor_types::{HASH_ALGO_SHA1, HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512};

use crate::commands::common::CO;
use crate::commands::common::SCOPE_EPHEMERAL;
use crate::commands::common::SCOPE_LOCAL;
use crate::commands::common::SCOPE_SECURITY_DOMAIN;
use crate::commands::common::SCOPE_SESSION;
use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// Masked-key envelope length for a given HMAC key length: `header(8) ‖
/// iv(12) ‖ aad(192) ‖ pt(key) ‖ tag(16)`.
fn masked_len(key_len: usize) -> usize {
    8 + 12 + 192 + key_len + 16
}

/// A representative in-range key length for a wire hash discriminant (the
/// digest size = the minimum of each variant's `VarLenHmac` range), used
/// where the exact length is not the focus of the test.
fn default_key_len(hash: u8) -> usize {
    match hash {
        HASH_ALGO_SHA256 => 32,
        HASH_ALGO_SHA384 => 48,
        HASH_ALGO_SHA512 => 64,
        other => panic!("unexpected hash discriminant {other}"),
    }
}

/// Happy path for a `(scope, hash, key_len)` tuple on the given active
/// session: the masked key has the expected length, is non-zero, and a
/// second call yields a distinct blob.
fn roundtrip(ctx: &TestCtx, session_id: u16, scope: u8, hash: u8, key_len: usize) {
    let req = TborHmacGenerateKeyReq {
        session_id,
        scope,
        hash_algo: hash,
        key_length: key_len as u8,
        key_label: b"hmac-key".to_vec(),
    };
    let resp = ctx.tbor(&req).expect("HmacGenerateKey roundtrip");
    assert_eq!(
        resp.masked_key.len(),
        masked_len(key_len),
        "masked key length must match the requested key_length",
    );
    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "masked_key must not be all-zero",
    );
    // Exercise unmask-on-use, including variable-length key metadata.
    let mac_req = TborHmacReq {
        session_id,
        masked_key: resp.masked_key.clone(),
        msg: b"generated HMAC key coverage".to_vec(),
    };
    let tag = ctx.tbor(&mac_req).expect("MAC with generated key").tag;
    assert_eq!(tag.len(), default_key_len(hash));
    assert_eq!(tag, ctx.tbor(&mac_req).expect("repeat MAC").tag);
    // Each call samples fresh randomness → a distinct masked blob.
    let resp2 = ctx.tbor(&req).expect("second HmacGenerateKey");
    assert_ne!(
        resp.masked_key, resp2.masked_key,
        "each generation must yield a distinct masked key",
    );
    let second_mac_req = TborHmacReq {
        masked_key: resp2.masked_key,
        ..mac_req
    };
    assert_ne!(
        tag,
        ctx.tbor(&second_mac_req).expect("MAC with second key").tag,
        "independent keys must produce distinct tags for the same message",
    );
}

/// Generates and uses HMAC keys successfully for every supported hash algorithm.
#[test]
fn hmac_generate_key_roundtrip_all_hashes() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for hash in [HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512] {
        roundtrip(
            &ctx,
            session.session_id,
            SCOPE_EPHEMERAL,
            hash,
            default_key_len(hash),
        );
    }
}

/// Accepts representative minimum, middle, and maximum key lengths for each HMAC variant.
#[test]
fn hmac_generate_key_variable_lengths() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    // (hash, [min, mid, max]) across each variant's VarLenHmac range.
    let cases: &[(u8, [usize; 3])] = &[
        (HASH_ALGO_SHA256, [32, 48, 64]),
        (HASH_ALGO_SHA384, [48, 96, 128]),
        (HASH_ALGO_SHA512, [64, 96, 128]),
    ];
    for &(hash, lens) in cases {
        for key_len in lens {
            roundtrip(&ctx, session.session_id, SCOPE_LOCAL, hash, key_len);
        }
    }
}

/// Rejects HMAC key lengths outside the valid range for each hash algorithm.
#[test]
fn hmac_generate_key_rejects_out_of_range_length() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    // (hash, key_length) pairs just outside the variant's [min, max].
    let cases: &[(u8, u8)] = &[
        (HASH_ALGO_SHA256, 0),   // zero is always invalid
        (HASH_ALGO_SHA256, 31),  // below min (32)
        (HASH_ALGO_SHA256, 65),  // above max (64)
        (HASH_ALGO_SHA384, 47),  // below min (48)
        (HASH_ALGO_SHA384, 129), // above max (128)
        (HASH_ALGO_SHA512, 63),  // below min (64)
        (HASH_ALGO_SHA512, 129), // above max (128)
        (HASH_ALGO_SHA384, 0),
        (HASH_ALGO_SHA512, 0),
        (HASH_ALGO_SHA256, u8::MAX),
        (HASH_ALGO_SHA384, u8::MAX),
        (HASH_ALGO_SHA512, u8::MAX),
    ];
    for &(hash, key_length) in cases {
        let req = TborHmacGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: hash,
            key_length,
            key_label: Vec::new(),
        };
        ctx.expect_fw_reject(&req, TborStatus::InvalidKeyLength);
    }
}

/// Generates and uses HMAC keys successfully with every supported non-SD key scope.
#[test]
fn hmac_generate_key_roundtrip_all_scopes() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    // Session / Ephemeral / Local masking keys all exist on an Initialized
    // partition with an Active session.
    for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
        roundtrip(&ctx, session.session_id, scope, HASH_ALGO_SHA256, 32);
    }
}

/// Generates and uses a Session-scoped HMAC key before partition finalization.
#[test]
fn hmac_generate_key_session_scope_before_finalize() {
    // Session-scoped keys are masked under the per-session masking key, so
    // they do not require a finalized partition — only an Active session.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    roundtrip(
        &ctx,
        session.session_id,
        SCOPE_SESSION,
        HASH_ALGO_SHA256,
        32,
    );
}

/// Rejects SecurityDomain scope when its masking key has not been provisioned.
#[test]
fn hmac_generate_key_rejects_security_domain_scope() {
    // The SecurityDomain masking key (SDMK) is only provisioned by
    // CreateSD, so the scope is rejected with the dedicated error.
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_SECURITY_DOMAIN,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 32,
        key_label: Vec::new(),
    };
    ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
}

/// Rejects non-Session HMAC key scopes before partition finalization.
#[test]
fn hmac_generate_key_rejects_non_session_scopes_before_finalize() {
    // Ephemeral / Local masking keys are provisioned at PartFinal, so a
    // non-Session scope before finalize is rejected with InvalidArg.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_EPHEMERAL,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 32,
        key_label: Vec::new(),
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Rejects unsupported HMAC hash algorithm discriminants.
#[test]
fn hmac_generate_key_rejects_unknown_hash() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for hash_algo in [0, 4, u8::MAX] {
        let req = TborHmacGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_EPHEMERAL,
            hash_algo,
            key_length: 32,
            key_label: Vec::new(),
        };
        ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
    }
}

/// Rejects unsupported HMAC key scope discriminants.
#[test]
fn hmac_generate_key_rejects_unknown_scope() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for scope in [0, 5, u8::MAX] {
        let req = TborHmacGenerateKeyReq {
            session_id: session.session_id,
            scope,
            hash_algo: HASH_ALGO_SHA256,
            key_length: 32,
            key_label: Vec::new(),
        };
        ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
    }
}

/// CU: generates and uses SHA-256/384/512 HMAC keys with session scope.
#[test]
fn hmac_generate_key_crypto_user_session_scope() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    for hash in [HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512] {
        roundtrip(
            &ctx,
            session.session_id,
            SCOPE_SESSION,
            hash,
            default_key_len(hash),
        );
    }
}

/// Accepts a non-empty key label and returns a usable masked key.
#[test]
fn hmac_generate_key_accepts_non_empty_key_label() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_LOCAL,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 32,
        key_label: b"hmac-test-key".to_vec(),
    };
    let resp = ctx
        .tbor(&req)
        .expect("HmacGenerateKey with non-empty key label");
    assert_eq!(resp.masked_key.len(), masked_len(32));
    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "masked_key must not be all-zero",
    );
    let mac_req = TborHmacReq {
        session_id: session.session_id,
        masked_key: resp.masked_key,
        msg: b"non-empty key label coverage".to_vec(),
    };
    let tag = ctx
        .tbor(&mac_req)
        .expect("MAC with labeled generated key")
        .tag;
    assert_eq!(tag.len(), default_key_len(HASH_ALGO_SHA256));
}

/// CO: rejects HMAC key generation before the default PSK is rotated.
#[test]
fn hmac_generate_key_rejects_default_psk() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open session");
    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id(),
        scope: SCOPE_SESSION,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 32,
        key_label: Vec::new(),
    };
    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}

/// Rejects HMAC key generation after the CO session is closed.
#[test]
fn hmac_generate_key_rejects_closed_session() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    ctx.session_close(session.session_id)
        .expect("close session");
    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_SESSION,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 32,
        key_label: Vec::new(),
    };
    ctx.expect_fw_reject(&req, TborStatus::SessionNotFound);
}

/// Rejects a request whose session id does not match the active session.
#[test]
fn hmac_generate_key_rejects_invalid_session_id() {
    let ctx = TestCtx::new();

    // Rotate the CO PSK, then close the session so the CU session can open.
    let co_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    ctx.session_close(co_session.session_id)
        .expect("close rotated CO session");

    // Rotate the CU PSK as well. Both role PSKs must be non-default so the
    // dispatcher reaches active-session validation instead of the default-PSK gate.
    let cu_session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    ctx.session_close(cu_session.session_id)
        .expect("close rotated CU session");

    assert_ne!(
        co_session.session_id,
        u16::MAX,
        "CO session ID must not be the invalid test ID",
    );

    assert_ne!(
        cu_session.session_id,
        u16::MAX,
        "CU session ID must not be the invalid test ID",
    );

    let req = TborHmacGenerateKeyReq {
        session_id: u16::MAX,
        scope: SCOPE_SESSION,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 32,
        key_label: Vec::new(),
    };

    ctx.expect_fw_reject(&req, TborStatus::SessionNotFound);
}

/// Accepts the exact minimum and maximum key length for every HMAC variant.
#[test]
fn hmac_generate_key_accepts_exact_length_boundaries() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let cases = [
        (HASH_ALGO_SHA256, 32usize),
        (HASH_ALGO_SHA256, 64),
        (HASH_ALGO_SHA384, 48),
        (HASH_ALGO_SHA384, 128),
        (HASH_ALGO_SHA512, 64),
        (HASH_ALGO_SHA512, 128),
    ];
    for (hash, key_len) in cases {
        roundtrip(&ctx, session.session_id, SCOPE_EPHEMERAL, hash, key_len);
    }
}

/// Accepts non-boundary key lengths inside each algorithm's valid range.
#[test]
fn hmac_generate_key_accepts_non_digest_key_lengths() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let cases = [
        (HASH_ALGO_SHA256, 33usize),
        (HASH_ALGO_SHA256, 63),
        (HASH_ALGO_SHA384, 49),
        (HASH_ALGO_SHA384, 127),
        (HASH_ALGO_SHA512, 65),
        (HASH_ALGO_SHA512, 127),
    ];
    for (hash, key_len) in cases {
        roundtrip(&ctx, session.session_id, SCOPE_LOCAL, hash, key_len);
    }
}

/// Accepts an empty key label.
#[test]
fn hmac_generate_key_accepts_empty_key_label() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_LOCAL,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 32,
        key_label: Vec::new(),
    };

    let resp = ctx
        .tbor(&req)
        .expect("HmacGenerateKey with empty key label");

    assert_eq!(resp.masked_key.len(), masked_len(32));
}

/// Accepts arbitrary bytes in the key label.
#[test]
fn hmac_generate_key_accepts_binary_key_label() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_LOCAL,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 32,
        key_label: vec![0x00, 0x80, 0xff, 0x41],
    };

    let resp = ctx
        .tbor(&req)
        .expect("HmacGenerateKey with binary key label");

    assert_eq!(resp.masked_key.len(), masked_len(32));
}

/// Accepts the maximum supported key-label length.
#[test]
fn hmac_generate_key_accepts_max_key_label_length() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_LOCAL,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 32,
        key_label: vec![b'L'; TBOR_KEY_LABEL_MAX_LEN],
    };

    let resp = ctx
        .tbor(&req)
        .expect("HmacGenerateKey with maximum key-label length");

    assert_eq!(resp.masked_key.len(), masked_len(32));
}

/// Rejects a key label longer than the supported maximum.
#[test]
fn hmac_generate_key_rejects_oversized_key_label() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_LOCAL,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 32,
        key_label: vec![b'L'; TBOR_KEY_LABEL_MAX_LEN + 1],
    };

    ctx.expect_fw_reject(&req, TborStatus::TborInvalidFixedLength);
}

/// Rejects a generated HMAC key when its masked-key envelope is corrupted.
#[test]
fn hmac_generate_key_tampered_masked_key_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_LOCAL,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 32,
        key_label: Vec::new(),
    };

    let mut generated = ctx.tbor(&req).expect("generate HMAC key");

    // Corrupt the authenticated masked-key envelope.
    let last = generated
        .masked_key
        .last_mut()
        .expect("masked key must not be empty");
    *last ^= 0x01;

    let mac_req = TborHmacReq {
        session_id: session.session_id,
        masked_key: generated.masked_key,
        msg: b"tampered generated key".to_vec(),
    };

    ctx.expect_fw_reject(&mac_req, TborStatus::AesGcmDecryptTagDoesNotMatch);
}

/// Rejects a generated HMAC key whose masked-key envelope is truncated.
#[test]
fn hmac_generate_key_truncated_masked_key_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_LOCAL,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 32,
        key_label: Vec::new(),
    };

    let mut generated = ctx.tbor(&req).expect("generate HMAC key");
    generated.masked_key.pop();

    let mac_req = TborHmacReq {
        session_id: session.session_id,
        masked_key: generated.masked_key,
        msg: b"truncated generated key".to_vec(),
    };

    ctx.expect_fw_reject(&mac_req, TborStatus::TborInvalidFixedLength);
}

/// CU: generate and use HMAC keys with variable valid key lengths.
#[test]
fn hmac_generate_key_cu_variable_lengths() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    let cases = [
        (HASH_ALGO_SHA256, 32usize),
        (HASH_ALGO_SHA256, 48),
        (HASH_ALGO_SHA256, 64),
        (HASH_ALGO_SHA384, 48),
        (HASH_ALGO_SHA384, 96),
        (HASH_ALGO_SHA384, 128),
        (HASH_ALGO_SHA512, 64),
        (HASH_ALGO_SHA512, 96),
        (HASH_ALGO_SHA512, 128),
    ];

    for (hash, key_len) in cases {
        roundtrip(&ctx, session.session_id, SCOPE_SESSION, hash, key_len);
    }
}

/// CU: reject key lengths outside the supported range.
#[test]
fn hmac_generate_key_cu_rejects_invalid_lengths() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    let cases = [
        (HASH_ALGO_SHA256, 0u8),
        (HASH_ALGO_SHA256, 31),
        (HASH_ALGO_SHA256, 65),
        (HASH_ALGO_SHA384, 47),
        (HASH_ALGO_SHA384, 129),
        (HASH_ALGO_SHA512, 63),
        (HASH_ALGO_SHA512, 129),
    ];

    for (hash_algo, key_length) in cases {
        let req = TborHmacGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SESSION,
            hash_algo,
            key_length,
            key_label: Vec::new(),
        };

        ctx.expect_fw_reject(&req, TborStatus::InvalidKeyLength);
    }
}

/// CU: reject unsupported hash algorithm discriminants.
#[test]
fn hmac_generate_key_cu_rejects_unknown_hash() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    for hash_algo in [0u8, 4, u8::MAX] {
        let req = TborHmacGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SESSION,
            hash_algo,
            key_length: 32,
            key_label: Vec::new(),
        };

        ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
    }
}

/// CU: accept a binary key label and generate a usable key.
#[test]
fn hmac_generate_key_cu_accepts_binary_key_label() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_SESSION,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 32,
        key_label: vec![0x00, 0x80, 0xff, 0x41],
    };

    let generated = ctx
        .tbor(&req)
        .expect("CU HmacGenerateKey with binary label");

    assert_eq!(generated.masked_key.len(), masked_len(32));

    let mac_req = TborHmacReq {
        session_id: session.session_id,
        masked_key: generated.masked_key,
        msg: b"CU binary label test".to_vec(),
    };

    let tag = ctx.tbor(&mac_req).expect("CU HMAC using labeled key").tag;

    assert_eq!(tag.len(), 32);
}

/// CU: reject HmacGenerateKey after its session is closed.
#[test]
fn hmac_generate_key_cu_rejects_closed_session() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    ctx.session_close(session.session_id)
        .expect("close CU session");

    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_SESSION,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 32,
        key_label: Vec::new(),
    };

    ctx.expect_fw_reject(&req, TborStatus::SessionNotFound);
}

/// Rejects a 20-byte SHA-256 HMAC key below the minimum supported length.
#[test]
fn hmac_generate_key_sha256_rejects_sha1_sized_key() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_LOCAL,
        hash_algo: HASH_ALGO_SHA256,
        key_length: 20,
        key_label: b"sha1-sized-key".to_vec(),
    };

    ctx.expect_fw_reject(&req, TborStatus::InvalidKeyLength);
}

/// CO: rejects SHA-1 HMAC key generation.
#[test]
fn hmac_generate_key_co_sha1_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_SESSION,
        hash_algo: HASH_ALGO_SHA1,
        key_length: 32,
        key_label: b"co-sha1-rejected".to_vec(),
    };

    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// CU: rejects SHA-1 HMAC key generation.
#[test]
fn hmac_generate_key_cu_sha1_rejected() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_SESSION,
        hash_algo: HASH_ALGO_SHA1,
        key_length: 32,
        key_label: b"cu-sha1-rejected".to_vec(),
    };

    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}
