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
//!   maximum → 260 B masked blob.
//! * Out-of-range `key_length` (below min / above max) → `InvalidKeyLength`.
//! * Every masking-key scope: `Session` (masked under the per-session
//!   key, works pre-finalize), `Ephemeral` / `Local` (provisioned by
//!   `PartFinal`).
//! * `SecurityDomain` scope before `CreateSD` → `UnsupportedKeyScope`.
//! * Non-session scopes before `PartFinal` → `InvalidArg`.
//! * Unknown scopes/hashes and closed sessions are rejected.
//! * Crypto-User access and default-PSK gating.
//! * Generated keys produce repeatable MACs and independent generations
//!   produce distinct tags for the same message.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborHmacGenerateKeyReq;
use azihsm_ddi_tbor_types::TborHmacReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::HMAC_HASH_SHA256;
use azihsm_ddi_tbor_types::HMAC_HASH_SHA384;
use azihsm_ddi_tbor_types::HMAC_HASH_SHA512;

use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::harness::bootstrap_rotated_co;
use crate::harness::bootstrap_rotated_cu;
use crate::harness::TestCtx;
use crate::harness::CO_PSK_ID as CO;
use crate::harness::ROTATED_CO_PSK;
use crate::harness::ROTATED_CU_PSK;

/// `KeyScope` discriminants (wire mirror of the firmware `HsmKeyScope`).
pub(crate) const SCOPE_SESSION: u8 = 0b001;
pub(crate) const SCOPE_EPHEMERAL: u8 = 0b010;
pub(crate) const SCOPE_LOCAL: u8 = 0b011;
pub(crate) const SCOPE_SECURITY_DOMAIN: u8 = 0b100;

/// Masked-key envelope length for a given HMAC key length: `header(8) ‖
/// iv(12) ‖ aad(96) ‖ pt(key) ‖ tag(16)`.
fn masked_len(key_len: usize) -> usize {
    8 + 12 + 96 + key_len + 16
}

/// A representative in-range key length for a wire hash discriminant (the
/// digest size = the minimum of each variant's `VarLenHmac` range), used
/// where the exact length is not the focus of the test.
fn default_key_len(hash: u8) -> usize {
    match hash {
        HMAC_HASH_SHA256 => 32,
        HMAC_HASH_SHA384 => 48,
        HMAC_HASH_SHA512 => 64,
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

#[test]
fn hmac_generate_key_roundtrip_all_hashes() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for hash in [HMAC_HASH_SHA256, HMAC_HASH_SHA384, HMAC_HASH_SHA512] {
        roundtrip(
            &ctx,
            session.session_id,
            SCOPE_EPHEMERAL,
            hash,
            default_key_len(hash),
        );
    }
}

#[test]
fn hmac_generate_key_variable_lengths() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    // (hash, [min, mid, max]) across each variant's VarLenHmac range.
    let cases: &[(u8, [usize; 3])] = &[
        (HMAC_HASH_SHA256, [32, 48, 64]),
        (HMAC_HASH_SHA384, [48, 96, 128]),
        (HMAC_HASH_SHA512, [64, 96, 128]),
    ];
    for &(hash, lens) in cases {
        for key_len in lens {
            roundtrip(&ctx, session.session_id, SCOPE_LOCAL, hash, key_len);
        }
    }
}

#[test]
fn hmac_generate_key_rejects_out_of_range_length() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    // (hash, key_length) pairs just outside the variant's [min, max].
    let cases: &[(u8, u8)] = &[
        (HMAC_HASH_SHA256, 0),   // zero is always invalid
        (HMAC_HASH_SHA256, 31),  // below min (32)
        (HMAC_HASH_SHA256, 65),  // above max (64)
        (HMAC_HASH_SHA384, 47),  // below min (48)
        (HMAC_HASH_SHA384, 129), // above max (128)
        (HMAC_HASH_SHA512, 63),  // below min (64)
        (HMAC_HASH_SHA512, 129), // above max (128)
        (HMAC_HASH_SHA384, 0),
        (HMAC_HASH_SHA512, 0),
        (HMAC_HASH_SHA256, u8::MAX),
        (HMAC_HASH_SHA384, u8::MAX),
        (HMAC_HASH_SHA512, u8::MAX),
    ];
    for &(hash, key_length) in cases {
        let req = TborHmacGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: hash,
            key_length,
        };
        ctx.expect_fw_reject(&req, TborStatus::InvalidKeyLength);
    }
}

#[test]
fn hmac_generate_key_roundtrip_all_scopes() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    // Session / Ephemeral / Local masking keys all exist on an Initialized
    // partition with an Active session.
    for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
        roundtrip(&ctx, session.session_id, scope, HMAC_HASH_SHA256, 32);
    }
}

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
        HMAC_HASH_SHA256,
        32,
    );
}

#[test]
fn hmac_generate_key_rejects_security_domain_scope() {
    // The SecurityDomain masking key (SDMK) is only provisioned by
    // CreateSD, so the scope is rejected with the dedicated error.
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_SECURITY_DOMAIN,
        hash_algo: HMAC_HASH_SHA256,
        key_length: 32,
    };
    ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
}

#[test]
fn hmac_generate_key_rejects_non_session_scopes_before_finalize() {
    // Ephemeral / Local masking keys are provisioned at PartFinal, so a
    // non-Session scope before finalize is rejected with InvalidArg.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    for scope in [SCOPE_EPHEMERAL, SCOPE_LOCAL, SCOPE_SECURITY_DOMAIN] {
        let req = TborHmacGenerateKeyReq {
            session_id: session.session_id,
            scope,
            hash_algo: HMAC_HASH_SHA256,
            key_length: 32,
        };
        ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
    }
}

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
        };
        ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
    }
}

#[test]
fn hmac_generate_key_rejects_unknown_scope() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for scope in [0, 5, u8::MAX] {
        let req = TborHmacGenerateKeyReq {
            session_id: session.session_id,
            scope,
            hash_algo: HMAC_HASH_SHA256,
            key_length: 32,
        };
        ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
    }
}

#[test]
fn hmac_generate_key_crypto_user_session_scope() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    for hash in [HMAC_HASH_SHA256, HMAC_HASH_SHA384, HMAC_HASH_SHA512] {
        roundtrip(
            &ctx,
            session.session_id,
            SCOPE_SESSION,
            hash,
            default_key_len(hash),
        );
    }
}

#[test]
fn hmac_generate_key_rejects_default_psk() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open session");
    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id(),
        scope: SCOPE_SESSION,
        hash_algo: HMAC_HASH_SHA256,
        key_length: 32,
    };
    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}

#[test]
fn hmac_generate_key_rejects_closed_session() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    ctx.session_close(session.session_id)
        .expect("close session");
    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_SESSION,
        hash_algo: HMAC_HASH_SHA256,
        key_length: 32,
    };
    ctx.expect_fw_reject(&req, TborStatus::SessionNotFound);
}

/// Rejects session IDs that do not identify an active session.
#[test]
fn hmac_generate_key_rejects_invalid_session_id() {
    let ctx = TestCtx::new();

    for session_id in [0, u16::MAX] {
        let req = TborHmacGenerateKeyReq {
            session_id,
            scope: SCOPE_SESSION,
            hash_algo: HMAC_HASH_SHA256,
            key_length: 32,
        };

        ctx.expect_fw_reject(&req, TborStatus::SessionNotFound);
    }
}

/// Accepts the exact minimum and maximum key length for every HMAC variant.
#[test]
fn hmac_generate_key_accepts_exact_length_boundaries() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let cases = [
        (HMAC_HASH_SHA256, 32usize),
        (HMAC_HASH_SHA256, 64),
        (HMAC_HASH_SHA384, 48),
        (HMAC_HASH_SHA384, 128),
        (HMAC_HASH_SHA512, 64),
        (HMAC_HASH_SHA512, 128),
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
        (HMAC_HASH_SHA256, 33usize),
        (HMAC_HASH_SHA256, 63),
        (HMAC_HASH_SHA384, 49),
        (HMAC_HASH_SHA384, 127),
        (HMAC_HASH_SHA512, 65),
        (HMAC_HASH_SHA512, 127),
    ];

    for (hash, key_len) in cases {
        roundtrip(&ctx, session.session_id, SCOPE_LOCAL, hash, key_len);
    }
}
