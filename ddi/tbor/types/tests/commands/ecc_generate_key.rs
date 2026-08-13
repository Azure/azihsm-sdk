// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `EccGenerateKey` command.
//!
//! `EccGenerateKey` generates a fresh ECC keypair on the requested NIST
//! curve and returns the private key **masked** under the requested scope
//! plus the wire public key (nothing is persisted on-device).  These tests
//! check the masked-blob / public-key lengths per curve, that keys can be
//! generated under each provisioned scope, and that an unknown curve is
//! rejected.
//!
//! Signing / deriving with the generated key is exercised by the
//! [`ecc_sign`](super::ecc_sign) and [`ecdh_derive`](super::ecdh_derive)
//! tests, which build on this command.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::ECC_CURVE_P384;
use azihsm_ddi_tbor_types::ECC_CURVE_P521;

use crate::commands::sd_sealing_key_gen::finalized_co_session;
use azihsm_ddi_tbor_test_harness::TestCtx;

/// `KeyScope::Session` discriminant — masks under the per-session key.
const SCOPE_SESSION: u8 = 0b001;
/// `KeyScope::Ephemeral` discriminant.
const SCOPE_EPHEMERAL: u8 = 0b010;
/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// Expected wire public-key length (`x ‖ y`, P-521 padded) per curve.
fn wire_pub_len(curve: u8) -> usize {
    match curve {
        ECC_CURVE_P256 => 64,
        ECC_CURVE_P384 => 96,
        ECC_CURVE_P521 => 136,
        _ => unreachable!(),
    }
}

/// Expected masked private-key envelope length per curve:
/// `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(wire_priv) ‖ tag(16)` = 132 + priv.
fn masked_key_len(curve: u8) -> usize {
    match curve {
        ECC_CURVE_P256 => 132 + 32,
        ECC_CURVE_P384 => 132 + 48,
        ECC_CURVE_P521 => 132 + 68,
        _ => unreachable!(),
    }
}

/// Generate an ECC key on `curve` under `scope` and assert well-formedness.
fn generate(ctx: &TestCtx, session_id: u16, scope: u8, curve: u8) {
    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope,
            curve,
        })
        .expect("EccGenerateKey");

    assert_eq!(
        resp.pub_key.len(),
        wire_pub_len(curve),
        "public key length must match the curve",
    );
    assert_eq!(
        resp.masked_key.len(),
        masked_key_len(curve),
        "masked private key envelope length must match the curve",
    );
    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "masked private key must not be all-zero",
    );
    assert!(
        resp.pub_key.iter().any(|&b| b != 0),
        "public key must not be all-zero",
    );
}

#[test]
fn ecc_generate_key_all_curves_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for curve in [ECC_CURVE_P256, ECC_CURVE_P384, ECC_CURVE_P521] {
        generate(&ctx, session.session_id, SCOPE_LOCAL, curve);
    }
}

#[test]
fn ecc_generate_key_scopes_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    // `finalized_co_session` provisions the Ephemeral and Local masking
    // keys; the Session masking key exists for any active session.
    for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
        generate(&ctx, session.session_id, scope, ECC_CURVE_P256);
    }
}

#[test]
fn ecc_generate_key_unknown_curve_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    // Curve discriminant `0` is not one of P-256 / P-384 / P-521.
    ctx.expect_fw_reject(
        &TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: 0,
        },
        TborStatus::InvalidArg,
    );
}
