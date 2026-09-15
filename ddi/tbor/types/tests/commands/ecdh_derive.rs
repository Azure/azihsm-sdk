// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `EcdhDerive` command.
//!
//! `EcdhDerive` derives an ECDH shared secret from a caller-held
//! **masked** local ECC private key (from
//! [`EccGenerateKey`](super::ecc_generate_key)) and a host-supplied peer
//! public key, returning the secret **masked** under the requested scope.
//!
//! Because the derived secret is returned only in masked form (there is no
//! TBOR command to observe its plaintext), these tests validate the
//! command's plumbing: a well-formed masked secret of the correct length
//! for each curve, derivation under each provisioned scope, and rejection
//! of a peer public key of the wrong length.  The underlying ECDH
//! primitive's correctness is covered by the MBOR `EcdhKeyExchange` tests
//! and the std-PAL ECC driver tests, which share the same `pal.ecdh_derive`.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::TborEcdhDeriveReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::ECC_CURVE_P384;
use azihsm_ddi_tbor_types::ECC_CURVE_P521;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Session` discriminant.
const SCOPE_SESSION: u8 = 0b001;
/// `KeyScope::Ephemeral` discriminant.
const SCOPE_EPHEMERAL: u8 = 0b010;
/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// Expected masked shared-secret envelope length per curve:
/// `header(8) ‖ iv(12) ‖ aad(96) ‖ secret(raw_coord) ‖ tag(16)` = 132 + raw.
fn masked_secret_len(curve: u8) -> usize {
    match curve {
        ECC_CURVE_P256 => 132 + 32,
        ECC_CURVE_P384 => 132 + 48,
        ECC_CURVE_P521 => 132 + 66,
        _ => unreachable!(),
    }
}

/// Generate an ECC key on-device for `curve`, returning `(masked_key,
/// wire_pub_key)`.
fn generate(ctx: &TestCtx, session_id: u16, curve: u8) -> (Vec<u8>, Vec<u8>) {
    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            curve,
        })
        .expect("EccGenerateKey");
    (resp.masked_key, resp.pub_key)
}

/// Derive a shared secret from local key `masked_key` against `peer_pub`
/// under `scope`.
fn derive(
    ctx: &TestCtx,
    session_id: u16,
    scope: u8,
    masked_key: Vec<u8>,
    peer_pub: Vec<u8>,
) -> Vec<u8> {
    ctx.tbor(&TborEcdhDeriveReq {
        session_id,
        scope,
        masked_key,
        peer_pub_key: peer_pub,
    })
    .expect("EcdhDerive")
    .masked_secret
}

#[test]
fn ecdh_derive_all_curves_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for curve in [ECC_CURVE_P256, ECC_CURVE_P384, ECC_CURVE_P521] {
        // Two device-generated keypairs on the same curve; each side's
        // public key is a valid wire-LE peer point for the other.
        let (masked_a, pub_a) = generate(&ctx, session.session_id, curve);
        let (masked_b, pub_b) = generate(&ctx, session.session_id, curve);

        let secret_ab = derive(&ctx, session.session_id, SCOPE_LOCAL, masked_a, pub_b);
        let secret_ba = derive(&ctx, session.session_id, SCOPE_LOCAL, masked_b, pub_a);

        for secret in [&secret_ab, &secret_ba] {
            assert_eq!(
                secret.len(),
                masked_secret_len(curve),
                "masked shared-secret envelope length must match the curve",
            );
            assert!(
                secret.iter().any(|&b| b != 0),
                "masked shared secret must not be all-zero",
            );
        }
    }
}

#[test]
fn ecdh_derive_scopes_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let (masked_a, _pub_a) = generate(&ctx, session.session_id, ECC_CURVE_P256);
    let (_masked_b, pub_b) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    // The derived secret can be masked under any provisioned scope.
    for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
        let secret = derive(
            &ctx,
            session.session_id,
            scope,
            masked_a.clone(),
            pub_b.clone(),
        );
        assert_eq!(secret.len(), masked_secret_len(ECC_CURVE_P256));
        assert!(secret.iter().any(|&b| b != 0));
    }
}

#[test]
fn ecdh_derive_bad_peer_pub_len_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_a, pub_b) = {
        let (ma, _) = generate(&ctx, session.session_id, ECC_CURVE_P256);
        let (_, pb) = generate(&ctx, session.session_id, ECC_CURVE_P256);
        (ma, pb)
    };

    // A peer public key one byte short of the P-256 wire length (64) is
    // rejected before any derivation.
    let mut truncated = pub_b;
    truncated.pop();
    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            masked_key: masked_a,
            peer_pub_key: truncated,
        },
        TborStatus::InvalidArg,
    );
}
