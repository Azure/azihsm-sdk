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
//! command's plumbing: well-formed masked secrets for every curve and
//! provisioned scope; exact peer-key length and point validation; masked-key
//! authentication and class checks; target-scope and session validation.
//! The underlying ECDH primitive's correctness is covered by the MBOR
//! `EcdhKeyExchange` tests and the std-PAL ECC driver tests, which share the
//! same `pal.ecdh_derive`.

#![cfg(feature = "emu")]

use azihsm_crypto::EccCurve;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::ExportableKey;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::TborEcdhDeriveReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::ECC_CURVE_P384;
use azihsm_ddi_tbor_types::ECC_CURVE_P521;
use azihsm_ddi_tbor_types::KEY_CLASS_AES;
use azihsm_ddi_tbor_types::KEY_CLASS_ECC;
use azihsm_ddi_tbor_types::KEY_USAGE_DERIVE;
use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;
use azihsm_ddi_tbor_types::KEY_USAGE_VERIFY;

use crate::commands::common::SCOPE_EPHEMERAL;
use crate::commands::common::SCOPE_LOCAL;
use crate::commands::common::SCOPE_SECURITY_DOMAIN;
use crate::commands::common::SCOPE_SESSION;
use crate::commands::part_init::bootstrap_rotated_co;
use crate::commands::part_init::CO;
use crate::commands::part_init::CU;
use crate::commands::part_init::ROTATED_CO_PSK;
use crate::commands::part_init::ROTATED_CU_PSK;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap;
use crate::commands::unwrap_key::unwrap_with_usage;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;
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

/// Generate an ECC key on-device under `scope`.
fn generate_in_scope(ctx: &TestCtx, session_id: u16, scope: u8, curve: u8) -> (Vec<u8>, Vec<u8>) {
    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope,
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
fn ecdh_derive_all_curves() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for curve in [ECC_CURVE_P256, ECC_CURVE_P384, ECC_CURVE_P521] {
        // Two device-generated keypairs on the same curve; each side's
        // public key is a valid wire-LE peer point for the other.
        let (masked_a, pub_a) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, curve);
        let (masked_b, pub_b) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, curve);

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
fn ecdh_derive_scopes() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let (masked_a, _pub_a) =
        generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);
    let (_masked_b, pub_b) =
        generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);

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
fn ecdh_derive_bad_peer_pub_len_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_a, pub_b) = {
        let (ma, _) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);
        let (_, pb) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);
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

/// Rejects trailing bytes in an otherwise valid peer public key.
#[test]
fn ecdh_derive_peer_pub_trailing_byte_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);
    let (_, peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);

    let overlong = [peer_pub.as_slice(), &[0xAA]].concat();
    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            masked_key,
            peer_pub_key: overlong,
        },
        TborStatus::InvalidArg,
    );
}

/// Rejects a peer public key whose wire size belongs to another curve.
#[test]
fn ecdh_derive_peer_curve_mismatch_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);
    let (_, p384_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P384);

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            masked_key,
            peer_pub_key: p384_pub,
        },
        TborStatus::InvalidArg,
    );
}

/// Rejects a correctly sized peer point that is not a valid curve point.
#[test]
fn ecdh_derive_invalid_peer_point_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, peer_pub) =
        generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            masked_key,
            peer_pub_key: vec![0; peer_pub.len()],
        },
        TborStatus::EccPublicKeyValidationFailed,
    );
}

/// Rejects a masked private key whose authenticated ciphertext was modified.
#[test]
fn ecdh_derive_tampered_masked_key_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (mut masked_key, _) =
        generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);
    let (_, peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);
    let last = masked_key.len() - 1;
    masked_key[last] ^= 1;

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            masked_key,
            peer_pub_key: peer_pub,
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// Rejects a valid masked key whose class is AES rather than ECC private.
#[test]
fn ecdh_derive_wrong_key_class_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let aes = unwrap(&ctx, session.session_id, KEY_CLASS_AES, &[0x54; 32]);
    let (_, peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            masked_key: aes.masked_key,
            peer_pub_key: peer_pub,
        },
        TborStatus::InvalidKeyType,
    );
}

/// Rejects a target scope whose masking key has not been provisioned.
#[test]
fn ecdh_derive_unsupported_target_scope_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);
    let (_, peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_SECURITY_DOMAIN,
            masked_key,
            peer_pub_key: peer_pub,
        },
        TborStatus::UnsupportedKeyScope,
    );
}

/// Rejects deriving when the request uses a `session_id` that does not match the active session on this device handle.
#[test]
fn ecdh_derive_unknown_session_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);
    let (_, peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);
    assert_ne!(session.session_id, u16::MAX, "test requires an unused id");

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: u16::MAX,
            scope: SCOPE_LOCAL,
            masked_key,
            peer_pub_key: peer_pub,
        },
        TborStatus::FileHandleSessionIdDoesNotMatch,
    );
}

/// Session-scoped keys and results work before partition finalization.
#[test]
fn ecdh_derive_session_scope_before_finalize() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (masked_a, _) = generate_in_scope(&ctx, session.session_id, SCOPE_SESSION, ECC_CURVE_P256);
    let (_, pub_b) = generate_in_scope(&ctx, session.session_id, SCOPE_SESSION, ECC_CURVE_P256);

    let secret = derive(&ctx, session.session_id, SCOPE_SESSION, masked_a, pub_b);
    assert_eq!(secret.len(), masked_secret_len(ECC_CURVE_P256));
}

/// Confirms a Crypto-User (`PlainText`) session is authorized to derive.
#[test]
fn ecdh_derive_allowed_on_crypto_user_session() {
    let ctx = TestCtx::new();
    let bootstrap = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open bootstrap CU session");
    ctx.psk_change(bootstrap.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");
    bootstrap.close().expect("close bootstrap CU session");

    let opts = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_CU_PSK);
    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("open CU session under rotated PSK");
    let session = ctx
        .session_open_finish(pending)
        .expect("finish CU session open");
    let (masked_a, _) = generate_in_scope(&ctx, session.session_id, SCOPE_SESSION, ECC_CURVE_P256);
    let (_, pub_b) = generate_in_scope(&ctx, session.session_id, SCOPE_SESSION, ECC_CURVE_P256);

    let secret = derive(&ctx, session.session_id, SCOPE_SESSION, masked_a, pub_b);
    assert_eq!(secret.len(), masked_secret_len(ECC_CURVE_P256));
}

/// Derives with an ECC private key imported with `Derive` usage.
#[test]
fn ecdh_derive_with_unwrapped_key() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let host_key = EccPrivateKey::from_curve(EccCurve::P256).expect("generate host ECC key");
    let der = host_key.to_vec().expect("PKCS#8 DER export");
    let imported = unwrap_with_usage(
        &ctx,
        session.session_id,
        KEY_CLASS_ECC,
        KEY_USAGE_DERIVE,
        &der,
    );
    let (_, peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);

    let secret = derive(
        &ctx,
        session.session_id,
        SCOPE_LOCAL,
        imported.masked_key,
        peer_pub,
    );
    assert_eq!(secret.len(), masked_secret_len(ECC_CURVE_P256));
}

/// Rejects an imported ECC key that has signing but not derivation usage.
#[test]
fn ecdh_derive_key_without_derive_usage_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let host_key = EccPrivateKey::from_curve(EccCurve::P256).expect("generate host ECC key");
    let der = host_key.to_vec().expect("PKCS#8 DER export");
    let imported = unwrap_with_usage(
        &ctx,
        session.session_id,
        KEY_CLASS_ECC,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &der,
    );
    let (_, peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            masked_key: imported.masked_key,
            peer_pub_key: peer_pub,
        },
        TborStatus::InvalidPermissions,
    );
}

/// Rejects an empty peer public key.
#[test]
fn ecdh_derive_empty_peer_pub_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            masked_key,
            peer_pub_key: Vec::new(),
        },
        TborStatus::InvalidArg,
    );
}

/// Rejects an empty masked private-key envelope.
#[test]
fn ecdh_derive_empty_masked_key_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (_, peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            masked_key: Vec::new(),
            peer_pub_key: peer_pub,
        },
        TborStatus::TborInvalidFixedLength,
    );
}

/// Rejects a truncated masked private-key envelope.
#[test]
fn ecdh_derive_truncated_masked_key_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (mut masked_key, _) =
        generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);
    let (_, peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);

    masked_key.pop();

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            masked_key,
            peer_pub_key: peer_pub,
        },
        TborStatus::TborInvalidFixedLength,
    );
}

/// Rejects an unknown target-scope discriminant.
#[test]
fn ecdh_derive_invalid_scope_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);
    let (_, peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: 0xff,
            masked_key,
            peer_pub_key: peer_pub,
        },
        TborStatus::UnsupportedKeyScope,
    );
}

/// Rejects a Local result scope before partition finalization.
#[test]
fn ecdh_derive_local_target_before_finalize_rejected() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let (masked_key, _) =
        generate_in_scope(&ctx, session.session_id, SCOPE_SESSION, ECC_CURVE_P256);
    let (_, peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_SESSION, ECC_CURVE_P256);

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            masked_key,
            peer_pub_key: peer_pub,
        },
        TborStatus::UnsupportedKeyScope,
    );
}

/// Rejects an Ephemeral result scope before partition finalization.
#[test]
fn ecdh_derive_ephemeral_target_before_finalize_rejected() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let (masked_key, _) =
        generate_in_scope(&ctx, session.session_id, SCOPE_SESSION, ECC_CURVE_P256);
    let (_, peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_SESSION, ECC_CURVE_P256);

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_EPHEMERAL,
            masked_key,
            peer_pub_key: peer_pub,
        },
        TborStatus::UnsupportedKeyScope,
    );
}

/// Rejects a session-scoped ECC private key after its originating session is closed.
#[test]
fn ecdh_derive_session_key_from_other_session_rejected() {
    let ctx = TestCtx::new();
    let session_a = finalized_co_session(&ctx);

    let (masked_key, _) =
        generate_in_scope(&ctx, session_a.session_id, SCOPE_SESSION, ECC_CURVE_P256);

    ctx.session_close(session_a.session_id)
        .expect("close originating CO session");

    let opts =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&ROTATED_CO_PSK);

    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("open replacement CO session");

    let session_b = ctx
        .session_open_finish(pending)
        .expect("finish replacement CO session");

    let (_, peer_pub) =
        generate_in_scope(&ctx, session_b.session_id, SCOPE_SESSION, ECC_CURVE_P256);

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session_b.session_id,
            scope: SCOPE_SESSION,
            masked_key,
            peer_pub_key: peer_pub,
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// A local-scoped ECC private key remains usable after reopening the session.
#[test]
fn ecdh_derive_local_key_across_sessions() {
    let ctx = TestCtx::new();
    let session_a = finalized_co_session(&ctx);

    let (masked_key, _) =
        generate_in_scope(&ctx, session_a.session_id, SCOPE_LOCAL, ECC_CURVE_P256);

    ctx.session_close(session_a.session_id)
        .expect("close originating CO session");

    let opts =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&ROTATED_CO_PSK);

    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("open replacement CO session");

    let session_b = ctx
        .session_open_finish(pending)
        .expect("finish replacement CO session");

    let (_, peer_pub) = generate_in_scope(&ctx, session_b.session_id, SCOPE_LOCAL, ECC_CURVE_P256);

    let secret = derive(
        &ctx,
        session_b.session_id,
        SCOPE_LOCAL,
        masked_key,
        peer_pub,
    );

    assert_eq!(
        secret.len(),
        masked_secret_len(ECC_CURVE_P256),
        "local-scoped key must remain usable after reopening the session",
    );

    assert!(
        secret.iter().any(|&b| b != 0),
        "derived secret must not be all-zero",
    );
}
