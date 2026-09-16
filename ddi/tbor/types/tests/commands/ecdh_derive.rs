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
//! TBOR command to observe its plaintext), these tests validate command
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
use azihsm_ddi_tbor_types::PSK_LEN;

use crate::commands::common::SCOPE_EPHEMERAL;
use crate::commands::common::SCOPE_LOCAL;
use crate::commands::common::SCOPE_SECURITY_DOMAIN;
use crate::commands::common::SCOPE_SESSION;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap;
use crate::commands::unwrap_key::unwrap_with_usage;
use crate::harness::bootstrap_rotated_co;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CO_PSK;

const CO: u8 = 0;
const CU: u8 = 1;

/// Non-default CU PSK used to pass the default-PSK gate.
const ROTATED_CU_PSK: [u8; PSK_LEN] = [0xA5; PSK_LEN];

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
            key_usage: KEY_USAGE_DERIVE,
            key_label: Vec::new(),
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

/// Derives well-formed masked shared secrets in both directions for every supported ECC curve.
#[test]
fn ecdh_derive_all_curves() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for curve in [ECC_CURVE_P256, ECC_CURVE_P384, ECC_CURVE_P521] {
        // Exercise the complete supported curve set.
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
            assert!(secret.iter().any(|&b| b != 0));
        }
    }
}

/// Derives a shared secret into every provisioned output scope.
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

/// Rejects peer public keys whose length is one byte short for every supported curve.
#[test]
fn ecdh_derive_bad_peer_pub_len_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for curve in [ECC_CURVE_P256, ECC_CURVE_P384, ECC_CURVE_P521] {
        let (masked_key, _) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, curve);
        let (_, mut peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, curve);

        peer_pub.pop();

        ctx.expect_fw_reject(
            &TborEcdhDeriveReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                masked_key,
                peer_pub_key: peer_pub,
            },
            TborStatus::InvalidArg,
        );
    }
}

/// Rejects an overlong P-256 peer public key with `InvalidArg`.
#[test]
fn ecdh_derive_p256_peer_pub_trailing_byte_rejected() {
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

/// Rejects an overlong P-384 peer public key with `InvalidArg`.
#[test]
fn ecdh_derive_p384_peer_pub_trailing_byte_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P384);
    let (_, peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P384);
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

/// Rejects an overlong P-521 peer public key at the TBOR fixed-length boundary.
#[test]
fn ecdh_derive_p521_peer_pub_trailing_byte_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let (masked_key, _) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P521);
    let (_, peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P521);

    // A valid P-521 peer public key already occupies the full 136-byte
    // `peer_pub_key` TBOR maximum. Appending one byte makes it 137 bytes,
    // so TBOR rejects the request before curve-specific ECDH validation.
    let overlong = [peer_pub.as_slice(), &[0xAA]].concat();

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            masked_key,
            peer_pub_key: overlong,
        },
        TborStatus::TborInvalidFixedLength,
    );
}

/// Rejects every supported local/peer curve mismatch based on peer wire length.
#[test]
fn ecdh_derive_peer_curve_mismatch_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for (local_curve, peer_curve) in [
        (ECC_CURVE_P256, ECC_CURVE_P384),
        (ECC_CURVE_P256, ECC_CURVE_P521),
        (ECC_CURVE_P384, ECC_CURVE_P256),
        (ECC_CURVE_P384, ECC_CURVE_P521),
        (ECC_CURVE_P521, ECC_CURVE_P256),
        (ECC_CURVE_P521, ECC_CURVE_P384),
    ] {
        let (masked_key, _) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, local_curve);
        let (_, peer_pub) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, peer_curve);

        ctx.expect_fw_reject(
            &TborEcdhDeriveReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                masked_key,
                peer_pub_key: peer_pub,
            },
            TborStatus::InvalidArg,
        );
    }
}

/// Rejects all-zero peer coordinates for every supported ECC curve.
#[test]
fn ecdh_derive_invalid_peer_coordinates_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for curve in [ECC_CURVE_P256, ECC_CURVE_P384, ECC_CURVE_P521] {
        let (masked_key, peer_pub) =
            generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, curve);

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
}

/// Rejects P-256 peer coordinates that exceed the field modulus upper bound.
#[test]
fn ecdh_derive_peer_coordinates_above_upper_bound_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let (masked_key, _) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);

    // P-256 wire format is x_le || y_le, with 32 bytes per coordinate.
    // All-ones coordinates are larger than the P-256 field modulus, so this
    // specifically exercises the coordinate upper-bound validation branch.
    let peer_pub = vec![0xff; 64];

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            masked_key,
            peer_pub_key: peer_pub,
        },
        TborStatus::EccPublicKeyValidationFailed,
    );
}

/// Rejects an in-range P-256 peer point that does not satisfy the curve equation.
#[test]
fn ecdh_derive_off_curve_peer_point_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let (masked_key, _) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);

    // P-256 wire format is x_le || y_le, with 32 bytes per coordinate.
    // x = 1 and y = 1 are both in range, but (1, 1) is not on the P-256 curve.
    let mut peer_pub = vec![0u8; 64];
    peer_pub[0] = 1;
    peer_pub[32] = 1;

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            masked_key,
            peer_pub_key: peer_pub,
        },
        TborStatus::EccPointValidationFailed,
    );
}

/// Rejects a masked private key after its authenticated envelope is tampered with.
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

/// Rejects a valid masked key when its key class is AES instead of ECC.
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

/// Rejects derivation into a target scope whose masking key is not provisioned.
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

/// Rejects a request whose `session_id` does not match the active device-handle session.
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

/// Rejects ECDH derive from a CO session until the default CO PSK is rotated.
#[test]
fn ecdh_derive_rejects_default_co_psk() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open CO session under default PSK");

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id(),
            scope: SCOPE_SESSION,
            masked_key: Vec::new(),
            peer_pub_key: Vec::new(),
        },
        TborStatus::DefaultPskMustRotate,
    );
}

/// Rejects ECDH derive from a CU session until the default CU PSK is rotated.
#[test]
fn ecdh_derive_rejects_default_cu_psk() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open CU session under default PSK");

    ctx.expect_fw_reject(
        &TborEcdhDeriveReq {
            session_id: session.session_id(),
            scope: SCOPE_SESSION,
            masked_key: Vec::new(),
            peer_pub_key: Vec::new(),
        },
        TborStatus::DefaultPskMustRotate,
    );
}

/// Allows session-scoped ECDH keys and results before partition finalization.
#[test]
fn ecdh_derive_session_scope_before_finalize() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (masked_a, _) = generate_in_scope(&ctx, session.session_id, SCOPE_SESSION, ECC_CURVE_P256);
    let (_, pub_b) = generate_in_scope(&ctx, session.session_id, SCOPE_SESSION, ECC_CURVE_P256);

    let secret = derive(&ctx, session.session_id, SCOPE_SESSION, masked_a, pub_b);
    assert_eq!(secret.len(), masked_secret_len(ECC_CURVE_P256));
}

/// Allows ECDH derivation from a Crypto-User (`PlainText`) session after PSK rotation.
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

/// Derives successfully with an imported ECC private key that has `Derive` usage.
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

/// Rejects an imported ECC key that lacks `Derive` permission.
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

/// Rejects a request with an empty peer public-key payload.
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

/// Rejects a request with an empty masked private-key envelope.
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

/// Rejects a masked private-key envelope that is shorter than its fixed length.
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

/// Rejects an unknown output-scope discriminant.
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

/// Rejects a Local output scope before the partition is finalized.
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

/// Rejects an Ephemeral output scope before the partition is finalized.
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

/// Rejects reuse of a session-scoped ECC private key from a replacement session.
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

/// Allows reuse of a Local-scoped ECC private key after reopening the session.
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
}
