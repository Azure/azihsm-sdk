// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `EccSign` command.
//!
//! `EccSign` produces a raw ECDSA `r ‖ s` signature over a host-supplied
//! pre-computed digest using a caller-held **masked** ECC private key
//! (from [`EccGenerateKey`](super::ecc_generate_key)). These tests
//! generate a key on-device, sign a digest, and verify the signature on
//! the host with `azihsm_crypto` (OpenSSL) against the returned public key
//! — exercising the full unmask → sign → return path for every curve.
//!
//! The device speaks the PKA-native **little-endian** wire format: the
//! public key is `x_le ‖ y_le` and the signature is `r_le ‖ s_le` (each
//! component zero-padded to the curve's wire coordinate length; P-521 pads
//! 66→68). `azihsm_crypto` is big-endian native, so the test reverses
//! each component before verifying. The host verifies the full big-endian
//! digest; ECDSA truncation retains its most significant curve-width bits
//! when the digest is longer than the curve's order.

#![cfg(feature = "emu")]

use azihsm_crypto::EccCurve;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::ExportableKey;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_cu;
use azihsm_ddi_tbor_test_harness::SessionOpenInitOptions;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::ROTATED_CU_PSK;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::TborEccSignReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::ECC_CURVE_P384;
use azihsm_ddi_tbor_types::ECC_CURVE_P521;
use azihsm_ddi_tbor_types::KEY_CLASS_AES;
use azihsm_ddi_tbor_types::KEY_CLASS_ECC;
use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;

use crate::commands::common::assert_ecc_signs;
use crate::commands::common::sign;
use crate::commands::common::verify_wire_ecdsa;
use crate::commands::common::with_generated_ecc_key;
use crate::commands::common::CO;
use crate::commands::common::SCOPE_LOCAL;
use crate::commands::common::SCOPE_SESSION;
#[cfg(feature = "emu")]
use crate::commands::sd_sealing_key_gen::finalized_co_session;
#[cfg(feature = "emu")]
use crate::commands::unwrap_key::unwrap;

/// All supported ECC curves used by command tests.
pub(crate) const ECC_CURVES: [u8; 3] = [ECC_CURVE_P256, ECC_CURVE_P384, ECC_CURVE_P521];

/// `KeyScope::Unspecified` discriminant.
#[cfg(feature = "emu")]
const SCOPE_UNSPECIFIED: u8 = 0b000;

/// `KeyScope::Internal` discriminant.
#[cfg(feature = "emu")]
const SCOPE_INTERNAL: u8 = 0b101;

/// Generate an ECC key on-device for `curve` under `scope`.
fn generate_in_scope(ctx: &TestCtx, session_id: u16, scope: u8, curve: u8) -> (Vec<u8>, Vec<u8>) {
    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope,
            curve,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");
    (resp.masked_key, resp.pub_key)
}

/// Signs and verifies a curve-appropriate digest on every supported ECC curve.
#[test]
fn ecc_sign_roundtrip_all_curves() {
    for (curve, digest_len) in [
        (ECC_CURVE_P256, 32usize),
        (ECC_CURVE_P384, 48usize),
        (ECC_CURVE_P521, 64usize),
    ] {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            assert_ecc_signs(ctx, session_id, masked_key, &pub_key, digest_len);
        });
    }
}

/// Verifies every supported ECC curve and SHA-2 digest-length pairing.
#[test]
fn ecc_sign_all_supported_curve_digest_pairs() {
    for (curve, digest_lens) in [
        (ECC_CURVE_P256, &[32usize, 48, 64][..]),
        (ECC_CURVE_P384, &[32usize, 48, 64][..]),
        (ECC_CURVE_P521, &[32usize, 48, 64][..]),
    ] {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            for &digest_len in digest_lens {
                let digest: Vec<u8> = (0..digest_len)
                    .map(|i| (i as u8).wrapping_mul(13).wrapping_add(0x29))
                    .collect();
                let signature = sign(ctx, session_id, masked_key.clone(), &digest);
                assert!(
                    verify_wire_ecdsa(&pub_key, &signature, &digest),
                    "signature must verify for curve {curve} with a {digest_len}-byte digest",
                );
            }
        });
    }
}

/// Confirms a signature authenticates only the digest that was actually signed.
#[test]
fn ecc_sign_signature_rejects_different_digest() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let digest = vec![0x31; 32];
            let signature = sign(ctx, session_id, masked_key, &digest);

            let different_digest = vec![0x32; 32];
            assert!(verify_wire_ecdsa(&pub_key, &signature, &digest));
            assert!(
                !verify_wire_ecdsa(&pub_key, &signature, &different_digest),
                "signature must not verify against a different digest",
            );
        });
    }
}

/// Confirms distinct digest request values produce signatures bound to each digest.
#[test]
fn ecc_sign_distinct_digests_are_independently_verified() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let digest_a = vec![0x11; 32];
            let digest_b = vec![0x22; 32];

            let signature_a = sign(ctx, session_id, masked_key.clone(), &digest_a);

            let signature_b = sign(ctx, session_id, masked_key, &digest_b);
            assert!(
                verify_wire_ecdsa(&pub_key, &signature_a, &digest_a),
                "first signature must verify against its original digest",
            );

            assert!(
                verify_wire_ecdsa(&pub_key, &signature_b, &digest_b),
                "second signature must verify against its original digest",
            );

            assert!(
                !verify_wire_ecdsa(&pub_key, &signature_a, &digest_b),
                "first signature must not verify against the second digest",
            );

            assert!(
                !verify_wire_ecdsa(&pub_key, &signature_b, &digest_a),
                "second signature must not verify against the first digest",
            );
        });
    }
}

/// Signs and verifies a digest containing zero-valued bytes.
#[test]
fn ecc_sign_digest_with_zero_bytes_roundtrip() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let mut digest = vec![0u8; 32];
            digest[1] = 0xA5;
            digest[15] = 0x5A;
            digest[30] = 0xC3;
            let signature = sign(ctx, session_id, masked_key, &digest);
            assert!(
                verify_wire_ecdsa(&pub_key, &signature, &digest),
                "digest containing zero bytes must survive the TBOR request unchanged",
            );
        });
    }
}

/// Verifies P-521 signatures zero-fill the two wire-padding bytes per component.
#[test]
fn ecc_sign_p521_signature_padding_is_zero() {
    with_generated_ecc_key(ECC_CURVE_P521, |ctx, session_id, masked_key, pub_key| {
        let digest = vec![0x43; 64];
        let signature = sign(ctx, session_id, masked_key, &digest);
        assert_eq!(signature.len(), 136);
        assert_eq!(&signature[66..68], &[0, 0], "r padding must be zero");
        assert_eq!(&signature[134..136], &[0, 0], "s padding must be zero");
        assert!(verify_wire_ecdsa(&pub_key, &signature, &digest));
    });
}

/// Signs and verifies with a key masked under the partition-local scope.
#[cfg(feature = "emu")]
#[test]
fn ecc_sign_local_scoped_key_emu() {
    for curve in ECC_CURVES {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);
        let (masked_key, pub_key) = generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, curve);
        let digest = vec![0x5A; 32];
        let signature = sign(&ctx, session.session_id, masked_key, &digest);
        assert!(verify_wire_ecdsa(&pub_key, &signature, &digest));
    }
}

/// Confirms a Crypto-User (`PlainText`) session is authorized to sign.
#[test]
fn ecc_sign_allowed_on_crypto_user_session() {
    for curve in ECC_CURVES {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
        let (masked_key, pub_key) =
            generate_in_scope(&ctx, session.session_id, SCOPE_SESSION, curve);
        let digest = vec![0x6B; 32];
        let signature = sign(&ctx, session.session_id, masked_key, &digest);
        assert!(verify_wire_ecdsa(&pub_key, &signature, &digest));
    }
}

/// Signs and verifies with an ECC private key imported through `UnwrapKey`.
#[cfg(feature = "emu")]
#[test]
fn ecc_sign_with_unwrapped_key_emu() {
    for (curve, host_curve) in [
        (ECC_CURVE_P256, EccCurve::P256),
        (ECC_CURVE_P384, EccCurve::P384),
        (ECC_CURVE_P521, EccCurve::P521),
    ] {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);
        let host_key = EccPrivateKey::from_curve(host_curve).expect("generate host ECC key");
        let der = host_key.to_vec().expect("PKCS#8 DER export");
        let imported = unwrap(&ctx, session.session_id, KEY_CLASS_ECC, &der);
        assert!(
            !imported.pub_key.is_empty(),
            "an imported ECC key returns a re-derived public key",
        );
        let digest: Vec<u8> = (0..32)
            .map(|i| (i as u8).wrapping_mul(5).wrapping_add(3))
            .collect();
        let signature = sign(&ctx, session.session_id, imported.masked_key, &digest);
        assert!(
            verify_wire_ecdsa(&imported.pub_key, &signature, &digest),
            "signature from the unwrapped ECC key must verify for curve {curve}",
        );
    }
}

/// Rejects an empty digest because it does not identify a supported SHA-2 algorithm.
#[test]
fn ecc_sign_empty_digest_rejected() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, _pub_key| {
            ctx.expect_fw_reject(
                &TborEccSignReq {
                    session_id,
                    masked_key,
                    digest: Vec::new(),
                },
                TborStatus::InvalidArg,
            );
        });
    }
}

/// Rejects digest lengths that do not identify a supported SHA-2 algorithm.
#[test]
fn ecc_sign_non_sha2_digest_lengths_rejected() {
    for curve in ECC_CURVES {
        for digest_len in [1usize, 31, 33, 47, 49, 63] {
            with_generated_ecc_key(curve, |ctx, session_id, masked_key, _pub_key| {
                ctx.expect_fw_reject(
                    &TborEccSignReq {
                        session_id,
                        masked_key,
                        digest: vec![0xAB; digest_len],
                    },
                    TborStatus::InvalidArg,
                );
            });
        }
    }
}

/// Rejects the unsupported SHA-1 digest length.
#[test]
fn ecc_sign_unsupported_digest_len_rejected() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, _pub_key| {
            ctx.expect_fw_reject(
                &TborEccSignReq {
                    session_id,
                    masked_key,
                    digest: vec![0xAB; 20],
                },
                TborStatus::InvalidArg,
            );
        });
    }
}

/// Verifies long digests retain their most significant curve-width bits.
#[test]
fn ecc_sign_long_digests_use_most_significant_curve_bits() {
    for (curve, digest_len) in [
        (ECC_CURVE_P256, 48usize),
        (ECC_CURVE_P256, 64usize),
        (ECC_CURVE_P384, 64usize),
    ] {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let digest: Vec<u8> = (0..digest_len)
                .map(|index| u8::try_from(index).expect("digest byte offset must fit u8"))
                .collect();
            let signature = sign(ctx, session_id, masked_key, &digest);
            assert!(
                verify_wire_ecdsa(&pub_key, &signature, &digest),
                "long digest signature must verify (curve {curve}, digest {digest_len} B)",
            );

            let mut discarded_bit_changed = digest.clone();
            *discarded_bit_changed.first_mut().expect("nonempty digest") ^= 0x01;
            assert!(
                verify_wire_ecdsa(&pub_key, &signature, &discarded_bit_changed),
                "discarded low digest bits must not affect verification (curve {curve}, digest {digest_len} B)",
            );

            let mut retained_bit_changed = digest;
            *retained_bit_changed.last_mut().expect("nonempty digest") ^= 0x01;
            assert!(
                !verify_wire_ecdsa(&pub_key, &signature, &retained_bit_changed),
                "changed high digest bits must invalidate the signature (curve {curve}, digest {digest_len} B)",
            );
        });
    }
}

/// Rejects a masked private key whose authenticated ciphertext was modified.
#[test]
fn ecc_sign_tampered_masked_key_rejected() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, mut masked_key, _pub_key| {
            let last = masked_key
                .len()
                .checked_sub(1)
                .expect("masked ECC key must not be empty");
            masked_key[last] ^= 0x01;
            ctx.expect_fw_reject(
                &TborEccSignReq {
                    session_id,
                    masked_key,
                    digest: vec![0x7C; 32],
                },
                TborStatus::AesGcmDecryptTagDoesNotMatch,
            );
        });
    }
}

/// Rejects a valid masked key whose key class is AES rather than ECC private.
#[cfg(feature = "emu")]
#[test]
fn ecc_sign_wrong_key_class_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let aes = unwrap(&ctx, session.session_id, KEY_CLASS_AES, &[0x54; 32]);

    ctx.expect_fw_reject(
        &TborEccSignReq {
            session_id: session.session_id,
            masked_key: aes.masked_key,
            digest: vec![0x65; 32],
        },
        TborStatus::InvalidKeyType,
    );
}

#[test]
fn ecc_sign_mismatched_session_id_rejected() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, _pub_key| {
            let mismatched_session_id = u16::MAX;

            assert_ne!(
                session_id, mismatched_session_id,
                "test requires a mismatched session id",
            );

            ctx.expect_fw_reject(
                &TborEccSignReq {
                    session_id: mismatched_session_id,
                    masked_key,
                    digest: vec![0x8D; 32],
                },
                TborStatus::FileHandleSessionIdDoesNotMatch,
            );
        });
    }
}

/// Rejects `KeyScope::Unspecified` for a caller-generated ECC key.
#[cfg(feature = "emu")]
#[test]
fn ecc_generate_key_unspecified_scope_rejected_emu() {
    for curve in ECC_CURVES {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        ctx.expect_fw_reject(
            &TborEccGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_UNSPECIFIED,
                curve,
                key_usage: KEY_USAGE_SIGN,
                key_label: Vec::new(),
            },
            TborStatus::UnsupportedKeyScope,
        );
    }
}

/// Rejects the firmware-internal scope for a caller-generated ECC key.
#[cfg(feature = "emu")]
#[test]
fn ecc_generate_key_internal_scope_rejected_emu() {
    for curve in ECC_CURVES {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        ctx.expect_fw_reject(
            &TborEccGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_INTERNAL,
                curve,
                key_usage: KEY_USAGE_SIGN,
                key_label: Vec::new(),
            },
            TborStatus::UnsupportedKeyScope,
        );
    }
}

/// Confirms a signature does not verify against a different public key.
#[test]
fn ecc_sign_signature_rejects_different_public_key() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let other = ctx
                .tbor(&TborEccGenerateKeyReq {
                    session_id,
                    scope: SCOPE_SESSION,
                    curve,
                    key_usage: KEY_USAGE_SIGN,
                    key_label: Vec::new(),
                })
                .expect("EccGenerateKey");
            let digest = vec![0x42; 32];
            let signature = sign(ctx, session_id, masked_key, &digest);
            assert!(
                verify_wire_ecdsa(&pub_key, &signature, &digest),
                "signature must verify against the originating public key",
            );
            assert!(
                !verify_wire_ecdsa(&other.pub_key, &signature, &digest),
                "signature must not verify against a different public key",
            );
        });
    }
}

/// Rejects a session-scoped ECC private key from a replacement session.
#[test]
fn ecc_sign_session_scoped_key_rejected_in_different_session() {
    for curve in ECC_CURVES {
        let ctx = TestCtx::new();
        let session_a = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
        let (masked_key, _) = generate_in_scope(&ctx, session_a.session_id, SCOPE_SESSION, curve);
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
        ctx.expect_fw_reject(
            &TborEccSignReq {
                session_id: session_b.session_id,
                masked_key,
                digest: vec![0x91; 32],
            },
            TborStatus::AesGcmDecryptTagDoesNotMatch,
        );
    }
}

/// Confirms changing one bit of the digest invalidates the signature.
#[test]
fn ecc_sign_signature_rejects_single_bit_digest_change() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let digest = vec![0xA5; 32];
            let signature = sign(ctx, session_id, masked_key, &digest);
            let mut modified_digest = digest.clone();
            modified_digest[17] ^= 0x01;
            assert!(
                verify_wire_ecdsa(&pub_key, &signature, &digest),
                "signature must verify against the original digest",
            );

            assert!(
                !verify_wire_ecdsa(&pub_key, &signature, &modified_digest),
                "changing one digest bit must invalidate the signature",
            );
        });
    }
}

/// Signs and verifies an all-zero SHA-256 digest.
#[test]
fn ecc_sign_all_zero_digest_roundtrip() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let digest = vec![0u8; 32];
            let signature = sign(ctx, session_id, masked_key, &digest);
            assert!(
                verify_wire_ecdsa(&pub_key, &signature, &digest),
                "an all-zero 32-byte digest must be signed and verified correctly",
            );
        });
    }
}

/// Signs and verifies a SHA-256 digest containing all 0xFF bytes.
#[test]
fn ecc_sign_all_ones_digest_roundtrip() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            let digest = vec![0xFF; 32];
            let signature = sign(ctx, session_id, masked_key, &digest);
            assert!(
                verify_wire_ecdsa(&pub_key, &signature, &digest),
                "an all-0xFF digest must be signed and verified correctly",
            );
        });
    }
}

/// Confirms the same masked ECC key can sign multiple digests.
#[test]
fn ecc_sign_masked_key_can_be_reused() {
    for curve in ECC_CURVES {
        with_generated_ecc_key(curve, |ctx, session_id, masked_key, pub_key| {
            for value in [0x11u8, 0x22, 0x33] {
                let digest = vec![value; 32];
                let signature = sign(ctx, session_id, masked_key.clone(), &digest);
                assert!(
                    verify_wire_ecdsa(&pub_key, &signature, &digest),
                    "reused masked key must sign digest value {value:#04x}",
                );
            }
        });
    }
}
