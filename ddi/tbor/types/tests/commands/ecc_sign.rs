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
//! each component before verifying. Likewise the device internally
//! reverses the supplied wire-LE digest to big-endian before signing, so
//! the host verifies against the reversed digest.

#![cfg(feature = "emu")]

use azihsm_crypto::EccAlgo;
use azihsm_crypto::EccCurve;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::EccPublicKey;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::Verifier;
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

use crate::commands::common::CO;
use crate::commands::common::SCOPE_LOCAL;
use crate::commands::common::SCOPE_SESSION;
#[cfg(feature = "emu")]
use crate::commands::sd_sealing_key_gen::finalized_co_session;
#[cfg(feature = "emu")]
use crate::commands::unwrap_key::unwrap;
use crate::harness::bootstrap_rotated_co;
use crate::harness::bootstrap_rotated_cu;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CO_PSK;
use crate::harness::ROTATED_CU_PSK;

/// `KeyScope::Unspecified` discriminant.
#[cfg(feature = "emu")]
const SCOPE_UNSPECIFIED: u8 = 0b000;

/// `KeyScope::Internal` discriminant.
#[cfg(feature = "emu")]
const SCOPE_INTERNAL: u8 = 0b101;

/// Per-curve wire sizes: `(wire_coord_len, raw_coord_len)`.
///
/// `wire_coord_len` is the padded on-wire component size (P-521 → 68);
/// `raw_coord_len` is the cryptographic component size (P-521 → 66).
fn coord_sizes(pub_len: usize) -> (usize, usize) {
    match pub_len {
        64 => (32, 32),
        96 => (48, 48),
        136 => (68, 66),
        _ => panic!("unexpected public-key length {pub_len}"),
    }
}

/// Generate an ECC key on-device for `curve`, returning `(masked_key, wire_pub_key)`.
fn generate(ctx: &TestCtx, session_id: u16, curve: u8) -> (Vec<u8>, Vec<u8>) {
    generate_in_scope(ctx, session_id, SCOPE_SESSION, curve)
}

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

/// Sign `digest` with a caller-held masked key.
fn sign(ctx: &TestCtx, session_id: u16, masked_key: Vec<u8>, digest: &[u8]) -> Vec<u8> {
    ctx.tbor(&TborEccSignReq {
        session_id,
        masked_key,
        digest: digest.to_vec(),
    })
    .expect("EccSign")
    .signature
}

/// Reverse the low `len` bytes of `src` into a fresh big-endian vec.
fn rev(src: &[u8], len: usize) -> Vec<u8> {
    src[..len].iter().rev().copied().collect()
}

/// Verify a wire-LE ECDSA signature on the host with `azihsm_crypto`.
///
/// * `pub_le` — `x_le ‖ y_le`, each `wire_coord_len` bytes.
/// * `sig_le` — `r_le ‖ s_le`, each `wire_coord_len` bytes.
/// * `digest_le` — the wire-LE digest that was handed to `EccSign`.
fn verify_wire_ecdsa(pub_le: &[u8], sig_le: &[u8], digest_le: &[u8]) -> bool {
    let (wire_coord, raw_coord) = coord_sizes(pub_le.len());
    assert_eq!(sig_le.len(), wire_coord * 2, "signature length mismatch");

    // Public key: reverse each full padded wire coordinate → big-endian
    // `hsm_point_size` coordinates. Trailing LE pad becomes leading BE
    // zeros, which `from_hsm_bytes` tolerates.
    let (x_le, y_le) = pub_le.split_at(wire_coord);
    let mut pub_be = rev(x_le, wire_coord);
    pub_be.extend(rev(y_le, wire_coord));
    let pubkey = EccPublicKey::from_hsm_bytes(&pub_be).expect("import public key");

    // Signature: reverse the meaningful `raw_coord` bytes of each component
    // → big-endian `r ‖ s`.
    let (r_le, s_le) = sig_le.split_at(wire_coord);
    let mut sig_be = rev(r_le, raw_coord);
    sig_be.extend(rev(s_le, raw_coord));

    // The device reversed the wire-LE digest to big-endian before signing;
    // verify against that same big-endian digest.
    let digest_be = rev(digest_le, digest_le.len());

    Verifier::verify(&mut EccAlgo::default(), &pubkey, &digest_be, &sig_be)
        .expect("host ECDSA verify")
}

/// Signs and verifies a curve-appropriate digest on every supported ECC curve.
#[test]
fn ecc_sign_roundtrip_all_curves() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    for (curve, digest_len) in [
        (ECC_CURVE_P256, 32usize),
        (ECC_CURVE_P384, 48usize),
        (ECC_CURVE_P521, 64usize),
    ] {
        let (masked_key, pub_key) = generate(&ctx, session.session_id, curve);

        let digest: Vec<u8> = (0..digest_len)
            .map(|i| (i as u8).wrapping_mul(7).wrapping_add(0x11))
            .collect();

        let signature = sign(&ctx, session.session_id, masked_key, &digest);

        assert_eq!(
            signature.len(),
            pub_key.len(),
            "wire signature length equals wire public-key length for curve {curve}",
        );
        assert!(
            verify_wire_ecdsa(&pub_key, &signature, &digest),
            "ECDSA signature must verify against the generated public key (curve {curve})",
        );
    }
}

/// Verifies every supported ECC curve and SHA-2 digest-length pairing.
#[test]
fn ecc_sign_all_supported_curve_digest_pairs() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    for (curve, digest_lens) in [
        (ECC_CURVE_P256, &[32usize][..]),
        (ECC_CURVE_P384, &[32usize, 48][..]),
        (ECC_CURVE_P521, &[32usize, 48, 64][..]),
    ] {
        let (masked_key, pub_key) = generate(&ctx, session.session_id, curve);

        for &digest_len in digest_lens {
            let digest: Vec<u8> = (0..digest_len)
                .map(|i| (i as u8).wrapping_mul(13).wrapping_add(0x29))
                .collect();
            let signature = sign(&ctx, session.session_id, masked_key.clone(), &digest);
            assert!(
                verify_wire_ecdsa(&pub_key, &signature, &digest),
                "signature must verify for curve {curve} with a {digest_len}-byte digest",
            );
        }
    }
}

/// Confirms a signature authenticates only the digest that was actually signed.
#[test]
fn ecc_sign_signature_rejects_different_digest() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (masked_key, pub_key) = generate(&ctx, session.session_id, ECC_CURVE_P256);
    let digest = vec![0x31; 32];
    let signature = sign(&ctx, session.session_id, masked_key, &digest);

    let different_digest = vec![0x32; 32];
    assert!(verify_wire_ecdsa(&pub_key, &signature, &digest));
    assert!(
        !verify_wire_ecdsa(&pub_key, &signature, &different_digest),
        "signature must not verify against a different digest",
    );
}

/// Confirms distinct digest request values produce signatures bound to each digest.
#[test]
fn ecc_sign_distinct_digests_are_independently_verified() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (masked_key, pub_key) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    let digest_a = vec![0x11; 32];
    let digest_b = vec![0x22; 32];

    let signature_a = sign(&ctx, session.session_id, masked_key.clone(), &digest_a);

    let signature_b = sign(&ctx, session.session_id, masked_key, &digest_b);

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
}

/// Signs and verifies a digest containing zero-valued bytes.
#[test]
fn ecc_sign_digest_with_zero_bytes_roundtrip() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (masked_key, pub_key) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    let mut digest = vec![0u8; 32];
    digest[1] = 0xA5;
    digest[15] = 0x5A;
    digest[30] = 0xC3;

    let signature = sign(&ctx, session.session_id, masked_key, &digest);

    assert!(
        verify_wire_ecdsa(&pub_key, &signature, &digest),
        "digest containing zero bytes must survive the TBOR request unchanged",
    );
}

/// Verifies P-521 signatures zero-fill the two wire-padding bytes per component.
#[test]
fn ecc_sign_p521_signature_padding_is_zero() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (masked_key, pub_key) = generate(&ctx, session.session_id, ECC_CURVE_P521);
    let digest = vec![0x43; 64];
    let signature = sign(&ctx, session.session_id, masked_key, &digest);

    assert_eq!(signature.len(), 136);
    assert_eq!(&signature[66..68], &[0, 0], "r padding must be zero");
    assert_eq!(&signature[134..136], &[0, 0], "s padding must be zero");
    assert!(verify_wire_ecdsa(&pub_key, &signature, &digest));
}

/// Signs and verifies with a key masked under the partition-local scope.
#[cfg(feature = "emu")]
#[test]
fn ecc_sign_local_scoped_key_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, pub_key) =
        generate_in_scope(&ctx, session.session_id, SCOPE_LOCAL, ECC_CURVE_P256);
    let digest = vec![0x5A; 32];
    let signature = sign(&ctx, session.session_id, masked_key, &digest);
    assert!(verify_wire_ecdsa(&pub_key, &signature, &digest));
}

/// Confirms a Crypto-User (`PlainText`) session is authorized to sign.
#[test]
fn ecc_sign_allowed_on_crypto_user_session() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    let (masked_key, pub_key) =
        generate_in_scope(&ctx, session.session_id, SCOPE_SESSION, ECC_CURVE_P256);
    let digest = vec![0x6B; 32];
    let signature = sign(&ctx, session.session_id, masked_key, &digest);
    assert!(verify_wire_ecdsa(&pub_key, &signature, &digest));
}

/// Signs and verifies with an ECC private key imported through `UnwrapKey`.
#[cfg(feature = "emu")]
#[test]
fn ecc_sign_with_unwrapped_key_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let host_key = EccPrivateKey::from_curve(EccCurve::P256).expect("generate host ECC key");
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
        "signature from the unwrapped ECC key must verify",
    );
}

/// Rejects an empty digest because it does not identify a supported SHA-2 algorithm.
#[test]
fn ecc_sign_empty_digest_rejected() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (masked_key, _) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    ctx.expect_fw_reject(
        &TborEccSignReq {
            session_id: session.session_id,
            masked_key,
            digest: Vec::new(),
        },
        TborStatus::InvalidArg,
    );
}

/// Rejects digest lengths that do not identify a supported SHA-2 algorithm.
#[test]
fn ecc_sign_non_sha2_digest_lengths_rejected() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    // Use P-521 so all valid SHA-2 digest lengths fit the curve field.
    // Any rejection here is therefore caused by the unsupported digest
    // length rather than by the selected curve.
    for digest_len in [1usize, 31, 33, 47, 49, 63] {
        let (masked_key, _) = generate(&ctx, session.session_id, ECC_CURVE_P521);

        ctx.expect_fw_reject(
            &TborEccSignReq {
                session_id: session.session_id,
                masked_key,
                digest: vec![0xAB; digest_len],
            },
            TborStatus::InvalidArg,
        );
    }
}

/// Rejects the unsupported SHA-1 digest length.
#[test]
fn ecc_sign_unsupported_digest_len_rejected() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (masked_key, _) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    ctx.expect_fw_reject(
        &TborEccSignReq {
            session_id: session.session_id,
            masked_key,
            digest: vec![0xAB; 20],
        },
        TborStatus::InvalidArg,
    );
}

/// Rejects a valid SHA-2 digest that exceeds the selected curve's field width.
#[test]
fn ecc_sign_digest_longer_than_curve_field_rejected() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (masked_key, _) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    ctx.expect_fw_reject(
        &TborEccSignReq {
            session_id: session.session_id,
            masked_key,
            digest: vec![0xAB; 64],
        },
        TborStatus::InvalidArg,
    );
}

/// Rejects a masked private key whose authenticated ciphertext was modified.
#[test]
fn ecc_sign_tampered_masked_key_rejected() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (mut masked_key, _) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    let last = masked_key
        .len()
        .checked_sub(1)
        .expect("masked ECC key must not be empty");
    masked_key[last] ^= 0x01;
    ctx.expect_fw_reject(
        &TborEccSignReq {
            session_id: session.session_id,
            masked_key,
            digest: vec![0x7C; 32],
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
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

/// Rejects signing when the request is bound to an unknown session identifier.
#[test]
fn ecc_sign_unknown_session_rejected() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (masked_key, _) = generate(&ctx, session.session_id, ECC_CURVE_P256);
    assert_ne!(session.session_id, u16::MAX, "test requires an unused id");

    ctx.expect_fw_reject(
        &TborEccSignReq {
            session_id: u16::MAX,
            masked_key,
            digest: vec![0x8D; 32],
        },
        TborStatus::FileHandleSessionIdDoesNotMatch,
    );
}

/// Rejects `KeyScope::Unspecified` for a caller-generated ECC key.
#[cfg(feature = "emu")]
#[test]
fn ecc_generate_key_unspecified_scope_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    ctx.expect_fw_reject(
        &TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_UNSPECIFIED,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        },
        TborStatus::UnsupportedKeyScope,
    );
}

/// Rejects the firmware-internal scope for a caller-generated ECC key.
#[cfg(feature = "emu")]
#[test]
fn ecc_generate_key_internal_scope_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    ctx.expect_fw_reject(
        &TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_INTERNAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        },
        TborStatus::UnsupportedKeyScope,
    );
}

/// Confirms a signature does not verify against a different public key.
#[test]
fn ecc_sign_signature_rejects_different_public_key() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let (masked_key, pub_key) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    let (_other_masked_key, other_pub_key) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    let digest = vec![0x42; 32];
    let signature = sign(&ctx, session.session_id, masked_key, &digest);

    assert!(
        verify_wire_ecdsa(&pub_key, &signature, &digest),
        "signature must verify against the originating public key",
    );

    assert!(
        !verify_wire_ecdsa(&other_pub_key, &signature, &digest),
        "signature must not verify against a different public key",
    );
}

/// Rejects a session-scoped ECC private key from a replacement session.
#[test]
fn ecc_sign_session_scoped_key_rejected_in_different_session() {
    let ctx = TestCtx::new();

    let session_a = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let (masked_key, _) = generate(&ctx, session_a.session_id, ECC_CURVE_P256);

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

/// Confirms changing one bit of the digest invalidates the signature.
#[test]
fn ecc_sign_signature_rejects_single_bit_digest_change() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (masked_key, pub_key) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    let digest = vec![0xA5; 32];
    let signature = sign(&ctx, session.session_id, masked_key, &digest);

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
}
/// Signs and verifies an all-zero SHA-256 digest.
#[test]
fn ecc_sign_all_zero_digest_roundtrip() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (masked_key, pub_key) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    let digest = vec![0u8; 32];
    let signature = sign(&ctx, session.session_id, masked_key, &digest);

    assert!(
        verify_wire_ecdsa(&pub_key, &signature, &digest),
        "an all-zero 32-byte digest must be signed and verified correctly",
    );
}
/// Signs and verifies a SHA-256 digest containing all 0xFF bytes.
#[test]
fn ecc_sign_all_ones_digest_roundtrip() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (masked_key, pub_key) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    let digest = vec![0xFF; 32];
    let signature = sign(&ctx, session.session_id, masked_key, &digest);

    assert!(
        verify_wire_ecdsa(&pub_key, &signature, &digest),
        "an all-0xFF digest must be signed and verified correctly",
    );
}

/// Confirms the same masked ECC key can sign multiple digests.
#[test]
fn ecc_sign_masked_key_can_be_reused() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let (masked_key, pub_key) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    for value in [0x11u8, 0x22, 0x33] {
        let digest = vec![value; 32];

        let signature = sign(&ctx, session.session_id, masked_key.clone(), &digest);

        assert!(
            verify_wire_ecdsa(&pub_key, &signature, &digest),
            "reused masked key must sign digest value {value:#04x}",
        );
    }
}
