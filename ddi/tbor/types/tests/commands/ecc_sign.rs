// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `EccSign` command.
//!
//! `EccSign` produces a raw ECDSA `r ‖ s` signature over a host-supplied
//! pre-computed digest using a caller-held **masked** ECC private key
//! (from [`EccGenerateKey`](super::ecc_generate_key)).  These tests
//! generate a key on-device, sign a digest, and verify the signature on
//! the host with `azihsm_crypto` (OpenSSL) against the returned public key
//! — exercising the full unmask → sign → return path for every curve.
//!
//! The device speaks the PKA-native **little-endian** wire format: the
//! public key is `x_le ‖ y_le` and the signature is `r_le ‖ s_le` (each
//! component zero-padded to the curve's wire coordinate length; P-521 pads
//! 66→68).  `azihsm_crypto` is big-endian native, so the test reverses
//! each component before verifying.  Likewise the device internally
//! reverses the supplied wire-LE digest to big-endian before signing, so
//! the host verifies against the reversed digest.

#![cfg(feature = "emu")]

use azihsm_crypto::EccAlgo;
use azihsm_crypto::EccCurve;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::EccPublicKey;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::Verifier;
use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::TborEccSignReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::ECC_CURVE_P384;
use azihsm_ddi_tbor_types::ECC_CURVE_P521;
use azihsm_ddi_tbor_types::KEY_CLASS_ECC;
use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;

use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap;
use crate::harness::TestCtx;

/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

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

/// Generate an ECC key on-device for `curve`, returning `(masked_key,
/// wire_pub_key)`.
fn generate(ctx: &TestCtx, session_id: u16, curve: u8) -> (Vec<u8>, Vec<u8>) {
    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            curve,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");
    (resp.masked_key, resp.pub_key)
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
    // `hsm_point_size` coordinates (trailing LE pad becomes leading BE
    // zeros, which `from_hsm_bytes` tolerates).
    let (x_le, y_le) = pub_le.split_at(wire_coord);
    let mut pub_be = rev(x_le, wire_coord);
    pub_be.extend(rev(y_le, wire_coord));
    let pubkey = EccPublicKey::from_hsm_bytes(&pub_be).expect("import public key");

    // Signature: reverse the meaningful `raw_coord` bytes of each component
    // → big-endian `r ‖ s` (each `raw_coord` = the curve's point size).
    let (r_le, s_le) = sig_le.split_at(wire_coord);
    let mut sig_be = rev(r_le, raw_coord);
    sig_be.extend(rev(s_le, raw_coord));

    // The device reversed the wire-LE digest to big-endian before signing;
    // verify against that same big-endian digest.
    let digest_be = rev(digest_le, digest_le.len());

    Verifier::verify(&mut EccAlgo::default(), &pubkey, &digest_be, &sig_be)
        .expect("host ECDSA verify")
}

#[test]
fn ecc_sign_roundtrip_all_curves_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for (curve, digest_len) in [
        (ECC_CURVE_P256, 32usize),
        (ECC_CURVE_P384, 48usize),
        (ECC_CURVE_P521, 64usize),
    ] {
        let (masked_key, pub_key) = generate(&ctx, session.session_id, curve);

        // A deterministic, non-trivial digest of the algorithm's length.
        let digest: Vec<u8> = (0..digest_len)
            .map(|i| (i as u8).wrapping_mul(7).wrapping_add(0x11))
            .collect();

        let resp = ctx
            .tbor(&TborEccSignReq {
                session_id: session.session_id,
                masked_key,
                digest: digest.clone(),
            })
            .expect("EccSign");

        assert_eq!(
            resp.signature.len(),
            pub_key.len(),
            "wire signature length equals wire public-key length for the curve",
        );
        assert!(
            verify_wire_ecdsa(&pub_key, &resp.signature, &digest),
            "ECDSA signature must verify against the generated public key (curve {curve})",
        );
    }
}

#[test]
fn ecc_sign_with_unwrapped_key_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // Import a host-generated P-256 ECC private key via `UnwrapKey` (Ecc
    // class): RSA-AES-wrap its PKCS#8 DER, unwrap on-device into a masked
    // blob.  This exercises the full unwrap → sign interoperability — an
    // ECC key imported through `UnwrapKey` must be consumable by `EccSign`.
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
    let sign_resp = ctx
        .tbor(&TborEccSignReq {
            session_id: session.session_id,
            masked_key: imported.masked_key,
            digest: digest.clone(),
        })
        .expect("EccSign with an unwrapped key");

    assert!(
        verify_wire_ecdsa(&imported.pub_key, &sign_resp.signature, &digest),
        "signature from the unwrapped ECC key must verify",
    );
}

#[test]
fn ecc_sign_wrong_digest_len_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _pub_key) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    // A 31-byte digest is not one of the supported SHA-2 digest lengths
    // (32 / 48 / 64), so the hash algorithm cannot be inferred and it is
    // rejected.
    ctx.expect_fw_reject(
        &TborEccSignReq {
            session_id: session.session_id,
            masked_key,
            digest: vec![0xAB; 31],
        },
        TborStatus::InvalidArg,
    );
}

#[test]
fn ecc_sign_unsupported_digest_len_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _pub_key) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    // A 20-byte digest (SHA-1 length) is a real hash length but not one of
    // the supported SHA-2 digest lengths (32 / 48 / 64), so the algorithm is
    // not inferable and the request is rejected.
    ctx.expect_fw_reject(
        &TborEccSignReq {
            session_id: session.session_id,
            masked_key,
            digest: vec![0xAB; 20],
        },
        TborStatus::InvalidArg,
    );
}

#[test]
fn ecc_sign_digest_longer_than_curve_field_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _pub_key) = generate(&ctx, session.session_id, ECC_CURVE_P256);

    // A 64-byte digest (SHA-512 length) is a valid SHA-2 length but exceeds
    // the P-256 ECDSA field width (32 B); it cannot be zero-extended into the
    // curve operand, so it is rejected rather than silently truncated.
    ctx.expect_fw_reject(
        &TborEccSignReq {
            session_id: session.session_id,
            masked_key,
            digest: vec![0xAB; 64],
        },
        TborStatus::InvalidArg,
    );
}
