// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for ECC HSM wire format (to_hsm_bytes / from_hsm_bytes).

use crate::ExportableHsmKey;
use crate::Signer;
use crate::Verifier;
use crate::ecc::*;

#[test]
fn ecc_p256_private_hsm_round_trip() {
    let key = EccPrivateKey::from_curve(EccCurve::P256).unwrap();
    let hsm = key.to_hsm_bytes_vec().unwrap();
    assert_eq!(hsm.len(), 32, "P-256 private HSM bytes should be 32");

    let imported = EccPrivateKey::from_hsm_bytes(&hsm).unwrap();
    assert_eq!(imported.curve(), EccCurve::P256);

    // Verify same scalar by re-exporting
    let re_exported = imported.to_hsm_bytes_vec().unwrap();
    assert_eq!(hsm, re_exported);
}

#[test]
fn ecc_p384_private_hsm_round_trip() {
    let key = EccPrivateKey::from_curve(EccCurve::P384).unwrap();
    let hsm = key.to_hsm_bytes_vec().unwrap();
    assert_eq!(hsm.len(), 48, "P-384 private HSM bytes should be 48");

    let imported = EccPrivateKey::from_hsm_bytes(&hsm).unwrap();
    assert_eq!(imported.curve(), EccCurve::P384);

    let re_exported = imported.to_hsm_bytes_vec().unwrap();
    assert_eq!(hsm, re_exported);
}

#[test]
fn ecc_p521_private_hsm_round_trip() {
    let key = EccPrivateKey::from_curve(EccCurve::P521).unwrap();
    let hsm = key.to_hsm_bytes_vec().unwrap();
    assert_eq!(
        hsm.len(),
        68,
        "P-521 private HSM bytes should be 68 (hardware-aligned)"
    );

    let imported = EccPrivateKey::from_hsm_bytes(&hsm).unwrap();
    assert_eq!(imported.curve(), EccCurve::P521);

    let re_exported = imported.to_hsm_bytes_vec().unwrap();
    assert_eq!(hsm, re_exported);
}

#[test]
fn ecc_p256_public_hsm_round_trip() {
    let priv_key = EccPrivateKey::from_curve(EccCurve::P256).unwrap();
    let pub_key = priv_key.public_key().unwrap();
    let hsm = pub_key.to_hsm_bytes_vec().unwrap();
    assert_eq!(hsm.len(), 64, "P-256 public HSM bytes should be 64");

    let imported = EccPublicKey::from_hsm_bytes(&hsm).unwrap();
    assert_eq!(imported.curve(), EccCurve::P256);

    let re_exported = imported.to_hsm_bytes_vec().unwrap();
    assert_eq!(hsm, re_exported);
}

#[test]
fn ecc_p384_public_hsm_round_trip() {
    let priv_key = EccPrivateKey::from_curve(EccCurve::P384).unwrap();
    let pub_key = priv_key.public_key().unwrap();
    let hsm = pub_key.to_hsm_bytes_vec().unwrap();
    assert_eq!(hsm.len(), 96, "P-384 public HSM bytes should be 96");

    let imported = EccPublicKey::from_hsm_bytes(&hsm).unwrap();
    assert_eq!(imported.curve(), EccCurve::P384);

    let re_exported = imported.to_hsm_bytes_vec().unwrap();
    assert_eq!(hsm, re_exported);
}

#[test]
fn ecc_p521_public_hsm_round_trip() {
    let priv_key = EccPrivateKey::from_curve(EccCurve::P521).unwrap();
    let pub_key = priv_key.public_key().unwrap();
    let hsm = pub_key.to_hsm_bytes_vec().unwrap();
    assert_eq!(
        hsm.len(),
        136,
        "P-521 public HSM bytes should be 136 (hardware-aligned)"
    );

    let imported = EccPublicKey::from_hsm_bytes(&hsm).unwrap();
    assert_eq!(imported.curve(), EccCurve::P521);

    let re_exported = imported.to_hsm_bytes_vec().unwrap();
    assert_eq!(hsm, re_exported);
}

#[test]
fn ecc_private_hsm_buf_api() {
    let key = EccPrivateKey::from_curve(EccCurve::P256).unwrap();
    let mut buf = [0u8; 32];
    let written = key.to_hsm_bytes(&mut buf).unwrap();
    assert_eq!(written, 32);
    assert_ne!(buf, [0u8; 32], "should not be all zeros");
}

#[test]
fn ecc_private_hsm_buf_too_small() {
    let key = EccPrivateKey::from_curve(EccCurve::P256).unwrap();
    let mut buf = [0u8; 16];
    assert!(key.to_hsm_bytes(&mut buf).is_err());
}

#[test]
fn ecc_private_hsm_invalid_length() {
    assert!(EccPrivateKey::from_hsm_bytes(&[0u8; 33]).is_err());
    assert!(EccPrivateKey::from_hsm_bytes(&[0u8; 64]).is_err());
    assert!(EccPrivateKey::from_hsm_bytes(&[0u8; 66]).is_err()); // 66 is no longer valid, must be 68
}

#[test]
fn ecc_public_hsm_invalid_length() {
    assert!(EccPublicKey::from_hsm_bytes(&[0u8; 65]).is_err());
    assert!(EccPublicKey::from_hsm_bytes(&[0u8; 132]).is_err()); // 132 is no longer valid, must be 136
}

#[test]
fn ecc_hsm_sign_verify_after_import() {
    let priv_key = EccPrivateKey::from_curve(EccCurve::P256).unwrap();
    let pub_key = priv_key.public_key().unwrap();

    // Export to HSM format
    let priv_hsm = priv_key.to_hsm_bytes_vec().unwrap();
    let pub_hsm = pub_key.to_hsm_bytes_vec().unwrap();

    // Import back
    let imported_priv = EccPrivateKey::from_hsm_bytes(&priv_hsm).unwrap();
    let imported_pub = EccPublicKey::from_hsm_bytes(&pub_hsm).unwrap();

    // Sign with imported private key, verify with imported public key
    let digest = [0x42u8; 32];
    let mut algo = EccAlgo::default();
    let sig = Signer::sign_vec(&mut algo, &imported_priv, &digest).unwrap();
    let valid = Verifier::verify(&mut algo, &imported_pub, &digest, &sig).unwrap();
    assert!(valid, "signature should verify after HSM round-trip");
}

#[test]
fn ecc_hsm_bytes_len() {
    let p256 = EccPrivateKey::from_curve(EccCurve::P256).unwrap();
    let p384 = EccPrivateKey::from_curve(EccCurve::P384).unwrap();
    let p521 = EccPrivateKey::from_curve(EccCurve::P521).unwrap();

    assert_eq!(p256.hsm_bytes_len(), 32);
    assert_eq!(p384.hsm_bytes_len(), 48);
    assert_eq!(p521.hsm_bytes_len(), 68);

    assert_eq!(p256.public_key().unwrap().hsm_bytes_len(), 64);
    assert_eq!(p384.public_key().unwrap().hsm_bytes_len(), 96);
    assert_eq!(p521.public_key().unwrap().hsm_bytes_len(), 136);
}
