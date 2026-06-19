// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::unwrap_used)]

//! Tests for RSA HSM wire format (to_hsm_bytes / from_hsm_bytes).

use crate::ExportableHsmKey;
use crate::ExportableHsmRsaKey;
use crate::KeyGenerationOp;
use crate::Signer;
use crate::Verifier;
use crate::rsa::*;

fn generate_rsa_key(bits: usize) -> RsaPrivateKey {
    <RsaPrivateKey as KeyGenerationOp>::generate(bits / 8).unwrap()
}

// ── RSA 2048 ───────────────────────────────────────────────────────

#[test]
fn rsa_2k_private_hsm_round_trip() {
    let key = generate_rsa_key(2048);
    let hsm = key.to_hsm_bytes_vec().unwrap();
    assert_eq!(
        hsm.len(),
        516,
        "RSA-2048 non-CRT HSM bytes: 256 + 4 + 128 + 128 = 516"
    );

    let imported = RsaPrivateKey::from_hsm_bytes(&hsm).unwrap();
    assert_eq!(imported.size(), 256);
}

#[test]
fn rsa_2k_private_crt_hsm_round_trip() {
    let key = generate_rsa_key(2048);
    let hsm = key.to_hsm_crt_bytes_vec().unwrap();
    assert_eq!(
        hsm.len(),
        1156,
        "RSA-2048 CRT HSM bytes: 256 + 4 + 256 + 128*5 = 1156"
    );

    let imported = RsaPrivateKey::from_hsm_bytes(&hsm).unwrap();
    assert_eq!(imported.size(), 256);
}

#[test]
fn rsa_2k_public_hsm_round_trip() {
    let priv_key = generate_rsa_key(2048);
    let pub_key = priv_key.public_key().unwrap();
    let hsm = pub_key.to_hsm_bytes_vec().unwrap();
    assert_eq!(hsm.len(), 260, "RSA-2048 public HSM bytes: 256 + 4 = 260");

    let imported = RsaPublicKey::from_hsm_bytes(&hsm).unwrap();
    assert_eq!(imported.size(), 256);
}

// ── RSA 3072 ───────────────────────────────────────────────────────

#[test]
fn rsa_3k_private_hsm_round_trip() {
    let key = generate_rsa_key(3072);
    let hsm = key.to_hsm_bytes_vec().unwrap();
    assert_eq!(
        hsm.len(),
        772,
        "RSA-3072 non-CRT: 384 + 4 + 192 + 192 = 772"
    );

    let imported = RsaPrivateKey::from_hsm_bytes(&hsm).unwrap();
    assert_eq!(imported.size(), 384);
}

#[test]
fn rsa_3k_private_crt_hsm_round_trip() {
    let key = generate_rsa_key(3072);
    let hsm = key.to_hsm_crt_bytes_vec().unwrap();
    assert_eq!(
        hsm.len(),
        1732,
        "RSA-3072 CRT: 384 + 4 + 384 + 192*5 = 1732"
    );

    let imported = RsaPrivateKey::from_hsm_bytes(&hsm).unwrap();
    assert_eq!(imported.size(), 384);
}

#[test]
fn rsa_3k_public_hsm_round_trip() {
    let priv_key = generate_rsa_key(3072);
    let pub_key = priv_key.public_key().unwrap();
    let hsm = pub_key.to_hsm_bytes_vec().unwrap();
    assert_eq!(hsm.len(), 388, "RSA-3072 public: 384 + 4 = 388");

    let imported = RsaPublicKey::from_hsm_bytes(&hsm).unwrap();
    assert_eq!(imported.size(), 384);
}

// ── RSA 4096 ───────────────────────────────────────────────────────

#[test]
fn rsa_4k_private_hsm_round_trip() {
    let key = generate_rsa_key(4096);
    let hsm = key.to_hsm_bytes_vec().unwrap();
    assert_eq!(
        hsm.len(),
        1028,
        "RSA-4096 non-CRT: 512 + 4 + 256 + 256 = 1028"
    );

    let imported = RsaPrivateKey::from_hsm_bytes(&hsm).unwrap();
    assert_eq!(imported.size(), 512);
}

#[test]
fn rsa_4k_private_crt_hsm_round_trip() {
    let key = generate_rsa_key(4096);
    let hsm = key.to_hsm_crt_bytes_vec().unwrap();
    assert_eq!(
        hsm.len(),
        2308,
        "RSA-4096 CRT: 512 + 4 + 512 + 256*5 = 2308"
    );

    let imported = RsaPrivateKey::from_hsm_bytes(&hsm).unwrap();
    assert_eq!(imported.size(), 512);
}

#[test]
fn rsa_4k_public_hsm_round_trip() {
    let priv_key = generate_rsa_key(4096);
    let pub_key = priv_key.public_key().unwrap();
    let hsm = pub_key.to_hsm_bytes_vec().unwrap();
    assert_eq!(hsm.len(), 516, "RSA-4096 public: 512 + 4 = 516");

    let imported = RsaPublicKey::from_hsm_bytes(&hsm).unwrap();
    assert_eq!(imported.size(), 512);
}

// ── Buf API ────────────────────────────────────────────────────────

#[test]
fn rsa_private_hsm_buf_api() {
    let key = generate_rsa_key(2048);
    let mut buf = [0u8; 516];
    let written = key.to_hsm_bytes(&mut buf).unwrap();
    assert_eq!(written, 516);
}

#[test]
fn rsa_private_hsm_buf_too_small() {
    let key = generate_rsa_key(2048);
    let mut buf = [0u8; 100];
    assert!(key.to_hsm_bytes(&mut buf).is_err());
}

#[test]
fn rsa_public_hsm_buf_too_small() {
    let priv_key = generate_rsa_key(2048);
    let pub_key = priv_key.public_key().unwrap();
    let mut buf = [0u8; 100];
    assert!(pub_key.to_hsm_bytes(&mut buf).is_err());
}

// ── Invalid lengths ────────────────────────────────────────────────

#[test]
fn rsa_private_hsm_invalid_length() {
    assert!(RsaPrivateKey::from_hsm_bytes(&[0u8; 100]).is_err());
    assert!(RsaPrivateKey::from_hsm_bytes(&[0u8; 260]).is_err()); // public size, not private
}

#[test]
fn rsa_public_hsm_invalid_length() {
    assert!(RsaPublicKey::from_hsm_bytes(&[0u8; 100]).is_err());
    assert!(RsaPublicKey::from_hsm_bytes(&[0u8; 772]).is_err()); // private non-CRT size for RSA-3072
}

// ── hsm_bytes_len ──────────────────────────────────────────────────

#[test]
fn rsa_hsm_bytes_len() {
    let k2 = generate_rsa_key(2048);
    assert_eq!(k2.hsm_bytes_len(), 516);
    assert_eq!(k2.hsm_crt_bytes_len(), 1156);
    assert_eq!(k2.public_key().unwrap().hsm_bytes_len(), 260);

    let k3 = generate_rsa_key(3072);
    assert_eq!(k3.hsm_bytes_len(), 772);
    assert_eq!(k3.hsm_crt_bytes_len(), 1732);
    assert_eq!(k3.public_key().unwrap().hsm_bytes_len(), 388);

    let k4 = generate_rsa_key(4096);
    assert_eq!(k4.hsm_bytes_len(), 1028);
    assert_eq!(k4.hsm_crt_bytes_len(), 2308);
    assert_eq!(k4.public_key().unwrap().hsm_bytes_len(), 516);
}

// ── Sign/verify after import ───────────────────────────────────────

#[test]
fn rsa_hsm_sign_verify_after_non_crt_import() {
    let key = generate_rsa_key(2048);
    let pub_key = key.public_key().unwrap();

    let priv_hsm = key.to_hsm_bytes_vec().unwrap();
    let pub_hsm = pub_key.to_hsm_bytes_vec().unwrap();

    let imported_priv = RsaPrivateKey::from_hsm_bytes(&priv_hsm).unwrap();
    let imported_pub = RsaPublicKey::from_hsm_bytes(&pub_hsm).unwrap();

    // Raw sign (no padding) with imported keys
    let input = vec![0x42u8; 256];
    let mut sign_algo = RsaSignAlgo::with_no_padding();
    let sig = Signer::sign_vec(&mut sign_algo, &imported_priv, &input).unwrap();
    assert_eq!(sig.len(), 256);

    let mut verify_algo = RsaSignAlgo::with_no_padding();
    let recovered_len =
        Verifier::verify_recover(&mut verify_algo, &imported_pub, &sig, None).unwrap();
    let mut recovered = vec![0u8; recovered_len];
    Verifier::verify_recover(&mut verify_algo, &imported_pub, &sig, Some(&mut recovered)).unwrap();
    assert_eq!(recovered, input);
}

#[test]
fn rsa_hsm_sign_verify_after_crt_import() {
    let key = generate_rsa_key(2048);
    let pub_key = key.public_key().unwrap();

    let priv_hsm = key.to_hsm_crt_bytes_vec().unwrap();
    let pub_hsm = pub_key.to_hsm_bytes_vec().unwrap();

    let imported_priv = RsaPrivateKey::from_hsm_bytes(&priv_hsm).unwrap();
    let imported_pub = RsaPublicKey::from_hsm_bytes(&pub_hsm).unwrap();

    let input = vec![0x42u8; 256];
    let mut sign_algo = RsaSignAlgo::with_no_padding();
    let sig = Signer::sign_vec(&mut sign_algo, &imported_priv, &input).unwrap();

    let mut verify_algo = RsaSignAlgo::with_no_padding();
    let recovered_len =
        Verifier::verify_recover(&mut verify_algo, &imported_pub, &sig, None).unwrap();
    let mut recovered = vec![0u8; recovered_len];
    Verifier::verify_recover(&mut verify_algo, &imported_pub, &sig, Some(&mut recovered)).unwrap();
    assert_eq!(recovered, input);
}
