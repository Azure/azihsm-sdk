// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deterministic input fixtures (KEY / IV / AAD / PT) for the
//! `aead_envelope` round-trip tests in `ops_tests.rs`.
//!
//! What is pinned here:
//!   * fixed test inputs (so failures are reproducible),
//!   * the wire-layout positions of the envelope header / IV / AAD
//!     slots inside the `round_trip` helper below.
//!
//! What is **not** pinned here: an `ENVELOPE` byte blob.  The
//! envelope is intentionally re-sealed at runtime in each test
//! (using the host AEAD-GCM backend) and `open()` is called on the
//! freshly-sealed bytes — this exercises the host seal+open paths
//! end-to-end without coupling tests to a specific compiler /
//! OpenSSL nonce-handling quirk.  Cross-platform "golden ciphertext"
//! pinning belongs on the fw side (where the implementation is fixed)
//! and is not duplicated here.

#![allow(dead_code)] // fixtures are consumed by ops_tests below.

use crate::AesKey;
use crate::ImportableKey;
use crate::aead_envelope::AeadAlg;
use crate::aead_envelope::FORMAT_TAG;
use crate::aead_envelope::open;
use crate::aead_envelope::seal;

/// Fixture 1 — AES-256-GCM, AAD = 0 bytes, PT = 11 bytes.
pub mod fixture_aad0_pt11 {
    pub const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    pub const IV: [u8; 12] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
    ];
    pub const AAD: &[u8] = &[];
    pub const PT: &[u8] = b"hello world";
}

/// Fixture 2 — AES-256-GCM, AAD = 32 bytes, PT = 17 bytes.
pub mod fixture_aad32_pt17 {
    pub const KEY: [u8; 32] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];
    pub const IV: [u8; 12] = [
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
    ];
    pub const AAD: &[u8; 32] = &[0xCC; 32];
    pub const PT: &[u8] = b"AAD-protected msg";
}

/// Fixture 3 — AES-256-GCM, AAD = 64 bytes, PT = 0 bytes (header
/// + IV + AAD + tag only).
pub mod fixture_aad64_pt0 {
    pub const KEY: [u8; 32] = [0x55; 32];
    pub const IV: [u8; 12] = [0x77; 12];
    pub const AAD: &[u8; 64] = &[0xEE; 64];
    pub const PT: &[u8] = &[];
}

/// Helper: round-trip a fixture (seal then open) and assert
/// recovered plaintext matches.
fn round_trip(key_bytes: &[u8], iv: &[u8], aad: &[u8], pt: &[u8]) {
    let key = AesKey::from_bytes(key_bytes).expect("AesKey");

    // Size query.
    let needed = seal(AeadAlg::AesGcm256, &key, iv, aad, pt, None).expect("size query");
    assert_eq!(needed, 8 + 12 + aad.len() + pt.len() + 16);

    let mut env = vec![0u8; needed];
    let n = seal(AeadAlg::AesGcm256, &key, iv, aad, pt, Some(&mut env)).expect("seal");
    assert_eq!(n, needed);

    // Wire-format sanity checks pinning byte positions.
    assert_eq!(&env[..4], &FORMAT_TAG);
    assert_eq!(env[4], AeadAlg::AesGcm256.as_u8());
    assert_eq!(env[5], 0, "reserved byte");
    assert_eq!(
        u16::from_be_bytes([env[6], env[7]]) as usize,
        aad.len(),
        "aad_len_be"
    );
    assert_eq!(&env[8..20], iv, "IV slot");
    assert_eq!(&env[20..20 + aad.len()], aad, "AAD slot");

    // Open in place.
    let view = open(&key, &mut env).expect("open");
    assert_eq!(view.alg, AeadAlg::AesGcm256);
    assert_eq!(view.iv, iv);
    assert_eq!(view.aad, aad);
    assert_eq!(view.payload, pt);
    assert_eq!(view.tag.len(), 16);
}

#[test]
fn fixture_aad0_pt11_round_trip() {
    use fixture_aad0_pt11::*;
    round_trip(&KEY, &IV, AAD, PT);
}

#[test]
fn fixture_aad32_pt17_round_trip() {
    use fixture_aad32_pt17::*;
    round_trip(&KEY, &IV, AAD, PT);
}

#[test]
fn fixture_aad64_pt0_round_trip() {
    use fixture_aad64_pt0::*;
    round_trip(&KEY, &IV, AAD, PT);
}
