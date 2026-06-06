// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Round-trip and error-path tests for the host AEAD envelope API.

use crate::AesKey;
use crate::CryptoError;
use crate::ImportableKey;
use crate::aead_envelope::AeadAlg;
use crate::aead_envelope::AeadEnvelope;
use crate::aead_envelope::FORMAT_TAG;
use crate::aead_envelope::HEADER_LEN;
use crate::aead_envelope::MAX_AAD_LEN;
use crate::aead_envelope::inspect;
use crate::aead_envelope::open;
use crate::aead_envelope::seal;

const K32: [u8; 32] = [0x42; 32];
const IV12: [u8; 12] = [0x24; 12];

fn key() -> AesKey {
    AesKey::from_bytes(&K32).expect("AesKey")
}

fn seal_into(aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let needed = seal(AeadAlg::AesGcm256, &key(), &IV12, aad, pt, None).unwrap();
    let mut out = vec![0u8; needed];
    let n = seal(AeadAlg::AesGcm256, &key(), &IV12, aad, pt, Some(&mut out)).unwrap();
    assert_eq!(n, needed);
    out
}

#[test]
fn round_trip_zero_aad_zero_pt() {
    let mut env = seal_into(&[], &[]);
    let view = open(&key(), &mut env).unwrap();
    assert_eq!(view.alg, AeadAlg::AesGcm256);
    assert_eq!(view.aad, b"");
    assert_eq!(view.payload, b"");
    assert_eq!(view.iv, IV12);
}

#[test]
fn round_trip_various_sizes() {
    // (aad_len, pt_len) pairs spanning interesting boundaries.
    let cases = [
        (0, 0),
        (0, 1),
        (0, 31),
        (0, 32),
        (0, 33),
        (32, 0),
        (32, 1),
        (32, 64),
        (64, 100),
    ];
    for (al, pl) in cases {
        let aad: Vec<u8> = (0..al).map(|i| (i & 0xFF) as u8).collect();
        let pt: Vec<u8> = (0..pl).map(|i| ((i ^ 0x5A) & 0xFF) as u8).collect();
        let mut env = seal_into(&aad, &pt);
        let view = open(&key(), &mut env).expect("open round-trip");
        assert_eq!(view.aad, aad.as_slice(), "aad mismatch ({al},{pl})");
        assert_eq!(view.payload, pt.as_slice(), "pt mismatch ({al},{pl})");
    }
}

#[test]
fn inspect_returns_ciphertext_does_not_decrypt() {
    let pt = b"sensitive plaintext payload!!!!";
    let env = seal_into(&[], pt);
    let view: AeadEnvelope<'_> = inspect(&env).unwrap();
    assert_eq!(view.alg, AeadAlg::AesGcm256);
    assert_eq!(view.iv, IV12);
    assert_eq!(view.payload.len(), pt.len());
    assert_ne!(view.payload, pt, "inspect must not decrypt");
    assert_eq!(view.tag.len(), 16);
}

#[test]
fn seal_size_query_returns_required_length() {
    let needed = seal(AeadAlg::AesGcm256, &key(), &IV12, &[], b"abc", None).unwrap();
    assert_eq!(needed, HEADER_LEN + 12 + 3 + 16);
}

#[test]
fn seal_size_query_rejects_bad_aad_length() {
    // aad_len = 17 is not 0 and not a multiple of 32.
    let bad_aad = vec![0u8; 17];
    let err = seal(AeadAlg::AesGcm256, &key(), &IV12, &bad_aad, b"x", None).unwrap_err();
    assert_eq!(err, CryptoError::AeadEnvelopeInvalidAadLength);
}

#[test]
fn seal_rejects_short_key() {
    let short = AesKey::from_bytes(&[0u8; 16]).expect("AES-128 key");
    let mut out = [0u8; 64];
    let err = seal(AeadAlg::AesGcm256, &short, &IV12, &[], b"x", Some(&mut out)).unwrap_err();
    assert_eq!(err, CryptoError::GcmInvalidKeySize);
}

#[test]
fn seal_rejects_short_iv() {
    let bad_iv = [0u8; 11];
    let mut out = [0u8; 64];
    let err = seal(
        AeadAlg::AesGcm256,
        &key(),
        &bad_iv,
        &[],
        b"x",
        Some(&mut out),
    )
    .unwrap_err();
    assert_eq!(err, CryptoError::GcmInvalidIvLength);
}

#[test]
fn seal_rejects_small_output_buffer() {
    let mut tiny = [0u8; 8];
    let err = seal(
        AeadAlg::AesGcm256,
        &key(),
        &IV12,
        &[],
        b"hello",
        Some(&mut tiny),
    )
    .unwrap_err();
    assert_eq!(err, CryptoError::GcmBufferTooSmall);
}

#[test]
fn open_detects_tampered_payload() {
    let mut env = seal_into(&[], b"some plaintext");
    let payload_off = HEADER_LEN + 12; // aad_len = 0
    env[payload_off] ^= 0x01;
    let err = open(&key(), &mut env).unwrap_err();
    assert_eq!(err, CryptoError::GcmDecryptionFailed);
}

#[test]
fn open_detects_tampered_tag() {
    let mut env = seal_into(&[], b"some plaintext");
    let last = env.len() - 1;
    env[last] ^= 0x80;
    let err = open(&key(), &mut env).unwrap_err();
    assert_eq!(err, CryptoError::GcmDecryptionFailed);
}

#[test]
fn open_detects_tampered_aad() {
    let aad = vec![0u8; 32];
    let mut env = seal_into(&aad, b"data");
    let aad_off = HEADER_LEN + 12;
    env[aad_off] ^= 0x01;
    let err = open(&key(), &mut env).unwrap_err();
    assert_eq!(err, CryptoError::GcmDecryptionFailed);
}

#[test]
fn open_rejects_wrong_key() {
    let mut env = seal_into(&[], b"data");
    let other = AesKey::from_bytes(&[0xAA; 32]).unwrap();
    let err = open(&other, &mut env).unwrap_err();
    assert_eq!(err, CryptoError::GcmDecryptionFailed);
}

#[test]
fn open_rejects_wrong_key_length() {
    let mut env = seal_into(&[], b"data");
    let short = AesKey::from_bytes(&[0u8; 16]).unwrap();
    let err = open(&short, &mut env).unwrap_err();
    assert_eq!(err, CryptoError::GcmInvalidKeySize);
}

#[test]
fn inspect_rejects_bad_magic() {
    let mut env = seal_into(&[], b"x");
    env[0] = b'X'; // break magic byte
    assert_eq!(
        inspect(&env).unwrap_err(),
        CryptoError::AeadEnvelopeInvalidFormat
    );
}

#[test]
fn inspect_rejects_unknown_alg() {
    let mut env = seal_into(&[], b"x");
    env[4] = 0x01; // alg byte is at offset 4
    assert_eq!(
        inspect(&env).unwrap_err(),
        CryptoError::AeadEnvelopeUnsupportedAlg
    );
}

#[test]
fn inspect_rejects_nonzero_reserved() {
    let mut env = seal_into(&[], b"x");
    env[5] = 0xFF; // reserved byte must be 0
    assert_eq!(
        inspect(&env).unwrap_err(),
        CryptoError::AeadEnvelopeInvalidFormat
    );
}

#[test]
fn inspect_rejects_bad_aad_len() {
    let mut env = seal_into(&[], b"x");
    env[7] = 17; // aad_len low byte (high byte already 0); 17 isn't multiple of 32
    assert_eq!(
        inspect(&env).unwrap_err(),
        CryptoError::AeadEnvelopeInvalidAadLength
    );
}

#[test]
fn inspect_rejects_short_header() {
    assert_eq!(
        inspect(b"AEAD\x03\x00\x00").unwrap_err(),
        CryptoError::GcmBufferTooSmall
    );
}

#[test]
fn open_rejects_truncated_envelope() {
    let mut env = seal_into(&[], b"hello");
    let new_len = env.len() - 1;
    env.truncate(new_len);
    let err = open(&key(), &mut env).unwrap_err();
    // Could be BufferTooSmall (header math) or decryption failure
    // depending on where truncation lands; both are acceptable
    // rejections.
    assert!(
        matches!(
            err,
            CryptoError::GcmBufferTooSmall | CryptoError::GcmDecryptionFailed
        ),
        "unexpected: {err:?}"
    );
}

#[test]
fn max_aad_len_constant_matches_u16_range() {
    assert_eq!(MAX_AAD_LEN, u16::MAX as usize);
}

#[test]
fn format_tag_constant_is_aead_ascii() {
    assert_eq!(FORMAT_TAG, *b"AEAD");
}
