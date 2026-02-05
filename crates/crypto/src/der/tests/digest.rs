// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use super::*;

/// Test vectors for SHA-1 DigestInfo DER encoding.
///
/// These are known-good DER encodings produced by standard cryptographic libraries.
const SHA1_DIGEST_INFO_DER: &[u8] = &[
    0x30, 0x21, // SEQUENCE, 33 bytes
    0x30, 0x09, // SEQUENCE, 9 bytes (AlgorithmIdentifier)
    0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, // OID 1.3.14.3.2.26 (SHA-1)
    0x05, 0x00, // NULL
    0x04, 0x14, // OCTET STRING, 20 bytes
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, // 20 bytes of digest
];

const SHA1_TEST_DIGEST: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14,
];

/// Test vectors for SHA-256 DigestInfo DER encoding.
const SHA256_DIGEST_INFO_DER: &[u8] = &[
    0x30, 0x31, // SEQUENCE, 49 bytes
    0x30, 0x0d, // SEQUENCE, 13 bytes (AlgorithmIdentifier)
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x01, // OID 2.16.840.1.101.3.4.2.1 (SHA-256)
    0x05, 0x00, // NULL
    0x04, 0x20, // OCTET STRING, 32 bytes
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, // 32 bytes of digest
];

const SHA256_TEST_DIGEST: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Test vectors for SHA-384 DigestInfo DER encoding.
const SHA384_DIGEST_INFO_DER: &[u8] = &[
    0x30, 0x41, // SEQUENCE, 65 bytes
    0x30, 0x0d, // SEQUENCE, 13 bytes (AlgorithmIdentifier)
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x02, // OID 2.16.840.1.101.3.4.2.2 (SHA-384)
    0x05, 0x00, // NULL
    0x04, 0x30, // OCTET STRING, 48 bytes
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, // 48 bytes of digest
];

const SHA384_TEST_DIGEST: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
];

/// Test vectors for SHA-512 DigestInfo DER encoding.
const SHA512_DIGEST_INFO_DER: &[u8] = &[
    0x30, 0x51, // SEQUENCE, 81 bytes
    0x30, 0x0d, // SEQUENCE, 13 bytes (AlgorithmIdentifier)
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x03, // OID 2.16.840.1.101.3.4.2.3 (SHA-512)
    0x05, 0x00, // NULL
    0x04, 0x40, // OCTET STRING, 64 bytes
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, // 64 bytes of digest
];

const SHA512_TEST_DIGEST: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
];

#[test]
fn test_sha1_to_der() {
    let digest_info = DerDigestInfo::new(DerDigestAlgo::Sha1, SHA1_TEST_DIGEST)
        .expect("Failed to create SHA-1 DigestInfo");

    let encoded = digest_info
        .to_der_vec()
        .expect("Failed to encode SHA-1 DigestInfo");

    assert_eq!(
        encoded, SHA1_DIGEST_INFO_DER,
        "SHA-1 DigestInfo DER encoding mismatch"
    );
}

#[test]
fn test_sha1_from_der() {
    let digest_info =
        DerDigestInfo::from_der(SHA1_DIGEST_INFO_DER).expect("Failed to decode SHA-1 DigestInfo");

    assert_eq!(digest_info.algo(), DerDigestAlgo::Sha1);
    assert_eq!(digest_info.digest(), SHA1_TEST_DIGEST);
}

#[test]
fn test_sha1_roundtrip() {
    let original = DerDigestInfo::new(DerDigestAlgo::Sha1, SHA1_TEST_DIGEST)
        .expect("Failed to create SHA-1 DigestInfo");

    let encoded = original.to_der_vec().expect("Failed to encode");
    let decoded = DerDigestInfo::from_der(&encoded).expect("Failed to decode");

    assert_eq!(decoded.algo(), original.algo());
    assert_eq!(decoded.digest(), original.digest());
}

#[test]
fn test_sha256_to_der() {
    let digest_info = DerDigestInfo::new(DerDigestAlgo::Sha256, SHA256_TEST_DIGEST)
        .expect("Failed to create SHA-256 DigestInfo");

    let encoded = digest_info
        .to_der_vec()
        .expect("Failed to encode SHA-256 DigestInfo");

    assert_eq!(
        encoded, SHA256_DIGEST_INFO_DER,
        "SHA-256 DigestInfo DER encoding mismatch"
    );
}

#[test]
fn test_sha256_from_der() {
    let digest_info = DerDigestInfo::from_der(SHA256_DIGEST_INFO_DER)
        .expect("Failed to decode SHA-256 DigestInfo");

    assert_eq!(digest_info.algo(), DerDigestAlgo::Sha256);
    assert_eq!(digest_info.digest(), SHA256_TEST_DIGEST);
}

#[test]
fn test_sha256_roundtrip() {
    let original = DerDigestInfo::new(DerDigestAlgo::Sha256, SHA256_TEST_DIGEST)
        .expect("Failed to create SHA-256 DigestInfo");

    let encoded = original.to_der_vec().expect("Failed to encode");
    let decoded = DerDigestInfo::from_der(&encoded).expect("Failed to decode");

    assert_eq!(decoded.algo(), original.algo());
    assert_eq!(decoded.digest(), original.digest());
}

#[test]
fn test_sha384_to_der() {
    let digest_info = DerDigestInfo::new(DerDigestAlgo::Sha384, SHA384_TEST_DIGEST)
        .expect("Failed to create SHA-384 DigestInfo");

    let encoded = digest_info
        .to_der_vec()
        .expect("Failed to encode SHA-384 DigestInfo");

    assert_eq!(
        encoded, SHA384_DIGEST_INFO_DER,
        "SHA-384 DigestInfo DER encoding mismatch"
    );
}

#[test]
fn test_sha384_from_der() {
    let digest_info = DerDigestInfo::from_der(SHA384_DIGEST_INFO_DER)
        .expect("Failed to decode SHA-384 DigestInfo");

    assert_eq!(digest_info.algo(), DerDigestAlgo::Sha384);
    assert_eq!(digest_info.digest(), SHA384_TEST_DIGEST);
}

#[test]
fn test_sha384_roundtrip() {
    let original = DerDigestInfo::new(DerDigestAlgo::Sha384, SHA384_TEST_DIGEST)
        .expect("Failed to create SHA-384 DigestInfo");

    let encoded = original.to_der_vec().expect("Failed to encode");
    let decoded = DerDigestInfo::from_der(&encoded).expect("Failed to decode");

    assert_eq!(decoded.algo(), original.algo());
    assert_eq!(decoded.digest(), original.digest());
}

#[test]
fn test_sha512_to_der() {
    let digest_info = DerDigestInfo::new(DerDigestAlgo::Sha512, SHA512_TEST_DIGEST)
        .expect("Failed to create SHA-512 DigestInfo");

    let encoded = digest_info
        .to_der_vec()
        .expect("Failed to encode SHA-512 DigestInfo");

    assert_eq!(
        encoded, SHA512_DIGEST_INFO_DER,
        "SHA-512 DigestInfo DER encoding mismatch"
    );
}

#[test]
fn test_sha512_from_der() {
    let digest_info = DerDigestInfo::from_der(SHA512_DIGEST_INFO_DER)
        .expect("Failed to decode SHA-512 DigestInfo");

    assert_eq!(digest_info.algo(), DerDigestAlgo::Sha512);
    assert_eq!(digest_info.digest(), SHA512_TEST_DIGEST);
}

#[test]
fn test_sha512_roundtrip() {
    let original = DerDigestInfo::new(DerDigestAlgo::Sha512, SHA512_TEST_DIGEST)
        .expect("Failed to create SHA-512 DigestInfo");

    let encoded = original.to_der_vec().expect("Failed to encode");
    let decoded = DerDigestInfo::from_der(&encoded).expect("Failed to decode");

    assert_eq!(decoded.algo(), original.algo());
    assert_eq!(decoded.digest(), original.digest());
}

#[test]
fn test_invalid_digest_size() {
    // SHA-256 expects 32 bytes, but we provide only 16
    let result = DerDigestInfo::new(DerDigestAlgo::Sha256, &[0u8; 16]);
    assert!(result.is_err());

    // SHA-1 expects 20 bytes, but we provide 32
    let result = DerDigestInfo::new(DerDigestAlgo::Sha1, &[0u8; 32]);
    assert!(result.is_err());
}

#[test]
fn test_to_der_with_buffer() {
    let digest_info = DerDigestInfo::new(DerDigestAlgo::Sha256, SHA256_TEST_DIGEST)
        .expect("Failed to create DigestInfo");

    // Query size first
    let size = digest_info.to_der(None).expect("Failed to query size");

    // Allocate buffer and encode
    let mut buffer = vec![0u8; size];
    let written = digest_info
        .to_der(Some(&mut buffer))
        .expect("Failed to encode");

    assert_eq!(written, size);
    assert_eq!(&buffer, SHA256_DIGEST_INFO_DER);
}

#[test]
fn test_to_der_buffer_too_small() {
    let digest_info = DerDigestInfo::new(DerDigestAlgo::Sha256, SHA256_TEST_DIGEST)
        .expect("Failed to create DigestInfo");

    // Buffer too small
    let mut buffer = vec![0u8; 10];
    let result = digest_info.to_der(Some(&mut buffer));

    assert!(result.is_err());
}
