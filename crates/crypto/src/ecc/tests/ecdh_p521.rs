// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[test]
fn test_ecdh_p521_nist_vectors() {
    for vector in ECDH_P521_TEST_VECTORS.iter() {
        let peer_pub = EccPublicKey::from_bytes(vector.qcavs_pubkey_der)
            .expect("Failed to parse Qcavs public key DER");
        let diut_priv = EccPrivateKey::from_bytes(vector.diut_privkey_der)
            .expect("Failed to parse Diut private key DER");

        let secret = EcdhAlgo::new(&peer_pub)
            .derive(&diut_priv, 66)
            .expect("ECDH derive failed");
        let secret_bytes = export_secret(&secret);

        assert_eq!(
            secret_bytes.as_slice(),
            vector.ziut,
            "ECDH P-521 derived secret mismatch"
        );
    }
}

#[test]
fn test_ecdh_p521_generated_keys_agree() {
    let initiator_priv = EccPrivateKey::from_curve(EccCurve::P521).expect("Key generation failed");
    let responder_priv = EccPrivateKey::from_curve(EccCurve::P521).expect("Key generation failed");

    let initiator_pub = initiator_priv
        .public_key()
        .expect("Failed to get public key");
    let responder_pub = responder_priv
        .public_key()
        .expect("Failed to get public key");

    let initiator_to_responder = EcdhAlgo::new(&responder_pub)
        .derive(&initiator_priv, 66)
        .expect("ECDH derive failed");
    let responder_to_initiator = EcdhAlgo::new(&initiator_pub)
        .derive(&responder_priv, 66)
        .expect("ECDH derive failed");

    let secret1 = export_secret(&initiator_to_responder);
    let secret2 = export_secret(&responder_to_initiator);

    assert_eq!(secret1.len(), EccCurve::P521.point_size());
    assert_eq!(secret1, secret2, "ECDH P-521 secrets do not match");
    assert!(
        secret1.iter().any(|&b| b != 0),
        "ECDH P-521 shared secret unexpectedly all-zero"
    );
}

#[test]
fn test_ecdh_p521_generated_keys_export_import_roundtrip() {
    let initiator_priv = EccPrivateKey::from_curve(EccCurve::P521).expect("Key generation failed");
    let responder_priv = EccPrivateKey::from_curve(EccCurve::P521).expect("Key generation failed");

    let initiator_pub = initiator_priv
        .public_key()
        .expect("Failed to get public key");
    let responder_pub = responder_priv
        .public_key()
        .expect("Failed to get public key");

    let initiator_priv_der = export_key_bytes(&initiator_priv);
    let responder_priv_der = export_key_bytes(&responder_priv);
    let initiator_pub_der = export_key_bytes(&initiator_pub);
    let responder_pub_der = export_key_bytes(&responder_pub);

    let initiator_priv2 = EccPrivateKey::from_bytes(&initiator_priv_der)
        .expect("Failed to import generated private key DER");
    let responder_priv2 = EccPrivateKey::from_bytes(&responder_priv_der)
        .expect("Failed to import generated private key DER");
    let initiator_pub2 = EccPublicKey::from_bytes(&initiator_pub_der)
        .expect("Failed to import generated public key DER");
    let responder_pub2 = EccPublicKey::from_bytes(&responder_pub_der)
        .expect("Failed to import generated public key DER");

    let initiator_to_responder = EcdhAlgo::new(&responder_pub2)
        .derive(&initiator_priv2, 66)
        .expect("ECDH derive failed");
    let responder_to_initiator = EcdhAlgo::new(&initiator_pub2)
        .derive(&responder_priv2, 66)
        .expect("ECDH derive failed");

    let secret1 = export_secret(&initiator_to_responder);
    let secret2 = export_secret(&responder_to_initiator);
    assert_eq!(secret1, secret2, "ECDH P-521 secrets do not match");
}

#[test]
fn test_ecdh_p521_mismatched_curve_fails() {
    let priv_p521 = EccPrivateKey::from_curve(EccCurve::P521).expect("Key generation failed");
    let peer_priv_p256 = EccPrivateKey::from_curve(EccCurve::P256).expect("Key generation failed");
    let peer_pub_p256 = peer_priv_p256
        .public_key()
        .expect("Failed to get public key");

    assert!(
        EcdhAlgo::new(&peer_pub_p256)
            .derive(&priv_p521, 66)
            .is_err(),
        "ECDH derive unexpectedly succeeded with mismatched curves"
    );
}

#[test]
fn test_ecdh_p521_invalid_peer_public_key_der_rejected() {
    let invalid_der = [0u8; 16];
    assert!(
        EccPublicKey::from_bytes(&invalid_der).is_err(),
        "Invalid DER unexpectedly parsed as an ECC public key"
    );
}

#[test]
fn test_ecdh_p521_invalid_derived_key_length() {
    let priv_key = EccPrivateKey::from_curve(EccCurve::P521).expect("Key generation failed");
    let peer_priv = EccPrivateKey::from_curve(EccCurve::P521).expect("Key generation failed");
    let peer_pub = peer_priv.public_key().expect("Failed to get public key");

    // P-521 key size is 66 bytes, try invalid lengths
    let invalid_lengths = [0, 16, 32, 48, 65, 67, 128, 256];

    for &invalid_len in &invalid_lengths {
        let result = EcdhAlgo::new(&peer_pub).derive(&priv_key, invalid_len);
        assert!(
            result.is_err(),
            "ECDH derive unexpectedly succeeded with invalid length {}",
            invalid_len
        );
    }

    // Valid length should succeed
    let valid_result = EcdhAlgo::new(&peer_pub).derive(&priv_key, 66);
    assert!(
        valid_result.is_ok(),
        "ECDH derive failed with valid length 66"
    );
}
