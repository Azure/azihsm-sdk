// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_masked_key_ecc_session_only_256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |_dev, ddi, path, _session_id| {
            test_ecc_session_only_key_gen(ddi, path, DdiEccCurve::P256);
        },
    );
}

#[test]
fn test_masked_key_ecc_session_only_384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |_dev, ddi, path, _session_id| {
            test_ecc_session_only_key_gen(ddi, path, DdiEccCurve::P384);
        },
    );
}

#[test]
fn test_masked_key_ecc_session_only_521() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |_dev, ddi, path, _session_id| {
            test_ecc_session_only_key_gen(ddi, path, DdiEccCurve::P521);
        },
    );
}

#[test]
fn test_masked_key_ecc_256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_ecc_key_gen(dev, session_id, DdiEccCurve::P256);
        },
    );
}

#[test]
fn test_masked_key_ecc_384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_ecc_key_gen(dev, session_id, DdiEccCurve::P384);
        },
    );
}

#[test]
fn test_masked_key_ecc_521() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_ecc_key_gen(dev, session_id, DdiEccCurve::P521);
        },
    );
}

fn test_ecc_session_only_key_gen(ddi: &DdiTest, path: &str, curve: DdiEccCurve) {
    let mut session_only_key_dev = ddi.open_dev(path).unwrap();

    set_device_kind(&mut session_only_key_dev);

    let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
        &session_only_key_dev,
        TEST_CRED_ID,
        TEST_CRED_PIN,
        TEST_SESSION_SEED,
    );

    let resp = helper_open_session(
        &session_only_key_dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        encrypted_credential,
        pub_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();

    let session_only_key_session = resp.hdr.sess_id;

    let resp = helper_ecc_generate_key_pair(
        &session_only_key_dev,
        session_only_key_session,
        Some(DdiApiRev { major: 1, minor: 0 }),
        curve,
        None,
        helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::Session),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();
    let private_key_id = resp.data.private_key_id;
    let pub_key = resp.data.pub_key;
    let masked_key = resp.data.masked_key;

    let resp = helper_get_new_key_id_from_unmask(
        &session_only_key_dev,
        session_only_key_session,
        Some(DdiApiRev { major: 1, minor: 0 }),
        private_key_id,
        false,
        masked_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let (new_key_id, _, new_pub_key) = resp.unwrap();
    assert!(new_pub_key.is_some());
    let new_pub_key = new_pub_key.unwrap();
    assert_eq!(new_pub_key.key_kind, pub_key.key_kind);
    assert_eq!(new_pub_key.der.as_slice(), pub_key.der.as_slice());

    // Sign a digest with the session-only key
    let digest = [1u8; 96];
    let digest_len = 20;

    let resp = helper_ecc_sign(
        &session_only_key_dev,
        session_only_key_session,
        Some(DdiApiRev { major: 1, minor: 0 }),
        new_key_id,
        MborByteArray::new(digest, digest_len).expect("failed to create byte array"),
        DdiHashAlgorithm::Sha256,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    let signature_len = resp.data.signature.len();

    // Should return true
    assert!(ecc_verify_local_openssl(
        &resp.data.signature.data()[..signature_len],
        &new_pub_key,
        digest,
        digest_len
    ));

    let mut tampered_digest = digest;
    tampered_digest[0] = tampered_digest[0].wrapping_add(0x1);

    // Should return false
    assert!(!ecc_verify_local_openssl(
        &resp.data.signature.data()[..signature_len],
        &new_pub_key,
        tampered_digest,
        digest_len
    ));
}

fn test_ecc_key_gen(dev: &mut <DdiTest as Ddi>::Dev, session_id: u16, curve: DdiEccCurve) {
    let (private_key_id, pub_key, masked_key) = ecc_gen_key_mcr(
        dev,
        curve,
        Some(1),
        Some(session_id),
        DdiKeyUsage::SignVerify,
    );

    let resp = helper_get_new_key_id_from_unmask(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        private_key_id,
        true,
        masked_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let (new_key_id, _, new_pub_key) = resp.unwrap();
    assert!(new_pub_key.is_some());
    let new_pub_key = new_pub_key.unwrap();
    assert_eq!(new_pub_key.key_kind, pub_key.key_kind);
    assert_eq!(new_pub_key.der.as_slice(), pub_key.der.as_slice());

    // Sign a digest with the session-only key
    let digest = [1u8; 96];
    let digest_len = 20;

    let resp = helper_ecc_sign(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        new_key_id,
        MborByteArray::new(digest, digest_len).expect("failed to create byte array"),
        DdiHashAlgorithm::Sha256,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    let signature_len = resp.data.signature.len();

    // Should return true
    assert!(ecc_verify_local_openssl(
        &resp.data.signature.data()[..signature_len],
        &new_pub_key,
        digest,
        digest_len
    ));

    let mut tampered_digest = digest;
    tampered_digest[0] = tampered_digest[0].wrapping_add(0x1);

    // Should return false
    assert!(!ecc_verify_local_openssl(
        &resp.data.signature.data()[..signature_len],
        &new_pub_key,
        tampered_digest,
        digest_len
    ));
}
