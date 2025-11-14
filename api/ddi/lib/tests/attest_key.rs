// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use attestation::report::*;
use crypto::ecc::CryptoEccCurve;
use crypto::ecc::EccOp;
use crypto::ecc::EccPublicKey;
use crypto::ecc::EccPublicOp;
use crypto::rsa::RsaOp;
use crypto::rsa::RsaPublicKey;
use crypto::sha::sha;
use crypto::sha::HashAlgorithm;
use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use test_with_tracing::test;
use x509::*;

use crate::common::*;

#[test]
fn test_attest_ecc_signing_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // TODO: remove once virtual device supports cert chain ddi commands
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!("Skipped test_attest_ecc_signing_key for virtual device");
                return;
            }

            let (private_key_id, pub_key_der, _) = ecc_gen_key_mcr(
                dev,
                DdiEccCurve::P256,
                None,
                Some(session_id),
                DdiKeyUsage::SignVerify,
            );

            let report_data = [2u8; REPORT_DATA_SIZE];
            let result = helper_attest_key_cmd(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                report_data,
                private_key_id,
            );
            assert!(result.is_ok(), "result {:?}", result);

            let resp = result.unwrap();
            let report = resp.data.report.data_take();
            let report_len = resp.data.report.len();
            assert!(report_len <= TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE);

            let cert_chain = helper_get_cert_chain(dev);
            assert!(helper_verify_cert_chain(&cert_chain).is_ok());
            let report_payload = verify_report(&report, &cert_chain);

            assert_eq!(report_payload.report_data, report_data);

            let keyflags: KeyFlags = report_payload.flags.into();
            assert!(!keyflags.is_imported());
            // App key
            assert!(!keyflags.is_session_key());
            assert!(keyflags.is_generated());
            assert!(!keyflags.can_encrypt());
            assert!(!keyflags.can_decrypt());
            assert!(keyflags.can_sign());
            assert!(keyflags.can_verify());
            assert!(!keyflags.can_wrap());
            assert!(!keyflags.can_unwrap());
            assert!(!keyflags.can_derive());

            assert!(report_payload.public_key.len() >= report_payload.public_key_size.into());
            let attested_key = decode_cose_key(
                &report_payload.public_key[..report_payload.public_key_size.into()],
            );

            let result =
                EccPublicKey::from_der(&pub_key_der.der.data()[..pub_key_der.der.len()], None);
            assert!(result.is_ok(), "result {:?}", result);
            let ecc_pub = result.unwrap();

            let CoseKey::EccPublic { crv, x, y } = attested_key else {
                panic!("Should be CoseKey::EccPublic")
            };

            let result = ecc_pub.coordinates();
            assert!(result.is_ok(), "result {:?}", result);
            let (expected_x, expected_y) = result.unwrap();

            // In the rare case where generate ECC key returns a point with leading zeros,
            // With feature use-openssl, expected_x (or y) would NOT have leading zeros as OpenSSL strips them.
            // With feature use-symcrypt, expected_x (or y) could have leading zeros as SymCrypt doesn't strip them.
            // CoseKey::EccPublic does not strip out leading zeros in the big number representation of the public key.
            // So here we remove leading zeros regardless
            assert_eq!(normalized_key(&x), normalized_key(&expected_x));
            assert_eq!(normalized_key(&y), normalized_key(&expected_y));

            let result = ecc_pub.curve();
            assert!(result.is_ok(), "result {:?}", result);
            let expected_crv = match result.unwrap() {
                CryptoEccCurve::P256 => 1,
                CryptoEccCurve::P384 => 2,
                CryptoEccCurve::P521 => 3,
            };
            assert_eq!(crv, expected_crv);
        },
    );
}

#[test]
fn test_attest_ecc_seed_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // TODO: remove once virtual device supports cert chain ddi commands
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!("Skipped test_attest_ecc_seed_key for virtual device");
                return;
            }

            let (private_key_id, pub_key_der, _) = ecc_gen_key_mcr(
                dev,
                DdiEccCurve::P256,
                None,
                Some(session_id),
                DdiKeyUsage::Derive,
            );

            let report_data = [2u8; REPORT_DATA_SIZE];
            let result = helper_attest_key_cmd(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                report_data,
                private_key_id,
            );
            assert!(result.is_ok(), "result {:?}", result);

            let resp = result.unwrap();
            let report = resp.data.report.data_take();
            let report_len = resp.data.report.len();
            assert!(report_len <= TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE);

            let cert_chain = helper_get_cert_chain(dev);
            assert!(helper_verify_cert_chain(&cert_chain).is_ok());
            let report_payload = verify_report(&report, &cert_chain);

            assert_eq!(report_payload.report_data, report_data);

            let keyflags: KeyFlags = report_payload.flags.into();
            assert!(!keyflags.is_imported());
            // App key
            assert!(!keyflags.is_session_key());
            assert!(keyflags.is_generated());
            assert!(!keyflags.can_encrypt());
            assert!(!keyflags.can_decrypt());
            assert!(!keyflags.can_sign());
            assert!(!keyflags.can_verify());
            assert!(!keyflags.can_wrap());
            assert!(!keyflags.can_unwrap());
            assert!(keyflags.can_derive());

            assert!(report_payload.public_key.len() >= report_payload.public_key_size.into());
            let attested_key = decode_cose_key(
                &report_payload.public_key[..report_payload.public_key_size.into()],
            );

            let result =
                EccPublicKey::from_der(&pub_key_der.der.data()[..pub_key_der.der.len()], None);
            assert!(result.is_ok(), "result {:?}", result);
            let ecc_pub = result.unwrap();

            let CoseKey::EccPublic { crv, x, y } = attested_key else {
                panic!("Should be CoseKey::EccPublic")
            };

            let result = ecc_pub.coordinates();
            assert!(result.is_ok(), "result {:?}", result);
            let (expected_x, expected_y) = result.unwrap();

            // In the rare case where generate ECC key returns a point with leading zeros,
            // With feature use-openssl, expected_x (or y) would NOT have leading zeros as OpenSSL strips them.
            // With feature use-symcrypt, expected_x (or y) could have leading zeros as SymCrypt doesn't strip them.
            // CoseKey::EccPublic does not strip out leading zeros in the big number representation of the public key.
            // So here we remove leading zeros regardless
            assert_eq!(normalized_key(&x), normalized_key(&expected_x));
            assert_eq!(normalized_key(&y), normalized_key(&expected_y));

            let result = ecc_pub.curve();
            assert!(result.is_ok(), "result {:?}", result);
            let expected_crv = match result.unwrap() {
                CryptoEccCurve::P256 => 1,
                CryptoEccCurve::P384 => 2,
                CryptoEccCurve::P521 => 3,
            };
            assert_eq!(crv, expected_crv);
        },
    );
}

#[test]
fn test_attest_rsa_unwrapping_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // TODO: remove once virtual device supports cert chain ddi commands
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!("Skipped test_attest_rsa_unwrapping_key for virtual device");
                return;
            }

            let (private_key_id, pub_key_der, _) = get_unwrapping_key(dev, session_id);

            let report_data = [2u8; REPORT_DATA_SIZE];
            let result = helper_attest_key_cmd(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                report_data,
                private_key_id,
            );
            assert!(result.is_ok(), "result {:?}", result);

            let resp = result.unwrap();
            let report = resp.data.report.data_take();
            let report_len = resp.data.report.len();
            assert!(report_len <= TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE);

            let cert_chain = helper_get_cert_chain(dev);
            assert!(helper_verify_cert_chain(&cert_chain).is_ok());
            let report_payload = verify_report(&report, &cert_chain);

            assert_eq!(report_payload.report_data, report_data);

            let keyflags: KeyFlags = report_payload.flags.into();
            assert!(!keyflags.is_imported());
            // App key
            assert!(!keyflags.is_session_key());
            assert!(keyflags.is_generated());
            assert!(!keyflags.can_encrypt());
            assert!(!keyflags.can_decrypt());
            assert!(!keyflags.can_sign());
            assert!(!keyflags.can_verify());
            assert!(!keyflags.can_wrap());
            assert!(keyflags.can_unwrap());
            assert!(!keyflags.can_derive());

            assert!(report_payload.public_key.len() >= report_payload.public_key_size.into());
            let attested_key = decode_cose_key(
                &report_payload.public_key[..report_payload.public_key_size.into()],
            );

            let result = RsaPublicKey::from_der(&pub_key_der, None);
            assert!(result.is_ok(), "result {:?}", result);
            let rsa_pub = result.unwrap();

            let CoseKey::RsaPublic { n, e } = attested_key else {
                panic!()
            };

            // Hardware device returns a big-endian slice.
            // Convert to little-endian and then compare.
            let e: Vec<u8> = e.iter().rev().cloned().collect();

            let result = rsa_pub.public_exponent();
            assert!(result.is_ok(), "result {:?}", result);
            let expected_e = result.unwrap();

            let result = rsa_pub.modulus();
            assert!(result.is_ok(), "result {:?}", result);
            let expected_n = result.unwrap();

            assert_eq!(e, expected_e);
            assert_eq!(n, expected_n);
        },
    );
}

#[test]
fn test_attest_rsa_decryption_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // TODO: remove once virtual device supports cert chain ddi commands
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!("Skipped test_attest_rsa_decryption_key for virtual device");
                return;
            }

            let (private_key_id, pub_key_der) = import_rsa_key(dev, session_id);

            let report_data = [2u8; REPORT_DATA_SIZE];
            let result = helper_attest_key_cmd(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                report_data,
                private_key_id,
            );
            assert!(result.is_ok(), "result {:?}", result);

            let resp = result.unwrap();
            let report = resp.data.report.data_take();
            let report_len = resp.data.report.len();
            assert!(report_len <= TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE);

            let cert_chain = helper_get_cert_chain(dev);
            assert!(helper_verify_cert_chain(&cert_chain).is_ok());
            let report_payload = verify_report(&report, &cert_chain);

            assert_eq!(report_payload.report_data, report_data);

            let keyflags: KeyFlags = report_payload.flags.into();
            assert!(keyflags.is_imported());
            // App key
            assert!(!keyflags.is_session_key());
            assert!(!keyflags.is_generated());
            assert!(keyflags.can_encrypt());
            assert!(keyflags.can_decrypt());
            assert!(!keyflags.can_sign());
            assert!(!keyflags.can_verify());
            assert!(!keyflags.can_wrap());
            assert!(!keyflags.can_unwrap());
            assert!(!keyflags.can_derive());

            assert!(report_payload.public_key.len() >= report_payload.public_key_size.into());
            let attested_key = decode_cose_key(
                &report_payload.public_key[..report_payload.public_key_size.into()],
            );

            let result = RsaPublicKey::from_der(&pub_key_der, None);
            assert!(result.is_ok(), "result {:?}", result);
            let rsa_pub = result.unwrap();

            let CoseKey::RsaPublic { n, e } = attested_key else {
                panic!()
            };

            // Hardware device returns a big-endian slice.
            // Convert to little-endian and then compare.
            let e: Vec<u8> = e.iter().rev().cloned().collect();

            let result = rsa_pub.public_exponent();
            assert!(result.is_ok(), "result {:?}", result);
            let expected_e = result.unwrap();

            let result = rsa_pub.modulus();
            assert!(result.is_ok(), "result {:?}", result);
            let expected_n = result.unwrap();

            assert_eq!(e, expected_e);
            assert_eq!(n, expected_n);
        },
    );
}

#[test]
fn test_attest_aes_key_negative() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // TODO: remove once virtual device supports cert chain ddi commands
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!("Skipped test_attest_aes_key_negative for virtual device");
                return;
            }

            let report_data = [2u8; REPORT_DATA_SIZE];
            let raw_msg = [1u8; 512];
            let msg_len = raw_msg.len() as u16;
            let mut msg = [0u8; 1024];
            msg[..msg_len as usize].clone_from_slice(&raw_msg);

            // Generate AES key
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let result = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );
            assert!(result.is_ok(), "result {:?}", result);

            let resp = result.unwrap();

            let key_id = resp.data.key_id;

            let result = helper_attest_key_cmd(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                report_data,
                key_id,
            );
            assert!(result.is_err(), "result {:?}", result);
            assert!(matches!(
                result.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidKeyType)
            ));
        },
    );
}

#[test]
fn test_attest_masked_key_rsa_2k_no_crt_der_import() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_attest_rsa_der_import(dev, session_id, 2, true);
        },
    );
}

#[test]
fn test_attest_masked_key_rsa_3k_no_crt_der_import() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_attest_rsa_der_import(dev, session_id, 3, true);
        },
    );
}

#[test]
fn test_attest_masked_key_rsa_4k_no_crt_der_import() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_attest_rsa_der_import(dev, session_id, 4, true);
        },
    );
}

#[test]
fn test_attest_masked_key_rsa_2k_der_import() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_attest_rsa_der_import(dev, session_id, 2, false);
        },
    );
}

#[test]
fn test_attest_masked_key_rsa_3k_der_import() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_attest_rsa_der_import(dev, session_id, 3, false);
        },
    );
}

#[test]
fn test_attest_masked_key_rsa_4k_der_import() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_attest_rsa_der_import(dev, session_id, 4, false);
        },
    );
}

/// Helper function to get certificate chain
fn helper_get_cert_chain(dev: &mut <DdiTest as Ddi>::Dev) -> Vec<Vec<u8>> {
    tracing::debug!("Getting certificate chain");
    // Gets the cert chain
    // 1. Gets the number of certs in the cert chain using DDI command GetCertChainInfo command
    // 2. Gets all certs in the cert chain using DDI command GetCertificate where
    //    cert id is 0 to num_certs - 1.
    // 3. Gets the partition id cert using DDI command GetCertificate which is the last cert in the chain

    let result = helper_get_cert_chain_info(dev);
    assert!(result.is_ok(), "result {:?}", result);

    let resp = result.unwrap();
    let num_certs = resp.data.num_certs;

    let mut cert_chain: Vec<Vec<u8>> = Vec::with_capacity(num_certs as usize);
    for i in 0..num_certs {
        let result = helper_get_certificate(dev, i);
        assert!(result.is_ok(), "result {:?}", result);

        let resp = result.unwrap();
        let der = &resp.data.certificate.as_slice();
        print!("cert DER {:?}", der);

        cert_chain.push(der.to_vec());
    }

    tracing::debug!(len = cert_chain.len(), "Done getting cert chain");
    cert_chain
}

fn import_rsa_key(dev: &mut <DdiTest as Ddi>::Dev, session_id: u16) -> (u16, Vec<u8>) {
    let (unwrap_key_id, unwrap_pub_key_der, _) = get_unwrapping_key(dev, session_id);

    let rsa_3k_private_wrapped = wrap_data(unwrap_pub_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

    let mut der = [0u8; 3072];
    der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

    let der_len = rsa_3k_private_wrapped.len();

    let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
    let result = helper_rsa_unwrap(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        unwrap_key_id,
        MborByteArray::new(der, der_len).expect("failed to create byte array"),
        DdiKeyClass::Rsa,
        DdiRsaCryptoPadding::Oaep,
        DdiHashAlgorithm::Sha256,
        None,
        key_props,
    );

    assert!(result.is_ok(), "result {:?}", result);
    let resp = result.unwrap();

    let key_id = resp.data.key_id;

    let pub_key = resp.data.pub_key;
    assert!(pub_key.is_some());
    let pub_key = pub_key.unwrap();

    (key_id, pub_key.der.data()[..pub_key.der.len()].to_vec())
}

/// Helper function to verify the report
fn verify_report(report: &[u8], cert_chain: &[Vec<u8>]) -> KeyAttestationReport {
    tracing::debug!("Verifying report");
    tracing::debug!(?report, ?cert_chain, "Dumping report and certificate chain");

    let (protected_header, report_payload, signature) = parse_report(report);

    let part_cert = x509::X509Certificate::from_der(cert_chain.last().unwrap()).unwrap();
    let public_key_der = part_cert.get_public_key_der().unwrap();

    let result = EccPublicKey::from_der(&public_key_der, None);
    assert!(result.is_ok(), "result {:?}", result);
    let ecc_public = result.unwrap();

    let tbs = create_tbs(&protected_header, &report_payload);

    let result = sha(HashAlgorithm::Sha384, &tbs);
    assert!(result.is_ok(), "result {:?}", result);
    let digest = result.unwrap();

    let result = ecc_public.verify(&digest, &signature);
    assert!(result.is_ok(), "result {:?}", result);

    decode_report_payload(&report_payload)
}

fn create_tbs(body_protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut sig_struct_buffer = [0u8; SIG_STRUCTURE_MAX_SIZE];

    let result = encode_sig_struct(body_protected, payload, &mut sig_struct_buffer);
    assert!(result.is_ok(), "result {:?}", result);
    let sig_struct_size = result.unwrap();

    sig_struct_buffer[..sig_struct_size].to_vec()
}

fn parse_report(data: &[u8]) -> ([u8; PROTECTED_HEADER_SIZE], Vec<u8>, [u8; SIGNATURE_SIZE]) {
    let mut decoder = minicbor::Decoder::new(data);

    let result = decoder.tag();
    assert!(result.is_ok(), "result {:?}", result);
    let tag = result.unwrap();
    // Tag 18 for COSE_Sign1
    assert_eq!(tag, minicbor::data::Tag::Unassigned(18));

    // Array
    let result = decoder.array();
    assert!(result.is_ok(), "result {:?}", result);

    let result = decoder.bytes();
    assert!(result.is_ok(), "result {:?}", result);
    let protected_header = result.unwrap();
    assert_eq!(protected_header.len(), PROTECTED_HEADER_SIZE);

    let protected_header = {
        let mut data = [0u8; PROTECTED_HEADER_SIZE];
        data.copy_from_slice(protected_header);
        data
    };

    // Unprotected header
    let result = decoder.map();
    assert!(result.is_ok(), "result {:?}", result);

    let result = decoder.bytes();
    assert!(result.is_ok(), "result {:?}", result);
    let payload = result.unwrap();

    let result = decoder.bytes();
    assert!(result.is_ok(), "result {:?}", result);
    let signature = result.unwrap();
    assert_eq!(signature.len(), SIGNATURE_SIZE);

    let signature = {
        let mut data = [0u8; SIGNATURE_SIZE];
        data.copy_from_slice(signature);
        data
    };

    (protected_header, payload.to_vec(), signature)
}

fn decode_report_payload(payload: &[u8]) -> KeyAttestationReport {
    let result = minicbor::decode(payload);
    assert!(result.is_ok(), "result {:?}", result);

    result.unwrap()
}

#[derive(Debug, PartialEq, PartialOrd)]
enum CoseKey {
    RsaPublic { n: Vec<u8>, e: Vec<u8> },
    EccPublic { crv: i8, x: Vec<u8>, y: Vec<u8> },
}

fn decode_cose_key(data: &[u8]) -> CoseKey {
    let mut decoder = minicbor::Decoder::new(data);

    let result = decoder.map();
    assert!(result.is_ok(), "result {:?}", result);
    let map = result.unwrap();
    assert!(map.is_some());
    let map_len = map.unwrap();
    assert!(matches!(map_len, 3 | 4));

    let result = decoder.u8();
    assert!(result.is_ok(), "result {:?}", result);
    let key_type_key = result.unwrap();
    assert_eq!(key_type_key, COSE_KEY_COMMON_PARAMETERS_KTY);

    let result = decoder.u8();
    assert!(result.is_ok(), "result {:?}", result);
    let key_type_val = result.unwrap();

    let cose_key = match key_type_val {
        COSE_KEY_TYPES_RSA => {
            let result = decoder.i8();
            assert!(result.is_ok(), "result {:?}", result);
            let n_key = result.unwrap();
            assert_eq!(n_key, COSE_KEY_TYPE_PARAMETERS_RSA_N);

            let result = decoder.bytes();
            assert!(result.is_ok(), "result {:?}", result);
            let n_val = result.unwrap();

            let result = decoder.i8();
            assert!(result.is_ok(), "result {:?}", result);
            let e_key = result.unwrap();
            assert_eq!(e_key, COSE_KEY_TYPE_PARAMETERS_RSA_E);

            let result = decoder.bytes();
            assert!(result.is_ok(), "result {:?}", result);
            let e_val = result.unwrap();

            CoseKey::RsaPublic {
                n: n_val.to_vec(),
                e: e_val.to_vec(),
            }
        }
        COSE_KEY_TYPES_EC2 => {
            let result = decoder.i8();
            assert!(result.is_ok(), "result {:?}", result);
            let crv_key = result.unwrap();
            assert_eq!(crv_key, COSE_KEY_TYPE_PARAMETERS_EC2_CRV);

            let result = decoder.i8();
            assert!(result.is_ok(), "result {:?}", result);
            let crv_val = result.unwrap();

            let result = decoder.i8();
            assert!(result.is_ok(), "result {:?}", result);
            let x_key = result.unwrap();
            assert_eq!(x_key, COSE_KEY_TYPE_PARAMETERS_EC2_X);

            let result = decoder.bytes();
            assert!(result.is_ok(), "result {:?}", result);
            let x_val = result.unwrap();

            let result = decoder.i8();
            assert!(result.is_ok(), "result {:?}", result);
            let y_key = result.unwrap();
            assert_eq!(y_key, COSE_KEY_TYPE_PARAMETERS_EC2_Y);

            let result = decoder.bytes();
            assert!(result.is_ok(), "result {:?}", result);
            let y_val = result.unwrap();

            CoseKey::EccPublic {
                crv: crv_val,
                x: x_val.to_vec(),
                y: y_val.to_vec(),
            }
        }
        _ => panic!(),
    };

    cose_key
}

// Helper function to strip out leading zeros from a public key coordinate.
fn normalized_key(key: &[u8]) -> Vec<u8> {
    let mut normalized_key = key.to_vec();
    while normalized_key.len() > 1 && normalized_key[0] == 0 {
        normalized_key.remove(0);
    }
    normalized_key
}

fn test_attest_rsa_der_import(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    key_size: u8,
    no_crt: bool,
) {
    if get_device_kind(dev) == DdiDeviceKind::Virtual {
        tracing::debug!(
            "Masked key test is only support in Physical platform. Skipping the test..."
        );
        return;
    }

    let (_key_id_pub, key_id_priv, masked_key) = if no_crt {
        store_rsa_keys_no_crt(
            dev,
            session_id,
            DdiKeyUsage::EncryptDecrypt,
            key_size,
            Some(1),
        )
    } else {
        store_rsa_keys_crt(
            dev,
            session_id,
            DdiKeyUsage::EncryptDecrypt,
            key_size,
            Some(1),
        )
    };

    let report_data = [2u8; REPORT_DATA_SIZE];
    let result = helper_attest_key_cmd(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        report_data,
        key_id_priv,
    );
    assert!(result.is_ok(), "result {:?}", result);

    let resp = result.unwrap();
    let report = resp.data.report.data_take();
    let report_len = resp.data.report.len();
    assert!(report_len <= TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE);

    let cert_chain = helper_get_cert_chain(dev);
    assert!(helper_verify_cert_chain(&cert_chain).is_ok());
    let report_payload = verify_report(&report, &cert_chain);

    assert_eq!(report_payload.report_data, report_data);

    let resp = helper_get_new_key_id_from_unmask(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id_priv,
        true,
        masked_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let (new_key_id, _, _) = resp.unwrap();

    let new_report_data = [2u8; REPORT_DATA_SIZE];
    let result = helper_attest_key_cmd(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        new_report_data,
        new_key_id,
    );
    assert!(result.is_ok(), "result {:?}", result);

    let resp = result.unwrap();
    let new_report = resp.data.report.data_take();
    let new_report_len = resp.data.report.len();
    assert!(new_report_len <= TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE);

    let new_report_payload = verify_report(&new_report, &cert_chain);

    assert_eq!(new_report_payload.report_data, new_report_data);

    assert_eq!(report_payload.app_uuid, new_report_payload.app_uuid);
    assert_eq!(report_payload.flags, new_report_payload.flags);
    assert_eq!(
        report_payload.public_key_size,
        new_report_payload.public_key_size
    );
    assert_eq!(
        report_payload.public_key[..report_payload.public_key_size as usize],
        new_report_payload.public_key[..report_payload.public_key_size as usize]
    );
    assert_eq!(report_payload.version, new_report_payload.version);
    assert_eq!(report_payload.vm_launch_id, new_report_payload.vm_launch_id);
}
