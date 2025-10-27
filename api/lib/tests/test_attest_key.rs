// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

#[cfg(feature = "mock")]
use attestation::attestation::KeyAttester;
#[cfg(feature = "mock")]
use attestation::error::AttestationError;
#[cfg(feature = "mock")]
use crypto::ecc::EccOp;
#[cfg(feature = "mock")]
use crypto::ecc::EccPublicKey;
use mcr_api::*;
use test_with_tracing::test;
#[cfg(feature = "mock")]
use x509::X509Certificate;
#[cfg(feature = "mock")]
use x509::X509CertificateOp;

use crate::common::*;

#[test]
#[cfg(feature = "testhooks")]
fn test_attest_after_session_closed() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.attest_key(&priv_key_handle, &[2; 128]);
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_attest_key_and_obtain_cert_with_fixed_rsa() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let mut report_data: [u8; 128] = [2; 128];
        report_data.copy_from_slice(&data);

        let result = app_session.attest_key_and_obtain_cert(&priv_key_handle, &report_data);
        assert!(result.is_ok(), "result {:?}", result);
        let (response_report, _cert) = result.unwrap();
        //TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE 834
        assert!(response_report.len() <= 834 && !response_report.is_empty());
    });
}

#[test]
fn test_attest_rsa_key_and_obtain_cert_with_unwrapped_rsa() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let mut report_data: [u8; 128] = [2; 128];
        report_data.copy_from_slice(&data);

        let result = app_session.attest_key_and_obtain_cert(&priv_key_handle, &report_data);
        assert!(result.is_ok(), "result {:?}", result);
        let (response_report, _cert) = result.unwrap();
        //TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE 834
        assert!(response_report.len() <= 834 && !response_report.is_empty());
    });
}

/// Setup function that clears device without establish credentials
#[cfg(feature = "mock")]
pub fn setup(_device: &HsmDevice, path: &str) {
    let result = HsmDevice::open(path);
    assert!(result.is_ok(), "result {:?}", result);
    let device = result.unwrap();

    // Establish credential can only happen once so it could fail
    // in future instances so ignore error
    let api_rev = device.get_api_revision_range().max;
    let mut bk3 = [0u8; 48];
    use crypto::rand::rand_bytes;
    let _ = rand_bytes(&mut bk3);
    let masked_bk3 = device.init_bk3(api_rev, &bk3).unwrap();
    let resp = device.establish_credential(api_rev, TEST_APP_CREDENTIALS, masked_bk3, None, None);
    if let Err(resp) = resp {
        println!("establish credential failed with {}. Ignoring since establish credential can only be done once and may have happened before", resp);
    } else {
        println!("establish credential succeeded");
    }

    let mut app_session = common_open_app_session(&device);
    let result = app_session.clear_device();
    assert!(result.is_ok(), "clear_device result {:?}", result);
}

#[test]
#[cfg(feature = "mock")]
fn test_attest_rsa_key_lm_then_obtain_cert_with_unwrapped_rsa() {
    api_test(setup, common_cleanup, |device, path| {
        let masked_bk3 = {
            let mut bk3 = [0u8; 48];
            crypto::rand::rand_bytes(&mut bk3).unwrap();

            common_establish_credential(device, &bk3)
        };

        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let mut report_data: [u8; 128] = [2; 128];
        report_data.copy_from_slice(&data);

        let result = app_session.attest_key(&priv_key_handle, &report_data);
        assert!(result.is_ok(), "result {:?}", result);
        let attestation_report = result.unwrap();

        // Trigger LM
        let migration_result = common_simulate_lm_reestablish_cred(path, masked_bk3);
        assert!(
            migration_result.is_ok(),
            "Migration simulation should succeed"
        );

        // Fetch cert
        let result = app_session.get_certificate();
        assert!(result.is_ok(), "result {:?}", result);
        let certificate = result.unwrap();

        // Manually verify the report with leaf cert
        {
            // Find the leaf cert from cert chain
            let leaf_cert_pem = {
                let pattern_header = "-----BEGIN CERTIFICATE-----".as_bytes();
                let pattern_footer = "-----END CERTIFICATE-----".as_bytes();

                let start = certificate
                    .windows(pattern_header.len())
                    .position(|window| window == pattern_header)
                    .unwrap();
                let end = certificate
                    .windows(pattern_footer.len())
                    .position(|window| window == pattern_footer)
                    .unwrap();

                // Move to end of footer
                let end = end + pattern_footer.len();

                &certificate[start..end]
            };

            // Parse the leaf cert to get a ECC Pub key
            let ecc_pub_key = {
                let cert = X509Certificate::from_pem(leaf_cert_pem).unwrap();
                let der = cert.get_public_key_der().unwrap();
                EccPublicKey::from_der(&der, None).unwrap()
            };

            let key_attester = KeyAttester::parse(&attestation_report).unwrap();

            // If error is AttestationError::ReportSignatureMismatch, LM might occurred
            let result = key_attester.verify(&ecc_pub_key);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err, AttestationError::ReportSignatureMismatch);
        }
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_attest() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        //size  REPORT_DATA_SIZE

        {
            let result = app_session.import_key(
                TEST_RSA_2K_PRIVATE_KEY.to_vec(),
                KeyClass::Rsa,
                None,
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::Session,
                },
            );
            assert!(result.is_ok(), "result {:?}", result);
            let priv_key_handle = result.unwrap();

            let data = generate_random_vector(128);
            let mut report_data: [u8; 128] = [2; 128];
            report_data.copy_from_slice(&data);

            let result = app_session.attest_key(&priv_key_handle, &report_data);
            assert!(result.is_ok(), "result {:?}", result);
            let response_report = result.unwrap();
            //TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE 834
            assert!(response_report.len() <= 834 && !response_report.is_empty());
        }
    });
}

#[test]
fn test_attest_aes_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::Aes256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let result = app_session.attest_key(&aes_key_handle, &[2; 128]);
        assert_eq!(result, Err(HsmError::InvalidKeyType));
    });
}

#[test]
fn test_attest_secret_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle1 = result.unwrap();

        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle2 = result.unwrap();

        // Get the DER from key handle
        let result = app_session.export_public_key(&priv_key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der2 = result.unwrap();

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &pub_key_der2,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let secret_handle = result.unwrap();

        let result = app_session.attest_key(&secret_handle, &[2; 128]);
        assert_eq!(result, Err(HsmError::InvalidKeyType));
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_attest_rsa_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
            let result = app_session.import_key(
                TEST_RSA_2K_PRIVATE_KEY.to_vec(),
                KeyClass::Rsa,
                None,
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::Session,
                },
            );
            assert!(result.is_ok(), "result {:?}", result);
            let priv_key_handle = result.unwrap();

            let result = app_session.attest_key(&priv_key_handle, &[2; 128]);
            assert!(result.is_ok(), "result {:?}", result);
        }
    });
}

#[test]
fn test_attest_ecc_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.attest_key(&priv_key_handle, &[2; 128]);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_attest_aes_key_negative() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::Aes256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let result = app_session.attest_key(&aes_key_handle, &[2; 128]);
        assert_eq!(result, Err(HsmError::InvalidKeyType));
    });
}

#[test]
fn test_attest_secret_negative() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle1 = result.unwrap();

        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle2 = result.unwrap();

        // Get the DER from key handle
        let result = app_session.export_public_key(&priv_key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der2 = result.unwrap();

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &pub_key_der2,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let secret_handle = result.unwrap();

        let result = app_session.attest_key(&secret_handle, &[2; 128]);
        assert_eq!(result, Err(HsmError::InvalidKeyType));
    });
}
