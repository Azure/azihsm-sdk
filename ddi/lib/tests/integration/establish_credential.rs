// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(test)]

use std::thread;

use azihsm_crypto::*;
use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::MborError;
use azihsm_ddi_types::*;
use test_with_tracing::test;
use x509::X509Certificate;
use x509::X509CertificateOp;

use super::common::*;
use super::invalid_ecc_pub_key_vectors::*;

pub fn setup(dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str) -> u16 {
    common_cleanup(dev, ddi, path, None);

    // Return incorrect session id since this is a no session command
    25
}

// Helper function to initialize the device and establish credential
fn helper_init_bk3_and_establish_credential(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    encrypted_credential: DdiEncryptedEstablishCredential,
    pub_key: DdiDerPublicKey,
) -> Result<DdiEstablishCredentialCmdResp, DdiError> {
    let masked_bk3 = helper_get_or_init_bk3(dev);

    let get_cert_chain_info = helper_get_cert_chain_info(dev).unwrap();
    // Get last cert
    let cert_resp = helper_get_certificate(dev, get_cert_chain_info.data.num_certs - 1).unwrap();
    let cert = cert_resp.data.certificate.as_slice();
    let cert = X509Certificate::from_der(cert).unwrap();
    let cert_pub_key = cert.get_public_key_der().unwrap();

    let hash_algo = HashAlgo::sha384();
    let mut ecdsa_algo = EcdsaAlgo::new(hash_algo);
    let tpm_priv_key = azihsm_crypto::EccPrivateKey::from_bytes(&TEST_TPM_ECC_PRIVATE_KEY).unwrap();
    let sig_len = Signer::sign(&mut ecdsa_algo, &tpm_priv_key, &cert_pub_key, None).unwrap();
    let mut signature = vec![0u8; sig_len];
    let _ = Signer::sign(
        &mut ecdsa_algo,
        &tpm_priv_key,
        &cert_pub_key,
        Some(&mut signature),
    )
    .unwrap();

    helper_establish_credential(
        dev,
        sess_id,
        rev,
        encrypted_credential,
        pub_key,
        masked_bk3,
        MborByteArray::from_slice(&[]).expect("Failed to create empty BMK"),
        MborByteArray::from_slice(&[]).expect("Failed to create empty masked unwrapping key"),
        MborByteArray::from_slice(&signature).expect("Failed to create signed PID"),
        DdiDerPublicKey {
            der: MborByteArray::from_slice(&TEST_TPM_ECC_PUB_KEY)
                .expect("Failed to create MborByteArray from TPM ECC public key"),
            key_kind: DdiKeyType::Ecc384Public,
        },
    )
}

#[test]
fn test_establish_credential_success_prov_failure_bad_masked_bk3() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let masked_bk3 = helper_get_or_init_bk3(dev);

            // tamper the masked bk3 to cause provisioning failure
            let mut tampered_masked_bk3 = masked_bk3;
            tampered_masked_bk3.data_mut()[10] =
                tampered_masked_bk3.data_take()[10].wrapping_add(1);

            let resp = helper_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential.clone(),
                pub_key.clone(),
                tampered_masked_bk3,
                MborByteArray::from_slice(&[]).expect("Failed to create empty BMK"),
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
                MborByteArray::from_slice(&[]).expect("Failed to create signed PID"),
                DdiDerPublicKey {
                    der: MborByteArray::from_slice(&[]).expect("Failed to create empty DER"),
                    key_kind: DdiKeyType::Ecc384Public,
                },
            );

            assert!(resp.is_err());

            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

            // lets re-attempt with correct masked bk3 to ensure success
            let resp = helper_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                masked_bk3,
                MborByteArray::from_slice(&[]).expect("Failed to create empty BMK"),
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
                MborByteArray::from_slice(&[]).expect("Failed to create signed PID"),
                DdiDerPublicKey {
                    der: MborByteArray::from_slice(&[]).expect("Failed to create empty DER"),
                    key_kind: DdiKeyType::Ecc384Public,
                },
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            assert!(resp.hdr.sess_id.is_none());
            assert_eq!(resp.hdr.op, DdiOp::EstablishCredential);
            assert_eq!(resp.hdr.status, DdiStatus::Success);
        },
    );
}

#[test]
fn test_establish_credential_with_session() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, incorrect_session_id| {
            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                Some(incorrect_session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidArg)
            ));
        },
    );
}

#[test]
fn test_establish_credential_without_revision() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                None,
                None,
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::UnsupportedRevision)
            ));
        },
    );
}

#[test]
fn test_establish_credential() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            assert!(resp.hdr.sess_id.is_none());
            assert_eq!(resp.hdr.op, DdiOp::EstablishCredential);
            assert_eq!(resp.hdr.status, DdiStatus::Success);
        },
    );
}

#[test]
fn test_establish_credential_without_get_key() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let encrypted_credential = DdiEncryptedEstablishCredential {
                encrypted_id: MborByteArray::new(
                    [
                        69, 237, 223, 217, 67, 83, 78, 223, 104, 238, 179, 193, 249, 43, 57, 102,
                    ],
                    16,
                )
                .expect("failed to create byte array"),
                encrypted_pin: MborByteArray::new(
                    [
                        240, 244, 194, 248, 223, 76, 238, 234, 13, 32, 210, 231, 13, 237, 38, 215,
                    ],
                    16,
                )
                .expect("failed to create byte array"),
                iv: MborByteArray::new(
                    [
                        211, 139, 212, 48, 114, 222, 183, 23, 106, 21, 2, 21, 251, 191, 145, 18,
                    ],
                    16,
                )
                .expect("failed to create byte array"),
                nonce: {
                    let mut nonce_bytes = [0u8; 32];
                    nonce_bytes[..4].copy_from_slice(&2187282822u32.to_le_bytes());
                    nonce_bytes
                },

                tag: [29; 48],
            };
            let pub_key = DdiDerPublicKey {
                der: MborByteArray::new(
                    [
                        48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34,
                        3, 98, 0, 4, 228, 32, 154, 215, 7, 164, 136, 26, 255, 240, 18, 97, 146,
                        199, 157, 131, 119, 73, 33, 204, 93, 243, 185, 33, 196, 61, 174, 170, 88,
                        184, 52, 43, 56, 60, 218, 178, 136, 240, 228, 185, 86, 20, 17, 21, 117,
                        186, 187, 35, 124, 103, 247, 209, 151, 99, 199, 184, 86, 211, 34, 178, 186,
                        186, 26, 198, 180, 234, 13, 173, 162, 86, 41, 213, 202, 15, 74, 78, 238,
                        23, 176, 178, 244, 177, 88, 186, 174, 161, 88, 156, 16, 7, 247, 14, 199,
                        98, 66, 224, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0,
                    ],
                    120,
                )
                .expect("failed to create byte array"),
                key_kind: DdiKeyType::Ecc384Public,
            };

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_establish_credential_multiple() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

            {
                let resp = helper_init_bk3_and_establish_credential(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_none());
                assert_eq!(resp.hdr.op, DdiOp::EstablishCredential);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
            }

            for _ in 0..10 {
                let resp = helper_init_bk3_and_establish_credential(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                );

                assert!(resp.is_err(), "resp {:?}", resp);
            }
        },
    );
}

#[test]
fn test_establish_credential_multiple_get_key() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            {
                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

                let resp = helper_init_bk3_and_establish_credential(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_none());
                assert_eq!(resp.hdr.op, DdiOp::EstablishCredential);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
            }

            for _ in 0..10 {
                let resp = helper_get_establish_cred_encryption_key(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );
                assert!(resp.is_err(), "resp {:?}", resp);

                let resp = helper_get_establish_cred_encryption_key(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );

                assert!(resp.is_err(), "resp {:?}", resp);
            }
        },
    );
}

#[test]
fn test_establish_credential_tamper_id() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let (mut tampered_encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);
            tampered_encrypted_credential.encrypted_id.data_mut()[10] =
                tampered_encrypted_credential.encrypted_id.data_take()[10].wrapping_add(1);

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                tampered_encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::PinDecryptionFailed)
            ));
        },
    );
}

#[test]
fn test_establish_credential_tamper_pin() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let (mut tampered_encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);
            tampered_encrypted_credential.encrypted_pin.data_mut()[10] =
                tampered_encrypted_credential.encrypted_pin.data_take()[10].wrapping_add(1);

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                tampered_encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::PinDecryptionFailed)
            ));
        },
    );
}

#[test]
fn test_establish_credential_tamper_iv() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let (mut tampered_encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);
            tampered_encrypted_credential.iv.data_mut()[10] =
                tampered_encrypted_credential.iv.data_take()[10].wrapping_add(1);

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                tampered_encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::PinDecryptionFailed)
            ));
        },
    );
}

#[test]
fn test_establish_credential_tamper_nonce() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let (mut tampered_encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);
            tampered_encrypted_credential.nonce[0] =
                tampered_encrypted_credential.nonce[0].wrapping_add(1);

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                tampered_encrypted_credential,
                pub_key,
            );

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::NonceMismatch)
            ));
        },
    );
}

#[test]
fn test_establish_credential_tamper_tag() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let (mut tampered_encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);
            tampered_encrypted_credential.tag[10] =
                tampered_encrypted_credential.tag[10].wrapping_add(1);

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                tampered_encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::PinDecryptionFailed)
            ));
        },
    );
}

#[test]
fn test_establish_credential_tamper_pub_key() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let (encrypted_credential, mut tampered_pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);
            tampered_pub_key.der.data_mut()[30] =
                tampered_pub_key.der.data_take()[30].wrapping_add(1);

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                tampered_pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_establish_credential_tamper_signed_pid() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let masked_bk3 = helper_get_or_init_bk3(dev);

            let get_cert_chain_info = helper_get_cert_chain_info(dev).unwrap();
            // Get last cert
            let cert_resp =
                helper_get_certificate(dev, get_cert_chain_info.data.num_certs - 1).unwrap();
            let cert = cert_resp.data.certificate.as_slice();
            let cert = X509Certificate::from_der(cert).unwrap();
            let cert_pub_key = cert.get_public_key_der().unwrap();

            let hash_algo = HashAlgo::sha384();
            let mut ecdsa_algo = EcdsaAlgo::new(hash_algo);
            let tpm_priv_key =
                azihsm_crypto::EccPrivateKey::from_bytes(&TEST_TPM_ECC_PRIVATE_KEY).unwrap();
            let sig_len =
                Signer::sign(&mut ecdsa_algo, &tpm_priv_key, &cert_pub_key, None).unwrap();
            let mut signature = vec![0u8; sig_len];
            let _ = Signer::sign(
                &mut ecdsa_algo,
                &tpm_priv_key,
                &cert_pub_key,
                Some(&mut signature),
            )
            .unwrap();

            let mut tampered_signature = signature.clone();
            tampered_signature[signature.len() / 2] =
                tampered_signature[signature.len() / 2].wrapping_add(1);

            let resp = helper_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                masked_bk3,
                MborByteArray::from_slice(&[]).expect("Failed to create empty BMK"),
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
                MborByteArray::from_slice(&tampered_signature)
                    .expect("Failed to create signed PID"),
                DdiDerPublicKey {
                    der: MborByteArray::from_slice(&TEST_TPM_ECC_PUB_KEY)
                        .expect("Failed to create MborByteArray from TPM ECC public key"),
                    key_kind: DdiKeyType::Ecc384Public,
                },
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_establish_credential_tamper_tpm_pub_key() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let masked_bk3 = helper_get_or_init_bk3(dev);

            let get_cert_chain_info = helper_get_cert_chain_info(dev).unwrap();
            // Get last cert
            let cert_resp =
                helper_get_certificate(dev, get_cert_chain_info.data.num_certs - 1).unwrap();
            let cert = cert_resp.data.certificate.as_slice();
            let cert = X509Certificate::from_der(cert).unwrap();
            let cert_pub_key = cert.get_public_key_der().unwrap();

            let hash_algo = HashAlgo::sha384();
            let mut ecdsa_algo = EcdsaAlgo::new(hash_algo);
            let tpm_priv_key =
                azihsm_crypto::EccPrivateKey::from_bytes(&TEST_TPM_ECC_PRIVATE_KEY).unwrap();
            let sig_len =
                Signer::sign(&mut ecdsa_algo, &tpm_priv_key, &cert_pub_key, None).unwrap();
            let mut signature = vec![0u8; sig_len];
            let _ = Signer::sign(
                &mut ecdsa_algo,
                &tpm_priv_key,
                &cert_pub_key,
                Some(&mut signature),
            )
            .unwrap();

            let mut tampered_tpm_pub_key = TEST_TPM_ECC_PUB_KEY.clone();
            tampered_tpm_pub_key[TEST_TPM_ECC_PUB_KEY.len() / 2] =
                tampered_tpm_pub_key[TEST_TPM_ECC_PUB_KEY.len() / 2].wrapping_add(1);

            let resp = helper_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                masked_bk3,
                MborByteArray::from_slice(&[]).expect("Failed to create empty BMK"),
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
                MborByteArray::from_slice(&signature).expect("Failed to create signed PID"),
                DdiDerPublicKey {
                    der: MborByteArray::from_slice(&tampered_tpm_pub_key)
                        .expect("Failed to create MborByteArray from TPM ECC public key"),
                    key_kind: DdiKeyType::Ecc384Public,
                },
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_establish_credential_tamper_tpm_pub_key_type() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let masked_bk3 = helper_get_or_init_bk3(dev);

            let get_cert_chain_info = helper_get_cert_chain_info(dev).unwrap();
            // Get last cert
            let cert_resp =
                helper_get_certificate(dev, get_cert_chain_info.data.num_certs - 1).unwrap();
            let cert = cert_resp.data.certificate.as_slice();
            let cert = X509Certificate::from_der(cert).unwrap();
            let cert_pub_key = cert.get_public_key_der().unwrap();

            let hash_algo = HashAlgo::sha384();
            let mut ecdsa_algo = EcdsaAlgo::new(hash_algo);
            let tpm_priv_key =
                azihsm_crypto::EccPrivateKey::from_bytes(&TEST_TPM_ECC_PRIVATE_KEY).unwrap();
            let sig_len =
                Signer::sign(&mut ecdsa_algo, &tpm_priv_key, &cert_pub_key, None).unwrap();
            let mut signature = vec![0u8; sig_len];
            let _ = Signer::sign(
                &mut ecdsa_algo,
                &tpm_priv_key,
                &cert_pub_key,
                Some(&mut signature),
            )
            .unwrap();

            let resp = helper_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                masked_bk3,
                MborByteArray::from_slice(&[]).expect("Failed to create empty BMK"),
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
                MborByteArray::from_slice(&signature).expect("Failed to create signed PID"),
                DdiDerPublicKey {
                    der: MborByteArray::from_slice(&TEST_TPM_ECC_PUB_KEY)
                        .expect("Failed to create MborByteArray from TPM ECC public key"),
                    key_kind: DdiKeyType::Ecc521Public,
                },
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_establish_credential_null_id() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, [0; 16], TEST_CRED_PIN);

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)
            ));
        },
    );
}

#[test]
fn test_establish_credential_null_pin() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, [0; 16]);

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)
            ));
        },
    );
}

#[test]
fn test_establish_credential_verify_nonce_change() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |_dev, _ddi, _path, _incorrect_session_id| {
            // Currently no way to verify this from this layer
        },
    );
}

#[test]
fn test_establish_credential_verify_public_key_change() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |_dev, _ddi, _path, _incorrect_session_id| {
            // Currently no way to verify this from this layer
        },
    );
}

#[test]
fn test_establish_credential_multi_threaded_single_winner_stress() {
    for _ in 0..10 {
        test_establish_credential_multi_threaded_single_winner();
    }
}

#[test]
fn test_establish_credential_multi_threaded_single_winner() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, path, _incorrect_session_id| {
            let thread_count = 16;

            let mut bk3 = vec![0u8; 48];
            Rng::rand_bytes(&mut bk3).unwrap();
            let masked_bk3_result = helper_get_or_init_bk3(dev);

            let mut thread_list = Vec::new();
            for i in 0..thread_count {
                let thread_id = i as u8;
                let thread_device_path = path.to_string();

                let thread = thread::spawn(move || {
                    test_thread_fn(thread_id, thread_device_path, masked_bk3_result)
                });
                thread_list.push(thread);
            }

            let mut threads_failed = 0;
            let mut threads_passed = 0;

            for thread in thread_list {
                let result = thread.join();

                if result.is_ok() {
                    threads_passed += 1;
                } else {
                    threads_failed += 1;
                }
            }

            assert_eq!(
                threads_passed, 1,
                "Only 1 thread should succeed, others must fail"
            );
            assert_eq!(
                threads_failed,
                thread_count - 1,
                "Only 1 thread should succeed, others must fail"
            );
        },
    );
}

fn test_thread_fn(_thread_id: u8, device_path: String, masked_bk3: MborByteArray<1024>) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);

    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_establish_cred(&dev, TEST_CRED_ID, TEST_CRED_PIN);

    let get_cert_chain_info = helper_get_cert_chain_info(&dev).unwrap();
    // Get last cert
    let cert_resp = helper_get_certificate(&dev, get_cert_chain_info.data.num_certs - 1).unwrap();
    let cert = cert_resp.data.certificate.as_slice();
    let cert = X509Certificate::from_der(cert).unwrap();
    let cert_pub_key = cert.get_public_key_der().unwrap();

    let hash_algo = HashAlgo::sha384();
    let mut ecdsa_algo = EcdsaAlgo::new(hash_algo);
    let tpm_priv_key = azihsm_crypto::EccPrivateKey::from_bytes(&TEST_TPM_ECC_PRIVATE_KEY).unwrap();
    let sig_len = Signer::sign(&mut ecdsa_algo, &tpm_priv_key, &cert_pub_key, None).unwrap();
    let mut signature = vec![0u8; sig_len];
    let _ = Signer::sign(
        &mut ecdsa_algo,
        &tpm_priv_key,
        &cert_pub_key,
        Some(&mut signature),
    )
    .unwrap();

    helper_establish_credential(
        &dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        encrypted_credential,
        pub_key,
        masked_bk3,
        MborByteArray::from_slice(&[]).expect("Failed to create empty BMK"),
        MborByteArray::from_slice(&[]).expect("Failed to create empty masked unwrapping key"),
        MborByteArray::from_slice(&signature).expect("Failed to create signed PID"),
        DdiDerPublicKey {
            der: MborByteArray::from_slice(&TEST_TPM_ECC_PUB_KEY)
                .expect("Failed to create MborByteArray from TPM ECC public key"),
            key_kind: DdiKeyType::Ecc384Public,
        },
    )
    .unwrap();
}

#[test]
fn test_establish_credential_null_id_then_proper_id() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let old_nonce;

            {
                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_establish_cred(dev, [0; 16], TEST_CRED_PIN);
                old_nonce = Some(encrypted_credential.nonce);

                let resp = helper_init_bk3_and_establish_credential(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );

                assert!(resp.is_err(), "resp {:?}", resp);

                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)
                ));
            }

            {
                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

                assert_ne!(
                    old_nonce.unwrap(),
                    encrypted_credential.nonce,
                    "Nonce is expected to be different now since crypto portion was successful previously"
                );

                let resp = helper_init_bk3_and_establish_credential(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_none());
                assert_eq!(resp.hdr.op, DdiOp::EstablishCredential);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
            }
        },
    );
}

#[test]
fn test_establish_credential_invalid_public_key_p384_y_as_prime() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (encrypted_credential, _) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

            // Invalid public key for P384 with y coordinate as prime
            let invalid_pub_key = DdiDerPublicKey {
                der: MborByteArray::from_slice(&TEST_ECC_384_PUBLIC_KEY_Y_AS_PRIME)
                    .expect("failed to create byte array"),
                key_kind: DdiKeyType::Ecc384Public,
            };

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                invalid_pub_key,
            );

            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::EccPublicKeyValidationFailed))
            ));
        },
    );
}

#[test]
fn test_establish_credential_invalid_public_key_p384_x_as_prime() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (encrypted_credential, _) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

            // Invalid public key for P384 with x coordinate as prime
            let invalid_pub_key = DdiDerPublicKey {
                der: MborByteArray::from_slice(&TEST_ECC_384_PUBLIC_KEY_X_AS_PRIME)
                    .expect("failed to create byte array"),
                key_kind: DdiKeyType::Ecc384Public,
            };

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                invalid_pub_key,
            );

            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::EccPublicKeyValidationFailed))
            ));
        },
    );
}

#[test]
fn test_establish_credential_invalid_public_key_p384_not_on_curve() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (encrypted_credential, _) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

            // Invalid public key for P384 with point not on the curve
            let invalid_pub_key = DdiDerPublicKey {
                der: MborByteArray::from_slice(&TEST_ECC_384_PUBLIC_KEY_INVALID_POINT_IN_CURVE)
                    .expect("failed to create byte array"),
                key_kind: DdiKeyType::Ecc384Public,
            };

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                invalid_pub_key,
            );

            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::EccPointValidationFailed))
            ));
        },
    );
}

#[test]
fn test_establish_credential_invalid_public_key_p384_point_at_infinity() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (encrypted_credential, _) =
                encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

            // Invalid public key for P384 with point at infinity
            let invalid_pub_key = DdiDerPublicKey {
                der: MborByteArray::from_slice(&ECC_384_PUBLIC_KEY_POINT_AT_INFINITY)
                    .expect("failed to create byte array"),
                key_kind: DdiKeyType::Ecc384Public,
            };

            let resp = helper_init_bk3_and_establish_credential(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                invalid_pub_key,
            );

            assert!(
                matches!(resp, Err(DdiError::MborError(MborError::EncodeError))),
                "Expected Encode Error, got: {:?}",
                resp
            );
        },
    );
}

#[test]
fn test_establish_credential_with_reset_in_middle() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, ddi, path, _incorrect_session_id| {
            {
                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

                let resp = helper_init_bk3_and_establish_credential(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_none());
                assert_eq!(resp.hdr.op, DdiOp::EstablishCredential);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
            }

            // This will do the reset function
            common_cleanup(dev, ddi, path, None);

            {
                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

                let resp = helper_init_bk3_and_establish_credential(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_none());
                assert_eq!(resp.hdr.op, DdiOp::EstablishCredential);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
            }
        },
    );
}

#[test]
fn test_establish_credential_after_reset() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let bmk = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            assert!(!bmk.is_empty());
        },
    );
}
