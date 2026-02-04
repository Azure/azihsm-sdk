// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(test)]

use azihsm_crypto::{EcdsaAlgo, HashAlgo, ImportableKey, Signer};
use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;
use x509::{X509Certificate, X509CertificateOp};

use super::common::*;

// For tests that do not open a session before Live migration
pub fn setup(dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str) -> u16 {
    common_cleanup(dev, ddi, path, None);

    // Return incorrect session id since this is a no session command
    25
}

#[test]
fn test_get_establish_cred_encryption_key_after_lm() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _session_id| {
        // Execute NSSR to simulate live migration
        let result = dev.simulate_nssr_after_lm();
        assert!(
            result.is_ok(),
            "Migration simulation should succeed: {:?}",
            result
        );

        // Confirm this is successful
        let resp = helper_get_establish_cred_encryption_key(
            dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
        );

        assert!(resp.is_ok(), "resp {:?}", resp);
    });
}

#[test]
fn test_establish_credential_after_lm() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _session_id| {
        let (encrypted_credential, pub_key) =
            encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

        // Execute NSSR to simulate live migration
        let result = dev.simulate_nssr_after_lm();
        assert!(
            result.is_ok(),
            "Migration simulation should succeed: {:?}",
            result
        );

        let masked_bk3 = helper_get_or_init_bk3(dev);

        let get_cert_chain_info = helper_get_cert_chain_info(dev).unwrap();
        // Get last cert
        let cert_resp =
            helper_get_certificate(dev, get_cert_chain_info.data.num_certs - 1).unwrap();
        let cert = cert_resp.data.certificate.as_slice();
        let cert = X509Certificate::from_der(cert).unwrap();
        let cert_pub_key_der = cert.get_public_key_der().unwrap();
        let cert_pub_key_obj = azihsm_crypto::DerEccPublicKey::from_der(&cert_pub_key_der).unwrap();
        let mut cert_pub_key_tbs = vec![0x04u8];
        cert_pub_key_tbs.extend_from_slice(&cert_pub_key_obj.x());
        cert_pub_key_tbs.extend_from_slice(&cert_pub_key_obj.y());

        let hash_algo = HashAlgo::sha384();
        let mut ecdsa_algo = EcdsaAlgo::new(hash_algo);
        let tpm_priv_key =
            azihsm_crypto::EccPrivateKey::from_bytes(&TEST_TPM_ECC_PRIVATE_KEY).unwrap();
        let sig_len =
            Signer::sign(&mut ecdsa_algo, &tpm_priv_key, &cert_pub_key_tbs, None).unwrap();
        let mut signature = vec![0u8; sig_len];
        let _ = Signer::sign(
            &mut ecdsa_algo,
            &tpm_priv_key,
            &cert_pub_key_tbs,
            Some(&mut signature),
        )
        .unwrap();

        // Confirm fails with NonceMismatch
        let resp = helper_establish_credential(
            dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            encrypted_credential,
            pub_key,
            masked_bk3,
            MborByteArray::from_slice(&[0u8; 1024]).unwrap(),
            MborByteArray::from_slice(&[0u8; 1024]).unwrap(),
            MborByteArray::from_slice(&signature).expect("Failed to create signed PID"),
            DdiDerPublicKey {
                der: MborByteArray::from_slice(&TEST_TPM_ECC_PUB_KEY)
                    .expect("Failed to create MborByteArray from TPM ECC public key"),
                key_kind: DdiKeyType::Ecc384Public,
            },
        );

        assert!(resp.is_err(), "resp {:?}", resp);

        assert!(
            matches!(
                resp.as_ref().unwrap_err(),
                DdiError::DdiStatus(DdiStatus::NonceMismatch)
            ),
            "resp {:?}",
            resp
        );
    });
}

#[test]
fn test_get_session_encryption_key_after_lm() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            // Execute NSSR to simulate live migration
            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            // Confirm fails with CredentialsNotEstablished
            let resp = helper_get_session_encryption_key(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::CredentialsNotEstablished)
                ),
                "resp {:?}",
                resp
            );
        },
    );
}

#[test]
fn test_open_session_after_lm() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            // Execute NSSR to simulate live migration
            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            // Confirm fails with CredentialsNotEstablished
            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::CredentialsNotEstablished)
                ),
                "resp {:?}",
                resp
            );
        },
    );
}

#[test]
fn test_reopen_session_after_lm() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            // Execute NSSR to simulate live migration
            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let resp = helper_reopen_session(
                dev,
                session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                MborByteArray::from_slice(&[]).expect("Failed to create empty BMK array"),
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::PartitionNotProvisioned)
                ),
                "resp {:?}",
                resp
            );
        },
    );
}
