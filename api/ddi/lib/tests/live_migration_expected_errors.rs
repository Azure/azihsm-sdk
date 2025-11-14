// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

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

        let masked_bk3 = helper_init_bk3(dev, vec![0u8; 48]).unwrap().data.masked_bk3;

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
