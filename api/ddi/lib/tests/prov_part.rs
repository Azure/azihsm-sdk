// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use crypto::rand::rand_bytes;
use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use session_parameter_encryption::DeviceCredentialEncryptionKey;
use test_with_tracing::test;

use crate::common::*;

pub fn setup(dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str) -> u16 {
    let session_id = common_setup(dev, ddi, path);

    // Execute NSSR to remove establish credential status.
    let result = dev.simulate_nssr_after_lm();
    assert!(
        result.is_ok(),
        "Migration simulation should succeed: {:?}",
        result
    );

    session_id
}

// Helper function to test SetSealedBk3 and GetSealedBk3
fn helper_test_set_get_sealed_bk3(
    dev: &mut <DdiTest as Ddi>::Dev,
    sealed_bk3: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = helper_set_sealed_bk3(dev, sealed_bk3.to_vec());
    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();
    assert_eq!(resp.hdr.op, DdiOp::SetSealedBk3);
    assert!(resp.hdr.rev.is_some());
    assert!(resp.hdr.sess_id.is_none());
    assert_eq!(resp.hdr.status, DdiStatus::Success);

    let resp = helper_get_sealed_bk3(dev);
    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();
    assert_eq!(resp.hdr.op, DdiOp::GetSealedBk3);
    assert!(resp.hdr.rev.is_some());
    assert!(resp.hdr.sess_id.is_none());
    assert_eq!(resp.hdr.status, DdiStatus::Success);

    let returned_sealed = resp.data.sealed_bk3.as_slice();
    assert_eq!(returned_sealed, sealed_bk3);

    Ok(())
}

#[test]
fn test_set_and_get_sealed_bk3() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let sealed_bk3 = [9u8; 499];
            let resp = helper_test_set_get_sealed_bk3(dev, &sealed_bk3);
            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_part_prov_test_provisioning() {
    ddi_dev_test(setup, common_cleanup, |_dev, ddi, path, _session_id| {
        let mut dev = ddi.open_dev(path).unwrap();

        // Set Device Kind
        set_device_kind(&mut dev);

        let mut bk3 = vec![0u8; 48];
        rand_bytes(&mut bk3).unwrap();
        let masked_bk3 = helper_init_bk3(&dev, bk3).unwrap().data.masked_bk3;

        let sealed_bk3 = [9u8; 499];
        let resp = helper_test_set_get_sealed_bk3(&mut dev, &sealed_bk3);
        assert!(resp.is_ok(), "resp {:?}", resp);

        // This is the initial setup so optional fields are empty
        let _ = helper_common_establish_credential_with_bmk(
            &mut dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            masked_bk3,
            MborByteArray::from_slice(&[]).expect("Failed to create empty BMK"),
            MborByteArray::from_slice(&[]).expect("Failed to create empty masked unwrapping key"),
        );

        let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
            &dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        );

        let resp = helper_open_session(
            &dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            encrypted_credential,
            pub_key,
        );
        assert!(resp.is_ok(), "resp {:?}", resp);
        let resp = resp.unwrap();
        assert!(resp.hdr.sess_id.is_some());
    });
}

#[test]
fn test_part_prov_test_lm() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            // simulate LM
            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let mut setup_dev = ddi.open_dev(path).unwrap();
            // Set Device Kind
            set_device_kind(&mut setup_dev);

            let _ = helper_common_establish_credential_with_bmk(
                &mut setup_dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"), // No unwrapping key is present, send an empty array
            );

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                &setup_dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let resp = helper_open_session(
                &setup_dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();
            assert!(resp.hdr.sess_id.is_some());
        },
    );
}

#[test]
fn test_part_not_prov() {
    ddi_dev_test(setup, common_cleanup, |_dev, ddi, path, _session_id| {
        let mut dev = ddi.open_dev(path).unwrap();

        // Set Device Kind
        set_device_kind(&mut dev);

        let mut bk3 = vec![0u8; 48];
        rand_bytes(&mut bk3).unwrap();
        let masked_bk3 = helper_init_bk3(&dev, bk3).unwrap().data.masked_bk3;

        let sealed_bk3 = [9u8; 499];
        let resp = helper_test_set_get_sealed_bk3(&mut dev, &sealed_bk3);
        assert!(resp.is_ok(), "resp {:?}", resp);

        // This is the initial setup so optional fields are empty
        let _ = helper_common_establish_credential_with_bmk(
            &mut dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            masked_bk3,
            MborByteArray::from_slice(&[]).expect("Failed to create empty BMK"),
            MborByteArray::from_slice(&[]).expect("Failed to create empty masked unwrapping key"),
        );

        let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
            &dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        );

        // Open session
        let resp = helper_open_session(
            &dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            encrypted_credential,
            pub_key,
        );
        assert!(resp.is_ok(), "resp {:?}", resp);
        let session_id = resp.unwrap().hdr.sess_id;

        // Send test action to clear the provisioning state
        let resp = helper_test_action_cmd(
            &mut dev,
            session_id.unwrap(),
            DdiTestAction::ClearProvisioningState,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        if let Err(err) = resp {
            assert!(
                matches!(err, DdiError::DdiStatus(DdiStatus::UnsupportedCmd)),
                "{:?}",
                err
            );

            println!("Firmware is not build with mcr_test_hooks");
            return;
        }

        // Generate AES key (in-session command)
        let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

        let resp = helper_aes_generate(
            &dev,
            session_id,
            Some(DdiApiRev { major: 1, minor: 0 }),
            DdiAesKeySize::Aes128,
            None,
            key_props,
        );

        // The command should fail with PartitionNotProvisioned error
        assert!(resp.is_err(), "resp {:?}", resp);
        assert!(matches!(
            resp.unwrap_err(),
            DdiError::DdiStatus(DdiStatus::PartitionNotProvisioned)
        ));
    });
}

#[test]
fn test_part_prov_only_once() {
    ddi_dev_test(setup, common_cleanup, |_dev, ddi, path, _session_id| {
        let mut dev = ddi.open_dev(path).unwrap();

        // Set Device Kind
        set_device_kind(&mut dev);

        let mut bk3 = vec![0u8; 48];
        rand_bytes(&mut bk3).unwrap();
        let masked_bk3 = helper_init_bk3(&dev, bk3).unwrap().data.masked_bk3;

        let sealed_bk3 = [9u8; 499];
        let resp = helper_test_set_get_sealed_bk3(&mut dev, &sealed_bk3);
        assert!(resp.is_ok(), "resp {:?}", resp);

        // This is the initial setup so optional fields are empty
        let _ = helper_common_establish_credential_with_bmk(
            &mut dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            masked_bk3,
            MborByteArray::from_slice(&[]).expect("Failed to create empty BMK"),
            MborByteArray::from_slice(&[]).expect("Failed to create empty masked unwrapping key"),
        );

        let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
            &dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        );

        // Open session
        let resp = helper_open_session(
            &dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            encrypted_credential,
            pub_key,
        );
        assert!(resp.is_ok(), "resp {:?}", resp);
        let session_id = resp.unwrap().hdr.sess_id;

        // Generate AES key (in-session command)
        let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

        let resp = helper_aes_generate(
            &dev,
            session_id,
            Some(DdiApiRev { major: 1, minor: 0 }),
            DdiAesKeySize::Aes128,
            None,
            key_props,
        );

        // The command should succeed as partition is provisioned
        assert!(resp.is_ok(), "resp {:?}", resp);

        // Send test action to clear the credentials
        let resp = helper_test_action_cmd(
            &mut dev,
            session_id.unwrap(),
            DdiTestAction::ClearUserCredentials,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        if let Err(err) = resp {
            assert!(
                matches!(err, DdiError::DdiStatus(DdiStatus::UnsupportedCmd)),
                "{:?}",
                err
            );

            println!("Firmware is not build with mcr_test_hooks");
            return;
        }

        // Get establish credential encryption key
        let resp = helper_get_establish_cred_encryption_key(
            &dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
        );
        assert!(resp.is_ok(), "resp {:?}", resp);

        // Establish credential
        let resp = resp.unwrap();
        let nonce = resp.data.nonce;
        let param_encryption_key =
            DeviceCredentialEncryptionKey::new(&resp.data.pub_key, nonce).unwrap();
        let (establish_cred_encryption_key, ddi_public_key) = param_encryption_key
            .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
            .unwrap();
        let ddi_encrypted_credential = establish_cred_encryption_key
            .encrypt_establish_credential(TEST_CRED_ID, TEST_CRED_PIN, nonce)
            .unwrap();

        let mut bk3 = vec![0u8; 48];
        rand_bytes(&mut bk3).unwrap();
        let masked_bk3 = helper_init_bk3(&dev, bk3).unwrap().data.masked_bk3;

        let resp = helper_establish_credential(
            &dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            ddi_encrypted_credential,
            ddi_public_key,
            masked_bk3,
            MborByteArray::from_slice(&[]).expect("Failed to create empty BMK"), // No BMK is present, as we are not simulating LM
            MborByteArray::from_slice(&[]).expect("Failed to create empty masked unwrapping key"), // No unwrapping key is present, send an empty array
        );

        // The command should fail with PartitionAlreadyProvisioned error
        assert!(resp.is_err(), "resp {:?}", resp);
        assert!(matches!(
            resp.unwrap_err(),
            DdiError::DdiStatus(DdiStatus::PartitionAlreadyProvisioned)
        ));
    });
}
