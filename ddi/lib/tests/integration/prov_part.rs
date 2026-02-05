// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto::*;
use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

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

#[test]
fn test_part_prov_test_provisioning() {
    ddi_dev_test(setup, common_cleanup, |dev, ddi, path, _session_id| {
        if get_device_kind(dev) != DdiDeviceKind::Physical {
            println!("Physical device NOT found. Test only supported on physical device.");
            return;
        }

        let mut dev = ddi.open_dev(path).unwrap();

        // Set Device Kind
        set_device_kind(&mut dev);

        let mut bk3 = vec![0u8; 48];
        Rng::rand_bytes(&mut bk3).unwrap();
        let masked_bk3 = helper_get_or_init_bk3(&dev);

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
fn test_part_prov_fail_then_succeed() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

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

            // Try establish credential with invalid partition_bmk
            let mut random_bmk = [0u8; 48];
            Rng::rand_bytes(&mut random_bmk).expect("Failed to create random bytes");

            let resp = helper_common_establish_credential_with_bmk_no_unwrap(
                &mut setup_dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                MborByteArray::from_slice(&random_bmk).expect("Failed to create mborbytearray"),
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"), // No unwrapping key is present, send an empty array
            );

            assert!(resp.is_err(), "resp {:?}", resp);
            println!("{:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::MaskedKeyDecodeFailed)
            ));

            // Now try with correct bmk; it should be successful
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
