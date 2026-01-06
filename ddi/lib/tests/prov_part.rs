// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use azihsm_crypto::*;
use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
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
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let sealed_bk3 = [9u8; 499];
            let resp = helper_test_set_get_sealed_bk3(dev, &sealed_bk3);
            assert!(resp.is_ok(), "resp {:?}", resp);
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
