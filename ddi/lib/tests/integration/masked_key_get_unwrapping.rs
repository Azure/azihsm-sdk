// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_masked_key_get_unwrapping_without_lm() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_, _, masked_key) = get_unwrapping_key(dev, session_id);

            let converted_masked_key: MborByteArray<3072> =
                MborByteArray::from_slice(masked_key.as_slice())
                    .expect("failed to create byte array");

            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                converted_masked_key,
            );
            // Host is not allowed to unmask the masked unwrapping key
            assert!(
                resp.is_err(),
                "Unmask key should fail: {:?}",
                resp.unwrap_err()
            );
        },
    )
}

#[test]
fn test_masked_key_get_unwrapping_with_lm() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let (_, pub_key_der, masked_key) = get_unwrapping_key(dev, setup_res.session_id);

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                masked_key,
            );

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let reopen_resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );

            assert!(
                reopen_resp.is_ok(),
                "Reopen session should succeed: {:?}",
                reopen_resp
            );
            let reopened_session = reopen_resp.unwrap();
            assert_eq!(
                reopened_session.data.sess_id, setup_res.session_id,
                "Reopened session should have same ID"
            );

            let converted_masked_key: MborByteArray<3072> =
                MborByteArray::from_slice(masked_key.as_slice())
                    .expect("failed to create byte array");

            let resp = helper_unmask_key(
                dev,
                Some(setup_res.session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                converted_masked_key,
            );
            // Host is not allowed to unmask the masked unwrapping key
            assert!(
                resp.is_err(),
                "Unmask key should fail: {:?}",
                resp.unwrap_err()
            );

            let (_, second_pub_key_der, _) = get_unwrapping_key(dev, setup_res.session_id);

            assert_eq!(pub_key_der, second_pub_key_der);
        },
    )
}
