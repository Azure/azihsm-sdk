// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(test)]

mod common;

use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

// This is a test that needs to interact with the file system on VM
// First it will check if a file exists to start the test
// Then it will setup for LM and wait for VF save and restore operation (which can either be done manually or via script)
// After successfully detecting another flag file, it will do partition provisioning and reopen session operation
// All the file operation should be done either manually or via a script like VF save and restore operation
#[test]
fn test_lm_context_save_and_restore() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            if get_device_kind(dev) == DdiDeviceKind::Virtual {
                tracing::debug!("Skip lm_context tests for virtual device");
                return;
            }

            let cwd = std::env::current_dir().unwrap();
            let test_start_file = cwd.join("lm_context_test");
            if !test_start_file.exists() {
                tracing::debug!(
                    "The file {} doesnt exist, skip the test",
                    test_start_file.display()
                );
                return;
            }

            let setup_res = common_setup_for_lm(dev, ddi, path);

            // Wait for a file to be written once VF save and restore is done.
            // while a file named "ready_for_lm" does not exist, wait.
            let flag_file = cwd.join("ready_for_lm");
            let timeout = std::time::Instant::now() + std::time::Duration::from_secs(60); // Timeout for one minute.

            while !flag_file.exists() && std::time::Instant::now() < timeout {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }

            if !flag_file.exists() {
                tracing::error!(
                    "Timeout reached. The file {} was not created.",
                    flag_file.display()
                );
                return;
            }

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"), // No unwrapping key is present, send an empty array
            );

            // reopen the session.
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            assert_eq!(resp.hdr.sess_id, Some(setup_res.session_id));
            assert_eq!(resp.hdr.op, DdiOp::ReopenSession);
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            assert!(!resp.data.bmk_session.is_empty());

            let resp = helper_get_sealed_bk3(dev);
            assert!(resp.is_ok(), "Get sealed bk3: {:?}", resp.err());

            let resp = resp.unwrap();
            assert_eq!(resp.hdr.op, DdiOp::GetSealedBk3);
            assert!(resp.hdr.rev.is_some());
            assert!(resp.hdr.sess_id.is_none());
            assert_eq!(resp.hdr.status, DdiStatus::Success);

            let returned_sealed = resp.data.sealed_bk3.as_slice();
            assert_eq!(returned_sealed, setup_res.masked_bk3.as_slice());
        },
    );
}
