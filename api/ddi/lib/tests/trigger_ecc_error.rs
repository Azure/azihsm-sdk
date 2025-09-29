// Copyright (C) Microsoft Corporation. All rights reserved.

// Import the macro from the self_test module
mod common;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn trigger_dtcm_ecc_error_cp0() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let ecc_error_info = DdiTestActionEccErrorInfo {
                ecc_error_type: DdiTestActionEccErrorType::DtcmDoubleBit,
                cpu_id: DdiTestActionSocCpuId::Admin,
            };

            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::TriggerEccError,
                None,
                None,
                None,
                None,
                None,
                Some(ecc_error_info),
                None,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Expect Err(DriverError(IoAborted)) due to crash and recovery
            assert!(resp.is_err(), "resp {:?}", resp);
            if let Err(err) = &resp {
                match err {
                    DdiError::DriverError(DriverError::IoAborted) => {}
                    _ => panic!("Failed due to unexpected error: {:?}", err),
                };
            };

            // Sleep for a second to allow device to reset
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
    );
}

#[test]
fn trigger_dtcm_ecc_error_cp1() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let ecc_error_info = DdiTestActionEccErrorInfo {
                ecc_error_type: DdiTestActionEccErrorType::DtcmDoubleBit,
                cpu_id: DdiTestActionSocCpuId::Hsm,
            };

            let resp = helper_test_action_cmd(
                dev,
                session_id,
                DdiTestAction::TriggerEccError,
                None,
                None,
                None,
                None,
                None,
                Some(ecc_error_info),
                None,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Expect Err(DriverError(IoAborted)) due to crash and recovery
            assert!(resp.is_err(), "resp {:?}", resp);
            if let Err(err) = &resp {
                match err {
                    DdiError::DriverError(DriverError::IoAborted) => {}
                    _ => panic!("Failed due to unexpected error: {:?}", err),
                };
            };

            // Sleep for a second to allow device to reset
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
    );
}

#[test]
fn trigger_cdma_ecc_corr_error_aes_gcm_single_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // Number of Enc/Dec IO Operation on each ECC error injected key
            let io_cycle = 5;
            // Expect only 1 INTR, as ECC error should be fixed after 1st KV reload operation
            // Key's ECC error should be fixed upon KV reload operation after ENC/DEC IO
            let expected_intr_count_increase = 1;

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);

            let (app_sess_id, short_app_sess_id) = open_test_session(dev);

            // Get previous CDMA ECC error interrupt count
            let prev_intr_count = match get_corr_ecc_intr_count(dev, app_sess_id, None, None) {
                Some(count) => count,
                None => return,
            };

            // Inject a correctable ECC error before AES GCM key generation
            if !inject_corr_ecc_error(dev, app_sess_id) {
                return;
            }

            // Generate AES GCM Key once and perform Enc/Dec IO operations for io_cycle times
            trigger_aes_gcm_encrypt_decrypt_io_cycle(dev, app_sess_id, short_app_sess_id, io_cycle)
                .expect("AES GCM encrypt/decrypt failed");

            // Validate only expected_intr_count_increase INTR is received irrespective of io_cycle
            get_corr_ecc_intr_count(
                dev,
                app_sess_id,
                Some(prev_intr_count),
                Some(expected_intr_count_increase),
            );

            // Close App Session
            let resp = helper_close_session(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);
        },
    );
}

#[test]
fn trigger_cdma_ecc_corr_error_aes_gcm_multiple_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // Number of Enc/Dec IO Operation on each ECC error injected key
            let io_cycle = 5;
            // Multiple keys generated with ecc error injection bit enabled
            let ecc_err_injected_key_gen = 5;
            // Expect only 5 INTR, as we are injecting errors on 5 separate keys
            // Each key's ECC error should be fixed upon KV reload operation after ENC/DEC IO
            let expected_intr_count_increase = 5;

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);

            let (app_sess_id, short_app_sess_id) = open_test_session(dev);

            // Get previous CDMA ECC error interrupt count
            let prev_intr_count = match get_corr_ecc_intr_count(dev, app_sess_id, None, None) {
                Some(count) => count,
                None => return,
            };

            // Validate error injection on separate keys and perform multiple IO cycle on each key
            for (key_idx, _) in (0..ecc_err_injected_key_gen).enumerate() {
                // Inject a correctable ECC error before AES GCM key generation
                if !inject_corr_ecc_error(dev, app_sess_id) {
                    return;
                }

                // AES GCM Key generation and Enc/Dec IO operations to increment the ECC error count
                trigger_aes_gcm_encrypt_decrypt_io_cycle(
                    dev,
                    app_sess_id,
                    short_app_sess_id,
                    io_cycle,
                )
                .expect("AES GCM encrypt/decrypt failed");

                // Validate only single INTR is received irrespective of io_cycle
                get_corr_ecc_intr_count(
                    dev,
                    app_sess_id,
                    Some(prev_intr_count),
                    Some(1 + key_idx as u32),
                );
            }

            // Validate only expected_intr_count_increase INTR is received irrespective of io_cycle
            get_corr_ecc_intr_count(
                dev,
                app_sess_id,
                Some(prev_intr_count),
                Some(expected_intr_count_increase),
            );

            // Close App Session
            let resp = helper_close_session(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);
        },
    );
}

#[test]
fn trigger_cdma_ecc_corr_error_aes_xts() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // Expect only 1 INTR, as ECC error should be fixed after 1st KV reload operation
            let expected_intr_count_increase = 1;

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);

            let (app_sess_id, short_app_sess_id) = open_test_session(dev);

            // Get previous CDMA ECC error interrupt count
            let prev_intr_count = match get_corr_ecc_intr_count(dev, app_sess_id, None, None) {
                Some(count) => count,
                None => return,
            };

            // Inject a correctable ECC error before AES GCM key generation
            if !inject_corr_ecc_error(dev, app_sess_id) {
                return;
            }

            // generate AES 256 bulk key 1
            let resp =
                generate_aes_bulk_256_key(dev, &app_sess_id, None, DdiAesKeySize::AesXtsBulk256);
            assert!(resp.is_ok(), "resp: {:?}", resp);
            let resp = resp.unwrap();

            assert!(resp.data.bulk_key_id.is_some());
            let key_id1_aes_bulk_256 = resp.data.bulk_key_id.unwrap() as u32;

            // Inject a correctable ECC error before AES GCM key generation
            if !inject_corr_ecc_error(dev, app_sess_id) {
                return;
            }

            // generate AES 256 bulk key 2
            let resp =
                generate_aes_bulk_256_key(dev, &app_sess_id, None, DdiAesKeySize::AesXtsBulk256);
            assert!(resp.is_ok(), "resp: {:?}", resp);
            let resp = resp.unwrap();

            assert!(resp.data.bulk_key_id.is_some());
            let key_id2_aes_bulk_256 = resp.data.bulk_key_id.unwrap() as u32;

            // set up requests for the xts encrypt operations
            let data = vec![4; 1024];
            let tweak = [0x4; 16usize];
            let data_len = data.len();

            // setup params for encrypt operation
            let mcr_fp_xts_params = DdiAesXtsParams {
                key_id1: key_id1_aes_bulk_256,
                key_id2: key_id2_aes_bulk_256,
                data_unit_len: data_len,
                session_id: app_sess_id,
                short_app_id: short_app_sess_id,
                tweak,
            };

            // execute encrypt operation
            let resp =
                dev.exec_op_fp_xts(DdiAesOp::Encrypt, mcr_fp_xts_params.clone(), data.clone());

            assert!(resp.is_ok(), "resp: {:?}", resp);
            let encrypted_resp = resp.unwrap();

            // ensure encrypted data length is the same as the original data
            // ensure encrypted data is different from original data
            assert_eq!(encrypted_resp.data.len(), data.len());
            assert_ne!(data, encrypted_resp.data);

            // execute decrypt operation
            let resp = dev.exec_op_fp_xts(
                DdiAesOp::Decrypt,
                mcr_fp_xts_params.clone(),
                encrypted_resp.data.clone(),
            );

            assert!(resp.is_ok(), "resp: {:?}", resp);
            let decrypted_resp = resp.unwrap();

            assert_eq!(decrypted_resp.data.len(), data.len());
            assert_eq!(decrypted_resp.data, data);

            // Validate only expected_intr_count_increase INTR is received irrespective of io_cycle
            get_corr_ecc_intr_count(
                dev,
                app_sess_id,
                Some(prev_intr_count),
                Some(expected_intr_count_increase),
            );

            // Close App Session
            let resp = helper_close_session(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);
        },
    );
}

fn is_unsupported_cmd(err: &DdiError) -> bool {
    if let DdiError::DdiStatus(DdiStatus::UnsupportedCmd) = err {
        println!("Firmware is not built with mcr_test_hooks.");
        true
    } else {
        false
    }
}

/// Performs AES-GCM encryption and decryption using the provided device, session, and app session IDs.
/// Returns Result<(), String> for test assertions.
fn trigger_aes_gcm_encrypt_decrypt_io_cycle(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    short_app_sess_id: u8,
    io_cycle: u32,
) -> Result<(), String> {
    // Generate AES bulk key for AES GCM IOs
    let resp = generate_aes_bulk_256_key(
        dev,
        &session_id,
        None,
        DdiAesKeySize::AesGcmBulk256Unapproved,
    )
    .map_err(|e| format!("generate_aes_bulk_256_key failed: {:?}", e))?;
    let key_id_aes_bulk_256 = resp.data.bulk_key_id.ok_or("bulk_key_id is None")?;

    // Run Enc-Dec operations on ECC error injected AES GCM key for io_cycle times
    for _ in 0..io_cycle {
        // set up requests for the gcm encrypt operations
        let data = vec![1; 16384];
        let aad = [0x4; 32usize];
        let iv = [0x3u8; 12];

        let mut mcr_fp_gcm_params = DdiAesGcmParams {
            key_id: key_id_aes_bulk_256 as u32,
            iv,
            aad: Some(aad.to_vec()),
            tag: None, // tag is not needed for encryption
            session_id,
            short_app_id: short_app_sess_id,
        };

        // Execute encrypt operation
        let encrypted_resp = dev
            .exec_op_fp_gcm(DdiAesOp::Encrypt, mcr_fp_gcm_params.clone(), data.clone())
            .map_err(|e| format!("Encrypt failed: {:?}", e))?;

        // ensure encrypted data length is the same as the original data
        if encrypted_resp.data.len() != data.len() {
            return Err("Encrypted data length mismatch".to_string());
        }
        if data == encrypted_resp.data {
            return Err("Encrypted data is same as original".to_string());
        }
        let tag = encrypted_resp.tag;

        // Execute decrypt operation
        mcr_fp_gcm_params.tag = tag;
        let decrypted_resp = dev
            .exec_op_fp_gcm(
                DdiAesOp::Decrypt,
                mcr_fp_gcm_params.clone(),
                encrypted_resp.data.clone(),
            )
            .map_err(|e| format!("Decrypt failed: {:?}", e))?;

        if decrypted_resp.data.len() != data.len() {
            return Err("Decrypted data length mismatch".to_string());
        }
        if decrypted_resp.data != data {
            return Err("Decrypted data does not match original".to_string());
        }
    }
    Ok(())
}

/// Injects a correctable CDMA ECC error for the HSM CPU.
/// Returns true if the command completed successfully, false otherwise.
fn inject_corr_ecc_error(dev: &mut <DdiTest as Ddi>::Dev, session_id: u16) -> bool {
    let ecc_error_info = DdiTestActionEccErrorInfo {
        ecc_error_type: DdiTestActionEccErrorType::CdmaSingleBit,
        cpu_id: DdiTestActionSocCpuId::Hsm,
    };

    let resp = helper_test_action_cmd(
        dev,
        session_id,
        DdiTestAction::TriggerEccError,
        None,
        None,
        None,
        None,
        None,
        Some(ecc_error_info),
        None,
    );

    if let Err(err) = &resp {
        assert!(
            is_unsupported_cmd(err),
            "ECC error injection failed: {:?}",
            err
        );
        return false;
    }

    true
}

/// Gets the CDMA ECC Single Bit Error Interrupt Count for the HSM CPU.
/// If `prev_intr_count` and `expected_count_increase` are provided, asserts the count.
/// Returns Option<u32>: Some(count) if successful, None if unsupported command or error.
fn get_corr_ecc_intr_count(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    prev_intr_count: Option<u32>,
    expected_count_increase: Option<u32>,
) -> Option<u32> {
    let ecc_error_info = DdiTestActionEccErrorInfo {
        ecc_error_type: DdiTestActionEccErrorType::CdmaEccErrIntrCount,
        cpu_id: DdiTestActionSocCpuId::Hsm,
    };

    let resp = helper_test_action_cmd(
        dev,
        session_id,
        DdiTestAction::TriggerEccError,
        None,
        None,
        None,
        None,
        None,
        Some(ecc_error_info),
        None,
    );

    if let Err(err) = &resp {
        assert!(
            is_unsupported_cmd(err),
            "Failed to get ECC error count: {:?}",
            err
        );
        return None;
    }

    let resp = resp.as_ref().unwrap();
    let count = resp.data.result;
    if count.is_none() {
        println!("Warning: ECC error count is None");
        return None;
    }
    let count = count.unwrap();

    if let (Some(prev_intr_cnt), Some(expected_intr_cnt_inc)) =
        (prev_intr_count, expected_count_increase)
    {
        assert!(
            count == prev_intr_cnt + expected_intr_cnt_inc,
            "Error: Expected {} CDMA ECC error interrupt count, but got {:?}",
            expected_intr_cnt_inc,
            count - prev_intr_cnt
        );
    }

    Some(count)
}

/// Helper to open a session and return session IDs
fn open_test_session(dev: &mut <DdiTest as Ddi>::Dev) -> (u16, u8) {
    set_device_kind(dev);
    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, TEST_CRED_PIN, TEST_SESSION_SEED);

    let resp = helper_open_session(
        dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        encrypted_credential,
        pub_key,
    );
    assert!(resp.is_ok(), "resp: {:?}", resp);
    let resp = resp.unwrap();

    (resp.data.sess_id, resp.data.short_app_id)
}
