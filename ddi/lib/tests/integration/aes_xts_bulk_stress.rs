// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]

use std::thread;
use std::time::Instant;

use azihsm_ddi::*;
use azihsm_ddi_types::*;
use chrono::Local;
use test_with_tracing::test;

use super::common::*;

const NUM_SECS: u64 = 5;

#[test]
fn test_aes_xts_encrypt_decrypt_multi_threaded_stress() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);

            // We create 2 keys in each thread and we can only do 7 bulk keys per table.
            let max_keys = get_device_info(ddi, path).tables as usize * 7;
            // We open a session in each thread and we can only do MAX_SESSIONS sessions max.
            let max_threads = MAX_SESSIONS;
            let thread_count = std::cmp::min(max_keys / 2, max_threads);
            println!("Thread count: {}", thread_count);

            let mut threads = Vec::new();
            for i in 0..thread_count {
                let thread_id = i as u8;
                let thread_device_path = path.to_string();

                let thread = thread::spawn(move || {
                    test_aes_xts_encrypt_decrypt_thread_fn(
                        thread_id,
                        thread_device_path,
                        thread_count,
                    );
                });
                threads.push(thread);
            }

            for thread in threads {
                thread.join().unwrap();
            }
        },
    );
}

fn test_aes_xts_encrypt_decrypt_thread_fn(
    _thread_id: u8,
    device_path: String,
    max_attempts: usize,
) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);

    let mut app_sess_id = None;
    let mut short_app_id = None;

    for _ in 0..max_attempts {
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
        if resp.as_ref().is_err() {
            if matches!(
                resp.as_ref().unwrap_err(),
                DdiError::DdiStatus(DdiStatus::NonceMismatch)
            ) {
                continue;
            }
        }

        assert!(resp.is_ok(), "resp {:?}", resp);

        let resp = resp.unwrap();

        assert!(resp.hdr.sess_id.is_some());
        assert_eq!(resp.hdr.op, DdiOp::OpenSession);
        assert_eq!(resp.hdr.status, DdiStatus::Success);

        app_sess_id = Some(resp.data.sess_id);
        short_app_id = Some(resp.data.short_app_id);

        break;
    }

    let app_sess_id = app_sess_id.unwrap();

    let short_app_sess_id = short_app_id.unwrap();

    thread::sleep(std::time::Duration::from_secs(1));

    // generate AES 256 bulk key 1
    let resp = generate_aes_bulk_256_key(&dev, &app_sess_id, None, DdiAesKeySize::AesXtsBulk256);
    assert!(resp.is_ok(), "resp: {:?}", resp);
    let resp = resp.unwrap();

    let key_id1_aes_bulk_256 = resp.data.bulk_key_id;
    assert!(key_id1_aes_bulk_256.is_some());

    // generate AES 256 bulk key 2
    let resp = generate_aes_bulk_256_key(&dev, &app_sess_id, None, DdiAesKeySize::AesXtsBulk256);
    assert!(resp.is_ok(), "resp: {:?}", resp);
    let resp = resp.unwrap();

    let key_id2_aes_bulk_256 = resp.data.bulk_key_id;
    assert!(key_id2_aes_bulk_256.is_some());

    // set up requests for the xts encrypt operations
    let data = vec![1; 1024 * 1024];
    let tweak = [0x4; 16usize];
    let data_len = data.len();

    // Get the current local time
    let now = Local::now();
    // Format the time with milliseconds
    println!("start {}", now.format("%Y-%m-%d %H:%M:%S%.3f"));
    let mut counter: usize = 0;
    let start_time = Instant::now();
    while Instant::now().duration_since(start_time).as_secs() < NUM_SECS {
        // setup params for encrypt operation
        let mcr_fp_xts_params = DdiAesXtsParams {
            key_id1: key_id1_aes_bulk_256.unwrap() as u32,
            key_id2: key_id2_aes_bulk_256.unwrap() as u32,
            data_unit_len: data_len,
            session_id: app_sess_id,
            short_app_id: short_app_sess_id,
            tweak,
        };

        // execute encrypt operation
        let resp = dev.exec_op_fp_xts(DdiAesOp::Encrypt, mcr_fp_xts_params.clone(), data.clone());

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

        thread::yield_now();

        counter += 1;
    }

    // Get the current local time
    let now = Local::now();
    thread::sleep(std::time::Duration::from_secs(1));
    // Format the time with milliseconds
    println!("End {}", now.format("%Y-%m-%d %H:%M:%S%.3f"));

    println!("Number of XTS Encrypt Decrypt ops completed : {}", counter);

    // Close App Session
    let resp = helper_close_session(
        &dev,
        Some(app_sess_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
    );
    assert!(resp.is_ok(), "resp: {:?}", resp);
}
