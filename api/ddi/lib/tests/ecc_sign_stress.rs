// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use std::thread;
use std::time::Instant;

use chrono::Local;
use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

const DIGEST: [u8; 96] = [100u8; 96];
const DIGEST_LEN: usize = 20;
const NUM_SECS: u64 = 5;

#[test]
fn test_ecc_sign_multi_threaded_stress() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let thread_count = MAX_SESSIONS - 1;

            let mut threads = Vec::new();
            for i in 0..thread_count {
                let thread_id = i as u8;
                let thread_device_path = path.to_string();

                let thread = thread::spawn(move || {
                    test_thread_fn(thread_id, thread_device_path, thread_count);
                });
                threads.push(thread);
            }

            for thread in threads {
                thread.join().unwrap();
            }
        },
    );
}

fn test_thread_fn(_thread_id: u8, device_path: String, max_attempts: usize) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);

    let mut app_sess_id = None;

    for _ in 0..max_attempts {
        let (encrypted_credential, pub_key) =
            encrypt_userid_pin_for_open_session(&dev, TEST_CRED_ID, TEST_CRED_PIN);

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

        break;
    }

    let app_sess_id = app_sess_id.unwrap();

    let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);

    let resp = helper_ecc_generate_key_pair(
        &dev,
        Some(app_sess_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        DdiEccCurve::P256,
        None,
        key_props,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    thread::sleep(std::time::Duration::from_secs(1));

    let req = DdiEccSignCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EccSign,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiEccSignReq {
            key_id: resp.data.private_key_id,
            digest: MborByteArray::new(DIGEST, DIGEST_LEN).expect("failed to create byte array"),
            digest_algo: DdiHashAlgorithm::Sha256,
        },
        ext: None,
    };

    // Get the current local time
    let now = Local::now();
    // Format the time with milliseconds
    println!("start {}", now.format("%Y-%m-%d %H:%M:%S%.3f"));
    let mut counter: usize = 0;
    let start_time = Instant::now();
    while Instant::now().duration_since(start_time).as_secs() < NUM_SECS {
        let mut cookie = None;
        let resp = dev.exec_op(&req, &mut cookie);
        assert!(resp.is_ok(), "resp {:?}", resp);
        thread::yield_now();

        counter += 1;
    }

    // Get the current local time
    let now = Local::now();
    thread::sleep(std::time::Duration::from_secs(1));
    // Format the time with milliseconds
    println!("End {}", now.format("%Y-%m-%d %H:%M:%S%.3f"));

    println!(
        "Number of Ecc-Sign ops/sec : {}",
        counter / NUM_SECS as usize
    );
}
