// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(test)]

use std::thread;

use azihsm_ddi::*;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

fn helper_get_certificate_chain(dev: &mut <DdiTest as Ddi>::Dev) -> (u8, [u8; 32]) {
    let (num_certs, thumbprint) = helper_get_cert_chain_info_data(dev);

    let mut dev_id_cert_chain_hash_input = Vec::new();

    let num_certs_from_hsp = num_certs - NUM_HSM_CALCULATED_CERT_HASHES as u8;

    // Certs in cert chain from 0 to num_certs_from_hsp are used to calculate the device ID cert chain hash
    // device ID cert chain hash is calculated as such:
    // dev_id_cert_chain_hash = SHA256_HASH(SHA256_HASH(cert_0) || ... || SHA256_HASH(cert_num_certs_from_hsp))
    for cert_id in 0..num_certs_from_hsp {
        let result = helper_get_certificate(dev, cert_id);
        assert!(result.is_ok(), "result {:?}", result);

        let resp = result.unwrap();
        let cert_data = resp.data.certificate.as_slice();

        dev_id_cert_chain_hash_input.extend(crypto_sha256(cert_data));
    }

    let mut thumbprint_input = crypto_sha256(&dev_id_cert_chain_hash_input);

    // Remaining certs have their hashes calculated by HSM
    for cert_id in num_certs_from_hsp..num_certs {
        let result = helper_get_certificate(dev, cert_id);
        assert!(result.is_ok(), "result {:?}", result);

        let resp = result.unwrap();
        let cert_data = resp.data.certificate.as_slice();

        thumbprint_input.extend(crypto_sha256(cert_data));
    }

    // Thumbprint is calculated as:
    // SHA256_HASH(dev_id_cert_chain_hash || alias_cert_hash || partition_id_cert_hash)
    let calc_thumbprint = crypto_sha256(&thumbprint_input);

    tracing::debug!(
        "Calculated thumbprint: {:02x?}, Expected thumbprint: {:02x?}",
        calc_thumbprint,
        thumbprint
    );

    // Compare the host calculated thumbprint with the one returned by the HSM
    assert_eq!(
        &calc_thumbprint, &thumbprint,
        "Calculated thumbprint does not match the expected thumbprint"
    );

    (num_certs, thumbprint)
}

// Test certificate chain info, then get each certificate and verify the thumbprint
#[test]
fn test_get_certificate_chain() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!("Skipped test_get_certificate_chain for virtual device");
                return;
            }

            close_app_session(dev, session_id);

            helper_get_certificate_chain(dev);
        },
    );
}

#[test]
fn test_get_cert_chain_length_multiple_times() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Skip test for virtual device as it doesn't support cert chain length yet
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!(
                    "Skipped test_get_cert_chain_length_multiple_times for virtual device"
                );
                return;
            }

            close_app_session(dev, session_id);

            let loop_count = 3;
            let mut previous_num_certs: u8 = 0;
            let mut previous_thumbprint = [0u8; 32];

            for i in 0..loop_count {
                let result = helper_get_cert_chain_info(dev);
                assert!(result.is_ok(), "result {:?}", result);
                let resp = result.unwrap();
                let num_certs = resp.data.num_certs;
                let thumbprint = resp.data.thumbprint.data_take();

                // Record and compare num_cert with previous runs
                if i == 0 {
                    previous_num_certs = num_certs;
                    previous_thumbprint = thumbprint;
                } else {
                    assert_eq!(
                        num_certs, previous_num_certs,
                        "num_certs should be the same",
                    );
                    assert_eq!(
                        thumbprint, previous_thumbprint,
                        "thumbprint should be the same",
                    );
                }
            }
        },
    );
}

#[test]
fn test_get_cert_chain_multithread() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            // Skip test for virtual device as it doesn't support cert chain length yet
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!("Skipped test_get_cert_chain_multithread for virtual device");
                return;
            }

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);

            let mut threads = Vec::new();
            let thread_count = MAX_SESSIONS - 1;
            println!("Thread count: {}", thread_count);

            for _ in 0..thread_count {
                let device_path = path.to_string();

                let thread = thread::spawn(move || {
                    let ddi = DdiTest::default();
                    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
                    set_device_kind(&mut dev);

                    thread::sleep(std::time::Duration::from_secs(2));

                    let (num_certs, thumbprint) = helper_get_certificate_chain(&mut dev);

                    thread::sleep(std::time::Duration::from_secs(1));

                    (num_certs, thumbprint)
                });
                threads.push(thread);
            }

            // Collect and compare the results
            let mut prev_num_cert = None;
            let mut prev_thumbprint = [0u8; 32];
            for thread in threads {
                let result = thread.join();
                assert!(result.is_ok(), "result {:?}", result);
                let (num_cert, thumbprint) = result.unwrap();

                match prev_num_cert {
                    Some(prev) => {
                        assert_eq!(prev, num_cert);
                        assert_eq!(prev_thumbprint, thumbprint);
                    }
                    None => {
                        prev_num_cert = Some(num_cert);
                        prev_thumbprint = thumbprint;
                    }
                }
            }
        },
    );
}

#[test]
fn test_get_cert_chain_info_multithread() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, path, session_id| {
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!("Skipped test_get_cert_chain_info_multithread for virtual device");
                return;
            }

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp: {:?}", resp);

            let mut threads = Vec::new();
            let thread_count = MAX_SESSIONS - 1;
            println!("Thread count: {}", thread_count);

            for _ in 0..thread_count {
                let device_path = path.to_string();

                let thread = thread::spawn(move || {
                    thread::sleep(std::time::Duration::from_secs(2));

                    let ddi = DdiTest::default();
                    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
                    set_device_kind(&mut dev);

                    let result = helper_get_cert_chain_info(&dev);
                    assert!(result.is_ok(), "result {:?}", result);
                    let resp = result.unwrap();
                    let num_certs = resp.data.num_certs;
                    let thumbprint = resp.data.thumbprint.data_take();

                    thread::sleep(std::time::Duration::from_secs(1));

                    (num_certs, thumbprint)
                });
                threads.push(thread);
            }

            // Collect and compare the results
            let mut prev_num_cert = None;
            let mut prev_thumbprint = [0u8; 32];
            for thread in threads {
                let result = thread.join();
                assert!(result.is_ok(), "result {:?}", result);
                let (num_cert, thumbprint) = result.unwrap();

                match prev_num_cert {
                    Some(prev) => {
                        assert_eq!(prev, num_cert);
                        assert_eq!(prev_thumbprint, thumbprint);
                    }
                    None => {
                        prev_num_cert = Some(num_cert);
                        prev_thumbprint = thumbprint;
                    }
                }
            }
        },
    );
}
