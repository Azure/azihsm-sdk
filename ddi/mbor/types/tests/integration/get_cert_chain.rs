// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]

use std::thread;

use azihsm_ddi::*;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

/// Fetch the full certificate chain and validate the properties the host
/// SDK actually relies on.
///
/// The `GetCertChainInfo` thumbprint is an *opaque change-detection token*,
/// not a verifiable digest: the SDK (`fetch_cert_chain_checked` in
/// `api/lib/src/ddi/partition.rs`) only re-reads it after fetching every
/// certificate and fails with `CertChainChanged` if it moved, catching a
/// chain rotation / live migration that happened during the multi-call
/// fetch. No consumer recomputes it from the certs, so this helper checks
/// the chain is well-formed and the thumbprint is *stable* across the
/// fetch, rather than asserting a specific hash construction that nothing
/// depends on.
fn helper_get_certificate_chain(dev: &mut <DdiTest as Ddi>::Dev) -> (u8, [u8; 32]) {
    let (num_certs, thumbprint) = helper_get_cert_chain_info_data(dev);

    assert!(
        num_certs > 0,
        "a provisioned partition must report at least one certificate"
    );
    assert!(
        thumbprint.iter().any(|&b| b != 0),
        "thumbprint must not be all zeros"
    );

    // Every advertised certificate must be fetchable and non-empty.
    for cert_id in 0..num_certs {
        let result = helper_get_certificate(dev, cert_id);
        assert!(result.is_ok(), "result {:?}", result);

        let resp = result.unwrap();
        assert!(
            !resp.data.certificate.as_slice().is_empty(),
            "certificate {} must not be empty",
            cert_id
        );
    }

    // Re-read the chain info after the fetch: the count and thumbprint must
    // be stable, mirroring the SDK's change-detection check. This is the
    // only guarantee the thumbprint actually provides.
    let (num_certs_after, thumbprint_after) = helper_get_cert_chain_info_data(dev);
    assert_eq!(
        num_certs, num_certs_after,
        "cert count must be stable across the fetch"
    );
    assert_eq!(
        thumbprint, thumbprint_after,
        "thumbprint must be stable across the fetch"
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
                    let dev = ddi.open_dev(device_path.as_str()).unwrap();

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
