// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use std::thread;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

pub fn setup(dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str) -> u16 {
    common_cleanup(dev, ddi, path, None);

    // Return incorrect session id since this is a no session command
    25
}

#[test]
fn test_get_establish_cred_encryption_key_with_session() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _session_id| {
        let session_id = 10;

        let req = DdiGetEstablishCredEncryptionKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetEstablishCredEncryptionKey,
                sess_id: Some(session_id),
                rev: None,
            },
            data: DdiGetEstablishCredEncryptionKeyReq {},
            ext: None,
        };
        let mut cookie = None;
        let resp = dev.exec_op(&req, &mut cookie);

        assert!(resp.is_err(), "resp {:?}", resp);

        assert!(matches!(
            resp.unwrap_err(),
            DdiError::DdiStatus(DdiStatus::InvalidArg)
        ));
    });
}

#[test]
fn test_get_establish_cred_encryption_key() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _session_id| {
        let req = DdiGetEstablishCredEncryptionKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetEstablishCredEncryptionKey,
                sess_id: None,
                rev: Some(DdiApiRev { major: 1, minor: 0 }),
            },
            data: DdiGetEstablishCredEncryptionKeyReq {},
            ext: None,
        };
        let mut cookie = None;
        let resp = dev.exec_op(&req, &mut cookie);

        assert!(resp.is_ok(), "resp: {:?}", resp);
    });
}

#[test]
fn test_get_establish_cred_encryption_key_twice() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _session_id| {
        let req = DdiGetEstablishCredEncryptionKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetEstablishCredEncryptionKey,
                sess_id: None,
                rev: Some(DdiApiRev { major: 1, minor: 0 }),
            },
            data: DdiGetEstablishCredEncryptionKeyReq {},
            ext: None,
        };
        let mut cookie = None;
        let resp = dev.exec_op(&req, &mut cookie);

        assert!(resp.is_ok(), "resp: {:?}", resp);
        let resp_data = resp.unwrap().data;
        let establish_cred_encrypt_pub_key = resp_data.pub_key;
        let establish_cred_encrypt_nonce = resp_data.nonce;

        let req = DdiGetEstablishCredEncryptionKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetEstablishCredEncryptionKey,
                sess_id: None,
                rev: Some(DdiApiRev { major: 1, minor: 0 }),
            },
            data: DdiGetEstablishCredEncryptionKeyReq {},
            ext: None,
        };
        let mut cookie = None;
        let resp = dev.exec_op(&req, &mut cookie);
        assert!(resp.is_ok(), "resp: {:?}", resp);

        let resp_data = resp.unwrap().data;
        let establish_cred_encrypt_pub_key2 = resp_data.pub_key;
        let establish_cred_encrypt_nonce2 = resp_data.nonce;

        assert_eq!(
            establish_cred_encrypt_pub_key,
            establish_cred_encrypt_pub_key2
        );
        assert_eq!(establish_cred_encrypt_nonce, establish_cred_encrypt_nonce2);
    });
}

#[test]
fn test_get_establish_cred_encryption_key_multi_threaded_stress() {
    ddi_dev_test(setup, common_cleanup, |_dev, _ddi, path, _session_id| {
        let thread_count = 128;
        println!("Thread count: {}", thread_count);

        let mut threads = Vec::new();
        for i in 0..thread_count {
            let thread_id = i as u8;
            let thread_device_path = path.to_string();

            let thread = thread::spawn(move || {
                test_get_establish_cred_encryption_key_thread_fn(thread_id, thread_device_path)
            });
            threads.push(thread);
        }

        let mut first_pub_key_der_nonce: Option<(Vec<u8>, [u8; 32])> = None;
        for thread in threads {
            let (pub_key_der, nonce) = thread.join().unwrap();
            if let Some((first_der, first_nonce)) = &first_pub_key_der_nonce {
                assert_eq!(&pub_key_der, first_der);
                assert_eq!(&nonce, first_nonce);
            } else {
                first_pub_key_der_nonce = Some((pub_key_der, nonce))
            }
        }
    });
}

fn test_get_establish_cred_encryption_key_thread_fn(
    _thread_id: u8,
    device_path: String,
) -> (Vec<u8>, [u8; 32]) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);

    let req = DdiGetEstablishCredEncryptionKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetEstablishCredEncryptionKey,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetEstablishCredEncryptionKeyReq {},
        ext: None,
    };
    let mut cookie = None;
    let resp = dev.exec_op(&req, &mut cookie);

    assert!(resp.is_ok(), "resp: {:?}", resp);
    let resp = resp.unwrap();
    (resp.data.pub_key.der.data().to_vec(), resp.data.nonce)
}

#[test]
fn test_get_establish_cred_encryption_key_changes_after_reset() {
    ddi_dev_test(setup, common_cleanup, |dev, ddi, path, _session_id| {
        let req = DdiGetEstablishCredEncryptionKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetEstablishCredEncryptionKey,
                sess_id: None,
                rev: Some(DdiApiRev { major: 1, minor: 0 }),
            },
            data: DdiGetEstablishCredEncryptionKeyReq {},
            ext: None,
        };
        let mut cookie = None;
        let resp = dev.exec_op(&req, &mut cookie);

        assert!(resp.is_ok(), "resp: {:?}", resp);
        let resp = resp.unwrap();

        let old_nonce = resp.data.nonce;
        let old_pub_key = resp.data.pub_key;

        // This will do the reset function
        common_cleanup(dev, ddi, path, None);

        let req = DdiGetEstablishCredEncryptionKeyCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetEstablishCredEncryptionKey,
                sess_id: None,
                rev: Some(DdiApiRev { major: 1, minor: 0 }),
            },
            data: DdiGetEstablishCredEncryptionKeyReq {},
            ext: None,
        };
        let mut cookie = None;
        let resp = dev.exec_op(&req, &mut cookie);

        assert!(resp.is_ok(), "resp: {:?}", resp);
        let resp = resp.unwrap();

        assert_ne!(
            old_pub_key, resp.data.pub_key,
            "Device pub key must change after reset"
        );
        assert_ne!(
            old_nonce, resp.data.nonce,
            "Device nonce must change after reset"
        );
    });
}
