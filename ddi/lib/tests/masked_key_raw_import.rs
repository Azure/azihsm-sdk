// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use crypto::rand::rand_bytes;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

const SECRET_256_SIZE: usize = 32;
const SECRET_384_SIZE: usize = 48;
const SECRET_521_SIZE: usize = 68;
const RAW_KEY_BUFFER_SIZE: usize = 3072;
const HMAC_SHA256_SIZE: usize = 32;
const HMAC_SHA384_SIZE: usize = 48;
const HMAC_SHA512_SIZE: usize = 64;

#[test]
fn test_masked_key_raw_key_import_secret_256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let mut secret_buf = [0u8; SECRET_256_SIZE];

            rand_bytes(&mut secret_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..secret_buf.len()].copy_from_slice(&secret_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let resp = helper_raw_key_import(
                dev,
                Some(session_id),
                raw_key,
                secret_buf.len(),
                DdiKeyType::Secret256,
                Some(1),
                key_properties,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            let resp = resp.unwrap();
            let key_id = resp.data.key_id;
            assert_ne!(key_id, 0);
            let masked_key = resp.data.masked_key;

            let resp = helper_get_new_key_id_from_unmask(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
                true,
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let (new_key_id, _, _) = resp.unwrap();

            let stored_key =
                retrieve_shared_raw_key::<SECRET_256_SIZE>(dev, session_id, new_key_id);
            match stored_key {
                Ok(key_data) => {
                    assert_eq!(&secret_buf[..], &key_data[..]);
                }
                Err(err) => panic!("Failed to retrieve key: {:?}", err),
            }
        },
    );
}

#[test]
fn test_masked_key_raw_key_import_secret_384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let mut secret_buf = [0u8; SECRET_384_SIZE];

            rand_bytes(&mut secret_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..secret_buf.len()].copy_from_slice(&secret_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let resp = helper_raw_key_import(
                dev,
                Some(session_id),
                raw_key,
                secret_buf.len(),
                DdiKeyType::Secret384,
                Some(1),
                key_properties,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            let resp = resp.unwrap();
            let key_id = resp.data.key_id;
            assert_ne!(key_id, 0);
            let masked_key = resp.data.masked_key;

            let resp = helper_get_new_key_id_from_unmask(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
                true,
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let (new_key_id, _, _) = resp.unwrap();

            let stored_key =
                retrieve_shared_raw_key::<SECRET_384_SIZE>(dev, session_id, new_key_id);
            match stored_key {
                Ok(key_data) => {
                    assert_eq!(&secret_buf[..], &key_data[..]);
                }
                Err(err) => panic!("Failed to retrieve key: {:?}", err),
            }
        },
    );
}

#[test]
fn test_masked_key_raw_key_import_secret_521() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let mut secret_buf = [0u8; SECRET_521_SIZE];

            rand_bytes(&mut secret_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..secret_buf.len()].copy_from_slice(&secret_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let resp = helper_raw_key_import(
                dev,
                Some(session_id),
                raw_key,
                secret_buf.len(),
                DdiKeyType::Secret521,
                Some(1),
                key_properties,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            let resp = resp.unwrap();
            let key_id = resp.data.key_id;
            assert_ne!(key_id, 0);
            let masked_key = resp.data.masked_key;

            let resp = helper_get_new_key_id_from_unmask(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
                true,
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let (new_key_id, _, _) = resp.unwrap();

            let stored_key =
                retrieve_shared_raw_key::<SECRET_521_SIZE>(dev, session_id, new_key_id);
            match stored_key {
                Ok(key_data) => {
                    assert_eq!(&secret_buf[..], &key_data[..]);
                }
                Err(err) => panic!("Failed to retrieve key: {:?}", err),
            }
        },
    );
}

#[test]
fn test_masked_key_raw_key_import_hmacsha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let mut secret_buf = [0u8; HMAC_SHA256_SIZE];

            rand_bytes(&mut secret_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..secret_buf.len()].copy_from_slice(&secret_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let resp = helper_raw_key_import(
                dev,
                Some(session_id),
                raw_key,
                secret_buf.len(),
                DdiKeyType::HmacSha256,
                Some(1),
                key_properties,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            let resp = resp.unwrap();
            let key_id = resp.data.key_id;
            assert_ne!(key_id, 0);
            let masked_key = resp.data.masked_key;

            let resp = helper_get_new_key_id_from_unmask(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
                true,
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let (new_key_id, _, _) = resp.unwrap();

            let stored_key =
                retrieve_shared_raw_key::<HMAC_SHA256_SIZE>(dev, session_id, new_key_id);
            match stored_key {
                Ok(key_data) => {
                    assert_eq!(&secret_buf[..], &key_data[..]);
                }
                Err(err) => panic!("Failed to retrieve key: {:?}", err),
            }
        },
    );
}

#[test]
fn test_masked_key_raw_key_import_hmacsha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let mut secret_buf = [0u8; HMAC_SHA384_SIZE];

            rand_bytes(&mut secret_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..secret_buf.len()].copy_from_slice(&secret_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let resp = helper_raw_key_import(
                dev,
                Some(session_id),
                raw_key,
                secret_buf.len(),
                DdiKeyType::HmacSha384,
                Some(1),
                key_properties,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            let resp = resp.unwrap();
            let key_id = resp.data.key_id;
            assert_ne!(key_id, 0);
            let masked_key = resp.data.masked_key;

            let resp = helper_get_new_key_id_from_unmask(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
                true,
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let (new_key_id, _, _) = resp.unwrap();

            let stored_key =
                retrieve_shared_raw_key::<HMAC_SHA384_SIZE>(dev, session_id, new_key_id);
            match stored_key {
                Ok(key_data) => {
                    assert_eq!(&secret_buf[..], &key_data[..]);
                }
                Err(err) => panic!("Failed to retrieve key: {:?}", err),
            }
        },
    );
}

#[test]
fn test_masked_key_raw_key_import_hmacsha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let mut secret_buf = [0u8; HMAC_SHA512_SIZE];

            rand_bytes(&mut secret_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..secret_buf.len()].copy_from_slice(&secret_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let resp = helper_raw_key_import(
                dev,
                Some(session_id),
                raw_key,
                secret_buf.len(),
                DdiKeyType::HmacSha512,
                Some(1),
                key_properties,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            let resp = resp.unwrap();
            let key_id = resp.data.key_id;
            assert_ne!(key_id, 0);
            let masked_key = resp.data.masked_key;

            let resp = helper_get_new_key_id_from_unmask(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
                true,
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let (new_key_id, _, _) = resp.unwrap();

            let stored_key =
                retrieve_shared_raw_key::<HMAC_SHA512_SIZE>(dev, session_id, new_key_id);
            match stored_key {
                Ok(key_data) => {
                    assert_eq!(&secret_buf[..], &key_data[..]);
                }
                Err(err) => panic!("Failed to retrieve key: {:?}", err),
            }
        },
    );
}
