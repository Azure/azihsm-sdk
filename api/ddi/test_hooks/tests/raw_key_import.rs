// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the `RawKeyImport` FIPS-validation hook
//! (`DdiOp` 2008).
//!
//! These drive raw key material into the device and read it back with
//! `GetPrivKey`. They only run on a physical device whose firmware is
//! built with `fips_validation_hooks`; otherwise they skip (either
//! because the device is virtual or the op answers `UnsupportedCmd`).
//!
//! Requires the `helpers` feature for the host send helpers.

#![cfg(feature = "helpers")]
#![allow(clippy::unwrap_used)]

mod common;

use azihsm_crypto::Rng;
use azihsm_ddi::Ddi;
use azihsm_ddi::DdiError;
use azihsm_ddi_mbor_types::DdiDeviceKind;
use azihsm_ddi_mbor_types::DdiKeyAvailability;
use azihsm_ddi_mbor_types::DdiKeyType;
use azihsm_ddi_mbor_types::DdiKeyUsage;
use azihsm_ddi_mbor_types::DdiStatus;
use azihsm_ddi_test_hooks::helper_raw_key_import;
use azihsm_ddi_test_hooks::retrieve_shared_raw_key;
use common::*;

const SECRET_256_SIZE: usize = 32;
const RAW_KEY_BUFFER_SIZE: usize = 3072;
const KEY_TAG: u16 = 0x5453;

/// Skip the test when the device is not physical (the hooks are
/// hardware-only).
fn verify_physical_device_and_hooks(dev: &mut <DdiTest as Ddi>::Dev) -> bool {
    if get_device_kind(dev) != DdiDeviceKind::Physical {
        println!("Physical device NOT found. Test only supported on physical device.");
        return false;
    }
    true
}

#[test]
fn test_raw_key_import_secret256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            let mut secret_buf = [0u8; SECRET_256_SIZE];
            Rng::rand_bytes(&mut secret_buf).expect("Failed to generate random bytes");

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
                Some(KEY_TAG),
                key_properties,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            let resp = resp.unwrap().data;
            assert_ne!(resp.key_id, 0);

            let stored_key =
                retrieve_shared_raw_key::<SECRET_256_SIZE>(dev, session_id, resp.key_id);
            match stored_key {
                Ok(key_data) => assert_eq!(&secret_buf[..], &key_data[..]),
                Err(err) => panic!("Failed to retrieve key: {:?}", err),
            }
        },
    );
}

#[test]
fn test_raw_key_import_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            if !verify_physical_device_and_hooks(dev) {
                return;
            }

            let mut secret_buf = [0u8; SECRET_256_SIZE];
            Rng::rand_bytes(&mut secret_buf).expect("Failed to generate random bytes");

            let mut raw_key = [0u8; RAW_KEY_BUFFER_SIZE];
            raw_key[..secret_buf.len()].copy_from_slice(&secret_buf);

            let key_properties =
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let resp = helper_raw_key_import(
                dev,
                None,
                raw_key,
                secret_buf.len(),
                DdiKeyType::Secret256,
                Some(KEY_TAG),
                key_properties,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
                ),
                "Expected FileHandleSessionIdDoesNotMatch error, got {:?}",
                resp
            );
        },
    );
}
