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
#![allow(clippy::unwrap_used)]

mod common;
#[path = "helper/raw_key_import.rs"]
mod helper;

use azihsm_crypto::Rng;
use azihsm_ddi::DdiError;
use azihsm_ddi_mbor_test_hooks::helper_raw_key_import;
use azihsm_ddi_mbor_types::DdiKeyAvailability;
use azihsm_ddi_mbor_types::DdiKeyType;
use azihsm_ddi_mbor_types::DdiKeyUsage;
use azihsm_ddi_mbor_types::DdiStatus;
use common::*;
use helper::*;
use test_with_tracing::test;

const KEY_TAG: u16 = 0x5453;
const KEY_TAG_1: u16 = 0x5454;

#[test]
fn test_raw_key_import_invalid_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            if !require_physical_device(dev) {
                return;
            }

            let key = [0x5au8; 32];
            let properties = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_raw_key_import(
                dev,
                Some(5),
                &key,
                DdiKeyType::Secret256,
                Some(KEY_TAG),
                properties,
            );

            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(
                    DdiStatus::FileHandleSessionIdDoesNotMatch
                ))
            ));
        },
    );
}

#[test]
fn test_raw_key_import_secret256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            let mut key = [0u8; 32];
            Rng::rand_bytes(&mut key).unwrap();
            import_and_verify(
                dev,
                session_id,
                &key,
                DdiKeyType::Secret256,
                DdiKeyUsage::Derive,
                Some(KEY_TAG),
            );
        },
    );
}

#[test]
fn test_raw_key_import_secret384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            let mut key = [0u8; 48];
            Rng::rand_bytes(&mut key).unwrap();
            import_and_verify(
                dev,
                session_id,
                &key,
                DdiKeyType::Secret384,
                DdiKeyUsage::Derive,
                Some(KEY_TAG),
            );
        },
    );
}

#[test]
fn test_raw_key_import_secret521() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            let mut key = [0u8; 68];
            Rng::rand_bytes(&mut key).unwrap();
            import_and_verify(
                dev,
                session_id,
                &key,
                DdiKeyType::Secret521,
                DdiKeyUsage::Derive,
                Some(KEY_TAG),
            );
        },
    );
}

#[test]
fn test_raw_key_import_hmacsha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            let mut key = [0u8; 32];
            Rng::rand_bytes(&mut key).unwrap();
            import_and_verify(
                dev,
                session_id,
                &key,
                DdiKeyType::HmacSha256,
                DdiKeyUsage::SignVerify,
                Some(KEY_TAG),
            );
        },
    );
}

#[test]
fn test_raw_key_import_hmacsha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            let mut key = [0u8; 48];
            Rng::rand_bytes(&mut key).unwrap();
            import_and_verify(
                dev,
                session_id,
                &key,
                DdiKeyType::HmacSha384,
                DdiKeyUsage::SignVerify,
                Some(KEY_TAG),
            );
        },
    );
}

#[test]
fn test_raw_key_import_hmacsha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            let mut key = [0u8; 64];
            Rng::rand_bytes(&mut key).unwrap();
            import_and_verify(
                dev,
                session_id,
                &key,
                DdiKeyType::HmacSha512,
                DdiKeyUsage::SignVerify,
                Some(KEY_TAG),
            );
        },
    );
}

#[test]
fn test_raw_key_import_var_hmacsha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            let mut selector = [0u8; 1];
            Rng::rand_bytes(&mut selector).unwrap();
            let mut key = vec![0u8; 32 + selector[0] as usize % 33];
            Rng::rand_bytes(&mut key).unwrap();
            import_and_verify(
                dev,
                session_id,
                &key,
                DdiKeyType::VarHmac256,
                DdiKeyUsage::SignVerify,
                Some(KEY_TAG),
            );
        },
    );
}

#[test]
fn test_raw_key_import_var_hmacsha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            let mut selector = [0u8; 1];
            Rng::rand_bytes(&mut selector).unwrap();
            let mut key = vec![0u8; 48 + selector[0] as usize % 81];
            Rng::rand_bytes(&mut key).unwrap();
            import_and_verify(
                dev,
                session_id,
                &key,
                DdiKeyType::VarHmac384,
                DdiKeyUsage::SignVerify,
                Some(KEY_TAG),
            );
        },
    );
}

#[test]
fn test_raw_key_import_var_hmacsha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            let mut selector = [0u8; 1];
            Rng::rand_bytes(&mut selector).unwrap();
            let mut key = vec![0u8; 64 + selector[0] as usize % 65];
            Rng::rand_bytes(&mut key).unwrap();
            import_and_verify(
                dev,
                session_id,
                &key,
                DdiKeyType::VarHmac512,
                DdiKeyUsage::SignVerify,
                Some(KEY_TAG),
            );
        },
    );
}

#[test]
fn test_raw_key_import_invalid_key_availability() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            expect_import_error(
                dev,
                session_id,
                DdiKeyType::Secret256,
                DdiKeyUsage::Derive,
                DdiKeyAvailability::Session,
                Some(KEY_TAG),
                DdiStatus::InvalidArg,
            );
        },
    );
}

#[test]
fn test_raw_key_import_invalid_key_type_aes_bulk_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            expect_import_error(
                dev,
                session_id,
                DdiKeyType::AesGcmBulk256Unapproved,
                DdiKeyUsage::EncryptDecrypt,
                DdiKeyAvailability::App,
                Some(KEY_TAG),
                DdiStatus::InvalidKeyType,
            );
        },
    );
}

#[test]
fn test_raw_key_import_invalid_key_type_rsa3kprivate() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            expect_import_error(
                dev,
                session_id,
                DdiKeyType::Rsa3kPrivate,
                DdiKeyUsage::Unwrap,
                DdiKeyAvailability::App,
                Some(KEY_TAG),
                DdiStatus::InvalidKeyType,
            );
        },
    );
}

#[test]
fn test_raw_key_import_unwrapping_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) || !require_raw_key_import(dev, session_id) {
                return;
            }

            let key = rsa2k_private_key();
            let properties = helper_key_properties(DdiKeyUsage::Unwrap, DdiKeyAvailability::App);
            let resp = helper_raw_key_import(
                dev,
                Some(session_id),
                &key,
                DdiKeyType::Rsa2kPrivate,
                Some(KEY_TAG),
                properties,
            )
            .unwrap()
            .data;

            assert_ne!(resp.key_id, 0);
            assert!(!resp.masked_key.is_empty());
        },
    );
}

#[test]
fn test_raw_key_import_invalid_key_usage() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            expect_rsa2k_import_error(
                dev,
                session_id,
                DdiKeyUsage::SignVerify,
                Some(KEY_TAG),
                DdiStatus::InvalidPermissions,
            );
        },
    );
}

#[test]
fn test_raw_key_import_rsa2k_decrypt_unsupported_key_usage() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            expect_rsa2k_import_error(
                dev,
                session_id,
                DdiKeyUsage::EncryptDecrypt,
                Some(KEY_TAG),
                DdiStatus::InvalidPermissions,
            );
        },
    );
}

#[test]
fn test_raw_key_import_invalid_key_type_rsa4kprivate() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            expect_import_error(
                dev,
                session_id,
                DdiKeyType::Rsa4kPrivate,
                DdiKeyUsage::Unwrap,
                DdiKeyAvailability::Session,
                None,
                DdiStatus::InvalidKeyType,
            );
        },
    );
}

#[test]
fn test_raw_key_import_aes256_unsupported_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            expect_import_error(
                dev,
                session_id,
                DdiKeyType::Aes256,
                DdiKeyUsage::EncryptDecrypt,
                DdiKeyAvailability::App,
                Some(KEY_TAG),
                DdiStatus::InvalidKeyType,
            );
        },
    );
}

#[test]
fn test_raw_key_import_multiple_keys_and_validate() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            let mut key1 = [0u8; 32];
            let mut key2 = [0u8; 32];
            Rng::rand_bytes(&mut key1).unwrap();
            Rng::rand_bytes(&mut key2).unwrap();

            import_and_verify(
                dev,
                session_id,
                &key1,
                DdiKeyType::Secret256,
                DdiKeyUsage::Derive,
                Some(KEY_TAG),
            );
            import_and_verify(
                dev,
                session_id,
                &key2,
                DdiKeyType::Secret256,
                DdiKeyUsage::Derive,
                Some(KEY_TAG_1),
            );
        },
    );
}

#[test]
fn test_raw_key_import_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            if !require_physical_device(dev) {
                return;
            }

            let key = [0x5au8; 32];
            let properties = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let resp = helper_raw_key_import(
                dev,
                None,
                &key,
                DdiKeyType::Secret256,
                Some(KEY_TAG),
                properties,
            );

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

#[test]
fn test_raw_key_import_fixed_hmac_rejects_derive() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            expect_import_error(
                dev,
                session_id,
                DdiKeyType::HmacSha256,
                DdiKeyUsage::Derive,
                DdiKeyAvailability::App,
                None,
                DdiStatus::InvalidPermissions,
            );
        },
    );
}

#[test]
fn test_raw_key_import_fixed_hmac_readback_preserves_type_and_bytes() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            let key = [0x5au8; 32];
            import_and_verify(
                dev,
                session_id,
                &key,
                DdiKeyType::HmacSha256,
                DdiKeyUsage::SignVerify,
                None,
            );
        },
    );
}

#[test]
fn test_raw_key_import_var_hmac_readback_preserves_type_and_bytes() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) {
                return;
            }

            let key = [0x5au8; 33];
            import_and_verify(
                dev,
                session_id,
                &key,
                DdiKeyType::VarHmac256,
                DdiKeyUsage::SignVerify,
                None,
            );
        },
    );
}

#[test]
fn test_raw_key_import_rsa2k_rejects_replacement() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !require_physical_device(dev) || !require_raw_key_import(dev, session_id) {
                return;
            }

            let key = rsa2k_private_key();
            let properties = helper_key_properties(DdiKeyUsage::Unwrap, DdiKeyAvailability::App);
            helper_raw_key_import(
                dev,
                Some(session_id),
                &key,
                DdiKeyType::Rsa2kPrivate,
                None,
                properties,
            )
            .unwrap();

            let properties = helper_key_properties(DdiKeyUsage::Unwrap, DdiKeyAvailability::App);
            let resp = helper_raw_key_import(
                dev,
                Some(session_id),
                &key,
                DdiKeyType::Rsa2kPrivate,
                None,
                properties,
            );
            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::InvalidArg))
            ));
        },
    );
}
