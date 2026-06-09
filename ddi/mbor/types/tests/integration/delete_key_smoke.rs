// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DeleteKey smoke tests.
//!
//! Exercises the `DeleteKey` firmware handler end-to-end on both
//! backends using an app AES key (the only key class creatable
//! without the not-yet-available unwrapping/masking ops):
//!
//! - **Delete + reuse:** generate an AES-128 key, delete it
//!   successfully, then confirm the freed id no longer resolves
//!   (`KeyNotFound` on a subsequent use).
//! - **Unknown key:** deleting a never-allocated id is rejected with
//!   `KeyNotFound`.
//! - **Idempotency:** a second delete of the same id is rejected with
//!   `KeyNotFound`.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

/// Generate an app AES-128 key and return its id.
fn create_aes_key(dev: &mut <DdiTest as Ddi>::Dev, session_id: u16) -> u16 {
    let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
    helper_aes_generate(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        DdiAesKeySize::Aes128,
        None,
        key_props,
    )
    .expect("aes_generate should succeed")
    .data
    .key_id
}

fn delete(dev: &mut <DdiTest as Ddi>::Dev, session_id: u16, key_id: u16) -> Result<(), DdiError> {
    helper_delete_key(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
    )
    .map(|_| ())
}

#[test]
fn test_delete_key_then_reuse_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_id = create_aes_key(dev, session_id);

            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            )
            .expect("DeleteKey should succeed for an app key");
            assert_eq!(resp.hdr.op, DdiOp::DeleteKey);
            assert_eq!(resp.hdr.status, DdiStatus::Success);

            // The deleted key id must no longer resolve.
            let err = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
                DdiAesOp::Encrypt,
                MborByteArray::from_slice(&[0u8; 16]).unwrap(),
                MborByteArray::new([0u8; 16], 16).unwrap(),
            )
            .expect_err("using a deleted key must fail");
            assert!(
                matches!(err, DdiError::DdiStatus(DdiStatus::KeyNotFound)),
                "expected KeyNotFound after delete, got {err:?}"
            );
        },
    );
}

#[test]
fn test_delete_key_unknown_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Id 0x0020 is an in-range but unallocated slot.
            let err =
                delete(dev, session_id, 0x0020).expect_err("deleting an unknown key must fail");
            assert!(
                matches!(err, DdiError::DdiStatus(DdiStatus::KeyNotFound)),
                "expected KeyNotFound, got {err:?}"
            );
        },
    );
}

#[test]
fn test_delete_key_idempotent_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_id = create_aes_key(dev, session_id);

            delete(dev, session_id, key_id).expect("first delete should succeed");

            let err = delete(dev, session_id, key_id)
                .expect_err("second delete of the same id must fail");
            assert!(
                matches!(err, DdiError::DdiStatus(DdiStatus::KeyNotFound)),
                "expected KeyNotFound on double-delete, got {err:?}"
            );
        },
    );
}
