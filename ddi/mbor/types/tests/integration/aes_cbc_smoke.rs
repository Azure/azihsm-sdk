// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AesEncryptDecrypt (CBC) smoke tests for the emu backend.
//!
//! - Happy path: generate an AES-128 key, encrypt a one-block
//!   message, then decrypt the ciphertext and assert we recover the
//!   original plaintext.
//! - Without a session: rejected by the host-side dev validator
//!   before the request reaches firmware.
//! - With an unknown key id: rejected with `KeyNotFound` /
//!   `InvalidKeyNumber`.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_test_helpers::helper_key_properties;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_aes_cbc_encrypt_decrypt_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
            let key_id = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            )
            .unwrap()
            .data
            .key_id;

            let plaintext = [0xa5u8; 16];
            let iv = [0u8; 16];

            let enc_resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
                DdiAesOp::Encrypt,
                MborByteArray::from_slice(&plaintext).unwrap(),
                MborByteArray::from_slice(&iv).unwrap(),
            )
            .unwrap();

            assert_eq!(enc_resp.hdr.op, DdiOp::AesEncryptDecrypt);
            assert_eq!(enc_resp.hdr.status, DdiStatus::Success);
            let ciphertext: Vec<u8> = enc_resp.data.msg.as_slice().to_vec();
            assert_eq!(ciphertext.len(), 16);
            assert_ne!(
                ciphertext,
                &plaintext[..],
                "ciphertext must differ from plaintext"
            );

            let dec_resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
                DdiAesOp::Decrypt,
                MborByteArray::from_slice(&ciphertext).unwrap(),
                MborByteArray::from_slice(&iv).unwrap(),
            )
            .unwrap();

            assert_eq!(dec_resp.hdr.status, DdiStatus::Success);
            assert_eq!(
                dec_resp.data.msg.as_slice(),
                &plaintext[..],
                "decryption must recover the original plaintext"
            );
        },
    );
}

#[test]
fn test_aes_cbc_no_session_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let plaintext = [0xa5u8; 16];
            let iv = [0u8; 16];
            let err = helper_aes_encrypt_decrypt(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                1, /* any key id — the request never reaches firmware */
                DdiAesOp::Encrypt,
                MborByteArray::from_slice(&plaintext).unwrap(),
                MborByteArray::from_slice(&iv).unwrap(),
            )
            .expect_err("AesEncryptDecrypt must be rejected without a session");

            // The host-side dev validator rejects InSession commands sent
            // with sess_id=None before the request reaches firmware.
            assert!(
                matches!(
                    err,
                    DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
                ),
                "expected FileHandleSessionIdDoesNotMatch, got {:?}",
                err
            );
        },
    );
}

#[test]
fn test_aes_cbc_unknown_key_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let plaintext = [0xa5u8; 16];
            let iv = [0u8; 16];
            let err = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0xFFFF, /* unknown key id */
                DdiAesOp::Encrypt,
                MborByteArray::from_slice(&plaintext).unwrap(),
                MborByteArray::from_slice(&iv).unwrap(),
            )
            .expect_err("AesEncryptDecrypt must reject an unknown key id");

            // The exact error code differs across backends — emu's
            // vault returns `KeyNotFound`, the mock returns
            // `InvalidKeyNumber`.  Both are acceptable as long as the
            // request fails.
            assert!(
                matches!(
                    err,
                    DdiError::DdiStatus(DdiStatus::KeyNotFound)
                        | DdiError::DdiStatus(DdiStatus::InvalidKeyNumber)
                ),
                "expected KeyNotFound or InvalidKeyNumber, got {:?}",
                err
            );
        },
    );
}
