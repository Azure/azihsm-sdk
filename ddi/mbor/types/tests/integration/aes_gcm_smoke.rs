// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fast-path AES-256-GCM smoke tests for the emu backend.
//!
//! Covers both bulk key variants:
//! - `AesGcmBulk256Unapproved` — the caller-supplied IV is used as-is.
//! - `AesGcmBulk256` (FIPS-approved) — the device generates the IV on
//!   encrypt and returns it; the caller IV is ignored.
//!
//! For each variant we assert an encrypt→decrypt round-trip (with AAD),
//! that ciphertext differs from plaintext, and that a tampered / missing
//! tag is rejected on decrypt.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

/// Encrypt then decrypt with a freshly generated bulk key, asserting the
/// round-trip recovers the plaintext and that authentication is enforced.
fn roundtrip(
    dev: &<DdiTest as Ddi>::Dev,
    session_id: u16,
    short_app_id: u8,
    key_size: DdiAesKeySize,
    approved: bool,
) {
    let resp = generate_aes_bulk_256_key(dev, &session_id, None, key_size).unwrap();
    let bulk_key_id = resp.data.bulk_key_id.expect("bulk key id must be present") as u32;

    let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let aad = vec![0x4u8; 32];
    let iv = [0x3u8; 12];

    let mut params = DdiAesGcmParams {
        key_id: bulk_key_id,
        iv,
        aad: Some(aad.clone()),
        tag: None,
        session_id,
        short_app_id,
    };

    let enc = dev
        .exec_op_fp_gcm(DdiAesOp::Encrypt, params.clone(), data.clone())
        .expect("encrypt must succeed");
    assert_eq!(enc.data.len(), data.len());
    assert_ne!(enc.data, data, "ciphertext must differ from plaintext");
    assert!(enc.tag.is_some(), "encrypt must return a tag");
    let returned_iv = enc.iv.expect("encrypt must return an IV");

    if approved {
        // Approved keys generate the IV on-device, ignoring the caller
        // IV — the returned IV must therefore differ from the input.
        assert_ne!(
            returned_iv, iv,
            "approved encrypt must return a device-generated IV"
        );
    } else {
        assert_eq!(
            returned_iv, iv,
            "unapproved encrypt must echo the caller-supplied IV"
        );
    }

    // Decrypt with the returned tag/IV recovers the plaintext.
    params.tag = enc.tag;
    params.iv = returned_iv;
    let dec = dev
        .exec_op_fp_gcm(DdiAesOp::Decrypt, params.clone(), enc.data.clone())
        .expect("decrypt must succeed");
    assert_eq!(dec.data, data, "decrypt must recover the plaintext");

    // A tampered tag must fail authentication.  The failure surfaces as
    // an FP crypto-engine tag-mismatch on hardware (`FpError`) or a
    // decrypt-failure `DdiStatus` on the simulator; both are accepted.
    let mut bad_tag = enc.tag.unwrap();
    bad_tag[0] ^= 0xFF;
    params.tag = Some(bad_tag);
    let err = dev
        .exec_op_fp_gcm(DdiAesOp::Decrypt, params.clone(), enc.data.clone())
        .expect_err("decrypt with a tampered tag must fail");
    assert!(
        matches!(
            err,
            DdiError::DdiStatus(DdiStatus::AesDecryptFailed)
                | DdiError::DdiStatus(DdiStatus::AesGcmDecryptTagDoesNotMatch)
                | DdiError::FpError(_)
        ),
        "expected an AES-GCM decrypt failure, got {:?}",
        err
    );

    // Decryption without a tag is rejected.
    params.tag = None;
    let err = dev
        .exec_op_fp_gcm(DdiAesOp::Decrypt, params, enc.data)
        .expect_err("decrypt without a tag must fail");
    assert!(
        matches!(err, DdiError::DdiStatus(DdiStatus::NoTagProvided)),
        "expected NoTagProvided, got {:?}",
        err
    );
}

#[test]
fn test_aes_gcm_unapproved_roundtrip_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (session_id, short_app_id) = reopen_session_with_short_app_id(dev, session_id);
            roundtrip(
                dev,
                session_id,
                short_app_id,
                DdiAesKeySize::AesGcmBulk256Unapproved,
                false,
            );
        },
    );
}

#[test]
fn test_aes_gcm_approved_roundtrip_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (session_id, short_app_id) = reopen_session_with_short_app_id(dev, session_id);
            roundtrip(
                dev,
                session_id,
                short_app_id,
                DdiAesKeySize::AesGcmBulk256,
                true,
            );
        },
    );
}
