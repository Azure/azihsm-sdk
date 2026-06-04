// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! EccSign smoke tests for the emu backend.
//!
//! - Happy path: generate a P-256 sign/verify key, sign a digest,
//!   and verify the signature against the returned public key with
//!   OpenSSL.
//! - Sign with an unknown key id: rejected (the exact error code
//!   differs across backends — emu returns `KeyNotFound`, the mock
//!   returns `InvalidKeyNumber`).

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_test_helpers::helper_key_properties;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_ecc_sign_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Generate a P-256 sign/verify key in the open session.
            let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);
            let gen_resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P256,
                None,
                key_props,
            )
            .unwrap();

            // Sign a 32-byte digest with the generated key.
            let digest = [0xaau8; 32];
            let sign_resp = helper_ecc_sign(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                gen_resp.data.private_key_id,
                MborByteArray::from_slice(&digest).unwrap(),
                DdiHashAlgorithm::Sha256,
            )
            .unwrap();

            assert_eq!(sign_resp.hdr.op, DdiOp::EccSign);
            assert_eq!(sign_resp.hdr.status, DdiStatus::Success);

            // Signature must be 64 bytes (P-256, r||s in BE after host
            // post_decode).
            let sig_len = sign_resp.data.signature.len();
            assert_eq!(sig_len, 64, "P-256 signature must be 64 bytes");

            // OpenSSL verifies the signature against the returned public
            // key and the digest we signed.  `ecc_verify_local_openssl`
            // takes the digest as a fixed-96-byte buffer + length, so
            // copy our 32-byte digest into a padded array.
            #[cfg(target_os = "linux")]
            {
                let mut digest_padded = [0u8; 96];
                digest_padded[..digest.len()].copy_from_slice(&digest);
                assert!(
                    ecc_verify_local_openssl(
                        &sign_resp.data.signature.data()[..sig_len],
                        &gen_resp.data.pub_key,
                        digest_padded,
                        digest.len(),
                    ),
                    "ECDSA signature must verify against the generated public key"
                );
            }
        },
    );
}

#[test]
fn test_ecc_sign_unknown_key_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let digest = [0xaau8; 32];
            let err = helper_ecc_sign(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0xFFFF, /* unknown key id */
                MborByteArray::from_slice(&digest).unwrap(),
                DdiHashAlgorithm::Sha256,
            )
            .expect_err("EccSign must reject an unknown key id");

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
