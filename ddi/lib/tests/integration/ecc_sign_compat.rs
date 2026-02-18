// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]

use azihsm_ddi::Ddi;
use azihsm_ddi::DdiError;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

/// Helper to perform the ECC sign command execution using the PKA HW.
pub fn ecc_sign_mcr(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    private_key_id: u16,
    digest: [u8; 96],
    digest_len: usize,
) -> Result<DdiEccSignCmdResp, DdiError> {
    assert!(digest.len() <= 96);

    let digest_algo = match digest_len {
        20 => DdiHashAlgorithm::Sha1,
        32 => DdiHashAlgorithm::Sha256,
        48 => DdiHashAlgorithm::Sha384,
        64 => DdiHashAlgorithm::Sha512,
        _ => panic!("Unsupported digest length"),
    };

    helper_ecc_sign(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        private_key_id,
        MborByteArray::new(digest, digest_len).expect("failed to create byte array"),
        digest_algo,
    )
}

/// Wrapper function to verify ECC signatures with FIPS awareness.
fn ecc_sign_verify_fips_aware(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    private_key_id: u16,
    pub_key: &DdiDerPublicKey,
    digest: [u8; 96],
    digest_len: usize,
    signature: &mut [u8],
) -> Result<(), DdiError> {
    let resp = ecc_sign_mcr(dev, session_id, private_key_id, digest, digest_len);
    if is_fips_approved_module(dev) && digest_len == 20 {
        assert!(resp.is_err(), "resp {:?}", resp);
        assert!(
            matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::NonFipsApprovedDigest))
            ),
            "resp {:?}",
            resp
        );
        println!("SHA1 digest is not FIPS approved, skipping test");
        return Ok(());
    }

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();
    let resp_sign = resp.data.signature;

    signature[..resp_sign.len()].clone_from_slice(&resp_sign.data()[..resp_sign.len()]);
    assert!(ecc_verify_local_openssl(
        signature, pub_key, digest, digest_len
    ));

    Ok(())
}

#[test]
fn test_ecc_gen_key_sign_256_compat() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let curve = DdiEccCurve::P256;

            let (private_key_id, pub_key, _) =
                ecc_gen_key_mcr(dev, curve, None, Some(session_id), DdiKeyUsage::SignVerify);
            let mut digest = [100u8; 96];
            let digest_len = 20;

            for (i, item) in digest.iter_mut().enumerate().take(digest_len) {
                *item = i as u8;
            }

            assert!(
                ecc_sign_verify_fips_aware(
                    dev,
                    session_id,
                    private_key_id,
                    &pub_key,
                    digest,
                    digest_len,
                    &mut [0u8; 64],
                )
                .is_ok(),
                "Failed to sign and verify ECC key with P256 curve"
            );
        },
    );
}

#[test]
fn test_ecc_gen_key_sign_256_digest_32_compat() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let curve = DdiEccCurve::P256;

            let (private_key_id, pub_key, _) =
                ecc_gen_key_mcr(dev, curve, None, Some(session_id), DdiKeyUsage::SignVerify);
            let mut digest = [100u8; 96];
            let digest_len = 32;

            for (i, item) in digest.iter_mut().enumerate().take(digest_len) {
                *item = i as u8;
            }

            assert!(
                ecc_sign_verify_fips_aware(
                    dev,
                    session_id,
                    private_key_id,
                    &pub_key,
                    digest,
                    digest_len,
                    &mut [0u8; 64],
                )
                .is_ok(),
                "Failed to sign and verify ECC key with P256 curve"
            );
        },
    );
}

#[test]
fn test_ecc_gen_key_sign_384_compat() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let curve = DdiEccCurve::P384;

            let (private_key_id, pub_key, _) =
                ecc_gen_key_mcr(dev, curve, None, Some(session_id), DdiKeyUsage::SignVerify);
            let mut digest = [100u8; 96];
            let digest_len = 20;

            for (i, item) in digest.iter_mut().enumerate().take(digest_len) {
                *item = i as u8;
            }

            assert!(
                ecc_sign_verify_fips_aware(
                    dev,
                    session_id,
                    private_key_id,
                    &pub_key,
                    digest,
                    digest_len,
                    &mut [0u8; 96],
                )
                .is_ok(),
                "Failed to sign and verify ECC key with P384 curve"
            );
        },
    );
}

#[test]
fn test_ecc_gen_key_sign_384_digest_32_compat() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let curve = DdiEccCurve::P384;

            let (private_key_id, pub_key, _) =
                ecc_gen_key_mcr(dev, curve, None, Some(session_id), DdiKeyUsage::SignVerify);
            let mut digest = [100u8; 96];
            let digest_len = 32;

            for (i, item) in digest.iter_mut().enumerate().take(digest_len) {
                *item = i as u8;
            }

            assert!(
                ecc_sign_verify_fips_aware(
                    dev,
                    session_id,
                    private_key_id,
                    &pub_key,
                    digest,
                    digest_len,
                    &mut [0u8; 96],
                )
                .is_ok(),
                "Failed to sign and verify ECC key with P384 curve"
            );
        },
    );
}

#[test]
fn test_ecc_gen_key_sign_384_digest_48_compat() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let curve = DdiEccCurve::P384;

            let (private_key_id, pub_key, _) =
                ecc_gen_key_mcr(dev, curve, None, Some(session_id), DdiKeyUsage::SignVerify);
            let mut digest = [100u8; 96];
            let digest_len = 48;

            for (i, item) in digest.iter_mut().enumerate().take(digest_len) {
                *item = i as u8;
            }

            assert!(
                ecc_sign_verify_fips_aware(
                    dev,
                    session_id,
                    private_key_id,
                    &pub_key,
                    digest,
                    digest_len,
                    &mut [0u8; 96],
                )
                .is_ok(),
                "Failed to sign and verify ECC key with P384 curve"
            );
        },
    );
}

#[test]
fn test_ecc_gen_key_sign_521_compat() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let curve = DdiEccCurve::P521;

            let (private_key_id, pub_key, _) =
                ecc_gen_key_mcr(dev, curve, None, Some(session_id), DdiKeyUsage::SignVerify);
            let mut digest = [100u8; 96];
            let digest_len = 20;

            for (i, item) in digest.iter_mut().enumerate().take(digest_len) {
                *item = i as u8;
            }

            assert!(
                ecc_sign_verify_fips_aware(
                    dev,
                    session_id,
                    private_key_id,
                    &pub_key,
                    digest,
                    digest_len,
                    &mut [0u8; 132],
                )
                .is_ok(),
                "Failed to sign and verify ECC key with P521 curve"
            );
        },
    );
}

#[test]
fn test_ecc_gen_key_sign_521_digest_32_compat() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let curve = DdiEccCurve::P521;

            let (private_key_id, pub_key, _) =
                ecc_gen_key_mcr(dev, curve, None, Some(session_id), DdiKeyUsage::SignVerify);
            let mut digest = [100u8; 96];
            let digest_len = 32;

            for (i, item) in digest.iter_mut().enumerate().take(digest_len) {
                *item = i as u8;
            }

            assert!(
                ecc_sign_verify_fips_aware(
                    dev,
                    session_id,
                    private_key_id,
                    &pub_key,
                    digest,
                    digest_len,
                    &mut [0u8; 132],
                )
                .is_ok(),
                "Failed to sign and verify ECC key with P521 curve"
            );
        },
    );
}

#[test]
fn test_ecc_gen_key_sign_521_digest_48_compat() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let curve = DdiEccCurve::P521;

            let (private_key_id, pub_key, _) =
                ecc_gen_key_mcr(dev, curve, None, Some(session_id), DdiKeyUsage::SignVerify);
            let mut digest = [100u8; 96];
            let digest_len = 48;

            for (i, item) in digest.iter_mut().enumerate().take(digest_len) {
                *item = i as u8;
            }

            assert!(
                ecc_sign_verify_fips_aware(
                    dev,
                    session_id,
                    private_key_id,
                    &pub_key,
                    digest,
                    digest_len,
                    &mut [0u8; 132],
                )
                .is_ok(),
                "Failed to sign and verify ECC key with P384 curve"
            );
        },
    );
}

#[test]
fn test_ecc_gen_key_sign_521_digest_64_compat() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let curve = DdiEccCurve::P521;

            let (private_key_id, pub_key, _) =
                ecc_gen_key_mcr(dev, curve, None, Some(session_id), DdiKeyUsage::SignVerify);
            let mut digest = [100u8; 96];
            let digest_len = 64;

            for (i, item) in digest.iter_mut().enumerate().take(digest_len) {
                *item = i as u8;
            }

            assert!(
                ecc_sign_verify_fips_aware(
                    dev,
                    session_id,
                    private_key_id,
                    &pub_key,
                    digest,
                    digest_len,
                    &mut [0u8; 132],
                )
                .is_ok(),
                "Failed to sign and verify ECC key with P521 curve"
            );
        },
    );
}
