// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RsaUnwrap smoke tests (`CKM_RSA_AES_KEY_WRAP`).
//!
//! For each key class the host builds a `[ RSA-OAEP(KEK) | AES-KWP(target) ]`
//! blob under the partition's RSA-2048 unwrapping key and unwraps it:
//! - AES import: confirm an AES-256 key is imported (`kind == Aes256`, no
//!   public key).
//! - RSA import (plain + CRT, 2k/3k/4k): confirm the vault kind and the
//!   returned public key.
//! - ECC import (P-256/384/521): confirm the vault kind and the returned
//!   public key.
//! - Tampered blob: a corrupted wrapped blob is rejected (the AES-KWP
//!   integrity check fails) rather than importing a bogus key.
//!
//! Each import is returned as a populated `masked_key` envelope (the
//! firmware masks the imported key in place into the response's reserved
//! slot); the AES, RSA, and ECC cases assert it is present and
//! well-formed.  We do *not* assert on the opaque `key_id` (the sim
//! backend may assign `0`).  Functional verification of the imported key
//! (RSA mod-exp, tag/OpenKey lookup) lives in the generated-key suite,
//! which needs those additional commands.

#![cfg(test)]

use azihsm_ddi::DdiError;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_rsa_unwrap_aes_key_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_der, _) = get_unwrapping_key(dev, session_id);

            // Host wraps an AES-256 key under the unwrapping key
            // (RSA-OAEP-wrapped ephemeral KEK + AES-KWP payload).
            let wrapped = wrap_data(unwrap_pub_der, TEST_AES_256.as_slice());

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::from_slice(&wrapped).expect("failed to create byte array"),
                DdiKeyClass::Aes,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            )
            .expect("rsa_unwrap should succeed");

            assert_eq!(resp.hdr.op, DdiOp::RsaUnwrap);
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            assert_eq!(resp.data.kind, DdiKeyType::Aes256);
            assert!(
                resp.data.pub_key.is_none(),
                "AES import must not return a public key"
            );

            // The imported key is returned as a populated masked-key
            // envelope with a randomized IV (firmware masks it in place).
            assert!(
                !resp.data.masked_key.as_slice().is_empty(),
                "masked_key must be populated"
            );
            assert!(
                verify_iv_not_default_from_masked_key(resp.data.masked_key.as_slice())
                    .unwrap_or(false),
                "masked_key IV must be randomized",
            );
            assert!(
                verify_masked_key_attributes(
                    resp.data.masked_key.as_slice(),
                    MaskedKeyAttributes::ENCRYPT | MaskedKeyAttributes::DECRYPT
                ),
                "AES unwrap masked_key attributes must include ENCRYPT|DECRYPT",
            );
        },
    );
}

#[test]
fn test_rsa_unwrap_tampered_blob_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_der, _) = get_unwrapping_key(dev, session_id);

            let mut wrapped = wrap_data(unwrap_pub_der, TEST_AES_256.as_slice());
            // Corrupt a byte in the AES-KWP payload (past the 256-byte
            // RSA segment) so the integrity check rejects it.
            let last = wrapped.len() - 1;
            wrapped[last] ^= 0xff;

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::from_slice(&wrapped).expect("failed to create byte array"),
                DdiKeyClass::Aes,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            );

            assert!(resp.is_err(), "tampered blob must be rejected: {:?}", resp);

            // Both the firmware (AES-KWP AIV failure mapped by the
            // key-unwrap crate) and the simulator surface a tampered payload
            // as the unwrap-specific `RsaUnwrapAesUnwrapFailed`.
            assert!(
                matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::RsaUnwrapAesUnwrapFailed)
                ),
                "tampered blob should surface as RsaUnwrapAesUnwrapFailed",
            );
        },
    );
}

#[test]
fn test_rsa_unwrap_ecc_key_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Import each supported NIST curve and confirm the vault kind
            // and that the returned public key matches the known public key
            // of the imported private key.
            let keys = [
                (
                    TEST_ECC_256_PRIVATE_KEY.as_slice(),
                    DdiKeyType::Ecc256Private,
                    TEST_ECC_256_PUBLIC_KEY.as_slice(),
                ),
                (
                    TEST_ECC_384_PRIVATE_KEY.as_slice(),
                    DdiKeyType::Ecc384Private,
                    TEST_ECC_384_PUBLIC_KEY.as_slice(),
                ),
                (
                    TEST_ECC_521_PRIVATE_KEY.as_slice(),
                    DdiKeyType::Ecc521Private,
                    TEST_ECC_521_PUBLIC_KEY.as_slice(),
                ),
            ];

            for (test_key, expected_kind, expected_pub) in keys.iter() {
                let (unwrap_key_id, unwrap_pub_der, _) = get_unwrapping_key(dev, session_id);
                let wrapped = wrap_data(unwrap_pub_der, test_key);

                let resp = helper_rsa_unwrap(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    unwrap_key_id,
                    MborByteArray::from_slice(&wrapped).expect("failed to create byte array"),
                    DdiKeyClass::Ecc,
                    DdiRsaCryptoPadding::Oaep,
                    DdiHashAlgorithm::Sha256,
                    None,
                    helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App),
                )
                .expect("ecc rsa_unwrap should succeed");

                assert_eq!(resp.hdr.op, DdiOp::RsaUnwrap);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
                assert_eq!(resp.data.kind, *expected_kind);

                // The imported key is returned as a populated masked-key
                // envelope with a randomized IV.
                assert!(
                    !resp.data.masked_key.as_slice().is_empty(),
                    "masked_key must be populated for {:?}",
                    expected_kind,
                );
                assert!(
                    verify_iv_not_default_from_masked_key(resp.data.masked_key.as_slice())
                        .unwrap_or(false),
                    "masked_key IV must be randomized for {:?}",
                    expected_kind,
                );
                assert!(
                    verify_masked_key_attributes(
                        resp.data.masked_key.as_slice(),
                        MaskedKeyAttributes::SIGN | MaskedKeyAttributes::VERIFY
                    ),
                    "masked_key attributes must include SIGN|VERIFY for {:?}",
                    expected_kind,
                );

                // The returned public key must be the imported key's public
                // key (derived firmware-side from the private key).
                let pub_key = resp
                    .data
                    .pub_key
                    .expect("ECC import must return a public key");
                assert_eq!(
                    pub_key.der.as_slice(),
                    *expected_pub,
                    "ECC public key must match the known public key",
                );
            }
        },
    );
}

#[test]
fn test_rsa_unwrap_rsa_key_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Import each RSA size in both the plain and CRT vault kinds and
            // confirm the reported kind plus that the returned public key
            // matches the known public key of the imported private key.
            let keys = [
                (
                    TEST_RSA_2K_PRIVATE_KEY.as_slice(),
                    DdiKeyClass::Rsa,
                    DdiKeyType::Rsa2kPrivate,
                    TEST_RSA_2K_PUBLIC_KEY.as_slice(),
                ),
                (
                    TEST_RSA_3K_PRIVATE_KEY.as_slice(),
                    DdiKeyClass::Rsa,
                    DdiKeyType::Rsa3kPrivate,
                    TEST_RSA_3K_PUBLIC_KEY.as_slice(),
                ),
                (
                    TEST_RSA_4K_PRIVATE_KEY.as_slice(),
                    DdiKeyClass::Rsa,
                    DdiKeyType::Rsa4kPrivate,
                    TEST_RSA_4K_PUBLIC_KEY.as_slice(),
                ),
                (
                    TEST_RSA_2K_PRIVATE_KEY.as_slice(),
                    DdiKeyClass::RsaCrt,
                    DdiKeyType::Rsa2kPrivateCrt,
                    TEST_RSA_2K_PUBLIC_KEY.as_slice(),
                ),
                (
                    TEST_RSA_3K_PRIVATE_KEY.as_slice(),
                    DdiKeyClass::RsaCrt,
                    DdiKeyType::Rsa3kPrivateCrt,
                    TEST_RSA_3K_PUBLIC_KEY.as_slice(),
                ),
                (
                    TEST_RSA_4K_PRIVATE_KEY.as_slice(),
                    DdiKeyClass::RsaCrt,
                    DdiKeyType::Rsa4kPrivateCrt,
                    TEST_RSA_4K_PUBLIC_KEY.as_slice(),
                ),
            ];

            for (test_key, key_class, expected_kind, expected_pub) in keys.iter() {
                let (unwrap_key_id, unwrap_pub_der, _) = get_unwrapping_key(dev, session_id);
                let wrapped = wrap_data(unwrap_pub_der, test_key);

                let resp = helper_rsa_unwrap(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    unwrap_key_id,
                    MborByteArray::from_slice(&wrapped).expect("failed to create byte array"),
                    *key_class,
                    DdiRsaCryptoPadding::Oaep,
                    DdiHashAlgorithm::Sha256,
                    None,
                    helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
                )
                .expect("rsa rsa_unwrap should succeed");

                assert_eq!(resp.hdr.op, DdiOp::RsaUnwrap);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
                assert_eq!(resp.data.kind, *expected_kind);

                // The imported key is returned as a populated masked-key
                // envelope — even for the largest RSA-4096-CRT key, which
                // the firmware masks in place into the reserved response
                // slot to stay within the per-IO DMA budget.
                assert!(
                    !resp.data.masked_key.as_slice().is_empty(),
                    "masked_key must be populated for {:?}",
                    expected_kind,
                );
                assert!(
                    verify_iv_not_default_from_masked_key(resp.data.masked_key.as_slice())
                        .unwrap_or(false),
                    "masked_key IV must be randomized for {:?}",
                    expected_kind,
                );
                assert!(
                    verify_masked_key_attributes(
                        resp.data.masked_key.as_slice(),
                        MaskedKeyAttributes::ENCRYPT | MaskedKeyAttributes::DECRYPT
                    ),
                    "masked_key attributes must include ENCRYPT|DECRYPT for {:?}",
                    expected_kind,
                );

                // The returned public key must be the imported key's public
                // key (derived firmware-side from the private key).
                let pub_key = resp
                    .data
                    .pub_key
                    .expect("RSA import must return a public key");
                assert_eq!(
                    pub_key.der.as_slice(),
                    *expected_pub,
                    "RSA public key must match the known public key",
                );
            }
        },
    );
}

/// An oversized OAEP-recovered KEK (a "KEK" longer than any valid AES key)
/// must be rejected rather than used.  On the firmware backends the PAL's
/// oversized-plaintext error is remapped to the command-specific
/// `RsaUnwrapInvalidKek`; the sim (mock) rejects it later, at AES-key
/// construction, with a different status — so we assert the specific status
/// only off-mock.
#[test]
fn test_rsa_unwrap_oversized_kek_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_der, _) = get_unwrapping_key(dev, session_id);

            let wrapped = wrap_data_with_oversized_kek(unwrap_pub_der);

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::from_slice(&wrapped).expect("failed to create byte array"),
                DdiKeyClass::Aes,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            );

            assert!(resp.is_err(), "oversized KEK must be rejected: {:?}", resp);

            #[cfg(not(feature = "mock"))]
            assert!(
                matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::RsaUnwrapInvalidKek)
                ),
                "oversized KEK should surface as RsaUnwrapInvalidKek on firmware",
            );
        },
    );
}
