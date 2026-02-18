// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]

use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_masked_key_rsa_unwrap_rsa_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der, _) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped =
                wrap_data(unwrap_pub_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::Rsa,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                Some(1),
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();
            let unwrapped_key_id = resp.data.key_id;
            let masked_key = resp.data.masked_key;
            assert_eq!(resp.data.kind, DdiKeyType::Rsa3kPrivate);

            let resp = helper_get_new_key_id_from_unmask(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrapped_key_id,
                true,
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let (new_key_id, _, _) = resp.unwrap();

            // Try encrypting and decrypting with new_key_id
            // to confirm unwrapped key is correct
            let orig_x = [0x1u8; 512];
            let data_len_to_test = 190;
            let resp = rsa_encrypt_local_openssl(
                &TEST_RSA_3K_PUBLIC_KEY,
                &orig_x,
                data_len_to_test,
                DdiRsaCryptoPadding::Oaep,
                Some(DdiHashAlgorithm::Sha256),
            );

            let mut y = [0u8; 512];
            y[..resp.len()].copy_from_slice(resp.as_slice());
            let y_len = resp.len();

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                new_key_id,
                MborByteArray::new(y, y_len).expect("failed to create byte array"),
                DdiRsaOpType::Decrypt,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            let mut padded_data = [0u8; 512];
            padded_data[..resp.data.x.len()]
                .copy_from_slice(&resp.data.x.data()[..resp.data.x.len()]);

            let unpadded_data_result = RsaEncoding::decode_oaep(
                &mut padded_data[..resp.data.x.len()],
                None,
                3072 / 8,
                RsaDigestKind::Sha256,
                crypto_sha256,
            );
            assert!(unpadded_data_result.is_ok());
            let unpadded_data = unpadded_data_result.unwrap();

            assert_eq!(orig_x[..data_len_to_test], unpadded_data);
        },
    );
}

#[test]
fn test_masked_key_rsa_unwrap_rsa_crt_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der, _) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped =
                wrap_data(unwrap_pub_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::RsaCrt,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                Some(1),
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();
            let unwrapped_key_id = resp.data.key_id;
            let masked_key = resp.data.masked_key;
            assert_eq!(resp.data.kind, DdiKeyType::Rsa3kPrivateCrt);

            let resp = helper_get_new_key_id_from_unmask(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrapped_key_id,
                true,
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let (new_key_id, _, _) = resp.unwrap();

            // Try encrypting and decrypting with new_key_id
            // to confirm unwrapped key is correct
            let orig_x = [0x1u8; 512];
            let data_len_to_test = 190;
            let resp = rsa_encrypt_local_openssl(
                &TEST_RSA_3K_PUBLIC_KEY,
                &orig_x,
                data_len_to_test,
                DdiRsaCryptoPadding::Oaep,
                Some(DdiHashAlgorithm::Sha256),
            );

            let mut y = [0u8; 512];
            y[..resp.len()].copy_from_slice(resp.as_slice());
            let y_len = resp.len();

            let resp = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                new_key_id,
                MborByteArray::new(y, y_len).expect("failed to create byte array"),
                DdiRsaOpType::Decrypt,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            let mut padded_data = [0u8; 512];
            padded_data[..resp.data.x.len()]
                .copy_from_slice(&resp.data.x.data()[..resp.data.x.len()]);

            let unpadded_data_result = RsaEncoding::decode_oaep(
                &mut padded_data[..resp.data.x.len()],
                None,
                3072 / 8,
                RsaDigestKind::Sha256,
                crypto_sha256,
            );
            assert!(unpadded_data_result.is_ok());
            let unpadded_data = unpadded_data_result.unwrap();

            assert_eq!(orig_x[..data_len_to_test], unpadded_data);
        },
    );
}

#[test]
fn test_masked_key_rsa_unwrap_ecc_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let keys = [
                (
                    TEST_ECC_256_PRIVATE_KEY.as_slice(),
                    DdiKeyType::Ecc256Private,
                    0x6677,
                ),
                (
                    TEST_ECC_384_PRIVATE_KEY.as_slice(),
                    DdiKeyType::Ecc384Private,
                    0x6678,
                ),
                (
                    TEST_ECC_521_PRIVATE_KEY.as_slice(),
                    DdiKeyType::Ecc521Private,
                    0x6679,
                ),
            ];

            for (test_key, expected_key_type, key_tag) in keys.iter() {
                let (unwrap_key_id, unwrap_pub_key_der, _) = get_unwrapping_key(dev, session_id);

                let ecc_wrapped = wrap_data(unwrap_pub_key_der, test_key);

                let mut der = [0u8; 3072];
                der[..ecc_wrapped.len()].copy_from_slice(&ecc_wrapped);

                let der_len = ecc_wrapped.len();

                let resp = helper_rsa_unwrap(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    unwrap_key_id,
                    MborByteArray::new(der, der_len).expect("failed to create byte array"),
                    DdiKeyClass::Ecc,
                    DdiRsaCryptoPadding::Oaep,
                    DdiHashAlgorithm::Sha256,
                    Some(*key_tag),
                    helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();
                assert_eq!(resp.data.kind, *expected_key_type);
                let unwrapped_key_id = resp.data.key_id;
                let masked_key = resp.data.masked_key;

                let resp = helper_get_new_key_id_from_unmask(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    unwrapped_key_id,
                    true,
                    masked_key,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let (new_key_id, _, _) = resp.unwrap();

                // Confirm we can find the unwrapped key by tag
                let resp = helper_open_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    *key_tag,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                assert_eq!(resp.data.key_id, new_key_id);
                assert_eq!(resp.data.key_kind, *expected_key_type);
            }
        },
    );
}

#[test]
fn test_masked_key_rsa_unwrap_aes_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der, _) = get_unwrapping_key(dev, session_id);

            let aes_256_wrapped = wrap_data(unwrap_pub_key_der, TEST_AES_256.as_slice());

            let mut der = [0u8; 3072];
            der[..aes_256_wrapped.len()].copy_from_slice(&aes_256_wrapped);

            let der_len = aes_256_wrapped.len();

            let key_tag = 0x5566;

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::Aes,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                Some(key_tag),
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();
            assert_eq!(resp.data.kind, DdiKeyType::Aes256);
            let unwrapped_key_id = resp.data.key_id;
            assert!(resp.data.pub_key.is_none());
            let masked_key = resp.data.masked_key;

            let resp = helper_get_new_key_id_from_unmask(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrapped_key_id,
                true,
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let (new_key_id, _, _) = resp.unwrap();

            // Confirm we can find the unwrapped key by tag
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_tag,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            assert_eq!(resp.data.key_id, new_key_id);
            assert_eq!(resp.data.key_kind, DdiKeyType::Aes256);
        },
    );
}

#[test]
fn test_masked_key_rsa_unwrap_aes_bulk_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der, _) = get_unwrapping_key(dev, session_id);

            let aes_256_wrapped = wrap_data(unwrap_pub_key_der, TEST_AES_256.as_slice());

            let mut der = [0u8; 3072];
            der[..aes_256_wrapped.len()].copy_from_slice(&aes_256_wrapped);

            let der_len = aes_256_wrapped.len();

            let mut blob = [0u8; 3072];
            blob[..TEST_AES_256_CKM_WRAPPED.len()].copy_from_slice(&TEST_AES_256_CKM_WRAPPED);
            let key_tag = 0x5566;

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::AesGcmBulkUnapproved,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                Some(key_tag),
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();
            assert_eq!(resp.data.kind, DdiKeyType::AesGcmBulk256Unapproved);
            let unwrapped_key_id = resp.data.key_id;
            assert!(resp.data.pub_key.is_none());
            let masked_key = resp.data.masked_key;

            let resp = helper_get_new_key_id_from_unmask(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrapped_key_id,
                true,
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let (new_key_id, _, _) = resp.unwrap();

            // Confirm we can find the unwrapped key by tag
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_tag,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            assert_eq!(resp.data.key_id, new_key_id);
            assert_eq!(resp.data.key_kind, DdiKeyType::AesGcmBulk256Unapproved);
        },
    );
}
