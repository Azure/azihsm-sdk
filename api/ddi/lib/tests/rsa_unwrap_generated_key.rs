// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use rsa_padding::RsaDigestKind;
use rsa_padding::RsaEncoding;

use crate::common::*;

/// Send a RSA unwrap request and get the response for AES bulk payload key.
///
/// # Arguments
///
/// * `session_id` - Session ID to use for the operation.
/// * `unwrap_key_id` - Key ID of the key to use for unwrapping.
/// * `der` - DER encoded data to unwrap.
/// * `der_len` - Length of the DER encoded data.
/// * `key_tag` - Key tag to use when stoting the unwrapped key in the device.
/// * `dev` - Device to use for the operation.
///
/// # Returns
///
/// * `DdiResult<T::OpResp>` - Response of the operation.
fn aes_bulk_unwrap_send_req_and_get_resp(
    session_id: &u16,
    unwrap_key_id: &u16,
    der: &[u8; 3072],
    der_len: &usize,
    key_tag: &u16,
    dev: &mut <DdiTest as Ddi>::Dev,
) -> Result<DdiRsaUnwrapCmdResp, mcr_ddi::DdiError> {
    let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

    helper_rsa_unwrap(
        dev,
        Some(*session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        *unwrap_key_id,
        MborByteArray::new(*der, *der_len).expect("failed to create byte array"),
        DdiKeyClass::AesBulk,
        DdiRsaCryptoPadding::Oaep,
        DdiHashAlgorithm::Sha256,
        Some(*key_tag),
        key_props,
    )
}

#[test]
fn test_rsa_unwrap_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped =
                wrap_data(unwrap_pub_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_rsa_unwrap(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::Rsa,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_rsa_unwrap_incorrect_session_id() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped =
                wrap_data(unwrap_pub_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let session_id = 20;

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::Rsa,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_rsa_unwrap_incorrect_key_num_table() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped =
                wrap_data(unwrap_pub_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id.wrapping_add(0x0300),
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::Rsa,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_rsa_unwrap_incorrect_key_num_entry() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped =
                wrap_data(unwrap_pub_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id.wrapping_add(0x0020),
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::Rsa,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::KeyNotFound)
            ));
        },
    );
}

#[test]
fn test_rsa_unwrap_incorrect_der_len() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped =
                wrap_data(unwrap_pub_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len() / 2;

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::Rsa,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_rsa_unwrap_incorrect_key_type() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped =
                wrap_data(unwrap_pub_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::Ecc,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_rsa_unwrap_incorrect_hash() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped =
                wrap_data(unwrap_pub_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::Rsa,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha1,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_rsa_unwrap_tampered_data() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped =
                wrap_data(unwrap_pub_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            // Tamper the data:
            der[(der_len / 2) as usize] = der[(der_len / 2) as usize].wrapping_add(1);

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::Rsa,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_rsa_unwrap_incorrect_input_key_usage() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Import a private key with incorrect usage
            let mut der = [0u8; 3072];
            der[..TEST_RSA_2K_PRIVATE_KEY.len()].copy_from_slice(&TEST_RSA_2K_PRIVATE_KEY);

            let req = DdiDerKeyImportCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::DerKeyImport,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiDerKeyImportReq {
                    der: MborByteArray::new(der, TEST_RSA_2K_PRIVATE_KEY.len())
                        .expect("failed to create byte array"),
                    key_class: DdiKeyClass::Rsa,
                    key_tag: None,
                    key_properties: helper_key_properties(
                        DdiKeyUsage::EncryptDecrypt,
                        DdiKeyAvailability::App,
                    ),
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp_data = resp.unwrap().data;
            assert_eq!(resp_data.kind, DdiKeyType::Rsa2kPrivate);

            let bad_unwrap_key_id = resp_data.key_id;
            let ddi_der_public_key = resp_data.pub_key.unwrap();
            let bad_unwrap_key_der =
                ddi_der_public_key.der.data()[..ddi_der_public_key.der.len()].to_vec();

            let rsa_3k_private_wrapped =
                wrap_data(bad_unwrap_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                bad_unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::Rsa,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_rsa_unwrap_rsa_key_sizes() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let keys = [
                (TEST_RSA_2K_PRIVATE_KEY.as_slice(), DdiKeyType::Rsa2kPrivate),
                (TEST_RSA_3K_PRIVATE_KEY.as_slice(), DdiKeyType::Rsa3kPrivate),
                (TEST_RSA_4K_PRIVATE_KEY.as_slice(), DdiKeyType::Rsa4kPrivate),
            ];

            for (test_key, expected_key_type) in keys.iter() {
                let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

                let rsa_private_wrapped = wrap_data(unwrap_pub_key_der, test_key);

                let mut der = [0u8; 3072];
                der[..rsa_private_wrapped.len()].copy_from_slice(&rsa_private_wrapped);

                let der_len = rsa_private_wrapped.len();

                let key_props =
                    helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);

                let resp = helper_rsa_unwrap(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    unwrap_key_id,
                    MborByteArray::new(der, der_len).expect("failed to create byte array"),
                    DdiKeyClass::Rsa,
                    DdiRsaCryptoPadding::Oaep,
                    DdiHashAlgorithm::Sha256,
                    None,
                    key_props,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();
                assert_eq!(resp.data.kind, *expected_key_type);
            }
        },
    );
}

#[test]
fn test_rsa_unwrap_rsa_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped =
                wrap_data(unwrap_pub_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::Rsa,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();
            let unwrapped_key_id = resp.data.key_id;
            assert_eq!(resp.data.kind, DdiKeyType::Rsa3kPrivate);

            // Try encrypting and decrypting with UNWRAPPED_KEY_ID
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

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: unwrapped_key_id,
                    y: MborByteArray::new(y, y_len).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Decrypt,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

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
fn test_rsa_unwrap_rsa_crt_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped =
                wrap_data(unwrap_pub_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::RsaCrt,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();
            let unwrapped_key_id = resp.data.key_id;
            assert_eq!(resp.data.kind, DdiKeyType::Rsa3kPrivateCrt);

            // Try encrypting and decrypting with UNWRAPPED_KEY_ID
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

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: unwrapped_key_id,
                    y: MborByteArray::new(y, y_len).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Decrypt,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

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
fn test_rsa_unwrap_rsa_with_key_tag() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped =
                wrap_data(unwrap_pub_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let key_tag = 0x6677;

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::Rsa,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                Some(key_tag),
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();
            assert_eq!(resp.data.kind, DdiKeyType::Rsa3kPrivate);
            let unwrapped_key_id = resp.data.key_id;

            // Confirm we can find the unwrapped key by tag
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_tag,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            assert_eq!(resp.data.key_id, unwrapped_key_id);
            assert_eq!(resp.data.key_kind, DdiKeyType::Rsa3kPrivate);
        },
    );
}

#[test]
fn test_rsa_unwrap_rsa_crt_with_key_tag() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped =
                wrap_data(unwrap_pub_key_der, TEST_RSA_3K_PRIVATE_KEY.as_slice());

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let key_tag = 0x6677;

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::RsaCrt,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                Some(key_tag),
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();
            assert_eq!(resp.data.kind, DdiKeyType::Rsa3kPrivateCrt);
            let unwrapped_key_id = resp.data.key_id;

            // Confirm we can find the unwrapped key by tag
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_tag,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            assert_eq!(resp.data.key_id, unwrapped_key_id);
            assert_eq!(resp.data.key_kind, DdiKeyType::Rsa3kPrivateCrt);
        },
    );
}

#[test]
fn test_rsa_unwrap_ecc_keys_with_key_tag() {
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
                let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

                let ecc_wrapped = wrap_data(unwrap_pub_key_der, test_key);

                let mut der = [0u8; 3072];
                der[..ecc_wrapped.len()].copy_from_slice(&ecc_wrapped);

                let der_len = ecc_wrapped.len();

                let key_props =
                    helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);

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
                    key_props,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();
                assert_eq!(resp.data.kind, *expected_key_type);
                let unwrapped_key_id = resp.data.key_id;

                // Confirm we can find the unwrapped key by tag
                let resp = helper_open_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    *key_tag,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                assert_eq!(resp.data.key_id, unwrapped_key_id);
                assert_eq!(resp.data.key_kind, *expected_key_type);
            }
        },
    );
}

#[test]
fn test_rsa_unwrap_aes_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let aes_256_wrapped = wrap_data(unwrap_pub_key_der, TEST_AES_256.as_slice());

            let mut der = [0u8; 3072];
            der[..aes_256_wrapped.len()].copy_from_slice(&aes_256_wrapped);

            let der_len = aes_256_wrapped.len();

            let key_tag = 0x5566;

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

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
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();
            assert_eq!(resp.data.kind, DdiKeyType::Aes256);
            let unwrapped_key_id = resp.data.key_id;
            assert!(resp.data.pub_key.is_none());

            // Confirm we can find the unwrapped key by tag
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_tag,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            assert_eq!(resp.data.key_id, unwrapped_key_id);
            assert_eq!(resp.data.key_kind, DdiKeyType::Aes256);
        },
    );
}

#[test]
fn test_rsa_unwrap_aes_with_key_tag() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let aes_256_wrapped = wrap_data(unwrap_pub_key_der, TEST_AES_256.as_slice());

            let mut der = [0u8; 3072];
            der[..aes_256_wrapped.len()].copy_from_slice(&aes_256_wrapped);

            let der_len = aes_256_wrapped.len();

            let key_tag = 0x6677;

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

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
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();
            assert_eq!(resp.data.kind, DdiKeyType::Aes256);
            let unwrapped_key_id = resp.data.key_id;

            // Confirm we can find the unwrapped key by tag
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_tag,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            assert_eq!(resp.data.key_id, unwrapped_key_id);
            assert_eq!(resp.data.key_kind, DdiKeyType::Aes256);
        },
    );
}

#[test]
fn test_rsa_unwrap_aes_bulk_key_with_rollback_error() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let aes_256_wrapped = wrap_data(unwrap_pub_key_der, TEST_AES_256.as_slice());

            let mut der = [0u8; 3072];
            der[..aes_256_wrapped.len()].copy_from_slice(&aes_256_wrapped);

            let der_len = aes_256_wrapped.len();

            if !set_test_action(ddi, path, DdiTestAction::TriggerIoFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            let mut blob = [0u8; 3072];
            blob[..TEST_AES_256_CKM_WRAPPED.len()].copy_from_slice(&TEST_AES_256_CKM_WRAPPED);
            let key_tag = 0x5566;

            match aes_bulk_unwrap_send_req_and_get_resp(
                &session_id,
                &unwrap_key_id,
                &der,
                &der_len,
                &key_tag,
                dev,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }
        },
    );
}

#[test]
fn test_rsa_unwrap_aes_bulk_key_with_rollback_error_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let aes_256_wrapped = wrap_data(unwrap_pub_key_der, TEST_AES_256.as_slice());

            let mut der = [0u8; 3072];
            der[..aes_256_wrapped.len()].copy_from_slice(&aes_256_wrapped);

            let der_len = aes_256_wrapped.len();

            let mut blob = [0u8; 3072];
            blob[..TEST_AES_256_CKM_WRAPPED.len()].copy_from_slice(&TEST_AES_256_CKM_WRAPPED);

            let mut key_tag: u16 = 0x1;

            let mut key_id = 0;
            loop {
                match aes_bulk_unwrap_send_req_and_get_resp(
                    &session_id,
                    &unwrap_key_id,
                    &der,
                    &der_len,
                    &key_tag,
                    dev,
                ) {
                    Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => break,
                    Err(err) => panic!("Unexpected error code: {:?}", err),
                    Ok(val) => key_id = val.data.key_id,
                }

                key_tag += 1;
            }

            // Delete Key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerIoFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            // Unwrap the key with test action set to fail and see it fails
            let key_tag = 3354;

            match aes_bulk_unwrap_send_req_and_get_resp(
                &session_id,
                &unwrap_key_id,
                &der,
                &der_len,
                &key_tag,
                dev,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            // Unwrap the key to see it completes successfully
            let key_tag = 3355;
            let resp = aes_bulk_unwrap_send_req_and_get_resp(
                &session_id,
                &unwrap_key_id,
                &der,
                &der_len,
                &key_tag,
                dev,
            );
            assert!(resp.is_ok(), "{:?}", resp);

            // Unwrap one extra key to see if it fails
            let key_tag = 3356;
            match aes_bulk_unwrap_send_req_and_get_resp(
                &session_id,
                &unwrap_key_id,
                &der,
                &der_len,
                &key_tag,
                dev,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }
        },
    );
}

#[test]
fn test_rsa_unwrap_aes_bulk_key_with_rollback_error_after_dma_out() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let aes_256_wrapped = wrap_data(unwrap_pub_key_der, TEST_AES_256.as_slice());

            let mut der = [0u8; 3072];
            der[..aes_256_wrapped.len()].copy_from_slice(&aes_256_wrapped);

            let der_len = aes_256_wrapped.len();

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaOutFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            let mut blob = [0u8; 3072];
            blob[..TEST_AES_256_CKM_WRAPPED.len()].copy_from_slice(&TEST_AES_256_CKM_WRAPPED);
            let key_tag = 0x5566;

            match aes_bulk_unwrap_send_req_and_get_resp(
                &session_id,
                &unwrap_key_id,
                &der,
                &der_len,
                &key_tag,
                dev,
            ) {
                Err(DdiError::DdiError(201)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }
        },
    );
}

#[test]
fn test_rsa_unwrap_aes_bulk_key_with_rollback_error_after_dma_out_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let aes_256_wrapped = wrap_data(unwrap_pub_key_der, TEST_AES_256.as_slice());

            let mut der = [0u8; 3072];
            der[..aes_256_wrapped.len()].copy_from_slice(&aes_256_wrapped);

            let der_len = aes_256_wrapped.len();

            let mut blob = [0u8; 3072];
            blob[..TEST_AES_256_CKM_WRAPPED.len()].copy_from_slice(&TEST_AES_256_CKM_WRAPPED);

            let mut key_tag: u16 = 0x1;

            let mut key_id = 0;
            loop {
                match aes_bulk_unwrap_send_req_and_get_resp(
                    &session_id,
                    &unwrap_key_id,
                    &der,
                    &der_len,
                    &key_tag,
                    dev,
                ) {
                    Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => break,
                    Err(err) => panic!("Unexpected error code: {:?}", err),
                    Ok(val) => key_id = val.data.key_id,
                }

                key_tag += 1;
            }

            // Delete Key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaOutFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            // Unwrap the key with test action set to fail and see it fails
            let key_tag = 3354;
            match aes_bulk_unwrap_send_req_and_get_resp(
                &session_id,
                &unwrap_key_id,
                &der,
                &der_len,
                &key_tag,
                dev,
            ) {
                Err(DdiError::DdiError(201)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            // Unwrap the key to see it completes successfully
            let key_tag = 3355;
            let resp = aes_bulk_unwrap_send_req_and_get_resp(
                &session_id,
                &unwrap_key_id,
                &der,
                &der_len,
                &key_tag,
                dev,
            );
            assert!(resp.is_ok(), "{:?}", resp);

            // Unwrap one extra key to see if it fails
            let key_tag = 3356;
            match aes_bulk_unwrap_send_req_and_get_resp(
                &session_id,
                &unwrap_key_id,
                &der,
                &der_len,
                &key_tag,
                dev,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }
        },
    );
}

#[test]
fn test_rsa_unwrap_aes_bulk_key_with_rollback_error_after_dma_end() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let aes_256_wrapped = wrap_data(unwrap_pub_key_der, TEST_AES_256.as_slice());

            let mut der = [0u8; 3072];
            der[..aes_256_wrapped.len()].copy_from_slice(&aes_256_wrapped);

            let der_len = aes_256_wrapped.len();

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaEndFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            let mut blob = [0u8; 3072];
            blob[..TEST_AES_256_CKM_WRAPPED.len()].copy_from_slice(&TEST_AES_256_CKM_WRAPPED);
            let key_tag = 0x5566;

            match aes_bulk_unwrap_send_req_and_get_resp(
                &session_id,
                &unwrap_key_id,
                &der,
                &der_len,
                &key_tag,
                dev,
            ) {
                Err(DdiError::DdiError(198)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }
        },
    );
}

#[test]
fn test_rsa_unwrap_aes_bulk_key_with_rollback_error_after_dma_end_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (unwrap_key_id, unwrap_pub_key_der) = get_unwrapping_key(dev, session_id);

            let aes_256_wrapped = wrap_data(unwrap_pub_key_der, TEST_AES_256.as_slice());

            let mut der = [0u8; 3072];
            der[..aes_256_wrapped.len()].copy_from_slice(&aes_256_wrapped);

            let der_len = aes_256_wrapped.len();

            let mut blob = [0u8; 3072];
            blob[..TEST_AES_256_CKM_WRAPPED.len()].copy_from_slice(&TEST_AES_256_CKM_WRAPPED);

            let mut key_tag: u16 = 0x1;

            let mut key_id = 0;
            loop {
                match aes_bulk_unwrap_send_req_and_get_resp(
                    &session_id,
                    &unwrap_key_id,
                    &der,
                    &der_len,
                    &key_tag,
                    dev,
                ) {
                    Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => break,
                    Err(err) => panic!("Unexpected error code: {:?}", err),
                    Ok(val) => key_id = val.data.key_id,
                }

                key_tag += 1;
            }

            // Delete Key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaEndFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            // Unwrap the key with test action set to fail and see it fails
            let key_tag = 3354;
            match aes_bulk_unwrap_send_req_and_get_resp(
                &session_id,
                &unwrap_key_id,
                &der,
                &der_len,
                &key_tag,
                dev,
            ) {
                Err(DdiError::DdiError(198)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            // Unwrap the key to see it completes successfully
            let key_tag = 3355;
            let resp = aes_bulk_unwrap_send_req_and_get_resp(
                &session_id,
                &unwrap_key_id,
                &der,
                &der_len,
                &key_tag,
                dev,
            );
            assert!(resp.is_ok(), "{:?}", resp);

            // Unwrap one extra key to see if it fails
            let key_tag = 3356;
            match aes_bulk_unwrap_send_req_and_get_resp(
                &session_id,
                &unwrap_key_id,
                &der,
                &der_len,
                &key_tag,
                dev,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }
        },
    );
}
