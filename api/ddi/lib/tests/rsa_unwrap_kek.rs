// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;

use crate::common::*;

#[test]
fn test_rsa_unwrap_rsa_kek_32() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (unwrap_key_id, unwrap_pub_key_der, _) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped = wrap_data_with_aes_key(
                unwrap_pub_key_der,
                TEST_RSA_3K_PRIVATE_KEY.as_slice(),
                TEST_EPHEMERAL_AES.as_slice(),
            );

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let resp = helper_rsa_unwrap_kek(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            println!("Unwrapped KEK: {:?}", resp.data.kek);
            assert_eq!(resp.data.kek.as_slice(), TEST_EPHEMERAL_AES.as_slice());
        },
    );
}

#[test]
fn test_rsa_unwrap_rsa_kek_16() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (unwrap_key_id, unwrap_pub_key_der, _) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped = wrap_data_with_aes_key(
                unwrap_pub_key_der,
                TEST_RSA_3K_PRIVATE_KEY.as_slice(),
                TEST_EPHEMERAL_AES_16.as_slice(),
            );

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let resp = helper_rsa_unwrap_kek(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            println!("Unwrapped KEK: {:?}", resp.data.kek);
            assert_eq!(resp.data.kek.as_slice(), TEST_EPHEMERAL_AES_16.as_slice());
        },
    );
}

#[test]
fn test_rsa_unwrap_rsa_kek_24() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (unwrap_key_id, unwrap_pub_key_der, _) = get_unwrapping_key(dev, session_id);

            let rsa_3k_private_wrapped = wrap_data_with_aes_key(
                unwrap_pub_key_der,
                TEST_RSA_3K_PRIVATE_KEY.as_slice(),
                TEST_EPHEMERAL_AES_24.as_slice(),
            );

            let mut der = [0u8; 3072];
            der[..rsa_3k_private_wrapped.len()].copy_from_slice(&rsa_3k_private_wrapped);

            let der_len = rsa_3k_private_wrapped.len();

            let resp = helper_rsa_unwrap_kek(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            println!("Unwrapped KEK: {:?}", resp.data.kek);
            assert_eq!(resp.data.kek.as_slice(), TEST_EPHEMERAL_AES_24.as_slice());
        },
    );
}
