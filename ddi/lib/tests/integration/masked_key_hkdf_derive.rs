// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]

#[cfg(not(feature = "mock"))]
use azihsm_crypto::Rng;
use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_mbor::MborDecode;
use azihsm_ddi_mbor::MborDecoder;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_masked_key_secret_hkdf() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt_vec = Some("salt".as_bytes().to_vec());
            let info_vec = Some("label".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_hkdf_sha1() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha1;
            let salt_vec = Some("salt".as_bytes().to_vec());
            let info_vec = Some("label".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_hkdf_no_salt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt_vec = None;
            let info_vec = Some("label".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes256;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_hkdf_no_info() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt_vec = Some("salt".as_bytes().to_vec());
            let info_vec = None;
            let key_type = DdiKeyType::Aes256;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_hkdf_aes128() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt_vec = Some("salt".as_bytes().to_vec());
            let info_vec = Some("label".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes128;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_hkdf_aes192() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt_vec = Some("salt".as_bytes().to_vec());
            let info_vec = Some("label".as_bytes().to_vec());
            let key_type = DdiKeyType::Aes192;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_helper(
                dev,
                hash_algorithm,
                salt_vec,
                info_vec,
                key_type,
                key_tag,
                key_properties,
                session_id,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_hkdf_aes_gcm_secret256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (session_id, short_app_id) = reopen_session_with_short_app_id(dev, session_id);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = "salt".as_bytes().to_vec();
            let info = "label".as_bytes().to_vec();
            let key_type = DdiKeyType::AesGcmBulk256Unapproved;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_aes_gcm_helper(
                dev,
                session_id,
                short_app_id,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
                DdiKeyType::Secret256,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_hkdf_aes_gcm_secret384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (session_id, short_app_id) = reopen_session_with_short_app_id(dev, session_id);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = "salt".as_bytes().to_vec();
            let info = "label".as_bytes().to_vec();
            let key_type = DdiKeyType::AesGcmBulk256Unapproved;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_aes_gcm_helper(
                dev,
                session_id,
                short_app_id,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
                DdiKeyType::Secret384,
            );
        },
    );
}

#[test]
fn test_masked_key_secret_hkdf_aes_gcm_secret521() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (session_id, short_app_id) = reopen_session_with_short_app_id(dev, session_id);

            let hash_algorithm = DdiHashAlgorithm::Sha256;
            let salt = "salt".as_bytes().to_vec();
            let info = "label".as_bytes().to_vec();
            let key_type = DdiKeyType::AesGcmBulk256Unapproved;
            let key_tag = Some(1);
            let key_properties =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            test_secret_hkdf_aes_gcm_helper(
                dev,
                session_id,
                short_app_id,
                hash_algorithm,
                salt,
                info,
                key_type,
                key_tag,
                key_properties,
                DdiKeyType::Secret521,
            );
        },
    );
}

#[test]
fn test_masked_key_hmac_sha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let res = create_hmac_key_ex(session_id, DdiKeyType::HmacSha256, dev, None);
            assert!(res.is_ok(), "create_hmac_key_ex failed: {:?}", res);

            let res = res.unwrap();
            let key_id = res.data.key_id;
            let masked_key = res.data.masked_key;

            // Delete that key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            // Import that key with masked key (Unmask this key)
            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let masked_key = resp.unwrap().data.masked_key;
            let metadata = extract_metadata_from_masked_key(masked_key.as_slice());
            assert!(
                metadata.is_some(),
                "failed to extract metadata from masked key"
            );
            let metadata = metadata.unwrap();
            let key_usage = get_key_usage_from_attributes(&metadata.key_attributes);
            assert!(
                key_usage.is_some(),
                "failed to get key usage from masked key attributes"
            );
            let key_usage = key_usage.unwrap();
            assert_eq!(key_usage, DdiKeyUsage::SignVerify);
        },
    );
}

#[test]
fn test_masked_key_hmac_sha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let res = create_hmac_key_ex(session_id, DdiKeyType::HmacSha384, dev, None);
            assert!(res.is_ok(), "create_hmac_key_ex failed: {:?}", res);

            let res = res.unwrap();
            let key_id = res.data.key_id;
            let masked_key = res.data.masked_key;

            // Delete that key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            // Import that key with masked key (Unmask this key)
            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let masked_key = resp.unwrap().data.masked_key;
            let metadata = extract_metadata_from_masked_key(masked_key.as_slice());
            assert!(
                metadata.is_some(),
                "failed to extract metadata from masked key"
            );
            let metadata = metadata.unwrap();
            let key_usage = get_key_usage_from_attributes(&metadata.key_attributes);
            assert!(
                key_usage.is_some(),
                "failed to get key usage from masked key attributes"
            );
            let key_usage = key_usage.unwrap();
            assert_eq!(key_usage, DdiKeyUsage::SignVerify);
        },
    );
}

#[test]
fn test_masked_key_hmac_sha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let res = create_hmac_key_ex(session_id, DdiKeyType::HmacSha512, dev, None);
            assert!(res.is_ok(), "create_hmac_key_ex failed: {:?}", res);

            let res = res.unwrap();
            let key_id = res.data.key_id;
            let masked_key = res.data.masked_key;

            // Delete that key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            // Import that key with masked key (Unmask this key)
            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let masked_key = resp.unwrap().data.masked_key;
            let metadata = extract_metadata_from_masked_key(masked_key.as_slice());
            assert!(
                metadata.is_some(),
                "failed to extract metadata from masked key"
            );
            let metadata = metadata.unwrap();
            let key_usage = get_key_usage_from_attributes(&metadata.key_attributes);
            assert!(
                key_usage.is_some(),
                "failed to get key usage from masked key attributes"
            );
            let key_usage = key_usage.unwrap();
            assert_eq!(key_usage, DdiKeyUsage::SignVerify);
        },
    );
}

#[cfg(not(feature = "mock"))]
#[test]
fn test_masked_key_var_hmac_sha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let mut bytes = [0u8; 1];
            Rng::rand_bytes(&mut bytes).expect("rand_bytes failure");

            let key_len = (bytes[0] % 33) + 32; // 32-64
            let res = create_hmac_key_ex(session_id, DdiKeyType::VarHmac256, dev, Some(key_len));
            assert!(res.is_ok(), "create_hmac_key_ex failed: {:?}", res);

            let res = res.unwrap();
            let key_id = res.data.key_id;
            let masked_key = res.data.masked_key;

            // Delete that key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            // Import that key with masked key (Unmask this key)
            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let masked_key = resp.unwrap().data.masked_key;
            let metadata = extract_metadata_from_masked_key(masked_key.as_slice());
            assert!(
                metadata.is_some(),
                "failed to extract metadata from masked key"
            );
            let metadata = metadata.unwrap();
            let key_usage = get_key_usage_from_attributes(&metadata.key_attributes);
            assert!(
                key_usage.is_some(),
                "failed to get key usage from masked key attributes"
            );
            let key_usage = key_usage.unwrap();
            assert_eq!(key_usage, DdiKeyUsage::SignVerify);
            assert_eq!(metadata.key_length, key_len.into());
        },
    );
}

#[cfg(not(feature = "mock"))]
#[test]
fn test_masked_key_var_hmac_sha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let mut bytes = [0u8; 1];
            Rng::rand_bytes(&mut bytes).expect("rand_bytes failure");

            let key_len = (bytes[0] % 81) + 48; // 48-128
            let res = create_hmac_key_ex(session_id, DdiKeyType::VarHmac384, dev, Some(key_len));
            assert!(res.is_ok(), "create_hmac_key_ex failed: {:?}", res);

            let res = res.unwrap();
            let key_id = res.data.key_id;
            let masked_key = res.data.masked_key;

            // Delete that key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            // Import that key with masked key (Unmask this key)
            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let masked_key = resp.unwrap().data.masked_key;
            let metadata = extract_metadata_from_masked_key(masked_key.as_slice());
            assert!(
                metadata.is_some(),
                "failed to extract metadata from masked key"
            );
            let metadata = metadata.unwrap();
            let key_usage = get_key_usage_from_attributes(&metadata.key_attributes);
            assert!(
                key_usage.is_some(),
                "failed to get key usage from masked key attributes"
            );
            let key_usage = key_usage.unwrap();
            assert_eq!(key_usage, DdiKeyUsage::SignVerify);
            assert_eq!(metadata.key_length, key_len.into());
        },
    );
}

#[cfg(not(feature = "mock"))]
#[test]
fn test_masked_key_var_hmac_sha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let mut bytes = [0u8; 1];
            Rng::rand_bytes(&mut bytes).expect("rand_bytes failure");

            let key_len = (bytes[0] % 65) + 64; // 64-128
            let res = create_hmac_key_ex(session_id, DdiKeyType::VarHmac512, dev, Some(key_len));
            assert!(res.is_ok(), "create_hmac_key_ex failed: {:?}", res);

            let res = res.unwrap();
            let key_id = res.data.key_id;
            let masked_key = res.data.masked_key;

            // Delete that key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            // Import that key with masked key (Unmask this key)
            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let masked_key = resp.unwrap().data.masked_key;
            let metadata = extract_metadata_from_masked_key(masked_key.as_slice());
            assert!(
                metadata.is_some(),
                "failed to extract metadata from masked key"
            );
            let metadata = metadata.unwrap();
            let key_usage = get_key_usage_from_attributes(&metadata.key_attributes);
            assert!(
                key_usage.is_some(),
                "failed to get key usage from masked key attributes"
            );
            let key_usage = key_usage.unwrap();
            assert_eq!(key_usage, DdiKeyUsage::SignVerify);
            assert_eq!(metadata.key_length, key_len.into());
        },
    );
}

// Uses HKDF to derive derived_key_id1 and derived_key_id2
// from secret_key_id1 and secret_key_id2, respectively.
// Then delete one of the key and unmask it.
// Verifies old key + new key can do an encrypt/decrypt loop
// key_tag is only used for DERIVED_KEY_ID1.
// Returns (derived_key_id1, derived_key_id2)
#[allow(clippy::too_many_arguments)]
fn test_secret_hkdf_helper(
    dev: &mut <DdiTest as Ddi>::Dev,
    hash_algorithm: DdiHashAlgorithm,
    salt: Option<Vec<u8>>,
    info: Option<Vec<u8>>,
    key_type: DdiKeyType,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
    session_id: u16,
) {
    let (secret_key_id1, secret_key_id2) =
        create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

    let salt = {
        if let Some(salt_vec) = salt {
            let mut salt_array = [0u8; 256];
            salt_array[..salt_vec.len()].copy_from_slice(&salt_vec);
            Some(
                MborByteArray::new(salt_array, salt_vec.len())
                    .expect("failed to create byte array"),
            )
        } else {
            None
        }
    };
    let info = {
        if let Some(info_vec) = info {
            let mut info_array = [0u8; 256];
            info_array[..info_vec.len()].copy_from_slice(&info_vec);
            Some(
                MborByteArray::new(info_array, info_vec.len())
                    .expect("failed to create byte array"),
            )
        } else {
            None
        }
    };

    // Derive from first secret key
    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id1,
        hash_algorithm,
        salt,
        info,
        key_type,
        key_tag,
        key_properties,
        Default::default(),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();
    let derived_key_id1 = resp.data.key_id;
    let masked_key = resp.data.masked_key;

    let resp = helper_get_new_key_id_from_unmask(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        derived_key_id1,
        true,
        masked_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let (new_derived_key_id1, _, _) = resp.unwrap();

    // Derive from second secret key

    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id2,
        hash_algorithm,
        salt,
        info,
        key_type,
        None,
        key_properties,
        Default::default(),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let derived_key_id2 = resp.unwrap().data.key_id;

    // Encrypt message with secret key 1
    let raw_msg = [1u8; 512];
    let msg_len = raw_msg.len();
    let mut msg = [0u8; 1024];
    msg[..msg_len].clone_from_slice(&raw_msg);

    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        new_derived_key_id1,
        DdiAesOp::Encrypt,
        MborByteArray::new(msg, msg_len).expect("failed to create byte array"),
        MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    // Decrypt with key 2 and confirm message is same

    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        derived_key_id2,
        DdiAesOp::Decrypt,
        resp.data.msg,
        MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    assert_eq!(resp.data.msg.data_take(), msg);
    assert_eq!(resp.data.msg.len(), msg_len);
}

#[allow(clippy::too_many_arguments)]
fn test_secret_hkdf_aes_gcm_helper(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    short_app_id: u8,
    hash_algorithm: DdiHashAlgorithm,
    salt: Vec<u8>,
    info: Vec<u8>,
    key_type: DdiKeyType,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
    secret_key_type: DdiKeyType,
) {
    let (secret_key_id1, secret_key_id2) = create_ecdh_secrets(session_id, dev, secret_key_type);

    let salt = {
        let mut salt_array = [0u8; 256];
        salt_array[..salt.len()].copy_from_slice(&salt);
        Some(MborByteArray::new(salt_array, salt.len()).expect("failed to create byte array"))
    };
    let info = {
        let mut info_array = [0u8; 256];
        info_array[..info.len()].copy_from_slice(&info);
        Some(MborByteArray::new(info_array, info.len()).expect("failed to create byte array"))
    };

    // Derive from first secret key
    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id1,
        hash_algorithm,
        salt,
        info,
        key_type,
        key_tag,
        key_properties,
        Default::default(),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();
    let derived_key_id1 = resp.data.key_id;
    let masked_key = resp.data.masked_key;

    let resp = helper_get_new_key_id_from_unmask(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        derived_key_id1,
        true,
        masked_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let (_, new_derived_key_id1, _) = resp.unwrap();
    assert!(new_derived_key_id1.is_some());
    let new_derived_key_id1 = new_derived_key_id1.unwrap();

    // Derive from second secret key
    let resp = helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id2,
        hash_algorithm,
        salt,
        info,
        key_type,
        None,
        key_properties,
        Default::default(),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let derived_key_id2 = resp.unwrap().data.bulk_key_id.unwrap();

    // set up requests for the gcm encrypt operations
    let data = vec![1; 16384];
    let aad = [0x4; 32usize];
    let iv = [0x3u8; 12];

    // setup params for encrypt operation
    let mut mcr_fp_gcm_params: DdiAesGcmParams = DdiAesGcmParams {
        key_id: new_derived_key_id1 as u32,
        iv,
        aad: Some(aad.to_vec()),
        tag: None, // tag is not needed for encryption
        session_id,
        short_app_id,
    };

    // execute encrypt operation
    let resp = dev.exec_op_fp_gcm(DdiAesOp::Encrypt, mcr_fp_gcm_params.clone(), data.clone());

    assert!(resp.is_ok(), "resp: {:?}", resp);
    let encrypted_resp = resp.unwrap();

    // ensure encrypted data length is the same as the original data
    // ensure encrypted data is different from original data
    assert_eq!(encrypted_resp.data.len(), data.len());
    assert_ne!(data, encrypted_resp.data);
    let tag = encrypted_resp.tag;

    // execute decrypt operation
    mcr_fp_gcm_params.tag = tag;

    // use derived_key_id2 for decryption
    mcr_fp_gcm_params.key_id = derived_key_id2 as u32;

    let resp = dev.exec_op_fp_gcm(
        DdiAesOp::Decrypt,
        mcr_fp_gcm_params.clone(),
        encrypted_resp.data.clone(),
    );

    assert!(resp.is_ok(), "resp: {:?}", resp);
    let decrypted_resp = resp.unwrap();

    assert_eq!(decrypted_resp.data.len(), data.len());
    assert_eq!(decrypted_resp.data, data);

    close_app_session(dev, session_id);
}

fn extract_metadata_from_masked_key(masked_key: &[u8]) -> Option<DdiMaskedKeyMetadata> {
    const FORMAT_OFFSET: usize = 2;
    const ALGORITHM_OFFSET: usize = FORMAT_OFFSET + 2;
    const IV_LEN_OFFSET: usize = ALGORITHM_OFFSET + 2;
    const IV_PADDING_OFFSET: usize = IV_LEN_OFFSET + 2;
    const METADATA_LEN_OFFSET: usize = IV_PADDING_OFFSET + 2;
    const METADATA_PADDING_OFFSET: usize = METADATA_LEN_OFFSET + 2;
    const ENCRYPTED_KEY_LEN_OFFSET: usize = METADATA_PADDING_OFFSET + 2;
    const ENCRYPTED_KEY_PADDING_OFFSET: usize = ENCRYPTED_KEY_LEN_OFFSET + 2;
    const TAG_LEN_OFFSET: usize = ENCRYPTED_KEY_PADDING_OFFSET + 2;
    const RESERVED_OFFSET: usize = TAG_LEN_OFFSET + 34;

    if masked_key.len() < RESERVED_OFFSET {
        return None;
    }

    let iv_len: usize = u16::from_le_bytes(
        masked_key[ALGORITHM_OFFSET..IV_LEN_OFFSET]
            .try_into()
            .unwrap(),
    )
    .into();
    let iv_padding_len: usize = u16::from_le_bytes(
        masked_key[IV_LEN_OFFSET..IV_PADDING_OFFSET]
            .try_into()
            .unwrap(),
    )
    .into();
    let metadata_len: usize = u16::from_le_bytes(
        masked_key[IV_PADDING_OFFSET..METADATA_LEN_OFFSET]
            .try_into()
            .unwrap(),
    )
    .into();

    let metadata_offset = RESERVED_OFFSET + iv_len + iv_padding_len;

    if masked_key.len() < metadata_offset + metadata_len {
        return None;
    }

    let metadata = &masked_key[metadata_offset..metadata_offset + metadata_len];
    let mut decoder = MborDecoder::new(metadata, false);

    let metadata = DdiMaskedKeyMetadata::mbor_decode(&mut decoder);
    if let Err(e) = &metadata {
        tracing::error!("mbor_decode error {:?}", e);

        return None;
    }

    metadata.ok()
}

fn get_key_usage_from_attributes(attributes: &DdiMaskedKeyAttributes) -> Option<DdiKeyUsage> {
    let masked_key_attributes = MaskedKeyAttributes::try_from(attributes).ok()?;

    if masked_key_attributes.contains(MaskedKeyAttributes::DERIVE) {
        Some(DdiKeyUsage::Derive)
    } else if masked_key_attributes.contains(MaskedKeyAttributes::ENCRYPT)
        && masked_key_attributes.contains(MaskedKeyAttributes::DECRYPT)
    {
        Some(DdiKeyUsage::EncryptDecrypt)
    } else if masked_key_attributes.contains(MaskedKeyAttributes::SIGN)
        && masked_key_attributes.contains(MaskedKeyAttributes::VERIFY)
    {
        Some(DdiKeyUsage::SignVerify)
    } else if masked_key_attributes.contains(MaskedKeyAttributes::UNWRAP) {
        Some(DdiKeyUsage::Unwrap)
    } else {
        None
    }
}
