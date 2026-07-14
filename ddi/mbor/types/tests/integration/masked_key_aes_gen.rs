// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::cmp::min;
use std::thread;

use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

const RAW_MSG: [u8; 512] = [1u8; 512];

#[test]
fn test_masked_key_aes_128_gen() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_masked_key_aes_gen(dev, session_id, DdiAesKeySize::Aes128);
        },
    );
}

#[test]
fn test_masked_key_aes_192_gen() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_masked_key_aes_gen(dev, session_id, DdiAesKeySize::Aes192);
        },
    );
}

#[test]
fn test_masked_key_aes_256_gen() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_masked_key_aes_gen(dev, session_id, DdiAesKeySize::Aes256);
        },
    );
}

#[test]
fn test_masked_key_aes_bulk_256_gen() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let max_keys = get_device_info(ddi, path).tables as usize * 7;
            // We open a session in each thread and we can only do MAX_SESSIONS sessions max.
            let max_threads = MAX_SESSIONS;
            let thread_count = min(max_keys, max_threads);
            let thread_device_path = path.to_string();
            let mut parent_dev = dev.clone();

            let thread = thread::spawn(move || {
                test_masked_key_aes_gcm_encrypt_decrypt_thread_fn(
                    thread_device_path,
                    thread_count,
                    &mut parent_dev,
                    session_id,
                );
            });
            thread.join().unwrap();
        },
    );
}

fn test_masked_key_aes_gen(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    key_size: DdiAesKeySize,
) {
    // Generate a key
    let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

    let resp = helper_aes_generate(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_size,
        Some(1),
        key_props,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();
    let key_id = resp.data.key_id;
    let masked_key = resp.data.masked_key;

    assert!(verify_iv_not_default_from_masked_key(masked_key.as_slice()).unwrap_or(false));

    assert!(verify_masked_key_attributes(
        masked_key.as_slice(),
        MaskedKeyAttributes::ENCRYPT | MaskedKeyAttributes::DECRYPT | MaskedKeyAttributes::LOCAL
    ));

    // Encrypt the plain text with the key
    let iv = MborByteArray::new([0x8; 16], 16).expect("failed to create byte array");

    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        DdiAesOp::Encrypt,
        MborByteArray::from_slice(&RAW_MSG).expect("failed to create byte array"),
        iv,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();
    assert_eq!(resp.data.msg.len(), RAW_MSG.len());
    assert_ne!(RAW_MSG, resp.data.msg.as_slice());

    let encrypted_msg = resp.data.msg.as_slice().to_vec();

    let resp = helper_get_new_key_id_from_unmask(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        false,
        masked_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let (new_key_id, _, _) = resp.unwrap();

    // Decrypt the plain text
    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        new_key_id,
        DdiAesOp::Decrypt,
        MborByteArray::from_slice(encrypted_msg.as_slice()).expect("failed to create byte array"),
        iv,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    // Verify the plain text
    assert_eq!(resp.data.msg.as_slice(), RAW_MSG);
    assert_eq!(resp.data.msg.len(), RAW_MSG.len());
}

fn test_masked_key_aes_gcm_encrypt_decrypt_thread_fn(
    device_path: String,
    max_attempts: usize,
    parent_dev: &mut <DdiTest as Ddi>::Dev,
    parent_session: u16,
) {
    let ddi = DdiTest::default();
    let dev = ddi.open_dev(device_path.as_str()).unwrap();
    let mut app_sess_id = None;
    let mut short_app_id = None;

    for _ in 0..max_attempts {
        let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
            &dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        );

        let resp = helper_open_session(
            &dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            encrypted_credential,
            pub_key,
        );
        if resp.as_ref().is_err() {
            if matches!(
                resp.as_ref().unwrap_err(),
                DdiError::DdiStatus(DdiStatus::NonceMismatch)
            ) {
                continue;
            }
        }

        assert!(resp.is_ok(), "resp {:?}", resp);

        let resp = resp.unwrap();

        assert!(resp.hdr.sess_id.is_some());
        assert_eq!(resp.hdr.op, DdiOp::OpenSession);
        assert_eq!(resp.hdr.status, DdiStatus::Success);

        app_sess_id = Some(resp.data.sess_id);
        short_app_id = Some(resp.data.short_app_id);

        break;
    }

    let app_sess_id = app_sess_id.unwrap();
    let short_app_sess_id = short_app_id.unwrap();

    thread::sleep(std::time::Duration::from_secs(1));

    let resp = generate_aes_bulk_256_key(
        parent_dev,
        &parent_session,
        Some(1),
        DdiAesKeySize::AesGcmBulk256Unapproved,
    );
    assert!(resp.is_ok(), "resp: {:?}", resp);
    let resp = resp.unwrap();

    let key_id = resp.data.key_id;
    let key_id_aes_bulk_256 = resp.data.bulk_key_id;
    let masked_key = resp.data.masked_key;
    assert!(key_id_aes_bulk_256.is_some());

    assert!(verify_iv_not_default_from_masked_key(masked_key.as_slice()).unwrap_or(false));

    assert!(verify_masked_key_attributes(
        masked_key.as_slice(),
        MaskedKeyAttributes::ENCRYPT | MaskedKeyAttributes::DECRYPT | MaskedKeyAttributes::LOCAL
    ));

    // Set up requests for the gcm encrypt operations
    let aad = [0x4; 32usize];
    let iv = [0x3u8; 12];

    // Setup params for encrypt operation
    let mut mcr_fp_gcm_params: DdiAesGcmParams = DdiAesGcmParams {
        key_id: key_id_aes_bulk_256.unwrap() as u32,
        iv,
        aad: Some(aad.to_vec()),
        tag: None, // tag is not needed for encryption
        session_id: app_sess_id,
        short_app_id: short_app_sess_id,
    };

    // Execute encrypt operation
    let resp = dev.exec_op_fp_gcm(
        DdiAesOp::Encrypt,
        mcr_fp_gcm_params.clone(),
        RAW_MSG.to_vec(),
    );

    assert!(resp.is_ok(), "resp: {:?}", resp);
    let encrypted_resp = resp.unwrap();

    // Ensure encrypted data length is the same as the original data
    // Ensure encrypted data is different from original data
    assert_eq!(encrypted_resp.data.len(), RAW_MSG.len());
    assert_ne!(RAW_MSG.to_vec(), encrypted_resp.data);
    let tag = encrypted_resp.tag;

    let resp = helper_get_new_key_id_from_unmask(
        parent_dev,
        Some(parent_session),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        true,
        masked_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let (_, new_bulk_key_id, _) = resp.unwrap();

    assert!(new_bulk_key_id.is_some());
    let newbulk_key_id = new_bulk_key_id.unwrap();

    // Execute decrypt operation
    mcr_fp_gcm_params.tag = tag;
    mcr_fp_gcm_params.key_id = newbulk_key_id as u32;
    let resp = dev.exec_op_fp_gcm(
        DdiAesOp::Decrypt,
        mcr_fp_gcm_params.clone(),
        encrypted_resp.data.clone(),
    );

    assert!(resp.is_ok(), "resp: {:?}", resp);
    let decrypted_resp = resp.unwrap();

    assert_eq!(decrypted_resp.data.len(), RAW_MSG.len());
    assert_eq!(decrypted_resp.data, RAW_MSG);
}

// Create session key, delete the key
// Unmask the key, should still be session key
#[test]
fn test_unmask_session_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::Session);

            // Create a session key
            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let data = resp.unwrap().data;

            let key_id = data.key_id;

            let masked_key = data.masked_key;
            assert!(!masked_key.is_empty());

            // Delete the original key
            {
                let resp = helper_delete_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
            }

            // Import/unmask the key
            let key_id = {
                let resp = helper_unmask_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    masked_key,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let data = resp.unwrap().data;
                data.key_id
            };

            // Check if this key is session key
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );
            // Should fail
            assert!(resp.is_err());

            // Close session and reopen
            let session_id = {
                let resp = helper_close_session(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );
                assert!(resp.is_ok(), "resp {:?}", resp);

                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                );

                let resp = helper_open_session(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_some());
                assert_eq!(resp.hdr.op, DdiOp::OpenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);

                resp.data.sess_id
            };

            // Check if the session key still exists
            // By using it to encrypt
            {
                let raw_msg = [1u8; 512];
                let msg_len = raw_msg.len();
                let mut msg = [0u8; 1024];
                msg[..msg_len].clone_from_slice(&raw_msg);

                let resp = helper_aes_encrypt_decrypt(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id,
                    DdiAesOp::Encrypt,
                    MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                    MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
                );

                assert!(resp.is_err(), "resp {:?}", resp);
            }
        },
    );
}

// Create named key, delete the key
// Unmask the key, should still be named key
#[test]
fn test_unmask_named_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            const KEY_TAG: u16 = 0x1234;
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            // Create a named key
            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                Some(KEY_TAG),
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let data = resp.unwrap().data;

            let key_id = data.key_id;

            let masked_key = data.masked_key;
            assert!(!masked_key.is_empty());

            // Delete the key
            {
                let resp = helper_delete_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
            }

            // Close session and open session with new seed
            let session_id = {
                let resp = helper_close_session(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );
                assert!(resp.is_ok(), "resp {:?}", resp);

                let new_session_seed = [42u8; 48];
                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    new_session_seed,
                );

                let resp = helper_open_session(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_some());
                assert_eq!(resp.hdr.op, DdiOp::OpenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);

                resp.data.sess_id
            };

            // Import/unmask the key
            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            // Check if this key is named key
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                KEY_TAG,
            );
            // Should pass
            assert!(resp.is_ok());

            // Key should still be there
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                KEY_TAG,
            );
            // Should pass
            assert!(resp.is_ok());
        },
    );
}

// Create session key
// Confirm unmasking into different session fails
#[test]
fn test_unmask_session_key_different_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::Session);

            // Create a session key
            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let data = resp.unwrap().data;

            let key_id = data.key_id;

            let masked_key = data.masked_key;
            assert!(!masked_key.is_empty());

            // Delete the original key
            {
                let resp = helper_delete_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
            }

            // Close session and open session with new seed
            let session_id = {
                let resp = helper_close_session(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );
                assert!(resp.is_ok(), "resp {:?}", resp);

                let new_session_seed = [42u8; 48];
                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    new_session_seed,
                );

                let resp = helper_open_session(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_some());
                assert_eq!(resp.hdr.op, DdiOp::OpenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);

                resp.data.sess_id
            };

            // Import/unmask the key; should fail
            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );
            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

/// Helper: generate a bulk key, extract and compare attributes after unmask.
///
/// 1. Generate an AES bulk key with the given size, availability, and optional key tag.
/// 2. Extract metadata/attributes from the original masked key blob.
/// 3. Delete the original key.
/// 4. Unmask the key from the masked blob.
/// 5. Extract metadata/attributes from the unmasked key's masked blob.
/// 6. Assert that attributes, raw attribute blob, and metadata fields match exactly.
fn unmask_bulk_key_and_verify_attributes(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    aes_key_size: DdiAesKeySize,
    availability: DdiKeyAvailability,
    key_tag: Option<u16>,
) {
    let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, availability);

    let resp = helper_aes_generate(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        aes_key_size,
        key_tag,
        key_props,
    );
    assert!(resp.is_ok(), "Failed to generate key: {:?}", resp);
    let data = resp.unwrap().data;

    let key_id = data.key_id;
    let original_masked_key = data.masked_key;
    assert!(!original_masked_key.is_empty());

    // Extract metadata from original masked key
    let original_metadata = extract_metadata_from_masked_key(original_masked_key.as_slice())
        .expect("Failed to extract metadata from original masked key");
    let original_attrs = MaskedKeyAttributes::try_from(&original_metadata.key_attributes)
        .expect("Failed to parse original attributes");

    // Delete the original key
    let resp = helper_delete_key(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
    );
    assert!(resp.is_ok(), "Failed to delete key: {:?}", resp);

    // Unmask the key
    let resp = helper_unmask_key(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        original_masked_key,
    );
    assert!(resp.is_ok(), "Failed to unmask key: {:?}", resp);
    let unmasked_data = resp.unwrap().data;

    // Extract metadata from unmasked key's masked blob
    let unmasked_masked_key = unmasked_data.masked_key;
    assert!(!unmasked_masked_key.is_empty());
    let unmasked_metadata = extract_metadata_from_masked_key(unmasked_masked_key.as_slice())
        .expect("Failed to extract metadata from unmasked masked key");
    let unmasked_attrs = MaskedKeyAttributes::try_from(&unmasked_metadata.key_attributes)
        .expect("Failed to parse unmasked attributes");

    // Exact attribute equality — catches any dropped flags
    assert_eq!(
        original_attrs, unmasked_attrs,
        "Key attributes mismatch after unmask: original {:?} != unmasked {:?}",
        original_attrs, unmasked_attrs
    );

    // Raw 32-byte attribute blob comparison
    assert_eq!(
        original_metadata.key_attributes.blob, unmasked_metadata.key_attributes.blob,
        "Raw attribute blob mismatch after unmask"
    );

    // Verify metadata fields are preserved
    assert_eq!(
        original_metadata.key_type, unmasked_metadata.key_type,
        "key_type mismatch after unmask"
    );
    assert_eq!(
        original_metadata.key_length, unmasked_metadata.key_length,
        "key_length mismatch after unmask"
    );
    assert_eq!(
        original_metadata.key_tag, unmasked_metadata.key_tag,
        "key_tag mismatch after unmask"
    );

    // Clean up the unmasked key
    let resp = helper_delete_key(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        unmasked_data.key_id,
    );
    assert!(resp.is_ok(), "Failed to delete unmasked key: {:?}", resp);
}

// Generate an AES XTS Bulk 256 App key, unmask it, and verify all attributes are preserved.
#[test]
fn test_unmask_xts_bulk_key_preserves_attributes() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            unmask_bulk_key_and_verify_attributes(
                dev,
                session_id,
                DdiAesKeySize::AesXtsBulk256,
                DdiKeyAvailability::App,
                Some(0x5001),
            );
        },
    );
}

// Generate an AES XTS Bulk 256 Session key, unmask it, and verify all attributes
// (including the SESSION flag) are preserved.
#[test]
fn test_unmask_xts_bulk_session_key_preserves_attributes() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            unmask_bulk_key_and_verify_attributes(
                dev,
                session_id,
                DdiAesKeySize::AesXtsBulk256,
                DdiKeyAvailability::Session,
                None,
            );
        },
    );
}

// Generate an AES GCM Bulk 256 App key, unmask it, and verify all attributes are preserved.
#[test]
fn test_unmask_gcm_bulk_key_preserves_attributes() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            unmask_bulk_key_and_verify_attributes(
                dev,
                session_id,
                DdiAesKeySize::AesGcmBulk256,
                DdiKeyAvailability::App,
                Some(0x5002),
            );
        },
    );
}

// Generate an AES GCM Bulk 256 Session key, unmask it, and verify all attributes
// (including the SESSION flag) are preserved.
#[test]
fn test_unmask_gcm_bulk_session_key_preserves_attributes() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            unmask_bulk_key_and_verify_attributes(
                dev,
                session_id,
                DdiAesKeySize::AesGcmBulk256,
                DdiKeyAvailability::Session,
                None,
            );
        },
    );
}
