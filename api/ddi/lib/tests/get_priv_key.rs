// Copyright (C) Microsoft Corporation. All rights reserved.

// TODO: Currently restricting tests to Linux as openssl use is disallowed on Windows
// and causes S360 issues. Need to find a good way to run these tests on Windows.
#![cfg(target_os = "linux")]

mod common;

use crypto::CryptoKeyKind;
use mcr_ddi::*;
use mcr_ddi_mbor::*;
use mcr_ddi_types::*;
use openssl::symm::Cipher;
use openssl::symm::Crypter;
use openssl::symm::Mode;
use test_with_tracing::test;

use crate::common::*;

// Test Digest
const DIGEST: [u8; 96] = [100u8; 96];

// Test Digest length
const DIGEST_LEN: usize = 32;

// Key tag
const KEY_TAG: u16 = 0x5453;

pub fn create_mbor_byte_array<const N: usize>(input: &[u8]) -> MborByteArray<N> {
    let mut fixed_array = [0u8; N];
    let len_to_copy = std::cmp::min(input.len(), N);
    fixed_array[..len_to_copy].copy_from_slice(&input[..len_to_copy]);
    MborByteArray::new(fixed_array, len_to_copy).expect("Failed to initialize MborByteArray")
}

fn create_get_privkey_request(session_id: Option<u16>, key_id: u16) -> DdiGetPrivKeyCmdReq {
    DdiGetPrivKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetPrivKey,
            sess_id: session_id,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetPrivKeyReq { key_id },
        ext: None,
    }
}

pub fn create_aes_key(dev: &mut <DdiTest as Ddi>::Dev, sess_id: u16) -> u16 {
    let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

    let resp = helper_aes_generate(
        dev,
        Some(sess_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        DdiAesKeySize::Aes128,
        Some(KEY_TAG),
        key_props,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();
    resp.data.key_id
}

/// Perform AES encryption or decryption
fn aes_crypt_local_openssl(key: &[u8], input: &[u8], mode: Mode) -> Vec<u8> {
    let cipher = match key.len() {
        16 => Cipher::aes_128_cbc(),
        24 => Cipher::aes_192_cbc(),
        32 => Cipher::aes_256_cbc(),
        _ => panic!("Invalid AES key size: {}", key.len()),
    };

    let mut crypter = Crypter::new(cipher, mode, key, Some(&[0u8; 16]))
        .expect("Failed to initialize AES crypter");

    let mut output = vec![0u8; input.len() + cipher.block_size()];
    let count = crypter
        .update(input, &mut output)
        .expect("AES operation update failed");
    let rest = crypter
        .finalize(&mut output[count..])
        .expect("AES operation finalize failed");

    output.truncate(count + rest);
    output
}

/// Perform the hardware AES encryption
fn aes_encrypt_hardware(
    dev: &mut <DdiTest as Ddi>::Dev,
    sess_id: u16,
    key_id: u16,
    plaintext: &[u8],
) -> Vec<u8> {
    const AES_BLOCK_SIZE: usize = 16;

    // Ensure input is aligned to AES block size
    let padded_len = plaintext.len().div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    let mut padded_plaintext = vec![0u8; padded_len];
    padded_plaintext[..plaintext.len()].copy_from_slice(plaintext);

    // Add PKCS7 padding
    let padding_len = padded_len - plaintext.len();
    padded_plaintext[plaintext.len()..padded_len].fill(padding_len as u8);

    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(sess_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        DdiAesOp::Encrypt,
        MborByteArray::new(
            {
                let mut data = [0u8; 1024];
                data[..padded_plaintext.len()].copy_from_slice(&padded_plaintext);
                data
            },
            padded_plaintext.len(),
        )
        .expect("failed to create byte array"),
        MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
    );

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();

    let ciphertext_len = resp.data.msg.len();
    resp.data.msg.data()[..ciphertext_len].to_vec()
}

/// Perform AES GCM decryption
fn aes_gcm_decrypt_local_openssl(
    key: &[u8],
    ciphertext: &[u8],
    iv: &[u8],
    aad: &[u8],
    tag: &[u8],
) -> Vec<u8> {
    // Ensure key length is valid
    let cipher = match key.len() {
        16 => Cipher::aes_128_gcm(),
        24 => Cipher::aes_192_gcm(),
        32 => Cipher::aes_256_gcm(),
        _ => panic!("Invalid AES key size: {}", key.len()),
    };

    let mut crypter =
        Crypter::new(cipher, Mode::Decrypt, key, Some(iv)).expect("Failed to initialize Crypter");

    crypter.aad_update(aad).expect("Failed to set AAD");

    let mut plaintext = vec![0u8; ciphertext.len() + cipher.block_size()];
    let count = crypter
        .update(ciphertext, &mut plaintext)
        .expect("Failed during AES-GCM decryption");

    // Set the tag for authentication
    crypter
        .set_tag(tag)
        .expect("Failed to set GCM tag for decryption");

    let rest = crypter
        .finalize(&mut plaintext[count..])
        .expect("Failed to finalize AES-GCM decryption");

    plaintext[..(count + rest)].to_vec()
}

/// Perform the hardware AES GCM encryption
fn aes_gcm_encrypt_hardware(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    short_app_id: u8,
    bulk_key_id: u16,
    plaintext: &[u8],
    aad: &[u8],
    iv: &[u8; 12],
) -> (Vec<u8>, Vec<u8>) {
    // Setup parameters for the GCM encrypt operation
    let gcm_params = DdiAesGcmParams {
        key_id: bulk_key_id as u32,
        iv: *iv,
        aad: Some(aad.to_vec()),
        tag: None,
        session_id,
        short_app_id,
    };

    let resp = dev.exec_op_fp_gcm(DdiAesOp::Encrypt, gcm_params.clone(), plaintext.to_vec());
    assert!(resp.is_ok(), "GCM encryption failed: {:?}", resp);

    let encrypted_resp = resp.unwrap();

    // Ensure encrypted data length matches original data length
    assert_eq!(
        encrypted_resp.data.len(),
        plaintext.len(),
        "Encrypted data length mismatch"
    );

    assert_ne!(
        plaintext, encrypted_resp.data,
        "Encryption did not modify plaintext"
    );

    let tag = encrypted_resp
        .tag
        .expect("Tag not generated during encryption");

    // Return the encrypted data and the tag
    (encrypted_resp.data, tag.to_vec())
}

pub fn retrieve_shared_secret(
    dev: &mut <DdiTest as Ddi>::Dev,
    sess_id: u16,
    secret_key_id: u16,
) -> Result<Vec<u8>, String> {
    let req = create_get_privkey_request(Some(sess_id), secret_key_id);
    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie);
    if let Err(err) = resp {
        return Err(format!("Failed to execute operation: {:?}", err));
    }

    // Extract the response and raw secret
    let resp = resp.unwrap();
    let raw_secret_len = resp.data.key_data.len();
    Ok(resp.data.key_data.data()[..raw_secret_len].to_vec())
}

#[test]
fn test_aes_get_and_validate_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // Generate and store AES key
            let aes_key_id = create_aes_key(dev, session_id);

            let req = create_get_privkey_request(Some(session_id), aes_key_id);
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    println!("Firmware is not built with fips_validation_hooks.");
                    return;
                }
            }

            // Extract the response
            let resp = resp.unwrap();
            let raw_aes_key_len = resp.data.key_data.len();

            // Extract the raw AES key
            let raw_aes_key = resp.data.key_data.data()[..raw_aes_key_len].to_vec();

            // Validate AES key by performing encryption and decryption
            let plaintext = b"This is a test message.";
            let ciphertext = aes_encrypt_hardware(dev, session_id, aes_key_id, plaintext);
            let decrypted_text = aes_crypt_local_openssl(&raw_aes_key, &ciphertext, Mode::Decrypt);

            assert_eq!(
                plaintext.to_vec(),
                decrypted_text,
                "AES encryption/decryption failed"
            );
        },
    );
}

#[test]
fn test_aes_bulk_get_and_validate_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // Open a new session and get app session ID and short app ID
            let (app_sess_id, short_app_sess_id) =
                reopen_session_with_short_app_id(dev, session_id);

            // Generate AES Bulk 256 key directly
            let resp = generate_aes_bulk_256_key(dev, &app_sess_id, None);
            assert!(resp.is_ok(), "AES bulk key generation failed: {:?}", resp);
            let resp = resp.unwrap();

            let aes_key_id = resp.data.key_id;
            let aes_bulk_key_id = resp.data.bulk_key_id.unwrap();

            // set up requests for the gcm encrypt operations
            let data = vec![1; 16384];
            let aad = [0x4; 32usize];
            let iv = [0x3u8; 12];
            // Perform encryption using hardware
            let (encrypted_data, tag) = aes_gcm_encrypt_hardware(
                dev,
                app_sess_id,
                short_app_sess_id,
                aes_bulk_key_id,
                &data,
                &aad,
                &iv,
            );

            // Retrieve the raw AES Bulk key
            let req = create_get_privkey_request(Some(session_id), aes_key_id);
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    println!("Firmware is not built with fips_validation_hooks.");
                    return;
                }
            }

            // Extract the response
            let resp = resp.unwrap();
            let raw_aes_bulk_key_len = resp.data.key_data.len();

            // Extract the raw AES bulk key
            let raw_aes_bulk_key = resp.data.key_data.data()[..raw_aes_bulk_key_len].to_vec();

            // Decrypt using OpenSSL
            let decrypted_data =
                aes_gcm_decrypt_local_openssl(&raw_aes_bulk_key, &encrypted_data, &iv, &aad, &tag);

            // Validate decryption matches plaintext
            assert_eq!(data, decrypted_data, "Decryption failed using OpenSSL");

            // Close the session explicitly
            close_app_session(dev, app_sess_id);
        },
    );
}

#[test]
fn test_secret_get_and_validate_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // Generate secret key
            let (secret_key_id1, secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);

            // Perform an early check for FIPS validation hooks support
            let check_req = create_get_privkey_request(Some(session_id), secret_key_id1);
            let mut cookie = None;

            let resp = dev.exec_op(&check_req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    println!("Firmware is not built with fips_validation_hooks.");
                    return;
                }
            }

            // Retrieve shared secret 1
            let shared_secret1 = retrieve_shared_secret(dev, session_id, secret_key_id1)
                .expect("Failed to retrieve shared secret 1");

            // Retrieve shared secret 2
            let shared_secret2 = retrieve_shared_secret(dev, session_id, secret_key_id2)
                .expect("Failed to retrieve shared secret 2");

            assert_eq!(
                shared_secret1, shared_secret2,
                "Shared secret mismatch: validation failed"
            );
        },
    );
}

#[test]
fn test_ecc_get_privkey() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (private_key_id, pub_key) =
                ecc_gen_key_mcr(dev, DdiEccCurve::P256, session_id, DdiKeyUsage::SignVerify);

            let req = create_get_privkey_request(Some(session_id), private_key_id);
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    println!("Firmware is not built with fips_validation_hooks.");
                    return;
                }
            }

            // Extract the response
            let resp = resp.unwrap();

            let raw_private_key_len = resp.data.key_data.len();

            // Convert raw private key data from little-endian to big-endian
            let mut raw_private_key = resp.data.key_data.data()[..raw_private_key_len].to_vec();
            raw_private_key.reverse();

            // Perform signing using the helper function
            let signature = ecc_sign_local(
                raw_private_key,
                CryptoKeyKind::Ecc256Private,
                DIGEST,
                DIGEST_LEN,
            );

            // Validate the signature
            assert!(!signature.is_empty(), "Signature generation failed");

            // Perform signature verification using the public key generated
            assert!(ecc_verify_local_openssl(
                &signature, &pub_key, DIGEST, DIGEST_LEN,
            ));
        },
    );
}

#[test]
fn test_ecc_get_privkey_key_not_found() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let invalid_key_id = 9999;

            let req = create_get_privkey_request(Some(session_id), invalid_key_id);
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    println!("Firmware is not built with fips_validation_hooks.");
                    return;
                }
            }

            // Validate error for key not found.
            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::KeyNotFound)
                ),
                "Expected KeyNotFound error, got {:?}",
                resp
            );
        },
    );
}

#[test]
fn test_ecc_get_privkey_deleted_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (private_key_id, _pub_key) =
                ecc_gen_key_mcr(dev, DdiEccCurve::P256, session_id, DdiKeyUsage::SignVerify);

            //Delete the key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                private_key_id,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let req = create_get_privkey_request(Some(session_id), private_key_id);
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    println!("Firmware is not built with fips_validation_hooks.");
                    return;
                }
            }

            // Validate error for deleted key.
            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::KeyNotFound)
                ),
                "Expected KeyNotFound error, got {:?}",
                resp
            );
        },
    );
}

#[test]
fn test_ecc_get_privkey_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (private_key_id, _pub_key) =
                ecc_gen_key_mcr(dev, DdiEccCurve::P256, session_id, DdiKeyUsage::SignVerify);

            let req = create_get_privkey_request(None, private_key_id);
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    println!("Firmware is not built with fips_validation_hooks.");
                    return;
                }
            }

            // Validate error for no session.
            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
                ),
                "Expected FileHandleSessionIdDoesNotMatch error, got {:?}",
                resp
            );
        },
    );
}

#[test]
fn test_ecc_get_privkey_incorrect_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let (private_key_id, _pub_key) =
                ecc_gen_key_mcr(dev, DdiEccCurve::P256, session_id, DdiKeyUsage::SignVerify);

            let session_id = 20;
            let req = create_get_privkey_request(Some(session_id), private_key_id);
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    println!("Firmware is not built with fips_validation_hooks.");
                    return;
                }
            }

            // Validate error for incorrect session.
            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
                ),
                "Expected FileHandleSessionIdDoesNotMatch error, got {:?}",
                resp
            );
        },
    );
}
