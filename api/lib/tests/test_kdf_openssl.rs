// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

fn test_ecdh_hkdf_aes_decrypt_encrypt(
    app_session: HsmSession,
    curve: EccCurve,
    digest_kind: DigestKind,
    aes_type: KeyType,
) {
    // Generate ecc key pair on device
    let result = app_session.ecc_generate(
        curve,
        None,
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok());
    let priv_key_handle1 = result.unwrap();

    // Get the DER from key handle
    let result = app_session.export_public_key(&priv_key_handle1);
    assert!(result.is_ok());
    let pub_key_der1 = result.unwrap();

    // Generate ecc key pair locally
    let (ecc_key_type, secret_key_type) = match curve {
        EccCurve::P256 => (KeyType::Ecc256Private, KeyType::Secret256),
        EccCurve::P384 => (KeyType::Ecc384Private, KeyType::Secret384),
        EccCurve::P521 => (KeyType::Ecc521Private, KeyType::Secret521),
    };
    let (priv_key_der2, pub_key_der2) = generate_ecc_der(ecc_key_type);

    // Key exchange on device
    let result = app_session.ecdh_key_exchange(
        &priv_key_handle1,
        &pub_key_der2,
        None,
        secret_key_type,
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok());
    let secret1 = result.unwrap();

    // Key exchange locally
    let secret2 = ecdh_derive(&priv_key_der2, &pub_key_der1);

    // HKDF on device
    let salt_vec = generate_random_vector(256);
    let info_vec = generate_random_vector(256);

    let params = HkdfDeriveParameters {
        hash_algorithm: digest_kind,
        salt: Some(&salt_vec),
        info: Some(&info_vec),
    };

    let result = app_session.hkdf_derive(
        &secret1,
        params,
        None,
        aes_type,
        KeyProperties {
            key_usage: KeyUsage::EncryptDecrypt,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok());
    let aes_key1 = result.unwrap();

    // HKDF locally
    let aes_size = match aes_type {
        KeyType::Aes128 => 16,
        KeyType::Aes192 => 24,
        KeyType::Aes256 => 32,
        _ => panic!(),
    };
    let aes_key2 = hkdf_derive(
        &secret2,
        Some(&salt_vec),
        Some(&info_vec),
        digest_kind,
        aes_size,
    );

    // Assert the AES keys are the same via encrypt/decrypt
    let data = generate_random_vector(128);

    let iv_vec = generate_random_vector(16);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&iv_vec);

    // Encrypt on the device
    let result = app_session.aes_encrypt_decrypt(&aes_key1, AesMode::Encrypt, data.clone(), iv);
    assert!(result.is_ok());
    let encrypted_data1 = result.unwrap().data;

    // Decrypt locally
    let decrypted_data1 = aes_decrypt_cbc(&aes_key2, &encrypted_data1, Some(&iv));
    assert_eq!(decrypted_data1, data);

    // Encrypt locally
    let encrypted_data2 = aes_encrypt_cbc(&aes_key2, &data, Some(&iv));

    // Encrypt on the device
    let result =
        app_session.aes_encrypt_decrypt(&aes_key1, AesMode::Decrypt, encrypted_data2.clone(), iv);
    assert!(result.is_ok());
    let decrypted_data2 = result.unwrap().data;
    assert_eq!(decrypted_data2, data);

    assert_eq!(encrypted_data1, encrypted_data2);
}

// fn test_ecdh_kbkdf_aes_decrypt_encrypt(
//     app_session: HsmSession,
//     curve: EccCurve,
//     digest_kind: DigestKind,
//     aes_type: KeyType,
// ) {
//     // Generate ecc key pair on device
//     let result = app_session.ecc_generate(
//         curve,
//         None,
//         KeyProperties {
//             key_usage: KeyUsage::Derive,
//             key_availability: KeyAvailability::Session,
//         },
//     );
//     assert!(result.is_ok());
//     let priv_key_handle1 = result.unwrap();

//     // Get the DER from key handle
//     let result = app_session.export_public_key(&priv_key_handle1);
//     assert!(result.is_ok());
//     let pub_key_der1 = result.unwrap();

//     // Generate ecc key pair locally
//     let (ecc_key_type, secret_key_type) = match curve {
//         EccCurve::P256 => (KeyType::Ecc256Private, KeyType::Secret256),
//         EccCurve::P384 => (KeyType::Ecc384Private, KeyType::Secret384),
//         EccCurve::P521 => (KeyType::Ecc521Private, KeyType::Secret521),
//     };
//     let (priv_key_der2, pub_key_der2) = generate_ecc_der(ecc_key_type);

//     // Key exchange on device
//     let result = app_session.ecdh_key_exchange(
//         &priv_key_handle1,
//         &pub_key_der2,
//         None,
//         secret_key_type,
//         KeyProperties {
//             key_usage: KeyUsage::Derive,
//             key_availability: KeyAvailability::Session,
//         },
//     );
//     assert!(result.is_ok());
//     let secret1 = result.unwrap();

//     // Key exchange locally
//     let secret2 = ecdh_derive(&priv_key_der2, &pub_key_der1);

//     // KBKDF on device
//     let label_vec = generate_random_vector(256);
//     let context_vec = generate_random_vector(256);

//     let params = KbkdfDeriveParameters {
//         hash_algorithm: digest_kind,
//         label: Some(&label_vec),
//         context: Some(&context_vec),
//     };

//     let result = app_session.kbkdf_counter_hmac_derive(
//         &secret1,
//         params,
//         None,
//         aes_type,
//         KeyProperties {
//             key_usage: KeyUsage::EncryptDecrypt,
//             key_availability: KeyAvailability::Session,
//         },
//     );
//     assert!(result.is_ok());
//     let aes_key1 = result.unwrap();

//     // KBKDF locally
//     let aes_size = match aes_type {
//         KeyType::Aes128 => 16,
//         KeyType::Aes192 => 24,
//         KeyType::Aes256 => 32,
//         _ => panic!(),
//     };
//     let aes_key2 = kbkdf_counter_hmac_derive(
//         &secret2,
//         Some(&label_vec),
//         Some(&context_vec),
//         digest_kind,
//         aes_size,
//     );

//     // Assert the AES keys are the same via encrypt/decrypt
//     let data = generate_random_vector(128);

//     let iv_vec = generate_random_vector(16);
//     let mut iv = [0u8; 16];
//     iv.copy_from_slice(&iv_vec);

//     // Encrypt on the device
//     let result = app_session.aes_encrypt_decrypt(&aes_key1, AesMode::Encrypt, data.clone(), iv);
//     assert!(result.is_ok());
//     let encrypted_data1 = result.unwrap().data;

//     // Decrypt locally
//     let decrypted_data1 = aes_decrypt_cbc(&aes_key2, &encrypted_data1, Some(&iv));
//     assert_eq!(decrypted_data1, data);

//     // Encrypt locally
//     let encrypted_data2 = aes_encrypt_cbc(&aes_key2, &data, Some(&iv));

//     // Encrypt on the device
//     let result =
//         app_session.aes_encrypt_decrypt(&aes_key1, AesMode::Decrypt, encrypted_data2.clone(), iv);
//     assert!(result.is_ok());
//     let decrypted_data2 = result.unwrap().data;
//     assert_eq!(decrypted_data2, data);

//     assert_eq!(encrypted_data1, encrypted_data2);
// }

#[test]
fn test_ecdh256_hkdf_sha256_aes256_decrypt_encrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        test_ecdh_hkdf_aes_decrypt_encrypt(
            app_session,
            EccCurve::P256,
            DigestKind::Sha256,
            KeyType::Aes256,
        );
    });
}

#[test]
fn test_ecdh521_hkdf_sha256_aes256_decrypt_encrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        test_ecdh_hkdf_aes_decrypt_encrypt(
            app_session,
            EccCurve::P521,
            DigestKind::Sha256,
            KeyType::Aes256,
        );
    });
}

#[test]
fn test_ecdh256_hkdf_sha1_aes256_decrypt_encrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        test_ecdh_hkdf_aes_decrypt_encrypt(
            app_session,
            EccCurve::P256,
            DigestKind::Sha1,
            KeyType::Aes256,
        );
    });
}

#[test]
fn test_ecdh256_hkdf_sha384_aes256_decrypt_encrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        test_ecdh_hkdf_aes_decrypt_encrypt(
            app_session,
            EccCurve::P256,
            DigestKind::Sha384,
            KeyType::Aes256,
        );
    });
}

#[test]
fn test_ecdh256_hkdf_sha256_aes128_decrypt_encrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        test_ecdh_hkdf_aes_decrypt_encrypt(
            app_session,
            EccCurve::P256,
            DigestKind::Sha256,
            KeyType::Aes128,
        );
    });
}

// #[test]
// #[ignore = "comment until the kbkdf_counter_hmac_derive is corrected"]
// fn test_ecdh256_kbkdf_sha256_aes256_decrypt_encrypt() {
//     api_test(common_setup, common_cleanup, |device, _path| {
//         let app_session = common_open_app_session(device);

//         test_ecdh_kbkdf_aes_decrypt_encrypt(
//             app_session,
//             EccCurve::P256,
//             DigestKind::Sha256,
//             KeyType::Aes256,
//         );
//     });
// }

// #[test]
// #[ignore = "comment until the kbkdf_counter_hmac_derive is corrected"]
// fn test_ecdh384_kbkdf_sha256_aes256_decrypt_encrypt() {
//     api_test(common_setup, common_cleanup, |device, _path| {
//         let app_session = common_open_app_session(device);

//         test_ecdh_kbkdf_aes_decrypt_encrypt(
//             app_session,
//             EccCurve::P384,
//             DigestKind::Sha256,
//             KeyType::Aes256,
//         );
//     });
// }

// #[test]
// #[ignore = "comment until the kbkdf_counter_hmac_derive is corrected"]
// fn test_ecdh256_kbkdf_sha512_aes256_decrypt_encrypt() {
//     api_test(common_setup, common_cleanup, |device, _path| {
//         let app_session = common_open_app_session(device);

//         test_ecdh_kbkdf_aes_decrypt_encrypt(
//             app_session,
//             EccCurve::P256,
//             DigestKind::Sha512,
//             KeyType::Aes256,
//         );
//     });
// }

// #[test]
// #[ignore = "comment until the kbkdf_counter_hmac_derive is corrected"]
// fn test_ecdh256_kbkdf_sha256_aes192_decrypt_encrypt() {
//     api_test(common_setup, common_cleanup, |device, _path| {
//         let app_session = common_open_app_session(device);

//         test_ecdh_kbkdf_aes_decrypt_encrypt(
//             app_session,
//             EccCurve::P256,
//             DigestKind::Sha256,
//             KeyType::Aes192,
//         );
//     });
// }

fn test_ecdh_hkdf_hmac_tag(
    app_session: HsmSession,
    curve: EccCurve,
    digest_kind: DigestKind,
    hmac_type: KeyType,
) {
    // Generate ecc key pair on device
    let result = app_session.ecc_generate(
        curve,
        None,
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok());
    let priv_key_handle1 = result.unwrap();

    // Get the DER from key handle
    let result = app_session.export_public_key(&priv_key_handle1);
    assert!(result.is_ok());
    let pub_key_der1 = result.unwrap();

    // Generate ecc key pair locally
    let (ecc_key_type, secret_key_type) = match curve {
        EccCurve::P256 => (KeyType::Ecc256Private, KeyType::Secret256),
        EccCurve::P384 => (KeyType::Ecc384Private, KeyType::Secret384),
        EccCurve::P521 => (KeyType::Ecc521Private, KeyType::Secret521),
    };
    let (priv_key_der2, pub_key_der2) = generate_ecc_der(ecc_key_type);

    // Key exchange on device
    let result = app_session.ecdh_key_exchange(
        &priv_key_handle1,
        &pub_key_der2,
        None,
        secret_key_type,
        KeyProperties {
            key_usage: KeyUsage::Derive,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok());
    let secret1 = result.unwrap();

    // Key exchange locally
    let secret2 = ecdh_derive(&priv_key_der2, &pub_key_der1);

    // HKDF on device
    let salt_vec = generate_random_vector(256);
    let info_vec = generate_random_vector(256);

    let params = HkdfDeriveParameters {
        hash_algorithm: digest_kind,
        salt: Some(&salt_vec),
        info: Some(&info_vec),
    };

    let result = app_session.hkdf_derive(
        &secret1,
        params,
        None,
        hmac_type,
        KeyProperties {
            key_usage: KeyUsage::SignVerify,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok());
    let hmac_key1 = result.unwrap();

    // HKDF locally
    let hmac_size = match hmac_type {
        KeyType::HmacSha256 => 32,
        KeyType::HmacSha384 => 48,
        KeyType::HmacSha512 => 64,
        _ => panic!(),
    };
    let hmac_key2 = hkdf_derive(
        &secret2,
        Some(&salt_vec),
        Some(&info_vec),
        digest_kind,
        hmac_size,
    );

    // Assert the HMAC keys are same by comparing tags
    let data = generate_random_vector(128);

    // Generate tag on device
    let result = app_session.hmac(hmac_key1, data.clone());
    assert!(result.is_ok(), "{:?}", result);
    let hmac_tag1 = result.unwrap();

    // Generate tag locally
    let hmac_tag2 = hmac(&hmac_key2, &data);

    assert_eq!(hmac_tag1, hmac_tag2);
}

// fn test_ecdh_kbkdf_hmac_tag(
//     app_session: HsmSession,
//     curve: EccCurve,
//     digest_kind: DigestKind,
//     hmac_type: KeyType,
// ) {
//     // Generate ecc key pair on device
//     let result = app_session.ecc_generate(
//         curve,
//         None,
//         KeyProperties {
//             key_usage: KeyUsage::Derive,
//             key_availability: KeyAvailability::Session,
//         },
//     );
//     assert!(result.is_ok());
//     let priv_key_handle1 = result.unwrap();

//     // Get the DER from key handle
//     let result = app_session.export_public_key(&priv_key_handle1);
//     assert!(result.is_ok());
//     let pub_key_der1 = result.unwrap();

//     // Generate ecc key pair locally
//     let (ecc_key_type, secret_key_type) = match curve {
//         EccCurve::P256 => (KeyType::Ecc256Private, KeyType::Secret256),
//         EccCurve::P384 => (KeyType::Ecc384Private, KeyType::Secret384),
//         EccCurve::P521 => (KeyType::Ecc521Private, KeyType::Secret521),
//     };
//     let (priv_key_der2, pub_key_der2) = generate_ecc_der(ecc_key_type);

//     // Key exchange on device
//     let result = app_session.ecdh_key_exchange(
//         &priv_key_handle1,
//         &pub_key_der2,
//         None,
//         secret_key_type,
//         KeyProperties {
//             key_usage: KeyUsage::Derive,
//             key_availability: KeyAvailability::Session,
//         },
//     );
//     assert!(result.is_ok());
//     let secret1 = result.unwrap();

//     // Key exchange locally
//     let secret2 = ecdh_derive(&priv_key_der2, &pub_key_der1);

//     // KBKDF on device
//     let label_vec = generate_random_vector(256);
//     let context_vec = generate_random_vector(256);

//     let params = KbkdfDeriveParameters {
//         hash_algorithm: digest_kind,
//         label: Some(&label_vec),
//         context: Some(&context_vec),
//     };

//     let result = app_session.kbkdf_counter_hmac_derive(
//         &secret1,
//         params,
//         None,
//         hmac_type,
//         KeyProperties {
//             key_usage: KeyUsage::SignVerify,
//             key_availability: KeyAvailability::Session,
//         },
//     );
//     assert!(result.is_ok());
//     let hmac_key1 = result.unwrap();

//     // KBKDF locally
//     let hmac_size = match hmac_type {
//         KeyType::HmacSha256 => 32,
//         KeyType::HmacSha384 => 48,
//         KeyType::HmacSha512 => 64,
//         _ => panic!(),
//     };
//     let hmac_key2 = kbkdf_counter_hmac_derive(
//         &secret2,
//         Some(&label_vec),
//         Some(&context_vec),
//         digest_kind,
//         hmac_size,
//     );

//     // Assert the HMAC keys are same by comparing tags
//     let data = generate_random_vector(128);

//     // Generate tag on device
//     let result = app_session.hmac(hmac_key1, data.clone());
//     assert!(result.is_ok(), "{:?}", result);
//     let hmac_tag1 = result.unwrap();

//     // Generate tag locally
//     let hmac_tag2 = hmac(&hmac_key2, &data);

//     assert_eq!(hmac_tag1, hmac_tag2);
// }

#[test]
fn test_ecdh256_hkdf_sha256_hmac256_tag() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        test_ecdh_hkdf_hmac_tag(
            app_session,
            EccCurve::P256,
            DigestKind::Sha256,
            KeyType::HmacSha256,
        );
    });
}

#[test]
fn test_ecdh256_hkdf_sha256_hmac384_tag() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        test_ecdh_hkdf_hmac_tag(
            app_session,
            EccCurve::P256,
            DigestKind::Sha256,
            KeyType::HmacSha384,
        );
    });
}

#[test]
fn test_ecdh384_hkdf_sha512_hmac512_tag() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        test_ecdh_hkdf_hmac_tag(
            app_session,
            EccCurve::P384,
            DigestKind::Sha512,
            KeyType::HmacSha512,
        );
    });
}

#[test]
fn test_ecdh521_hkdf_sha384_hmac256_tag() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        test_ecdh_hkdf_hmac_tag(
            app_session,
            EccCurve::P521,
            DigestKind::Sha384,
            KeyType::HmacSha256,
        );
    });
}

// #[test]
// fn test_ecdh256_kbkdf_sha256_hmac256_tag() {
//     api_test(common_setup, common_cleanup, |device, _path| {
//         let app_session = common_open_app_session(device);

//         test_ecdh_kbkdf_hmac_tag(
//             app_session,
//             EccCurve::P256,
//             DigestKind::Sha256,
//             KeyType::HmacSha256,
//         );
//     });
// }

// #[test]
// fn test_ecdh256_kbkdf_sha256_hmac384_tag() {
//     api_test(common_setup, common_cleanup, |device, _path| {
//         let app_session = common_open_app_session(device);

//         test_ecdh_kbkdf_hmac_tag(
//             app_session,
//             EccCurve::P256,
//             DigestKind::Sha256,
//             KeyType::HmacSha384,
//         );
//     });
// }

// #[test]
// fn test_ecdh521_kbkdf_sha384_hmac512_tag() {
//     api_test(common_setup, common_cleanup, |device, _path| {
//         let app_session = common_open_app_session(device);

//         test_ecdh_kbkdf_hmac_tag(
//             app_session,
//             EccCurve::P521,
//             DigestKind::Sha384,
//             KeyType::HmacSha512,
//         );
//     });
// }

// #[test]
// fn test_ecdh384_kbkdf_sha512_hmac256_tag() {
//     api_test(common_setup, common_cleanup, |device, _path| {
//         let app_session = common_open_app_session(device);

//         test_ecdh_kbkdf_hmac_tag(
//             app_session,
//             EccCurve::P384,
//             DigestKind::Sha512,
//             KeyType::HmacSha256,
//         );
//     });
// }
