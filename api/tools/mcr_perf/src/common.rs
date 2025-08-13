// Copyright (C) Microsoft Corporation. All rights reserved.

use core::panic;

use crypto::ecc::EccOp;
use crypto::rand::rand_bytes;
use mcr_ddi_sim::crypto::aes::AesOp;
use mcr_ddi_sim::crypto::rsa::*;
use session_parameter_encryption::DeviceCredentialEncryptionKey;

use super::*;

pub(crate) fn helper_print_banner() {
    println!();
    println!("    ███╗   ███╗ ██████╗██████╗     ██████╗ ███████╗██████╗ ███████╗");
    println!("    ████╗ ████║██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔══██╗██╔════╝");
    println!("    ██╔████╔██║██║     ██████╔╝    ██████╔╝█████╗  ██████╔╝█████╗  ");
    println!("    ██║╚██╔╝██║██║     ██╔══██╗    ██╔═══╝ ██╔══╝  ██╔══██╗██╔══╝  ");
    println!("    ██║ ╚═╝ ██║╚██████╗██║  ██║    ██║     ███████╗██║  ██║██║     ");
    println!("    ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝     ");
    println!();
}

pub(crate) fn helper_cleanup(device_path: String) -> DdiResult<()> {
    let ddi = DdiTest::default();
    let mut dev_cleanup = ddi.open_dev(device_path.as_str()).unwrap();
    helper_set_device_kind(&mut dev_cleanup)?;

    let _ =
        helper_common_establish_credential_no_unwrap(&mut dev_cleanup, TEST_CRED_ID, TEST_CRED_PIN);

    let (app_sess_id, _) =
        helper_open_app_session(&dev_cleanup, TEST_CRED_ID, TEST_CRED_PIN).unwrap();

    let keys_to_delete = [
        KEY_TAG_ECC_SIGN_256,
        KEY_TAG_ECC_SIGN_384,
        KEY_TAG_ECC_SIGN_521,
        KEY_TAG_RSA_MOD_EXP_2K,
        KEY_TAG_RSA_MOD_EXP_3K,
        KEY_TAG_RSA_MOD_EXP_4K,
        KEY_TAG_RSA_MOD_EXP_CRT_2K,
        KEY_TAG_RSA_MOD_EXP_CRT_3K,
        KEY_TAG_RSA_MOD_EXP_CRT_4K,
        KEY_TAG_AES_CBC_128,
        KEY_TAG_AES_CBC_192,
        KEY_TAG_AES_CBC_256,
        KEY_TAG_AES_BULK_256,
        KEY_TAG_AES_BULK_256_2,
        KEY_TAG_ECC_DERIVE_256,
        KEY_TAG_ECC_DERIVE_384,
        KEY_TAG_ECC_DERIVE_521,
        KEY_TAG_SECRET_256,
        KEY_TAG_SECRET_384,
        KEY_TAG_SECRET_521,
    ];

    for key_to_delete in keys_to_delete {
        let result = helper_open_key_return_key_id(&dev_cleanup, app_sess_id, key_to_delete);

        if let Ok(key_id) = result {
            helper_delete_key(&dev_cleanup, app_sess_id, key_id)?;
        }
    }

    Ok(())
}

pub(crate) fn helper_setup(device_path: String) -> DdiResult<()> {
    helper_cleanup(device_path.clone())?;

    let ddi = DdiTest::default();
    let mut dev_setup = ddi.open_dev(device_path.as_str()).unwrap();
    helper_set_device_kind(&mut dev_setup)?;

    let info = helper_get_device_info(&dev_setup)?;
    println!(
        "Device type: {:?}, Resource Count: {}, FIPS Approved: {}",
        info.kind, info.tables, info.fips_approved,
    );

    let _ =
        helper_common_establish_credential_no_unwrap(&mut dev_setup, TEST_CRED_ID, TEST_CRED_PIN);

    Ok(())
}

#[allow(dead_code)]
pub fn helper_common_get_establish_cred_encryption_key_no_unwrap(
    dev: &mut <DdiTest as Ddi>::Dev,
) -> Result<DdiGetEstablishCredEncryptionKeyCmdResp, DdiError> {
    let req = DdiGetEstablishCredEncryptionKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetEstablishCredEncryptionKey,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetEstablishCredEncryptionKeyReq {},
        ext: None,
    };

    let mut cookie = None;

    dev.exec_op(&req, &mut cookie)
}

pub fn helper_common_get_establish_cred_encryption_key(
    dev: &mut <DdiTest as Ddi>::Dev,
) -> DdiGetEstablishCredEncryptionKeyCmdResp {
    let resp = helper_common_get_establish_cred_encryption_key_no_unwrap(dev);
    assert!(resp.is_ok(), "resp {:?}", resp);
    resp.unwrap()
}

#[allow(dead_code)]
pub fn helper_common_establish_credential_no_unwrap(
    dev: &mut <DdiTest as Ddi>::Dev,
    id: [u8; 16],
    pin: [u8; 16],
) -> Result<(), DdiError> {
    // Get establish credential encryption key
    let resp = helper_common_get_establish_cred_encryption_key_no_unwrap(dev)?;

    // Establish credential
    let nonce = resp.data.nonce;
    let param_encryption_key =
        DeviceCredentialEncryptionKey::new(&resp.data.pub_key, nonce).unwrap();
    let (establish_cred_encryption_key, ddi_public_key) = param_encryption_key
        .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
        .unwrap();
    let ddi_encrypted_credential = establish_cred_encryption_key
        .encrypt(id, pin, nonce)
        .unwrap();

    let req = DdiEstablishCredentialCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EstablishCredential,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiEstablishCredentialReq {
            encrypted_credential: ddi_encrypted_credential,
            pub_key: ddi_public_key,
        },
        ext: None,
    };
    let mut cookie = None;
    let _ = dev.exec_op(&req, &mut cookie)?;

    Ok(())
}

#[allow(dead_code)]
pub fn helper_common_establish_credential(
    dev: &mut <DdiTest as Ddi>::Dev,
    id: [u8; 16],
    pin: [u8; 16],
) {
    // Get establish credential encryption key
    let resp = helper_common_get_establish_cred_encryption_key(dev);

    // Establish credential
    let nonce = resp.data.nonce;
    let param_encryption_key =
        DeviceCredentialEncryptionKey::new(&resp.data.pub_key, nonce).unwrap();
    let (establish_cred_encryption_key, ddi_public_key) = param_encryption_key
        .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
        .unwrap();
    let ddi_encrypted_credential = establish_cred_encryption_key
        .encrypt(id, pin, nonce)
        .unwrap();

    let req = DdiEstablishCredentialCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EstablishCredential,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiEstablishCredentialReq {
            encrypted_credential: ddi_encrypted_credential,
            pub_key: ddi_public_key,
        },
        ext: None,
    };
    let mut cookie = None;
    let resp = dev.exec_op(&req, &mut cookie);
    assert!(resp.is_ok(), "resp {:?}", resp);
    resp.unwrap();
}

#[allow(unused)]
pub fn encrypt_userid_pin_for_establish_cred(
    dev: &<DdiTest as Ddi>::Dev,
    id: [u8; 16],
    pin: [u8; 16],
) -> (DdiEncryptedCredential, DdiDerPublicKey) {
    let req = DdiGetEstablishCredEncryptionKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetEstablishCredEncryptionKey,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetEstablishCredEncryptionKeyReq {},
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie).unwrap();
    let nonce = resp.data.nonce;
    let param_encryption_key =
        DeviceCredentialEncryptionKey::new(&resp.data.pub_key, nonce).unwrap();
    let (establish_cred_encryption_key, ddi_public_key) = param_encryption_key
        .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
        .unwrap();
    let ddi_encrypted_credential = establish_cred_encryption_key
        .encrypt(id, pin, nonce)
        .unwrap();

    (ddi_encrypted_credential, ddi_public_key)
}

#[allow(unused)]
pub fn encrypt_userid_pin_for_open_session(
    dev: &<DdiTest as Ddi>::Dev,
    id: [u8; 16],
    pin: [u8; 16],
) -> (DdiEncryptedCredential, DdiDerPublicKey) {
    let req = DdiGetSessionEncryptionKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetSessionEncryptionKey,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetSessionEncryptionKeyReq {},
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie).unwrap();
    let nonce = resp.data.nonce;
    let param_encryption_key =
        DeviceCredentialEncryptionKey::new(&resp.data.pub_key, nonce).unwrap();
    let (establish_cred_encryption_key, ddi_public_key) = param_encryption_key
        .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
        .unwrap();
    let ddi_encrypted_credential = establish_cred_encryption_key
        .encrypt(id, pin, nonce)
        .unwrap();

    (ddi_encrypted_credential, ddi_public_key)
}

pub(crate) fn helper_create_keys_for_mix(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    short_app_id: u8,
) -> DdiResult<PerfMixKeys> {
    let key_id_ecc_sign_256 = helper_create_ecc_key(
        dev,
        app_sess_id,
        DdiEccCurve::P256,
        Some(KEY_TAG_ECC_SIGN_256),
        DdiKeyUsage::SignVerify,
    )?;
    let key_id_ecc_sign_384 = helper_create_ecc_key(
        dev,
        app_sess_id,
        DdiEccCurve::P384,
        Some(KEY_TAG_ECC_SIGN_384),
        DdiKeyUsage::SignVerify,
    )?;
    let key_id_ecc_sign_521 = helper_create_ecc_key(
        dev,
        app_sess_id,
        DdiEccCurve::P521,
        Some(KEY_TAG_ECC_SIGN_521),
        DdiKeyUsage::SignVerify,
    )?;

    let key_id_rsa_mod_exp_2k = helper_create_rsa_key(
        dev,
        app_sess_id,
        2048,
        Some(KEY_TAG_RSA_MOD_EXP_2K),
        DdiKeyUsage::SignVerify,
    )?;
    let key_id_rsa_mod_exp_3k = helper_create_rsa_key(
        dev,
        app_sess_id,
        3072,
        Some(KEY_TAG_RSA_MOD_EXP_3K),
        DdiKeyUsage::SignVerify,
    )?;
    let key_id_rsa_mod_exp_4k = helper_create_rsa_key(
        dev,
        app_sess_id,
        4096,
        Some(KEY_TAG_RSA_MOD_EXP_4K),
        DdiKeyUsage::SignVerify,
    )?;

    let key_id_rsa_mod_exp_crt_2k = helper_create_rsa_crt_key(
        dev,
        app_sess_id,
        2048,
        Some(KEY_TAG_RSA_MOD_EXP_CRT_2K),
        DdiKeyUsage::SignVerify,
    )?;
    let key_id_rsa_mod_exp_crt_3k = helper_create_rsa_crt_key(
        dev,
        app_sess_id,
        3072,
        Some(KEY_TAG_RSA_MOD_EXP_CRT_3K),
        DdiKeyUsage::SignVerify,
    )?;
    let key_id_rsa_mod_exp_crt_4k = helper_create_rsa_crt_key(
        dev,
        app_sess_id,
        4096,
        Some(KEY_TAG_RSA_MOD_EXP_CRT_4K),
        DdiKeyUsage::SignVerify,
    )?;

    let (key_id_aes_cbc_128, _) = helper_create_aes_key(
        dev,
        app_sess_id,
        DdiAesKeySize::Aes128,
        Some(KEY_TAG_AES_CBC_128),
    )?;
    let (key_id_aes_cbc_192, _) = helper_create_aes_key(
        dev,
        app_sess_id,
        DdiAesKeySize::Aes192,
        Some(KEY_TAG_AES_CBC_192),
    )?;
    let (key_id_aes_cbc_256, _) = helper_create_aes_key(
        dev,
        app_sess_id,
        DdiAesKeySize::Aes256,
        Some(KEY_TAG_AES_CBC_256),
    )?;
    let (_, key_id_aes_bulk_256_option) = helper_create_aes_key(
        dev,
        app_sess_id,
        DdiAesKeySize::AesBulk256,
        Some(KEY_TAG_AES_BULK_256),
    )?;
    let key_id_aes_bulk_256 = key_id_aes_bulk_256_option.unwrap();
    let (_, key_id_aes_bulk_256_2_option) = helper_create_aes_key(
        dev,
        app_sess_id,
        DdiAesKeySize::AesBulk256,
        Some(KEY_TAG_AES_BULK_256_2),
    )?;
    let key_id_aes_bulk_256_2 = key_id_aes_bulk_256_2_option.unwrap();
    let key_id_ecc_derive_256 = helper_create_ecc_key(
        dev,
        app_sess_id,
        DdiEccCurve::P256,
        Some(KEY_TAG_ECC_DERIVE_256),
        DdiKeyUsage::Derive,
    )?;
    let key_id_ecc_derive_384 = helper_create_ecc_key(
        dev,
        app_sess_id,
        DdiEccCurve::P384,
        Some(KEY_TAG_ECC_DERIVE_384),
        DdiKeyUsage::Derive,
    )?;
    let key_id_ecc_derive_521 = helper_create_ecc_key(
        dev,
        app_sess_id,
        DdiEccCurve::P521,
        Some(KEY_TAG_ECC_DERIVE_521),
        DdiKeyUsage::Derive,
    )?;

    let key_id_secret_256 = helper_create_ecdh_key(
        dev,
        app_sess_id,
        key_id_ecc_derive_256,
        Some(KEY_TAG_SECRET_256),
        TEST_ECC_256_PUBLIC_KEY_DATA,
        TEST_ECC_256_PUBLIC_KEY_LEN,
        DdiKeyType::Secret256,
    )?;
    let key_id_secret_384 = helper_create_ecdh_key(
        dev,
        app_sess_id,
        key_id_ecc_derive_384,
        Some(KEY_TAG_SECRET_384),
        TEST_ECC_384_PUBLIC_KEY_DATA,
        TEST_ECC_384_PUBLIC_KEY_LEN,
        DdiKeyType::Secret384,
    )?;
    let key_id_secret_521 = helper_create_ecdh_key(
        dev,
        app_sess_id,
        key_id_ecc_derive_521,
        Some(KEY_TAG_SECRET_521),
        TEST_ECC_521_PUBLIC_KEY_DATA,
        TEST_ECC_521_PUBLIC_KEY_LEN,
        DdiKeyType::Secret521,
    )?;

    let key_id_wrapping_key = helper_get_unwrapping_key(dev, app_sess_id).unwrap().0;

    let (encrypted_data_gcm_4k_vec, tag_gcm_4k) = helper_aes_gcm_encrypt_decrypt(
        dev,
        app_sess_id,
        short_app_id,
        key_id_aes_bulk_256,
        DdiAesOp::Encrypt,
        vec![100u8; 1024 * 4],
        [0x3; 12],
        Some([0x4; 32].to_vec()),
        None,
    )?;
    let mut encrypted_data_gcm_4k = [0u8; 1024 * 4];
    encrypted_data_gcm_4k.copy_from_slice(&encrypted_data_gcm_4k_vec);

    let (encrypted_data_gcm_16m_vec, tag_gcm_16m) = helper_aes_gcm_encrypt_decrypt(
        dev,
        app_sess_id,
        short_app_id,
        key_id_aes_bulk_256,
        DdiAesOp::Encrypt,
        vec![100u8; 1024 * 1024 * 16 - 32], // - 32 because we have AAD of 32
        [0x3; 12],
        Some([0x4; 32].to_vec()),
        None,
    )?;
    let encrypted_data_gcm_16m: Box<[u8]> = encrypted_data_gcm_16m_vec.into_boxed_slice();

    let wrapped_blob_ecc_sign_256 =
        local_helper_generate_wrapped_data_blob(dev, app_sess_id, DdiKeyType::Ecc256Private);
    let wrapped_blob_ecc_sign_384 =
        local_helper_generate_wrapped_data_blob(dev, app_sess_id, DdiKeyType::Ecc384Private);
    let wrapped_blob_ecc_sign_521 =
        local_helper_generate_wrapped_data_blob(dev, app_sess_id, DdiKeyType::Ecc521Private);
    let wrapped_blob_rsa_2k =
        local_helper_generate_wrapped_data_blob(dev, app_sess_id, DdiKeyType::Rsa2kPrivate);
    let wrapped_blob_rsa_3k =
        local_helper_generate_wrapped_data_blob(dev, app_sess_id, DdiKeyType::Rsa3kPrivate);
    let wrapped_blob_rsa_4k =
        local_helper_generate_wrapped_data_blob(dev, app_sess_id, DdiKeyType::Rsa4kPrivate);
    let wrapped_blob_rsa_crt_2k =
        local_helper_generate_wrapped_data_blob(dev, app_sess_id, DdiKeyType::Rsa2kPrivateCrt);
    let wrapped_blob_rsa_crt_3k =
        local_helper_generate_wrapped_data_blob(dev, app_sess_id, DdiKeyType::Rsa3kPrivateCrt);
    let wrapped_blob_rsa_crt_4k =
        local_helper_generate_wrapped_data_blob(dev, app_sess_id, DdiKeyType::Rsa4kPrivateCrt);
    let wrapped_blob_aes_cbc_128 =
        local_helper_generate_wrapped_data_blob(dev, app_sess_id, DdiKeyType::Aes128);
    let wrapped_blob_aes_cbc_192 =
        local_helper_generate_wrapped_data_blob(dev, app_sess_id, DdiKeyType::Aes192);
    let wrapped_blob_aes_cbc_256 =
        local_helper_generate_wrapped_data_blob(dev, app_sess_id, DdiKeyType::Aes256);
    let wrapped_blob_secret_256 =
        local_helper_generate_wrapped_data_blob(dev, app_sess_id, DdiKeyType::Secret256);
    let wrapped_blob_secret_384 =
        local_helper_generate_wrapped_data_blob(dev, app_sess_id, DdiKeyType::Secret384);
    let wrapped_blob_secret_521 =
        local_helper_generate_wrapped_data_blob(dev, app_sess_id, DdiKeyType::Secret521);

    Ok(PerfMixKeys {
        key_id_ecc_sign_256,
        key_id_ecc_sign_384,
        key_id_ecc_sign_521,
        key_id_rsa_mod_exp_2k,
        key_id_rsa_mod_exp_3k,
        key_id_rsa_mod_exp_4k,
        key_id_rsa_mod_exp_crt_2k,
        key_id_rsa_mod_exp_crt_3k,
        key_id_rsa_mod_exp_crt_4k,
        key_id_aes_cbc_128,
        key_id_aes_cbc_192,
        key_id_aes_cbc_256,
        key_id_ecc_derive_256,
        key_id_ecc_derive_384,
        key_id_ecc_derive_521,
        key_id_secret_256,
        key_id_secret_384,
        key_id_secret_521,
        key_id_wrapping_key,
        encrypted_data_gcm_4k: Some(encrypted_data_gcm_4k),
        tag_gcm_4k,
        encrypted_data_gcm_16m: Some(encrypted_data_gcm_16m),
        tag_gcm_16m,
        key_id_aes_bulk_256,
        key_id_aes_bulk_256_2,
        wrapped_blob_ecc_sign_256,
        wrapped_blob_ecc_sign_384,
        wrapped_blob_ecc_sign_521,
        wrapped_blob_rsa_2k,
        wrapped_blob_rsa_3k,
        wrapped_blob_rsa_4k,
        wrapped_blob_rsa_crt_2k,
        wrapped_blob_rsa_crt_3k,
        wrapped_blob_rsa_crt_4k,
        wrapped_blob_aes_cbc_128,
        wrapped_blob_aes_cbc_192,
        wrapped_blob_aes_cbc_256,
        wrapped_blob_secret_256,
        wrapped_blob_secret_384,
        wrapped_blob_secret_521,
    })
}

pub(crate) fn local_generate_aes(key_type: DdiKeyType) -> Vec<u8> {
    let buf_len = match key_type {
        DdiKeyType::Aes128 => 16,
        DdiKeyType::Aes192 => 24,
        DdiKeyType::Aes256 => 32,
        DdiKeyType::AesBulk256 => 32,
        _ => 32,
    };

    let mut buf = [0u8; 32];
    let buf_slice = &mut buf[..buf_len];
    let _ = rand_bytes(buf_slice);
    buf_slice.to_vec()
}

pub(crate) fn local_generate_rsa_der(key_type: DdiKeyType) -> Vec<u8> {
    // Rsa::generate() uses 65537 as public exponent

    let size = match key_type {
        DdiKeyType::Rsa2kPrivate => 2048,
        DdiKeyType::Rsa3kPrivate => 3072,
        DdiKeyType::Rsa4kPrivate => 4096,
        DdiKeyType::Rsa2kPrivateCrt => 2048,
        DdiKeyType::Rsa3kPrivateCrt => 3072,
        DdiKeyType::Rsa4kPrivateCrt => 4096,
        _ => 0,
    };

    let (rsa_private, _) = generate_rsa(size).expect("Failed to generate RSA key");
    rsa_private
        .to_der()
        .expect("Failed to convert RSA private key to DER")
}

pub(crate) fn local_generate_ecc_der(key_type: DdiKeyType) -> Vec<u8> {
    let curve_name = match key_type {
        DdiKeyType::Ecc256Private | DdiKeyType::Secret256 => crypto::ecc::CryptoEccCurve::P256,
        DdiKeyType::Ecc384Private | DdiKeyType::Secret384 => crypto::ecc::CryptoEccCurve::P384,
        DdiKeyType::Ecc521Private | DdiKeyType::Secret521 => crypto::ecc::CryptoEccCurve::P521,
        _ => panic!("Unsupported ECC key type: {:?}", key_type),
    };

    let (ecc_private, _) =
        crypto::ecc::generate_ecc(curve_name).expect("Failed to generate ECC key");

    ecc_private
        .to_der()
        .expect("Failed to convert ECC private key to DER")
}

pub(crate) fn local_wrap_data(wrapping_pub_key_der: Vec<u8>, data: &[u8]) -> Vec<u8> {
    let ace_binding = local_generate_aes(DdiKeyType::Aes256);
    let aes_key = ace_binding.as_slice();

    // Do RSA Encrypt of the aes_key with the wrapping public key
    let wrapping_pub_key = RsaPublicKey::from_der(&wrapping_pub_key_der, None).unwrap();
    let mut encrypted_aes_key = wrapping_pub_key
        .encrypt(aes_key, RsaCryptoPadding::Oaep, None)
        .unwrap();

    let aes_key =
        mcr_ddi_sim::crypto::aes::AesKey::from_bytes(aes_key).expect("Failed to create AES key");

    let mut encrypted_data = aes_key
        .wrap_pad(data)
        .expect("Failed to wrap data")
        .cipher_text;

    // Concatenate the encrypted_aes_key and encrypted_data to form the wrapped blob
    let mut wrapped_data = Vec::with_capacity(encrypted_aes_key.len() + encrypted_data.len());
    wrapped_data.append(&mut encrypted_aes_key);
    wrapped_data.append(&mut encrypted_data);

    wrapped_data
}

pub(crate) fn local_helper_generate_wrapped_data_blob(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_type: DdiKeyType,
) -> DataBlob {
    // Get  wrapping key der
    let wrapping_key_der = helper_get_unwrapping_key(dev, app_sess_id).unwrap().1;

    let pri_key = match key_type {
        DdiKeyType::Rsa2kPrivate | DdiKeyType::Rsa3kPrivate | DdiKeyType::Rsa4kPrivate => {
            local_generate_rsa_der(key_type)
        }

        DdiKeyType::Rsa2kPrivateCrt | DdiKeyType::Rsa3kPrivateCrt | DdiKeyType::Rsa4kPrivateCrt => {
            local_generate_rsa_der(key_type)
        }

        DdiKeyType::Aes128 | DdiKeyType::Aes192 | DdiKeyType::Aes256 => {
            local_generate_aes(key_type)
        }

        DdiKeyType::AesBulk256 => local_generate_aes(key_type),

        DdiKeyType::Ecc384Private
        | DdiKeyType::Ecc256Private
        | DdiKeyType::Ecc521Private
        | DdiKeyType::Secret256
        | DdiKeyType::Secret384
        | DdiKeyType::Secret521 => local_generate_ecc_der(key_type),
        _ => vec![],
    };

    let wrapped_data = local_wrap_data(wrapping_key_der, &pri_key);
    let mut wrapped_blob_arr: [u8; 3072] = [0u8; 3072];
    wrapped_blob_arr[..wrapped_data.len()].copy_from_slice(&wrapped_data);

    DataBlob {
        data: wrapped_blob_arr,
        len: wrapped_data.len(),
    }
}

pub fn helper_key_properties_with_label(
    key_usage: DdiKeyUsage,
    key_availability: DdiKeyAvailability,
    key_label: MborByteArray<DDI_MAX_KEY_LABEL_LENGTH>,
) -> DdiKeyProperties {
    DdiKeyProperties {
        key_usage,
        key_availability,
        key_label,
    }
}

pub fn helper_key_properties(
    key_usage: DdiKeyUsage,
    key_availability: DdiKeyAvailability,
) -> DdiKeyProperties {
    helper_key_properties_with_label(
        key_usage,
        key_availability,
        MborByteArray::from_slice(&[]).expect("Failed to create empty byte array for key label"),
    )
}
