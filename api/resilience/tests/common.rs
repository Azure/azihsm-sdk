// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(dead_code)]

use mcr_api_resilient::*;
use mcr_ddi::Ddi;
use mcr_ddi::DdiDev;
use mcr_ddi_types::*;
use uuid::Uuid;

cfg_if::cfg_if! {
    if #[cfg(feature = "mock")] {
        #[allow(dead_code)]
        pub type DdiTest = mcr_ddi_mock::DdiMock;
    } else if #[cfg(target_os = "linux")] {
        #[allow(dead_code)]
        pub type DdiTest = mcr_ddi_nix::DdiNix;
    }
    else if #[cfg(target_os = "windows")] {
        #[allow(dead_code)]
        pub type DdiTest = mcr_ddi_win::DdiWin;
    }
}

// 70FCF730-B876-4238-B835-8010CE8A3F76
pub(crate) const TEST_CRED_ID: [u8; 16] = [
    0x70, 0xFC, 0xF7, 0x30, 0xB8, 0x76, 0x42, 0x38, 0xB8, 0x35, 0x80, 0x10, 0xCE, 0x8A, 0x3F, 0x76,
];

// DB3DC77F-C22E-4300-80D4-1B31B6F04800
pub(crate) const TEST_CRED_PIN: [u8; 16] = [
    0xDB, 0x3D, 0xC7, 0x7F, 0xC2, 0x2E, 0x43, 0x00, 0x80, 0xD4, 0x1B, 0x31, 0xB6, 0xF0, 0x48, 0x00,
];

pub const TEST_CREDENTIALS: HsmAppCredentials = HsmAppCredentials {
    id: Uuid::from_bytes(TEST_CRED_ID),
    pin: TEST_CRED_PIN,
};

/// Helper function to set device kind by querying device info
#[allow(dead_code)]
fn set_device_kind(device: &mut <DdiTest as Ddi>::Dev) -> Result<(), Box<dyn std::error::Error>> {
    let req = DdiGetDeviceInfoCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetDeviceInfo,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetDeviceInfoReq {},
        ext: None,
    };
    let mut cookie = None;
    let resp_info = device.exec_op(&req, &mut cookie)?;
    device.set_device_kind(resp_info.data.kind);
    Ok(())
}

pub fn get_device_path_helper() -> String {
    let devices = HsmDevice::get_devices();

    // Return the device info for the first device
    let dev_info = &devices[0];
    dev_info.path.clone()
}

#[allow(dead_code)]
pub fn simulate_live_migration_helper(path: &str) {
    let ddi = DdiTest::default();

    let mut lm_dev = ddi.open_dev(path).unwrap();
    set_device_kind(&mut lm_dev).unwrap();

    lm_dev.simulate_nssr_after_lm().unwrap();
}

/// Helper function to set up a device
pub fn setup_device(device_path: &str) -> (HsmDevice, HsmApiRevision) {
    let device = HsmDevice::open(device_path).expect("Failed to open HSM device");
    let api_rev = device.get_api_revision_range().max;

    (device, api_rev)
}

/// Helper function to set up a device and open a session
pub fn setup_device_and_session(device_path: &str) -> (HsmDevice, HsmSession, HsmApiRevision) {
    let (device, api_rev) = setup_device(device_path);
    let session = device
        .open_session(api_rev, TEST_CREDENTIALS)
        .expect("Failed to open session");
    (device, session, api_rev)
}

pub(crate) const SESSION_KEY_PROPERTIES: KeyProperties = KeyProperties {
    key_usage: KeyUsage::EncryptDecrypt,
    key_availability: KeyAvailability::Session,
};

/// Helper function to generate an AES session key
pub fn generate_session_aes_key(session: &HsmSession, error_context: &str) -> HsmKeyHandle {
    let result = session.aes_generate(AesKeySize::Aes256, None, SESSION_KEY_PROPERTIES);

    match result {
        Ok(key_handle) => key_handle,
        Err(e) => panic!("{}: {:?}", error_context, e),
    }
}

/// Helper function to generate AES key bytes of the specified type
pub fn generate_aes_bytes(key_type: KeyType) -> Vec<u8> {
    use crypto::rand::rand_bytes;

    let buf_len = match key_type {
        KeyType::Aes128 => 16,
        KeyType::Aes192 => 24,
        KeyType::Aes256 => 32,
        KeyType::AesXtsBulk256 | KeyType::AesGcmBulk256 | KeyType::AesGcmBulk256Unapproved => 32,
        _ => 32,
    };

    let mut buf = [0u8; 32];
    let buf_slice = &mut buf[..buf_len];
    rand_bytes(buf_slice).expect("Failed to generate random bytes");
    buf_slice.to_vec()
}

/// Helper function to wrap data using RSA-OAEP + AES-KW
pub fn wrap_data(wrapping_pub_key_der: Vec<u8>, data: &[u8]) -> Vec<u8> {
    use mcr_ddi_sim::crypto::aes::AesKey;
    use mcr_ddi_sim::crypto::aes::AesOp;
    use mcr_ddi_sim::crypto::rsa::RsaCryptoPadding;
    use mcr_ddi_sim::crypto::rsa::RsaOp;
    use mcr_ddi_sim::crypto::rsa::RsaPublicKey;
    use mcr_ddi_sim::crypto::rsa::RsaPublicOp;
    use mcr_ddi_sim::crypto::sha::HashAlgorithm;

    // Generate a random AES-256 key
    let aes_key_bytes = generate_aes_bytes(KeyType::Aes256);

    // Encrypt the AES key with RSA-OAEP
    let wrapping_pub_key = RsaPublicKey::from_der(&wrapping_pub_key_der, None).unwrap();
    let encrypted_aes_key = wrapping_pub_key
        .encrypt(
            &aes_key_bytes,
            RsaCryptoPadding::Oaep,
            Some(HashAlgorithm::Sha256),
        )
        .unwrap();

    // Encrypt the data with AES
    let aes_key = AesKey::from_bytes(&aes_key_bytes).expect("Failed to create AES key");
    let encrypted_data = aes_key
        .wrap_pad(data)
        .expect("Failed to wrap data")
        .cipher_text;

    // Concatenate encrypted AES key and encrypted data
    let mut wrapped_data = Vec::with_capacity(encrypted_aes_key.len() + encrypted_data.len());
    wrapped_data.extend_from_slice(&encrypted_aes_key);
    wrapped_data.extend_from_slice(&encrypted_data);

    wrapped_data
}

/// Helper function to generate wrapped data (wrapped private RSA key and its public key)
pub fn generate_wrapped_data(wrapping_key_der: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    use mcr_ddi_sim::crypto::rsa::generate_rsa;
    use mcr_ddi_sim::crypto::rsa::RsaOp;

    // Generate a new 3072-bit RSA key pair
    let (rsa_priv, rsa_pub) = generate_rsa(3072).expect("Failed to generate RSA key");
    let target_der = rsa_priv.to_der().unwrap();
    let public_key_der = rsa_pub.to_der().unwrap();

    // Wrap the private key using the wrapping key
    let wrapped_key = wrap_data(wrapping_key_der, &target_der);

    (wrapped_key, public_key_der)
}
