// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Self-contained harness for the DDI test-hook integration tests.
//!
//! This mirrors the per-crate harness used by
//! `~/Martichoras/api/ddi/test_hooks/tests/common`: the low-level request
//! helpers are reused from `azihsm_ddi_mbor_test_helpers`, while device
//! provisioning and session orchestration are owned here so the test-hook
//! suite stays independent of the standard DDI suite.
//!
//! An OS-backed lock serializes separate integration-test processes on each
//! VM across setup, the test body, and cleanup. Separate VMs have independent
//! lock files and can continue running in parallel.

#![allow(dead_code)]

use std::fs;
use std::panic::AssertUnwindSafe;

use azihsm_cred_encrypt::DeviceCredKey;
use azihsm_crypto::*;
use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
pub use azihsm_ddi_mbor_test_helpers::*;
use azihsm_ddi_mbor_types::*;
use fs2::FileExt;
use x509::X509CertificateOp;
use x509::*;

// 70FCF730-B876-4238-B835-8010CE8A3F76
pub const TEST_CRED_ID: [u8; 16] = [
    0x70, 0xFC, 0xF7, 0x30, 0xB8, 0x76, 0x42, 0x38, 0xB8, 0x35, 0x80, 0x10, 0xCE, 0x8A, 0x3F, 0x76,
];

// DB3DC77F-C22E-4300-80D4-1B31B6F04800
pub const TEST_CRED_PIN: [u8; 16] = [
    0xDB, 0x3D, 0xC7, 0x7F, 0xC2, 0x2E, 0x43, 0x00, 0x80, 0xD4, 0x1B, 0x31, 0xB6, 0xF0, 0x48, 0x00,
];

pub const TEST_SESSION_SEED: [u8; 48] = [
    0xe5, 0x1b, 0x8b, 0x4b, 0xa7, 0x94, 0xc7, 0xc8, 0xa2, 0x32, 0x84, 0xec, 0xad, 0x2b, 0x6a, 0xc,
    0x37, 0xe8, 0x6a, 0x63, 0x6a, 0x9f, 0x43, 0x20, 0x95, 0xe1, 0x24, 0xd0, 0x85, 0x12, 0xe2, 0x12,
    0x95, 0x14, 0xaa, 0x0f, 0x6b, 0x05, 0x40, 0x71, 0xbf, 0x63, 0xa5, 0x87, 0xa6, 0x25, 0x70, 0x81,
];

pub const TEST_ECC_384_PRIVATE_KEY: [u8; 185] = [
    0x30, 0x81, 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b, 0x02, 0x01,
    0x01, 0x04, 0x30, 0xce, 0xbc, 0xbb, 0x90, 0x3d, 0x9a, 0x1d, 0x46, 0xd9, 0x59, 0x15, 0x16, 0xf9,
    0x7d, 0xbe, 0x6f, 0xf6, 0x44, 0xa3, 0x2d, 0xa4, 0x7b, 0x73, 0xfb, 0x6e, 0xad, 0xa5, 0x09, 0x9a,
    0x83, 0x2a, 0x67, 0x07, 0xd2, 0x25, 0xd3, 0x8e, 0x67, 0x52, 0xcd, 0x09, 0x90, 0xa8, 0x31, 0x06,
    0x66, 0xc0, 0xe4, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0xe4, 0x20, 0x9a, 0xd7, 0x07, 0xa4, 0x88,
    0x1a, 0xff, 0xf0, 0x12, 0x61, 0x92, 0xc7, 0x9d, 0x83, 0x77, 0x49, 0x21, 0xcc, 0x5d, 0xf3, 0xb9,
    0x21, 0xc4, 0x3d, 0xae, 0xaa, 0x58, 0xb8, 0x34, 0x2b, 0x38, 0x3c, 0xda, 0xb2, 0x88, 0xf0, 0xe4,
    0xb9, 0x56, 0x14, 0x11, 0x15, 0x75, 0xba, 0xbb, 0x23, 0x7c, 0x67, 0xf7, 0xd1, 0x97, 0x63, 0xc7,
    0xb8, 0x56, 0xd3, 0x22, 0xb2, 0xba, 0xba, 0x1a, 0xc6, 0xb4, 0xea, 0x0d, 0xad, 0xa2, 0x56, 0x29,
    0xd5, 0xca, 0x0f, 0x4a, 0x4e, 0xee, 0x17, 0xb0, 0xb2, 0xf4, 0xb1, 0x58, 0xba, 0xae, 0xa1, 0x58,
    0x9c, 0x10, 0x07, 0xf7, 0x0e, 0xc7, 0x62, 0x42, 0xe0,
];

pub const TEST_POTA_ECC_PRIVATE_KEY: [u8; 185] = [
    0x30, 0x81, 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b, 0x02, 0x01,
    0x01, 0x04, 0x30, 0x17, 0xe9, 0x1c, 0xac, 0xf7, 0xb7, 0x21, 0xd7, 0x75, 0x20, 0x02, 0x07, 0xbc,
    0xaa, 0x94, 0x2c, 0xe3, 0xb5, 0x5b, 0x78, 0x13, 0xcc, 0x8b, 0xde, 0x87, 0x65, 0x6b, 0xe1, 0x7b,
    0xc2, 0xa8, 0xcc, 0x89, 0x33, 0x4e, 0xcd, 0xaa, 0x9d, 0x1d, 0x09, 0xf1, 0xc7, 0x01, 0x1b, 0x64,
    0xeb, 0x78, 0x5b, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0x1f, 0x42, 0x0d, 0x73, 0xeb, 0xf0, 0x67,
    0xc2, 0xf9, 0x77, 0xbd, 0x51, 0xab, 0xfb, 0xe1, 0xf6, 0x53, 0x19, 0xb7, 0x57, 0xe0, 0xa9, 0x20,
    0xce, 0x4f, 0x21, 0xbb, 0xd4, 0xa7, 0x84, 0x1c, 0x93, 0x45, 0xf1, 0xea, 0xd9, 0x5f, 0xe5, 0x90,
    0xab, 0x57, 0xe1, 0xea, 0xfc, 0xd2, 0x06, 0xef, 0x21, 0xa2, 0xad, 0x10, 0xd3, 0x17, 0x6e, 0x99,
    0xc8, 0x22, 0x26, 0x23, 0x08, 0x57, 0xa7, 0x56, 0x08, 0x45, 0xe3, 0xda, 0x12, 0xc7, 0xdc, 0x3a,
    0xee, 0x01, 0xfc, 0x37, 0xab, 0x1c, 0x8d, 0xc6, 0xd0, 0x64, 0x7a, 0x7d, 0xc2, 0x67, 0xfc, 0x02,
    0x7d, 0x8d, 0xa3, 0xc8, 0x01, 0x4b, 0xa4, 0x0d, 0x98,
];

pub const TEST_POTA_ECC_PUB_KEY: [u8; 120] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x1f, 0x42, 0x0d, 0x73, 0xeb, 0xf0, 0x67, 0xc2,
    0xf9, 0x77, 0xbd, 0x51, 0xab, 0xfb, 0xe1, 0xf6, 0x53, 0x19, 0xb7, 0x57, 0xe0, 0xa9, 0x20, 0xce,
    0x4f, 0x21, 0xbb, 0xd4, 0xa7, 0x84, 0x1c, 0x93, 0x45, 0xf1, 0xea, 0xd9, 0x5f, 0xe5, 0x90, 0xab,
    0x57, 0xe1, 0xea, 0xfc, 0xd2, 0x06, 0xef, 0x21, 0xa2, 0xad, 0x10, 0xd3, 0x17, 0x6e, 0x99, 0xc8,
    0x22, 0x26, 0x23, 0x08, 0x57, 0xa7, 0x56, 0x08, 0x45, 0xe3, 0xda, 0x12, 0xc7, 0xdc, 0x3a, 0xee,
    0x01, 0xfc, 0x37, 0xab, 0x1c, 0x8d, 0xc6, 0xd0, 0x64, 0x7a, 0x7d, 0xc2, 0x67, 0xfc, 0x02, 0x7d,
    0x8d, 0xa3, 0xc8, 0x01, 0x4b, 0xa4, 0x0d, 0x98,
];

pub type DdiTest = AzihsmDdi;

/// Cross-process lock held for one complete hardware-test lifecycle.
struct HardwareTestLock {
    file: fs::File,
}

impl HardwareTestLock {
    fn acquire() -> Self {
        let path = std::env::temp_dir().join("azihsm-ddi-mbor-test-hooks.lock");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .expect("open DDI test-hook lock file");
        file.lock_exclusive()
            .expect("acquire DDI test-hook device lock");
        Self { file }
    }
}

impl Drop for HardwareTestLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

/// Run `test` against every discovered device, wrapping it in the shared
/// setup/cleanup lifecycle. Panics if no device is present.
pub fn ddi_dev_test(
    setup: fn(&mut <DdiTest as Ddi>::Dev, &DdiTest, &str) -> u16,
    cleanup: fn(&mut <DdiTest as Ddi>::Dev, &DdiTest, &str, Option<u16>),
    test: fn(&mut <DdiTest as Ddi>::Dev, &DdiTest, &str, u16),
) {
    let _hardware_test_lock = HardwareTestLock::acquire();
    let ddi = DdiTest::default();
    let dev_infos = ddi.dev_info_list();

    if dev_infos.is_empty() {
        panic!("No devices found");
    }

    for dev_info in dev_infos.iter() {
        let mut dev = ddi.open_dev(&dev_info.path).unwrap();

        let setup_session_id = setup(&mut dev, &ddi, &dev_info.path);
        let test_result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            test(&mut dev, &ddi, &dev_info.path, setup_session_id);
        }));
        cleanup(&mut dev, &ddi, &dev_info.path, Some(setup_session_id));
        if let Err(payload) = test_result {
            std::panic::resume_unwind(payload);
        }
    }
}

/// Erase the device, establish a fresh credential, and open a session.
/// Returns the opened session id.
pub fn common_setup(dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str) -> u16 {
    common_cleanup(dev, ddi, path, None);

    let mut setup_dev = ddi.open_dev(path).unwrap();

    helper_common_establish_credential_no_unwrap(&mut setup_dev, TEST_CRED_ID, TEST_CRED_PIN)
        .expect("establish test credential");

    let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
        &setup_dev,
        TEST_CRED_ID,
        TEST_CRED_PIN,
        TEST_SESSION_SEED,
    );

    let resp = helper_open_session(
        dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        encrypted_credential,
        pub_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();
    assert!(resp.hdr.sess_id.is_some());
    resp.hdr.sess_id.unwrap()
}

/// Close the session (if any) and erase the device.
pub fn common_cleanup(
    dev: &mut <DdiTest as Ddi>::Dev,
    ddi: &DdiTest,
    path: &str,
    session_to_close: Option<u16>,
) {
    if let Some(session_id) = session_to_close {
        let _resp = helper_close_session(
            dev,
            Some(session_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
        );
    }

    let cleanup_dev = ddi.open_dev(path).unwrap();
    let resp = cleanup_dev.erase();
    assert!(resp.is_ok(), "resp {:?}", resp);
}

/// Sign the device's attestation public key with the test POTA key to
/// produce the POTA endorsement `(signature, pota_pub_key)` pair.
pub fn helper_get_pota_endorsement(dev: &<DdiTest as Ddi>::Dev) -> (Vec<u8>, Vec<u8>) {
    let get_cert_chain_info = helper_get_cert_chain_info(dev).unwrap();
    let cert_resp = helper_get_certificate(dev, get_cert_chain_info.data.num_certs - 1).unwrap();
    let cert = cert_resp.data.certificate.as_slice();
    let cert = X509Certificate::from_der(cert).unwrap();
    let cert_pub_key_der = cert.get_public_key_der().unwrap();
    let cert_pub_key_obj = DerEccPublicKey::from_der(&cert_pub_key_der).unwrap();
    let mut cert_pub_uncomp = vec![0x04u8];
    cert_pub_uncomp.extend_from_slice(cert_pub_key_obj.x());
    cert_pub_uncomp.extend_from_slice(cert_pub_key_obj.y());
    let hash_algo = HashAlgo::sha384();
    let mut ecdsa_algo = EcdsaAlgo::new(hash_algo);
    let pota_priv_key = EccPrivateKey::from_bytes(&TEST_POTA_ECC_PRIVATE_KEY).unwrap();
    let sig_len = Signer::sign(&mut ecdsa_algo, &pota_priv_key, &cert_pub_uncomp, None).unwrap();
    let mut signature = vec![0u8; sig_len];
    let _ = Signer::sign(
        &mut ecdsa_algo,
        &pota_priv_key,
        &cert_pub_uncomp,
        Some(&mut signature),
    )
    .unwrap();

    (signature, TEST_POTA_ECC_PUB_KEY.to_vec())
}

/// Establish a credential without unwrapping-key material, using the test
/// ECC key and POTA endorsement.
pub fn helper_common_establish_credential_no_unwrap(
    dev: &mut <DdiTest as Ddi>::Dev,
    id: [u8; 16],
    pin: [u8; 16],
) -> Result<(), DdiError> {
    let resp = helper_get_establish_cred_encryption_key(
        dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
    )?;

    let nonce = resp.data.nonce;
    let param_encryption_key = DeviceCredKey::new(&resp.data.pub_key, nonce).unwrap();
    let (establish_cred_encryption_key, ddi_public_key) = param_encryption_key
        .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
        .unwrap();
    let ddi_encrypted_credential = establish_cred_encryption_key
        .encrypt_establish_credential(id, pin, nonce)
        .unwrap();

    let masked_bk3 = helper_get_or_init_bk3(dev);
    let (signature, pota_pub_key) = helper_get_pota_endorsement(dev);

    let _ = helper_establish_credential(
        dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        ddi_encrypted_credential,
        ddi_public_key,
        masked_bk3,
        MborByteArray::from_slice(&[]).expect("Failed to create empty BMK"),
        MborByteArray::from_slice(&[]).expect("Failed to create empty masked unwrapping key"),
        MborByteArray::from_slice(&signature).expect("Failed to create signed PID"),
        DdiDerPublicKey {
            der: MborByteArray::from_slice(&pota_pub_key)
                .expect("Failed to create MborByteArray from POTA ECC public key"),
            key_kind: DdiKeyType::Ecc384Public,
        },
    )?;

    Ok(())
}

/// Encrypt the user id + pin under a fresh session encryption key so a
/// session can be opened.
pub fn encrypt_userid_pin_for_open_session(
    dev: &<DdiTest as Ddi>::Dev,
    id: [u8; 16],
    pin: [u8; 16],
    seed: [u8; 48],
) -> (DdiEncryptedSessionCredential, DdiDerPublicKey) {
    let resp = helper_get_session_encryption_key(dev, None, Some(DdiApiRev { major: 1, minor: 0 }))
        .unwrap();
    let nonce = resp.data.nonce;
    let param_encryption_key = DeviceCredKey::new(&resp.data.pub_key, nonce).unwrap();
    let (establish_cred_encryption_key, ddi_public_key) = param_encryption_key
        .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
        .unwrap();
    let ddi_encrypted_credential = establish_cred_encryption_key
        .encrypt_session_credential(id, pin, seed, nonce)
        .unwrap();

    (ddi_encrypted_credential, ddi_public_key)
}

/// Query the device kind (Virtual vs Physical). The FIPS-validation
/// hooks only run on physical hardware.
pub fn get_device_kind(dev: &mut <DdiTest as Ddi>::Dev) -> DdiDeviceKind {
    let resp = helper_get_device_info(dev, None, Some(DdiApiRev { major: 1, minor: 0 })).unwrap();
    resp.data.kind
}

/// True when the error is `UnsupportedCmd` — i.e. the firmware was not
/// built with `fips_validation_hooks`, so the test should skip.
pub fn is_unsupported_cmd(err: &DdiError) -> bool {
    if let DdiError::DdiStatus(DdiStatus::UnsupportedCmd) = err {
        println!("Firmware is not built with fips_validation_hooks.");
        true
    } else {
        false
    }
}
