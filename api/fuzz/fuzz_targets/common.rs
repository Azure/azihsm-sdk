// Copyright (C) Microsoft Corporation. All rights reserved.

use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::arbitrary::Unstructured;
use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_sim::crypto::rand::rand_bytes;
use mcr_ddi_types::*;
use rand::prelude::*;
use session_parameter_encryption::DeviceCredentialEncryptionKey;

#[allow(dead_code)]
// 70FCF730-B876-4238-B835-8010CE8A3F76
pub(crate) const TEST_CRED_ID: [u8; 16] = [
    0x70, 0xFC, 0xF7, 0x30, 0xB8, 0x76, 0x42, 0x38, 0xB8, 0x35, 0x80, 0x10, 0xCE, 0x8A, 0x3F, 0x76,
];

#[allow(dead_code)]
// DB3DC77F-C22E-4300-80D4-1B31B6F04800
pub(crate) const TEST_CRED_PIN: [u8; 16] = [
    0xDB, 0x3D, 0xC7, 0x7F, 0xC2, 0x2E, 0x43, 0x00, 0x80, 0xD4, 0x1B, 0x31, 0xB6, 0xF0, 0x48, 0x00,
];

#[allow(dead_code)]
pub(crate) const TEST_ECC_384_PRIVATE_KEY: [u8; 185] = [
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

cfg_if::cfg_if! {
    if #[cfg(feature = "mock")] {
        pub type DdiTest = mcr_ddi_mock::DdiMock;
    } else if #[cfg(target_os = "linux")] {
        pub type DdiTest = mcr_ddi_nix::DdiNix;
    }
    else if #[cfg(target_os = "windows")] {
        pub type DdiTest = mcr_ddi_win::DdiWin;
    }
}

#[allow(unused)]
pub fn set_device_kind(dev: &mut <DdiTest as Ddi>::Dev) {
    // Set Device Kind
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
    let resp = dev.exec_op(&req, &mut cookie);

    assert!(resp.is_ok(), "resp {:?}", resp);
    dev.set_device_kind(resp.unwrap().data.kind);
}

#[allow(dead_code)]
pub fn helper_init_bk3(
    dev: &<DdiTest as Ddi>::Dev,
    bk3: Vec<u8>,
) -> Result<DdiInitBk3CmdResp, DdiError> {
    let req = DdiInitBk3CmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::InitBk3,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiInitBk3Req {
            bk3: MborByteArray::from_slice(&bk3).expect("failed to create byte array"),
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
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
        .encrypt_establish_credential(id, pin, nonce)
        .unwrap();

    let mut bk3 = vec![0u8; 48];
    rand_bytes(&mut bk3).unwrap();
    let masked_bk3 = helper_init_bk3(dev, bk3).unwrap().data.masked_bk3;

    let req = DdiEstablishCredentialCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EstablishCredential,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiEstablishCredentialReq {
            encrypted_credential: ddi_encrypted_credential,
            pub_key: ddi_public_key,
            masked_bk3,
            bmk: MborByteArray::from_slice(&[]).expect("Failed to create empty BMK"),
            masked_unwrapping_key: MborByteArray::from_slice(&[])
                .expect("Failed to create empty masked unwrapping key"),
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
        .encrypt_establish_credential(id, pin, nonce)
        .unwrap();

    let mut bk3 = vec![0u8; 48];
    rand_bytes(&mut bk3).unwrap();
    let masked_bk3 = helper_init_bk3(dev, bk3).unwrap().data.masked_bk3;

    let req = DdiEstablishCredentialCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EstablishCredential,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiEstablishCredentialReq {
            encrypted_credential: ddi_encrypted_credential,
            pub_key: ddi_public_key,
            masked_bk3,
            bmk: MborByteArray::from_slice(&[]).expect("Failed to create empty BMK"),
            masked_unwrapping_key: MborByteArray::from_slice(&[])
                .expect("Failed to create empty masked unwrapping key"),
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
) -> (DdiEncryptedEstablishCredential, DdiDerPublicKey) {
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
        .encrypt_establish_credential(id, pin, nonce)
        .unwrap();

    (ddi_encrypted_credential, ddi_public_key)
}

#[allow(unused)]
pub fn encrypt_userid_pin_for_open_session(
    dev: &<DdiTest as Ddi>::Dev,
    id: [u8; 16],
    pin: [u8; 16],
) -> (DdiEncryptedSessionCredential, DdiDerPublicKey) {
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
    let seed = [2; 48];
    let ddi_encrypted_credential = establish_cred_encryption_key
        .encrypt_session_credential(id, pin, seed, nonce)
        .unwrap();

    (ddi_encrypted_credential, ddi_public_key)
}

#[allow(dead_code)]
pub fn cleanup(ddi: &DdiTest, path: &str, _credentials: Option<([u8; 16], [u8; 16])>) {
    let mut cleanup_dev = ddi.open_dev(path).unwrap();
    set_device_kind(&mut cleanup_dev);
    // If a credential has been provided then we use it, otherwise use default
    let _ =
        helper_common_establish_credential_no_unwrap(&mut cleanup_dev, TEST_CRED_ID, TEST_CRED_PIN);

    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_open_session(&cleanup_dev, TEST_CRED_ID, TEST_CRED_PIN);

    let req = DdiOpenSessionCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::OpenSession,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiOpenSessionReq {
            encrypted_credential,
            pub_key,
        },
        ext: None,
    };
    let mut cookie = None;
    let resp = cleanup_dev.exec_op(&req, &mut cookie);

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();

    let sess_id = resp.data.sess_id;

    cleanup_with_session(&cleanup_dev, sess_id);
}

pub fn cleanup_with_session(cleanup_dev: &<DdiTest as Ddi>::Dev, session_id: u16) {
    let req = DdiResetFunctionCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::ResetFunction,
            sess_id: Some(session_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiResetFunctionReq {},
        ext: None,
    };
    let mut cookie = None;
    let resp = cleanup_dev.exec_op(&req, &mut cookie);

    assert!(resp.is_ok(), "resp {:?}", resp);
}

#[derive(Arbitrary, Debug)]
pub enum TestAppOps {
    OpenSession([u8; 16], [u8; 16]),
    CloseSession(u16),
}

#[derive(Arbitrary, Debug)]
pub enum TestDdiReqs {
    GetApiRev,
    GetDeviceInfo,
    OpenSession,
    CloseSession,
    DeleteKey,
    OpenKey,
    AttestKey,
    GetCertChainInfo,
    GetCertificate,
    RsaModExp,
    RsaUnwrap,
    GetUnwrappingKey,
    EccGenerateKeyPair,
    EccSign,
    AesGenerateKey,
    AesEncryptDecrypt,
    EcdhKeyExchange,
    HkdfDerive,
    KbkdfCounterHmacDerive,
    ChangePin,
    DerKeyImport,
    EstablishCredential,
    GetEstablishCredEncryptionKey,
    GetPerfLogChunk,
    GetPrivKey,
    GetRngGenerate,
    GetSessionEncryptionKey,
    Hmac,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum TestDdiReqData {
    GetApiRev,
    GetDeviceInfo,
    OpenSession,
    CloseSession,
    DeleteKey,
    OpenKey,
    AttestKey,
    GetCertChainInfo,
    GetCertificate,
    RsaModExp,
    RsaUnwrap,
    GetUnwrappingKey,
    EccGenerateKeyPair,
    EccSign,
    AesGenerateKey,
    AesEncryptDecrypt,
    EcdhKeyExchange,
    HkdfDerive,
    KbkdfCounterHmacDerive,
}

impl From<u32> for TestDdiReqData {
    fn from(value: u32) -> Self {
        // convert the integer to an in-range index, to allow us to
        // deterministically-randomly select one of the enum values
        let number_of_options: u32 = 18;
        let idx: u32 = value % number_of_options;

        // match the index and return
        match idx {
            0 => TestDdiReqData::GetApiRev,
            1 => TestDdiReqData::GetDeviceInfo,
            2 => TestDdiReqData::OpenSession,
            3 => TestDdiReqData::CloseSession,
            4 => TestDdiReqData::DeleteKey,
            5 => TestDdiReqData::OpenKey,
            6 => TestDdiReqData::AttestKey,
            7 => TestDdiReqData::GetCertChainInfo,
            8 => TestDdiReqData::GetCertificate,
            9 => TestDdiReqData::RsaModExp,
            10 => TestDdiReqData::RsaUnwrap,
            11 => TestDdiReqData::GetUnwrappingKey,
            12 => TestDdiReqData::EccGenerateKeyPair,
            13 => TestDdiReqData::EccSign,
            14 => TestDdiReqData::AesGenerateKey,
            15 => TestDdiReqData::AesEncryptDecrypt,
            16 => TestDdiReqData::EcdhKeyExchange,
            17 => TestDdiReqData::HkdfDerive,
            18 => TestDdiReqData::KbkdfCounterHmacDerive,
            _ => panic!("Invalid value for TestDdiReqData enum"),
        }
    }
}

/// A helper macro used in the below function to assist with generating a
/// randomly-chosen and randomly-filled DDI request object.
macro_rules! get_rand_ddi_request_helper {
    ($type:ident, $rng:expr, $hdr:expr) => {{
        // create a buffer that matches the size of the object and fill it
        // up with bytes from the RNG
        let buf_size = std::mem::size_of::<$type>();
        let mut buf = vec![0u8; buf_size];
        $rng.fill_bytes(buf.as_mut_slice());

        // derive the object via `Arbitrary`. If we received an error while
        // attempting to convert the object from arbitrary bytes into a struct,
        // return early
        let mut unstructured = Unstructured::new(buf.as_slice());
        let arbitrary_result = unstructured.arbitrary();
        if arbitrary_result.is_err() {
            return Err(String::from(
                "Failed to convert arbitrary data to DDI request object.",
            ));
        }
        let obj: $type = arbitrary_result.unwrap();

        // encode the object, and the header and store it in a buffer
        let mut result = vec![0u8; 1024];
        let encode_result = DdiEncoder::encode_parts($hdr, obj, result.as_mut_slice(), true);

        // if encoding succeeded, cut the result buffer down to size and
        // return an `Ok`
        if let Ok(result_len) = encode_result {
            result.truncate(result_len);
            return Ok(result);
        }

        // otherwise, return the encoding error
        Err(String::from(
            "Failed to encode random DDI request object and header.",
        ))
    }};
}

/// Helper function that accepts a `DdiReqHdr` and pairs it with a
/// randomly-selected and randomly-filled DDI request data structure. They are
/// encoded together using `DdiEncoder::encode_parts()`, and the resulting bytes
/// are returned in a vector.
///
/// The `seed` parameter is used to generate a random DDI request data structure
/// deterministically.
#[allow(dead_code)]
pub fn get_rand_ddi_request(hdr: DdiReqHdr, seed: u64) -> Result<Vec<u8>, String> {
    // initialize a RNG using the provided seed
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    // use the RNG to decide which kind of DDI request data to initialize
    let data_type = TestDdiReqData::from(rng.next_u32());
    match data_type {
        TestDdiReqData::GetApiRev => get_rand_ddi_request_helper!(DdiGetApiRevReq, rng, hdr),
        TestDdiReqData::GetDeviceInfo => {
            get_rand_ddi_request_helper!(DdiGetDeviceInfoReq, rng, hdr)
        }
        TestDdiReqData::OpenSession => get_rand_ddi_request_helper!(DdiOpenSessionReq, rng, hdr),
        TestDdiReqData::CloseSession => get_rand_ddi_request_helper!(DdiCloseSessionReq, rng, hdr),
        TestDdiReqData::DeleteKey => get_rand_ddi_request_helper!(DdiDeleteKeyReq, rng, hdr),
        TestDdiReqData::OpenKey => get_rand_ddi_request_helper!(DdiOpenKeyReq, rng, hdr),
        TestDdiReqData::AttestKey => get_rand_ddi_request_helper!(DdiAttestKeyReq, rng, hdr),
        TestDdiReqData::GetCertChainInfo => {
            get_rand_ddi_request_helper!(DdiGetCertChainInfoReq, rng, hdr)
        }
        TestDdiReqData::GetCertificate => {
            get_rand_ddi_request_helper!(DdiGetCertificateReq, rng, hdr)
        }
        TestDdiReqData::RsaModExp => get_rand_ddi_request_helper!(DdiRsaModExpReq, rng, hdr),
        TestDdiReqData::RsaUnwrap => get_rand_ddi_request_helper!(DdiRsaUnwrapReq, rng, hdr),
        TestDdiReqData::GetUnwrappingKey => {
            get_rand_ddi_request_helper!(DdiGetUnwrappingKeyReq, rng, hdr)
        }
        TestDdiReqData::EccGenerateKeyPair => {
            get_rand_ddi_request_helper!(DdiEccGenerateKeyPairReq, rng, hdr)
        }
        TestDdiReqData::EccSign => get_rand_ddi_request_helper!(DdiEccSignReq, rng, hdr),
        TestDdiReqData::AesGenerateKey => {
            get_rand_ddi_request_helper!(DdiAesGenerateKeyReq, rng, hdr)
        }
        TestDdiReqData::AesEncryptDecrypt => {
            get_rand_ddi_request_helper!(DdiAesEncryptDecryptReq, rng, hdr)
        }
        TestDdiReqData::EcdhKeyExchange => {
            get_rand_ddi_request_helper!(DdiEcdhKeyExchangeReq, rng, hdr)
        }
        TestDdiReqData::HkdfDerive => get_rand_ddi_request_helper!(DdiHkdfDeriveReq, rng, hdr),
        TestDdiReqData::KbkdfCounterHmacDerive => {
            get_rand_ddi_request_helper!(DdiKbkdfCounterHmacDeriveReq, rng, hdr)
        }
    }
}

// After establish credentials,
// we attempt to execute an arbitrary number of random app ops with random parameters
#[allow(dead_code)]
pub fn fuzz_app_ops(ops: Vec<TestAppOps>) {
    let ddi = DdiTest::default();
    let dev_infos = ddi.dev_info_list();
    if dev_infos.is_empty() {
        panic!("No devices found");
    }
    let mut dev = ddi.open_dev(&dev_infos[0].path).unwrap();
    set_device_kind(&mut dev);

    cleanup(&ddi, &dev_infos[0].path, None);

    let mut file_handles: Vec<Option<<DdiTest as Ddi>::Dev>> = Vec::new();

    helper_common_establish_credential(&mut dev, TEST_CRED_ID, TEST_CRED_PIN);

    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_open_session(&dev, TEST_CRED_ID, TEST_CRED_PIN);

    let req = DdiOpenSessionCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::OpenSession,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiOpenSessionReq {
            encrypted_credential,
            pub_key,
        },
        ext: None,
    };
    let mut cookie = None;
    let resp = dev.exec_op(&req, &mut cookie);
    let sess_id = resp.unwrap().hdr.sess_id.unwrap();

    for op in ops {
        match op {
            TestAppOps::OpenSession(id, pin) => {
                let mut file_handle = ddi.open_dev(&dev_infos[0].path).unwrap();
                set_device_kind(&mut file_handle);

                let (encrypted_credential, pub_key) =
                    encrypt_userid_pin_for_open_session(&file_handle, id, pin);

                let req = DdiOpenSessionCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::OpenSession,
                        sess_id: None,
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiOpenSessionReq {
                        encrypted_credential,
                        pub_key,
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);

                assert!(resp.is_err(), "resp {:?}", resp);

                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::FileHandleSessionLimitReached)
                ));
                let mut cookie = None;
                let _resp = file_handle.exec_op(&req, &mut cookie);
                file_handles.push(Some(file_handle));
            }
            TestAppOps::CloseSession(sess_id) => {
                if let Some(file_handle) = file_handles.pop() {
                    let file_handle = file_handle.unwrap();
                    let req = DdiCloseSessionCmdReq {
                        hdr: DdiReqHdr {
                            op: DdiOp::CloseSession,
                            sess_id: Some(sess_id),
                            rev: Some(DdiApiRev { major: 1, minor: 0 }),
                        },
                        data: DdiCloseSessionReq {},
                        ext: None,
                    };
                    let mut cookie = None;
                    let _resp = file_handle.exec_op(&req, &mut cookie);
                }
            }
        }
    }
    cleanup_with_session(&dev, sess_id);
}

/// A helper macro used in the below function to assist with generating a
/// randomized DDI command request.
macro_rules! get_rand_ddi_request_cmd {
    ($type:ident, $rng:expr) => {{
        // create a buffer that matches the size of the object and fill it
        // up with bytes from the RNG
        let buf_size = std::mem::size_of::<$type>();
        let mut buf = vec![0u8; buf_size];
        $rng.fill_bytes(buf.as_mut_slice());

        // derive the object via `Arbitrary`; if the byte fail to parse into a
        // valid object (i.e.  `arbitrary()` fails), return `None` using the
        // `.ok()` method to convert from a `Result` to an `Option`
        let mut unstructured = Unstructured::new(buf.as_slice());
        let result: Option<$type> = unstructured.arbitrary().ok();
        result
    }};
}

// After opening  session with credential and encrypted pins, we attempt to
// execute an arbitrary number of ops of random types with random params
#[allow(dead_code)]
pub fn fuzz_cmd_reqs(reqs: Vec<TestDdiReqs>, rand_seed: u64) {
    let ddi = DdiTest::default();
    let dev_infos = ddi.dev_info_list();
    if dev_infos.is_empty() {
        panic!("No devices found");
    }
    let mut dev = ddi.open_dev(&dev_infos[0].path).unwrap();
    set_device_kind(&mut dev);
    cleanup(&ddi, &dev_infos[0].path, None);

    helper_common_establish_credential(&mut dev, TEST_CRED_ID, TEST_CRED_PIN);

    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_open_session(&dev, TEST_CRED_ID, TEST_CRED_PIN);

    let req = DdiOpenSessionCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::OpenSession,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiOpenSessionReq {
            encrypted_credential,
            pub_key,
        },
        ext: None,
    };
    let mut cookie = None;
    let resp = dev.exec_op(&req, &mut cookie);
    let sess_id = resp.unwrap().hdr.sess_id.unwrap();

    // create a RNG object to assist with generating command requests filled
    // with random bytes
    let mut rng = rand::rngs::StdRng::seed_from_u64(rand_seed);

    // For each of the request enum types in the provided list, use the
    // `get_rand_ddi_request_cmd!()` macro to generate the corresponding DDI
    // command request object. (This macro uses the `Arbitrary` trait to derive
    // the command request struct from a randomized buffer, which results in a
    // command request object with all fields initialized to random bytes.)
    //
    // It's possible that `get_rand_ddi_request_cmd!()` will return `None` if
    // the bytes generated by the RNG could not be parsed via `arbitrary()`.
    // Because of this, we must check for `Some()` in each match code block
    // below.
    for req_enum in reqs {
        let mut cookie = None;
        match req_enum {
            TestDdiReqs::GetApiRev => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiGetApiRevCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::GetDeviceInfo => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiGetDeviceInfoCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::OpenSession => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiOpenSessionCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::CloseSession => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiCloseSessionCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::DeleteKey => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiDeleteKeyCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::OpenKey => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiOpenKeyCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::AttestKey => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiAttestKeyCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::GetCertChainInfo => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiGetCertChainInfoCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::GetCertificate => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiGetCertificateCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::RsaModExp => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiRsaModExpCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::RsaUnwrap => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiRsaUnwrapCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::GetUnwrappingKey => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiGetUnwrappingKeyCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::EccGenerateKeyPair => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiEccGenerateKeyPairCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::EccSign => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiEccSignCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::AesGenerateKey => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiAesGenerateKeyCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::AesEncryptDecrypt => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiAesEncryptDecryptCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::EcdhKeyExchange => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiEcdhKeyExchangeCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::HkdfDerive => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiHkdfDeriveCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::KbkdfCounterHmacDerive => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiKbkdfCounterHmacDeriveCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::ChangePin => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiChangePinCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::DerKeyImport => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiDerKeyImportCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::EstablishCredential => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiEstablishCredentialCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::GetEstablishCredEncryptionKey => {
                let cmdreq_result =
                    get_rand_ddi_request_cmd!(DdiGetEstablishCredEncryptionKeyCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::GetPerfLogChunk => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiGetPerfLogChunkCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::GetPrivKey => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiGetPrivKeyCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::GetRngGenerate => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiGetRngGenerateCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::GetSessionEncryptionKey => {
                let cmdreq_result =
                    get_rand_ddi_request_cmd!(DdiGetSessionEncryptionKeyCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
            TestDdiReqs::Hmac => {
                let cmdreq_result = get_rand_ddi_request_cmd!(DdiHmacCmdReq, rng);
                if let Some(cmdreq) = cmdreq_result {
                    let _ = dev.exec_op(&cmdreq, &mut cookie);
                }
            }
        };
    }
    cleanup_with_session(&dev, sess_id);
}
