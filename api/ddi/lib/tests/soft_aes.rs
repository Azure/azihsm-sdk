// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_mbor::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

fn exec_soft_aes_op(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    kek_len: usize,
    kek: &[u8],
    msg_len: usize,
    msg: &[u8],
    req_op: DdiSoftAesOp,
) -> DdiResult<DdiSoftAesCmdResp> {
    const MAX_KEY_LEN: usize = 32;
    const MAX_MSG_LEN: usize = 1024;

    let req = DdiSoftAesCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::SoftAes,
            sess_id: Some(session_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiSoftAesReq {
            key: MborByteArray::new(
                {
                    let mut data = [0u8; MAX_KEY_LEN];
                    data[..kek_len].copy_from_slice(kek);
                    data
                },
                kek_len,
            )
            .expect("failed to create byte array"),
            inout: MborByteArray::new(
                {
                    let mut data = [0u8; MAX_MSG_LEN];
                    data[..msg_len].copy_from_slice(msg);
                    data
                },
                msg_len,
            )
            .expect("failed to create byte array"),
            op: req_op,
        },
        ext: None,
    };

    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

#[test]
fn test_aes_unwrap_key_256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // AES 256 Key Wrap with Padding Authenticated Decryption (KWP-AD)
            //
            // [PLAINTEXT LENGTH = 64]
            // COUNT = 0
            // K = 3517f0efa7f0c4d74f91af83ece5e7503bcc5ab82907a6e4b7ed34d87b69ab1d
            // P = 897e0456b289ad31
            // C = 0b06a9b635d50cda9d4210cb3a71f990
            //
            // Source:
            // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/kwtestvectors.zip
            let kek: [u8; 32] = [
                0x35, 0x17, 0xf0, 0xef, 0xa7, 0xf0, 0xc4, 0xd7, 0x4f, 0x91, 0xaf, 0x83, 0xec, 0xe5,
                0xe7, 0x50, 0x3b, 0xcc, 0x5a, 0xb8, 0x29, 0x07, 0xa6, 0xe4, 0xb7, 0xed, 0x34, 0xd8,
                0x7b, 0x69, 0xab, 0x1d,
            ];

            let expected: [u8; 8] = [0x89, 0x7e, 0x04, 0x56, 0xb2, 0x89, 0xad, 0x31];

            let input: [u8; 16] = [
                0x0b, 0x06, 0xa9, 0xb6, 0x35, 0xd5, 0x0c, 0xda, 0x9d, 0x42, 0x10, 0xcb, 0x3a, 0x71,
                0xf9, 0x90,
            ];

            let resp = exec_soft_aes_op(
                dev,
                session_id,
                kek.len(),
                &kek,
                input.len(),
                &input,
                DdiSoftAesOp::Kwp,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Extract the response
            let resp = resp.unwrap();
            let resp = resp.data;

            // Check the response
            assert_eq!(resp.plaintext.data()[..expected.len()], expected);
        },
    );
}

#[test]
fn test_aes_unwrap_key_192() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // AES 192 Key Wrap with Padding Authenticated Decryption (KWP-AD)
            //
            // [PLAINTEXT LENGTH = 64]
            //
            // COUNT = 0
            // K = 9bb784983e6754eae0aae6269f15ac2571b3b8e4245d6297
            // C = 217f53e362c4a4a4b8ed31bb74ec35b8
            // P = 1fdc2c4df9eafd6b
            //
            // Source:
            // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/kwtestvectors.zip
            let kek: [u8; 24] = [
                0x9b, 0xb7, 0x84, 0x98, 0x3e, 0x67, 0x54, 0xea, 0xe0, 0xaa, 0xe6, 0x26, 0x9f, 0x15,
                0xac, 0x25, 0x71, 0xb3, 0xb8, 0xe4, 0x24, 0x5d, 0x62, 0x97,
            ];

            let expected: [u8; 8] = [0x1f, 0xdc, 0x2c, 0x4d, 0xf9, 0xea, 0xfd, 0x6b];

            let input: [u8; 16] = [
                0x21, 0x7f, 0x53, 0xe3, 0x62, 0xc4, 0xa4, 0xa4, 0xb8, 0xed, 0x31, 0xbb, 0x74, 0xec,
                0x35, 0xb8,
            ];

            let resp = exec_soft_aes_op(
                dev,
                session_id,
                kek.len(),
                &kek,
                input.len(),
                &input,
                DdiSoftAesOp::Kwp,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Extract the response
            let resp = resp.unwrap();
            let resp = resp.data;

            // Check the response
            assert_eq!(resp.plaintext.data()[..expected.len()], expected);
        },
    );
}

#[test]
fn test_aes_unwrap_key_128() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // AES 128 Key Wrap with Padding Authenticated Decryption (KWP-AD)
            //
            // [PLAINTEXT LENGTH = 64]
            //
            // COUNT = 0
            // K = bbf0833cae0202b830f7b9575596ef2f
            // C = 4736f4488b53d4dc27103e2f2e7d6841
            // P = 490f98c607fc7bb6
            //
            // Source:
            // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/kwtestvectors.zip
            let kek: [u8; 16] = [
                0xbb, 0xf0, 0x83, 0x3c, 0xae, 0x02, 0x02, 0xb8, 0x30, 0xf7, 0xb9, 0x57, 0x55, 0x96,
                0xef, 0x2f,
            ];

            let expected: [u8; 8] = [0x49, 0x0f, 0x98, 0xc6, 0x07, 0xfc, 0x7b, 0xb6];

            let input: [u8; 16] = [
                0x47, 0x36, 0xf4, 0x48, 0x8b, 0x53, 0xd4, 0xdc, 0x27, 0x10, 0x3e, 0x2f, 0x2e, 0x7d,
                0x68, 0x41,
            ];

            let resp = exec_soft_aes_op(
                dev,
                session_id,
                kek.len(),
                &kek,
                input.len(),
                &input,
                DdiSoftAesOp::Kwp,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Extract the response
            let resp = resp.unwrap();
            let resp = resp.data;

            // Check the response
            assert_eq!(resp.plaintext.data()[..expected.len()], expected);
        },
    );
}

#[test]
fn test_aes_unwrap_key_invalid_key_length() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let kek = [0xFF; 17];
            let input = [0xFF; 64];

            let resp = exec_soft_aes_op(
                dev,
                session_id,
                kek.len(),
                &kek,
                input.len(),
                &input,
                DdiSoftAesOp::Kwp,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::RsaUnwrapError)
            ));
        },
    );
}

#[test]
fn test_aes_unwrap_key_invalid_input_length() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let kek: [u8; 16] = [0xFF; 16];
            // Valid inputs are divisible by 8
            let input = [0xFF; 61];

            let resp = exec_soft_aes_op(
                dev,
                session_id,
                kek.len(),
                &kek,
                input.len(),
                &input,
                DdiSoftAesOp::Kwp,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::RsaUnwrapError)
            ));
        },
    );
}

#[test]
fn test_aes_ecb_decrypt_256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // Source:
            // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ECB.pdf
            let message: [u8; 64] = [
                0xF3, 0xEE, 0xD1, 0xBD, 0xB5, 0xD2, 0xA0, 0x3C, 0x06, 0x4B, 0x5A, 0x7E, 0x3D, 0xB1,
                0x81, 0xF8, 0x59, 0x1C, 0xCB, 0x10, 0xD4, 0x10, 0xED, 0x26, 0xDC, 0x5B, 0xA7, 0x4A,
                0x31, 0x36, 0x28, 0x70, 0xB6, 0xED, 0x21, 0xB9, 0x9C, 0xA6, 0xF4, 0xF9, 0xF1, 0x53,
                0xE7, 0xB1, 0xBE, 0xAF, 0xED, 0x1D, 0x23, 0x30, 0x4B, 0x7A, 0x39, 0xF9, 0xF3, 0xFF,
                0x06, 0x7D, 0x8D, 0x8F, 0x9E, 0x24, 0xEC, 0xC7,
            ];

            let key: [u8; 32] = [
                0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D,
                0x77, 0x81, 0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3,
                0x09, 0x14, 0xDF, 0xF4,
            ];

            let expected: [u8; 64] = [
                0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
                0x17, 0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC,
                0x45, 0xAF, 0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB,
                0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF, 0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
                0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10,
            ];

            let resp = exec_soft_aes_op(
                dev,
                session_id,
                key.len(),
                &key,
                message.len(),
                &message,
                DdiSoftAesOp::EcbDecrypt,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Extract the response
            let resp = resp.unwrap();
            let resp = resp.data;

            // Check the response
            assert_eq!(resp.plaintext.data()[..expected.len()], expected);
        },
    );
}

#[test]
fn test_aes_ecb_decrypt_192() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // Source:
            // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ECB.pdf
            let message: [u8; 64] = [
                0xBD, 0x33, 0x4F, 0x1D, 0x6E, 0x45, 0xF2, 0x5F, 0xF7, 0x12, 0xA2, 0x14, 0x57, 0x1F,
                0xA5, 0xCC, 0x97, 0x41, 0x04, 0x84, 0x6D, 0x0A, 0xD3, 0xAD, 0x77, 0x34, 0xEC, 0xB3,
                0xEC, 0xEE, 0x4E, 0xEF, 0xEF, 0x7A, 0xFD, 0x22, 0x70, 0xE2, 0xE6, 0x0A, 0xDC, 0xE0,
                0xBA, 0x2F, 0xAC, 0xE6, 0x44, 0x4E, 0x9A, 0x4B, 0x41, 0xBA, 0x73, 0x8D, 0x6C, 0x72,
                0xFB, 0x16, 0x69, 0x16, 0x03, 0xC1, 0x8E, 0x0E,
            ];

            let key: [u8; 24] = [
                0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90,
                0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B,
            ];

            let expected: [u8; 64] = [
                0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
                0x17, 0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC,
                0x45, 0xAF, 0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB,
                0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF, 0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
                0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10,
            ];

            let resp = exec_soft_aes_op(
                dev,
                session_id,
                key.len(),
                &key,
                message.len(),
                &message,
                DdiSoftAesOp::EcbDecrypt,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Extract the response
            let resp = resp.unwrap();
            let resp = resp.data;

            // Check the response
            assert_eq!(resp.plaintext.data()[..expected.len()], expected);
        },
    );
}

#[test]
fn test_aes_ecb_decrypt_128() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // Source:
            // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ECB.pdf
            let message: [u8; 64] = [
                0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66,
                0xEF, 0x97, 0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A,
                0x96, 0xFD, 0xBA, 0xAF, 0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B,
                0x00, 0xE3, 0xED, 0x03, 0x06, 0x88, 0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F,
                0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5D, 0xD4,
            ];

            let key: [u8; 16] = [
                0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
                0x4F, 0x3C,
            ];

            let expected: [u8; 64] = [
                0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
                0x17, 0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC,
                0x45, 0xAF, 0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB,
                0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF, 0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
                0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10,
            ];

            let resp = exec_soft_aes_op(
                dev,
                session_id,
                key.len(),
                &key,
                message.len(),
                &message,
                DdiSoftAesOp::EcbDecrypt,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Extract the response
            let resp = resp.unwrap();
            let resp = resp.data;

            // Check the response
            assert_eq!(resp.plaintext.data()[..expected.len()], expected);
        },
    );
}

#[test]
fn test_aes_ecb_decrypt_invalid_key_length() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let message: [u8; 64] = [0xFF; 64];
            let key: [u8; 17] = [0x00; 17];

            let resp = exec_soft_aes_op(
                dev,
                session_id,
                key.len(),
                &key,
                message.len(),
                &message,
                DdiSoftAesOp::EcbDecrypt,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::RsaUnwrapError)
            ));
        },
    );
}

#[test]
fn test_aes_ecb_decrypt_invalid_message_length() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let message: [u8; 61] = [0xFF; 61];
            let key: [u8; 32] = [0x00; 32];

            let resp = exec_soft_aes_op(
                dev,
                session_id,
                key.len(),
                &key,
                message.len(),
                &message,
                DdiSoftAesOp::EcbDecrypt,
            );

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::RsaUnwrapError)
            ));
        },
    );
}
