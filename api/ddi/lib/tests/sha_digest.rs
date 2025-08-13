// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_mbor::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

pub fn create_mbor_byte_array<const N: usize>(input: &[u8]) -> MborByteArray<N> {
    let mut fixed_array = [0u8; N];
    let len_to_copy = std::cmp::min(input.len(), N);
    fixed_array[..len_to_copy].copy_from_slice(&input[..len_to_copy]);
    MborByteArray::new(fixed_array, len_to_copy).expect("Failed to initialize MborByteArray")
}

fn create_sha_digest_request(
    session_id: Option<u16>,
    msg: &[u8],
    msg_len: usize,
    sha_mode: DdiHashAlgorithm,
) -> DdiShaDigestGenerateCmdReq {
    DdiShaDigestGenerateCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::ShaDigest,
            sess_id: session_id,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiShaDigestGenerateReq {
            sha_mode,
            msg: MborByteArray::new(
                {
                    let mut data = [0u8; 1024];
                    data[..msg_len].copy_from_slice(msg);
                    data
                },
                msg_len,
            )
            .expect("failed to create byte array"),
        },
        ext: None,
    }
}

#[test]
fn test_sha_digest_invalid_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let input_msg = [1u8; 10];
            let msg_len = input_msg.len();
            let req =
                create_sha_digest_request(Some(0x5), &input_msg, msg_len, DdiHashAlgorithm::Sha512);
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            // Validate error for incorrect session.
            assert!(resp.is_err(), "resp {:?}", resp);
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
fn test_sha_digest_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let input_msg = [1u8; 10];
            let msg_len = input_msg.len();

            let req =
                create_sha_digest_request(None, &input_msg, msg_len, DdiHashAlgorithm::Sha512);
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            // Validate error for no session.
            assert!(resp.is_err(), "resp {:?}", resp);
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
fn test_sha_digest_sha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Len = 10 Bytes
            // Msg = bad7c618f45be207975e
            // SHA512 = 5886828959d1f82254068be0bd14b6a88f59f534061fb20376a0541052dd3635edf3c6f0ca3d08775e13525df9333a2113c0b2af76515887529910b6c793c8a5
            let input_msg: [u8; 10] = [0xba, 0xd7, 0xc6, 0x18, 0xf4, 0x5b, 0xe2, 0x07, 0x97, 0x5e];
            let msg_len = input_msg.len();
            const EXPECTED_DIGEST: [u8; 64] = [
                0x58, 0x86, 0x82, 0x89, 0x59, 0xd1, 0xf8, 0x22, 0x54, 0x06, 0x8b, 0xe0, 0xbd, 0x14,
                0xb6, 0xa8, 0x8f, 0x59, 0xf5, 0x34, 0x06, 0x1f, 0xb2, 0x03, 0x76, 0xa0, 0x54, 0x10,
                0x52, 0xdd, 0x36, 0x35, 0xed, 0xf3, 0xc6, 0xf0, 0xca, 0x3d, 0x08, 0x77, 0x5e, 0x13,
                0x52, 0x5d, 0xf9, 0x33, 0x3a, 0x21, 0x13, 0xc0, 0xb2, 0xaf, 0x76, 0x51, 0x58, 0x87,
                0x52, 0x99, 0x10, 0xb6, 0xc7, 0x93, 0xc8, 0xa5,
            ];

            let req = create_sha_digest_request(
                Some(session_id),
                &input_msg,
                msg_len,
                DdiHashAlgorithm::Sha512,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Extract the response
            let resp = resp.unwrap();
            let resp = resp.data;

            let mut actual_digest = [0u8; EXPECTED_DIGEST.len()];
            actual_digest.copy_from_slice(&resp.digest.data()[..EXPECTED_DIGEST.len()]);

            // Check the response
            assert_eq!(actual_digest, EXPECTED_DIGEST);
        },
    );
}

#[test]
fn test_sha_digest_sha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Len = 32 Bytes
            // Msg = be01e520e69f04174ccf95455b1c81445298264d9adc4958574a52843d95b8ba
            // SHA384 = c5cf54b8e3105b1c7bf7a43754d915b0947f28b6dc94a019182929b5c848e11441c9e4e90c7449f4c3cd12954f0f5d99
            let input_msg: [u8; 32] = [
                0xbe, 0x01, 0xe5, 0x20, 0xe6, 0x9f, 0x04, 0x17, 0x4c, 0xcf, 0x95, 0x45, 0x5b, 0x1c,
                0x81, 0x44, 0x52, 0x98, 0x26, 0x4d, 0x9a, 0xdc, 0x49, 0x58, 0x57, 0x4a, 0x52, 0x84,
                0x3d, 0x95, 0xb8, 0xba,
            ];
            let msg_len = input_msg.len();
            const EXPECTED_DIGEST: [u8; 48] = [
                0xc5, 0xcf, 0x54, 0xb8, 0xe3, 0x10, 0x5b, 0x1c, 0x7b, 0xf7, 0xa4, 0x37, 0x54, 0xd9,
                0x15, 0xb0, 0x94, 0x7f, 0x28, 0xb6, 0xdc, 0x94, 0xa0, 0x19, 0x18, 0x29, 0x29, 0xb5,
                0xc8, 0x48, 0xe1, 0x14, 0x41, 0xc9, 0xe4, 0xe9, 0x0c, 0x74, 0x49, 0xf4, 0xc3, 0xcd,
                0x12, 0x95, 0x4f, 0x0f, 0x5d, 0x99,
            ];

            let req = create_sha_digest_request(
                Some(session_id),
                &input_msg,
                msg_len,
                DdiHashAlgorithm::Sha384,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Extract the response
            let resp = resp.unwrap();
            let resp = resp.data;

            let mut actual_digest = [0u8; EXPECTED_DIGEST.len()];
            actual_digest.copy_from_slice(&resp.digest.data()[..EXPECTED_DIGEST.len()]);

            // Check the response
            assert_eq!(actual_digest, EXPECTED_DIGEST);
        },
    );
}

#[test]
fn test_sha_digest_sha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Len = 64 Bytes
            // Msg = 5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509
            // SHA256 = 42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa
            let input_msg: [u8; 64] = [
                0x5a, 0x86, 0xb7, 0x37, 0xea, 0xea, 0x8e, 0xe9, 0x76, 0xa0, 0xa2, 0x4d, 0xa6, 0x3e,
                0x7e, 0xd7, 0xee, 0xfa, 0xd1, 0x8a, 0x10, 0x1c, 0x12, 0x11, 0xe2, 0xb3, 0x65, 0x0c,
                0x51, 0x87, 0xc2, 0xa8, 0xa6, 0x50, 0x54, 0x72, 0x08, 0x25, 0x1f, 0x6d, 0x42, 0x37,
                0xe6, 0x61, 0xc7, 0xbf, 0x4c, 0x77, 0xf3, 0x35, 0x39, 0x03, 0x94, 0xc3, 0x7f, 0xa1,
                0xa9, 0xf9, 0xbe, 0x83, 0x6a, 0xc2, 0x85, 0x09,
            ];
            let msg_len = input_msg.len();
            const EXPECTED_DIGEST: [u8; 32] = [
                0x42, 0xe6, 0x1e, 0x17, 0x4f, 0xbb, 0x38, 0x97, 0xd6, 0xdd, 0x6c, 0xef, 0x3d, 0xd2,
                0x80, 0x2f, 0xe6, 0x7b, 0x33, 0x19, 0x53, 0xb0, 0x61, 0x14, 0xa6, 0x5c, 0x77, 0x28,
                0x59, 0xdf, 0xc1, 0xaa,
            ];

            let req = create_sha_digest_request(
                Some(session_id),
                &input_msg,
                msg_len,
                DdiHashAlgorithm::Sha256,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Extract the response
            let resp = resp.unwrap();
            let resp = resp.data;

            let mut actual_digest = [0u8; EXPECTED_DIGEST.len()];
            actual_digest.copy_from_slice(&resp.digest.data()[..EXPECTED_DIGEST.len()]);

            // Check the response
            assert_eq!(actual_digest, EXPECTED_DIGEST);
        },
    );
}

#[test]
fn test_sha_digest_sha1() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Len = 8 Bytes
            // Msg = 7e3d7b3eada98866
            // SHA1 = 24a2c34b976305277ce58c2f42d5092031572520
            let input_msg: [u8; 8] = [0x7e, 0x3d, 0x7b, 0x3e, 0xad, 0xa9, 0x88, 0x66];
            let msg_len = input_msg.len();
            const EXPECTED_DIGEST: [u8; 20] = [
                0x24, 0xa2, 0xc3, 0x4b, 0x97, 0x63, 0x05, 0x27, 0x7c, 0xe5, 0x8c, 0x2f, 0x42, 0xd5,
                0x09, 0x20, 0x31, 0x57, 0x25, 0x20,
            ];

            let req = create_sha_digest_request(
                Some(session_id),
                &input_msg,
                msg_len,
                DdiHashAlgorithm::Sha1,
            );
            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Extract the response
            let resp = resp.unwrap();
            let resp = resp.data;

            let mut actual_digest = [0u8; EXPECTED_DIGEST.len()];
            actual_digest.copy_from_slice(&resp.digest.data()[..EXPECTED_DIGEST.len()]);

            // Check the response
            assert_eq!(actual_digest, EXPECTED_DIGEST);
        },
    );
}

#[test]
fn test_sha_digest_null_msg() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Len = 0 Bytes
            // Msg = 00
            // SHA1 = da39a3ee5e6b4b0d3255bfef95601890afd80709
            let msg_len = 0;
            const EXPECTED_DIGEST: [u8; 20] = [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
            ];

            let req: DdiShaDigestGenerateCmdReq = DdiShaDigestGenerateCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::ShaDigest,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiShaDigestGenerateReq {
                    sha_mode: DdiHashAlgorithm::Sha1,
                    msg: MborByteArray::new([0u8; 1024], msg_len)
                        .expect("failed to create byte array"),
                },
                ext: None,
            };

            let mut cookie = None;

            let resp = dev.exec_op(&req, &mut cookie);

            if let Err(err) = &resp {
                if is_unsupported_cmd(err) {
                    return;
                }
            }

            // Extract the response
            let resp = resp.unwrap();
            let resp = resp.data;

            let mut actual_digest = [0u8; EXPECTED_DIGEST.len()];
            actual_digest.copy_from_slice(&resp.digest.data()[..EXPECTED_DIGEST.len()]);

            // Check the response
            assert_eq!(actual_digest, EXPECTED_DIGEST);
        },
    );
}
