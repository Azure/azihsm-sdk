// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ShaDigest smoke tests.
//!
//! `ShaDigest` is an in-session command: the request must carry the
//! caller's open session id. These tests drive the DDI `ShaDigest` op end
//! to end against the backend, mirroring the host-side `sha_digest` test
//! hook.
//!
//! - Happy path (hooks enabled): NIST FIPS 180-4 known-answer vectors for SHA-1, SHA-256,
//!   SHA-384, SHA-512, and the empty message.
//!   If the backend returns `UnsupportedCmd` (e.g. firmware not built with `fips_validation_hooks`),
//!   the vector check is skipped.
//! - Wrong / missing session (both backends): the host-side dev validator
//!   rejects the request with `FileHandleSessionIdDoesNotMatch` before it
//!   reaches firmware.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

/// Build a 1024-byte message buffer holding `input` in its leading bytes.
fn sha_msg(input: &[u8]) -> MborByteArray<1024> {
    let mut data = [0u8; 1024];
    data[..input.len()].copy_from_slice(input);
    MborByteArray::new(data, input.len()).expect("failed to create byte array")
}

/// Submit `input` under `sha_mode` in-session and assert the digest matches
/// `expected`. Skips the check when the backend does not implement
/// `ShaDigest` (functional sim).
fn check_digest(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    sha_mode: DdiHashAlgorithm,
    input: &[u8],
    expected: &[u8],
) {
    let resp = helper_sha_digest(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        sha_msg(input),
        sha_mode,
    );

    if let Err(err) = &resp {
        if is_unsupported_cmd(err) {
            return;
        }
    }

    let resp = resp.unwrap_or_else(|e| panic!("ShaDigest {sha_mode:?} should succeed: {e:?}"));
    assert_eq!(resp.hdr.op, DdiOp::ShaDigest);
    assert_eq!(resp.hdr.status, DdiStatus::Success);
    assert_eq!(
        resp.data.digest.as_slice(),
        expected,
        "digest mismatch for {sha_mode:?}",
    );
}

#[test]
fn test_sha_digest_kat_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // SHA-1: "7e3d7b3eada98866"
            check_digest(
                dev,
                session_id,
                DdiHashAlgorithm::Sha1,
                &[0x7e, 0x3d, 0x7b, 0x3e, 0xad, 0xa9, 0x88, 0x66],
                &[
                    0x24, 0xa2, 0xc3, 0x4b, 0x97, 0x63, 0x05, 0x27, 0x7c, 0xe5, 0x8c, 0x2f, 0x42,
                    0xd5, 0x09, 0x20, 0x31, 0x57, 0x25, 0x20,
                ],
            );

            // SHA-256 over a 64-byte message.
            check_digest(
                dev,
                session_id,
                DdiHashAlgorithm::Sha256,
                &[
                    0x5a, 0x86, 0xb7, 0x37, 0xea, 0xea, 0x8e, 0xe9, 0x76, 0xa0, 0xa2, 0x4d, 0xa6,
                    0x3e, 0x7e, 0xd7, 0xee, 0xfa, 0xd1, 0x8a, 0x10, 0x1c, 0x12, 0x11, 0xe2, 0xb3,
                    0x65, 0x0c, 0x51, 0x87, 0xc2, 0xa8, 0xa6, 0x50, 0x54, 0x72, 0x08, 0x25, 0x1f,
                    0x6d, 0x42, 0x37, 0xe6, 0x61, 0xc7, 0xbf, 0x4c, 0x77, 0xf3, 0x35, 0x39, 0x03,
                    0x94, 0xc3, 0x7f, 0xa1, 0xa9, 0xf9, 0xbe, 0x83, 0x6a, 0xc2, 0x85, 0x09,
                ],
                &[
                    0x42, 0xe6, 0x1e, 0x17, 0x4f, 0xbb, 0x38, 0x97, 0xd6, 0xdd, 0x6c, 0xef, 0x3d,
                    0xd2, 0x80, 0x2f, 0xe6, 0x7b, 0x33, 0x19, 0x53, 0xb0, 0x61, 0x14, 0xa6, 0x5c,
                    0x77, 0x28, 0x59, 0xdf, 0xc1, 0xaa,
                ],
            );

            // SHA-384 over a 32-byte message.
            check_digest(
                dev,
                session_id,
                DdiHashAlgorithm::Sha384,
                &[
                    0xbe, 0x01, 0xe5, 0x20, 0xe6, 0x9f, 0x04, 0x17, 0x4c, 0xcf, 0x95, 0x45, 0x5b,
                    0x1c, 0x81, 0x44, 0x52, 0x98, 0x26, 0x4d, 0x9a, 0xdc, 0x49, 0x58, 0x57, 0x4a,
                    0x52, 0x84, 0x3d, 0x95, 0xb8, 0xba,
                ],
                &[
                    0xc5, 0xcf, 0x54, 0xb8, 0xe3, 0x10, 0x5b, 0x1c, 0x7b, 0xf7, 0xa4, 0x37, 0x54,
                    0xd9, 0x15, 0xb0, 0x94, 0x7f, 0x28, 0xb6, 0xdc, 0x94, 0xa0, 0x19, 0x18, 0x29,
                    0x29, 0xb5, 0xc8, 0x48, 0xe1, 0x14, 0x41, 0xc9, 0xe4, 0xe9, 0x0c, 0x74, 0x49,
                    0xf4, 0xc3, 0xcd, 0x12, 0x95, 0x4f, 0x0f, 0x5d, 0x99,
                ],
            );

            // SHA-512 over a 10-byte message.
            check_digest(
                dev,
                session_id,
                DdiHashAlgorithm::Sha512,
                &[0xba, 0xd7, 0xc6, 0x18, 0xf4, 0x5b, 0xe2, 0x07, 0x97, 0x5e],
                &[
                    0x58, 0x86, 0x82, 0x89, 0x59, 0xd1, 0xf8, 0x22, 0x54, 0x06, 0x8b, 0xe0, 0xbd,
                    0x14, 0xb6, 0xa8, 0x8f, 0x59, 0xf5, 0x34, 0x06, 0x1f, 0xb2, 0x03, 0x76, 0xa0,
                    0x54, 0x10, 0x52, 0xdd, 0x36, 0x35, 0xed, 0xf3, 0xc6, 0xf0, 0xca, 0x3d, 0x08,
                    0x77, 0x5e, 0x13, 0x52, 0x5d, 0xf9, 0x33, 0x3a, 0x21, 0x13, 0xc0, 0xb2, 0xaf,
                    0x76, 0x51, 0x58, 0x87, 0x52, 0x99, 0x10, 0xb6, 0xc7, 0x93, 0xc8, 0xa5,
                ],
            );

            // Empty message → SHA-1 of the empty string.
            check_digest(
                dev,
                session_id,
                DdiHashAlgorithm::Sha1,
                &[],
                &[
                    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95,
                    0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
                ],
            );
        },
    );
}

#[test]
fn test_sha_digest_no_session_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let err = helper_sha_digest(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                sha_msg(&[1u8; 10]),
                DdiHashAlgorithm::Sha512,
            )
            .expect_err("ShaDigest must be rejected without a session");

            assert!(
                matches!(
                    err,
                    DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
                ),
                "expected FileHandleSessionIdDoesNotMatch, got {err:?}",
            );
        },
    );
}

#[test]
fn test_sha_digest_invalid_session_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let err = helper_sha_digest(
                dev,
                Some(0x5),
                Some(DdiApiRev { major: 1, minor: 0 }),
                sha_msg(&[1u8; 10]),
                DdiHashAlgorithm::Sha512,
            )
            .expect_err("ShaDigest must be rejected for a mismatched session");

            assert!(
                matches!(
                    err,
                    DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
                ),
                "expected FileHandleSessionIdDoesNotMatch, got {err:?}",
            );
        },
    );
}
