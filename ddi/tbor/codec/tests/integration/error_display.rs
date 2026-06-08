// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `Display` coverage for `DecodeError` and `EncodeError`.

use super::common::*;

#[test]
fn decode_error_display_strings_are_distinct_and_descriptive() {
    let cases: &[(DecodeError, &str)] = &[
        (DecodeError::BufferTooShort, "buffer too short"),
        (DecodeError::UnsupportedVersion(0x02), "0x02"),
        (DecodeError::MessageTruncated, "truncated"),
        (DecodeError::OffsetLengthOutOfBounds, "out of bounds"),
        (DecodeError::InvalidFixedLength, "invalid length"),
        (DecodeError::UnexpectedTocType, "unexpected TOC"),
        (DecodeError::InvalidNonePayload, "reserved bits"),
        (DecodeError::FwError(0x0870_00DD), "0x087000DD"),
    ];
    for (err, expected) in cases {
        let rendered = std::format!("{}", err);
        assert!(
            rendered.contains(expected),
            "{:?} formatted as {:?}, expected substring {:?}",
            err,
            rendered,
            expected
        );
    }
}

#[test]
fn encode_error_display_strings_are_distinct_and_descriptive() {
    let cases: &[(EncodeError, &str)] = &[
        (EncodeError::BufferTooSmall, "buffer too small"),
        (EncodeError::TooManyTocEntries, "too many TOC entries"),
        (
            EncodeError::MissingTocEntries,
            "missing required TOC entries",
        ),
        (EncodeError::DataTooLarge, "data too large"),
        (EncodeError::DataOffsetOverflow, "data offset overflow"),
    ];
    for (err, expected) in cases {
        let rendered = std::format!("{}", err);
        assert!(
            rendered.contains(expected),
            "{:?} formatted as {:?}, expected substring {:?}",
            err,
            rendered,
            expected
        );
    }
}
