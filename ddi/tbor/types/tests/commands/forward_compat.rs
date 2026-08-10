// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the forward/backward-compatibility contract of derived
//! [`TborResp::decode_response`] implementations.
//!
//! The host derive emits a `toc_count() < expected_toc` gate so that:
//!
//! * **Fewer** entries than the schema knows ⇒
//!   [`codec::DecodeError::MessageTruncated`].
//! * **Exactly** the expected number of entries ⇒ the response decodes
//!   normally.
//! * **More** entries than the schema knows ⇒ trailing entries are
//!   ignored and the known prefix decodes successfully.
//!
//! `TborApiRevResp` is used because its schema contains two `Uint8`
//! entries:
//!
//! 1. `min_ver`
//! 2. `max_ver`

use azihsm_ddi_tbor_codec::EncodeError;
use azihsm_ddi_tbor_types::codec::DecodeError;
use azihsm_ddi_tbor_types::codec::ResponseEncoder;
use azihsm_ddi_tbor_types::codec::PROTOCOL_VERSION;
use azihsm_ddi_tbor_types::TborApiRevResp;
use azihsm_ddi_tbor_types::TborResp;

/// Decode a normal two-field `TborApiRevResp`.
fn decode_api_rev(min_ver: u8, max_ver: u8) -> TborApiRevResp {
    let mut buf = [0u8; 64];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(min_ver)
        .expect("encode min_ver")
        .uint8(max_ver)
        .expect("encode max_ver")
        .finish()
        .expect("finish response");

    TborApiRevResp::decode_response(bytes).expect("decode API revision response")
}

/// Encode the two known API revision fields followed by the supplied
/// future fields.
fn encode_api_rev_with_trailing<'a>(
    buf: &'a mut [u8],
    min_ver: u8,
    max_ver: u8,
    trailing: &[u8],
) -> &'a [u8] {
    let mut encoder = ResponseEncoder::new(buf, PROTOCOL_VERSION, 0, false)
        .uint8(min_ver)
        .expect("encode min_ver")
        .uint8(max_ver)
        .expect("encode max_ver");

    for (index, value) in trailing.iter().copied().enumerate() {
        encoder = encoder.uint8(value).unwrap_or_else(|err| {
            panic!(
                "encode trailing future field {index} \
                     with value {value:#04x}: {err:?}"
            )
        });
    }

    encoder.finish().expect("finish response")
}

/// Verifies that a response with exactly the expected TOC count decodes successfully.
#[test]
fn exact_toc_count_decodes_successfully() {
    let resp = decode_api_rev(0x05, 0x07);

    assert_eq!(resp.min_ver, 0x05);
    assert_eq!(resp.max_ver, 0x07);
}

/// Verifies that exact-count decoding preserves zero-valued known fields.
#[test]
fn exact_toc_count_preserves_zero_values() {
    let resp = decode_api_rev(0x00, 0x00);

    assert_eq!(resp.min_ver, 0x00);
    assert_eq!(resp.max_ver, 0x00);
}

/// Verifies that exact-count decoding preserves the full `u8` boundary range.
#[test]
fn exact_toc_count_preserves_uint8_boundary_values() {
    let resp = decode_api_rev(u8::MIN, u8::MAX);

    assert_eq!(resp.min_ver, u8::MIN);
    assert_eq!(resp.max_ver, u8::MAX);
}

/// Verifies that exact-count decoding preserves representative known-field pairs.
#[test]
fn exact_toc_count_preserves_representative_value_pairs() {
    let cases = [
        (0x00, 0x00),
        (0x00, 0xFF),
        (0xFF, 0x00),
        (0xFF, 0xFF),
        (0x01, 0x02),
        (0x7F, 0x80),
        (0x55, 0xAA),
        (0xAA, 0x55),
    ];

    for (min_ver, max_ver) in cases {
        let resp = decode_api_rev(min_ver, max_ver);

        assert_eq!(
            resp.min_ver, min_ver,
            "min_ver changed for pair ({min_ver:#04x}, {max_ver:#04x})",
        );
        assert_eq!(
            resp.max_ver, max_ver,
            "max_ver changed for pair ({min_ver:#04x}, {max_ver:#04x})",
        );
    }
}

/// Verifies that one appended future TOC entry is ignored.
#[test]
fn one_extra_trailing_toc_entry_is_ignored() {
    // TborApiRevResp expects two Uint8 TOC entries. Encode three:
    // the two known fields plus one future-field placeholder.
    let mut buf = [0u8; 64];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(0x05)
        .expect("encode min_ver")
        .uint8(0x07)
        .expect("encode max_ver")
        .uint8(0xFF)
        .expect("encode trailing future field")
        .finish()
        .expect("finish response");

    let resp = TborApiRevResp::decode_response(bytes)
        .expect("forward compatibility: trailing entry must be ignored");

    assert_eq!(resp.min_ver, 0x05);
    assert_eq!(resp.max_ver, 0x07);
}

/// Verifies that every possible `u8` value is ignored when appended as a future field.
#[test]
fn every_uint8_value_is_ignored_as_one_trailing_entry() {
    // The compatibility behavior must not depend on the encoded value
    // of the appended field.
    for trailing_value in u8::MIN..=u8::MAX {
        let mut buf = [0u8; 64];

        let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
            .uint8(0x12)
            .expect("encode min_ver")
            .uint8(0x34)
            .expect("encode max_ver")
            .uint8(trailing_value)
            .expect("encode trailing future field")
            .finish()
            .expect("finish response");

        let resp = TborApiRevResp::decode_response(bytes).unwrap_or_else(|err| {
            panic!(
                "trailing value {trailing_value:#04x} \
                     must be ignored: {err:?}"
            )
        });

        assert_eq!(
            resp.min_ver, 0x12,
            "min_ver changed for trailing value {trailing_value:#04x}",
        );
        assert_eq!(
            resp.max_ver, 0x34,
            "max_ver changed for trailing value {trailing_value:#04x}",
        );
    }
}

/// Verifies that multiple appended future TOC entries are ignored.
#[test]
fn multiple_extra_trailing_toc_entries_are_ignored() {
    // Verify that compatibility is not limited to exactly one appended
    // field. A newer firmware may append several fields over time.
    let mut buf = [0u8; 64];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(0x11)
        .expect("encode min_ver")
        .uint8(0x22)
        .expect("encode max_ver")
        .uint8(0x33)
        .expect("encode future field 1")
        .uint8(0x44)
        .expect("encode future field 2")
        .uint8(0x55)
        .expect("encode future field 3")
        .finish()
        .expect("finish response");

    let resp = TborApiRevResp::decode_response(bytes)
        .expect("forward compatibility: all trailing entries must be ignored");

    assert_eq!(resp.min_ver, 0x11);
    assert_eq!(resp.max_ver, 0x22);
}

/// Verifies that trailing future entries cannot overwrite known decoded fields.
#[test]
fn trailing_entries_do_not_overwrite_known_fields() {
    // Use deliberately different values for every entry to ensure the
    // decoder reads the known prefix rather than accidentally reading
    // the final entries.
    let mut buf = [0u8; 64];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(0x01)
        .expect("encode min_ver")
        .uint8(0x02)
        .expect("encode max_ver")
        .uint8(0xA1)
        .expect("encode future field 1")
        .uint8(0xA2)
        .expect("encode future field 2")
        .finish()
        .expect("finish response");

    let resp = TborApiRevResp::decode_response(bytes)
        .expect("trailing fields must not change known decoded fields");

    assert_eq!(resp.min_ver, 0x01);
    assert_eq!(resp.max_ver, 0x02);
    assert_ne!(resp.min_ver, 0xA1);
    assert_ne!(resp.max_ver, 0xA2);
}

/// Verifies that repeatedly decoding the same extended response produces identical results.
#[test]
fn repeated_decode_of_forward_compatible_message_is_deterministic() {
    let trailing = [0x10, 0x20, 0x30, 0x40, 0x50];
    let mut buf = [0u8; 128];

    let bytes = encode_api_rev_with_trailing(&mut buf, 0x09, 0x0B, &trailing);

    let first = TborApiRevResp::decode_response(bytes).expect("first decode with trailing entries");

    let second =
        TborApiRevResp::decode_response(bytes).expect("second decode with trailing entries");

    assert_eq!(first.min_ver, 0x09);
    assert_eq!(first.max_ver, 0x0B);
    assert_eq!(second.min_ver, first.min_ver);
    assert_eq!(second.max_ver, first.max_ver);
}

/// Verifies that a response missing the second required TOC entry is truncated.
#[test]
fn one_toc_entry_is_message_truncated() {
    // The first field exists, but max_ver is missing.
    let mut buf = [0u8; 64];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(0x05)
        .expect("encode min_ver")
        .finish()
        .expect("finish response");

    let err = TborApiRevResp::decode_response(bytes)
        .expect_err("missing max_ver must produce MessageTruncated");

    assert_eq!(err, DecodeError::MessageTruncated);
}

/// Verifies that the response encoder rejects an empty TOC.
#[test]
fn zero_toc_entries_cannot_be_encoded() {
    // ResponseEncoder requires at least one TOC entry, so an empty
    // response cannot reach TborApiRevResp::decode_response.
    let mut buf = [0u8; 64];

    let err = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .finish()
        .expect_err("an empty response must be rejected by the encoder");

    assert_eq!(err, EncodeError::MissingTocEntries);
}

/// Verifies that truncation depends on TOC count rather than the present field value.
#[test]
fn truncated_result_is_independent_of_present_field_value() {
    // The TOC count, rather than the value of the existing entry,
    // determines whether the message is truncated.
    for min_ver in [u8::MIN, 0x01, 0x7F, u8::MAX] {
        let mut buf = [0u8; 64];

        let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
            .uint8(min_ver)
            .expect("encode min_ver")
            .finish()
            .expect("finish response");

        let err = TborApiRevResp::decode_response(bytes).expect_err(
            "a one-entry response must be truncated regardless \
                 of field value",
        );

        assert_eq!(
            err,
            DecodeError::MessageTruncated,
            "unexpected result for min_ver={min_ver:#04x}",
        );
    }
}

/// Verifies for every `u8` value that omitting the second required field is truncated.
#[test]
fn every_uint8_first_field_value_is_truncated_when_second_is_missing() {
    // Exhaustively verify that no possible first-field value can alter
    // the schema-length check.
    for min_ver in u8::MIN..=u8::MAX {
        let mut buf = [0u8; 64];

        let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
            .uint8(min_ver)
            .expect("encode min_ver")
            .finish()
            .expect("finish response");

        let err = TborApiRevResp::decode_response(bytes)
            .expect_err("missing second field must produce MessageTruncated");

        assert_eq!(
            err,
            DecodeError::MessageTruncated,
            "unexpected result for min_ver={min_ver:#04x}",
        );
    }
}

/// Verifies that forward-compatible decoding preserves boundary-valued known fields.
#[test]
fn forward_compatibility_preserves_boundary_values() {
    // Exercise the compatibility behavior while the known fields
    // contain their minimum and maximum representable values.
    let mut buf = [0u8; 64];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(u8::MIN)
        .expect("encode minimum min_ver")
        .uint8(u8::MAX)
        .expect("encode maximum max_ver")
        .uint8(0x55)
        .expect("encode future field")
        .finish()
        .expect("finish response");

    let resp = TborApiRevResp::decode_response(bytes)
        .expect("boundary values with a trailing entry must decode");

    assert_eq!(resp.min_ver, u8::MIN);
    assert_eq!(resp.max_ver, u8::MAX);
}

/// Verifies that forward-compatible decoding preserves representative known-field values.
#[test]
fn forward_compatibility_preserves_representative_known_values() {
    let cases = [
        (0x00, 0x00),
        (0x00, 0xFF),
        (0xFF, 0x00),
        (0xFF, 0xFF),
        (0x01, 0xFE),
        (0x7F, 0x80),
        (0x55, 0xAA),
    ];

    let trailing = [0xDE, 0xAD, 0xBE, 0xEF];

    for (min_ver, max_ver) in cases {
        let mut buf = [0u8; 128];

        let bytes = encode_api_rev_with_trailing(&mut buf, min_ver, max_ver, &trailing);

        let resp = TborApiRevResp::decode_response(bytes).unwrap_or_else(|err| {
            panic!(
                "known pair ({min_ver:#04x}, {max_ver:#04x}) \
                     with trailing entries must decode: {err:?}"
            )
        });

        assert_eq!(resp.min_ver, min_ver);
        assert_eq!(resp.max_ver, max_ver);
    }
}

/// Verifies that the maximum supported TOC count still decodes the known prefix.
#[test]
fn maximum_supported_toc_count_decodes_known_prefix() {
    // ResponseEncoder supports at most 32 total TOC entries.
    // TborApiRevResp uses two known entries, leaving room for 30
    // trailing future entries.
    const TRAILING_COUNT: usize = 30;

    let trailing: [u8; TRAILING_COUNT] = core::array::from_fn(|index| index as u8);

    let mut buf = [0u8; 512];
    let bytes = encode_api_rev_with_trailing(&mut buf, u8::MIN, u8::MAX, &trailing);

    let resp = TborApiRevResp::decode_response(bytes)
        .expect("32-entry response must preserve the known prefix");

    assert_eq!(resp.min_ver, u8::MIN);
    assert_eq!(resp.max_ver, u8::MAX);
}

/// Verifies that the encoder rejects a TOC entry beyond its supported limit.
#[test]
fn toc_entry_beyond_encoder_limit_is_rejected() {
    // Two known fields plus 30 trailing fields reaches the encoder's
    // maximum of 32 TOC entries. One additional field must fail with
    // TooManyTocEntries.
    let mut buf = [0u8; 512];

    let mut encoder = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(0x12)
        .expect("encode min_ver")
        .uint8(0x34)
        .expect("encode max_ver");

    for index in 0..30u8 {
        encoder = encoder.uint8(index).unwrap_or_else(|err| {
            panic!(
                "trailing field {index} must fit within the \
                     32-entry limit: {err:?}"
            )
        });
    }

    let err = encoder
        .uint8(0xFF)
        .expect_err("the 33rd total TOC entry must be rejected");

    assert_eq!(err, EncodeError::TooManyTocEntries);
}

/// Verifies that the maximum supported number of trailing future entries is ignored.
#[test]
fn many_extra_trailing_toc_entries_are_ignored() {
    // Exercise the maximum number of future fields supported by the
    // encoder: two known fields plus 30 trailing entries.
    const TRAILING_COUNT: usize = 30;

    let trailing: [u8; TRAILING_COUNT] = core::array::from_fn(|index| index as u8);

    let mut buf = [0u8; 512];
    let bytes = encode_api_rev_with_trailing(&mut buf, 0x21, 0x43, &trailing);

    let resp = TborApiRevResp::decode_response(bytes).expect("30 trailing entries must be ignored");

    assert_eq!(resp.min_ver, 0x21);
    assert_eq!(resp.max_ver, 0x43);
}

/// Verifies that varying supported trailing-entry counts preserve the same known fields.
#[test]
fn different_trailing_counts_preserve_the_same_known_fields() {
    // Include values immediately below and at the encoder's maximum
    // supported trailing-entry count.
    for trailing_count in [0usize, 1, 2, 3, 8, 16, 29, 30] {
        let trailing: Vec<u8> = (0..trailing_count).map(|index| index as u8).collect();

        let mut buf = [0u8; 512];
        let bytes = encode_api_rev_with_trailing(&mut buf, 0x6A, 0xB5, &trailing);

        let resp = TborApiRevResp::decode_response(bytes).unwrap_or_else(|err| {
            panic!(
                "response with {trailing_count} trailing entries \
                     must decode: {err:?}"
            )
        });

        assert_eq!(
            resp.min_ver, 0x6A,
            "min_ver changed with {trailing_count} trailing entries",
        );

        assert_eq!(
            resp.max_ver, 0xB5,
            "max_ver changed with {trailing_count} trailing entries",
        );
    }
}

/// Verifies exact-count decoding for every possible pair of `u8` known-field values.
#[test]
fn exact_toc_count_exhaustively_preserves_all_uint8_pairs() {
    for min_ver in u8::MIN..=u8::MAX {
        for max_ver in u8::MIN..=u8::MAX {
            let resp = decode_api_rev(min_ver, max_ver);

            assert_eq!(
                resp.min_ver, min_ver,
                "min_ver changed for pair ({min_ver:#04x}, {max_ver:#04x})",
            );
            assert_eq!(
                resp.max_ver, max_ver,
                "max_ver changed for pair ({min_ver:#04x}, {max_ver:#04x})",
            );
        }
    }
}

/// Verifies that decoding preserves field values without imposing semantic version ordering.
#[test]
fn exact_toc_count_does_not_require_min_ver_to_be_less_than_max_ver() {
    let resp = decode_api_rev(0xFE, 0x01);

    assert_eq!(resp.min_ver, 0xFE);
    assert_eq!(resp.max_ver, 0x01);
}

/// Verifies that equal known-field values are preserved with appended future fields.
#[test]
fn forward_compatibility_preserves_equal_known_values() {
    let trailing = [0x10, 0x20, 0x30, 0x40];
    let mut buf = [0u8; 128];

    let bytes = encode_api_rev_with_trailing(&mut buf, 0x7F, 0x7F, &trailing);

    let resp = TborApiRevResp::decode_response(bytes)
        .expect("equal known fields with trailing entries must decode");

    assert_eq!(resp.min_ver, 0x7F);
    assert_eq!(resp.max_ver, 0x7F);
}

/// Verifies that maximum-count trailing entries filled with zero are ignored.
#[test]
fn maximum_supported_trailing_zero_values_are_ignored() {
    const TRAILING_COUNT: usize = 30;

    let trailing = [u8::MIN; TRAILING_COUNT];
    let mut buf = [0u8; 512];

    let bytes = encode_api_rev_with_trailing(&mut buf, 0x12, 0x34, &trailing);

    let resp = TborApiRevResp::decode_response(bytes)
        .expect("maximum-count zero-valued trailing entries must be ignored");

    assert_eq!(resp.min_ver, 0x12);
    assert_eq!(resp.max_ver, 0x34);
}

/// Verifies that maximum-count trailing entries filled with `u8::MAX` are ignored.
#[test]
fn maximum_supported_trailing_max_values_are_ignored() {
    const TRAILING_COUNT: usize = 30;

    let trailing = [u8::MAX; TRAILING_COUNT];
    let mut buf = [0u8; 512];

    let bytes = encode_api_rev_with_trailing(&mut buf, 0x56, 0x78, &trailing);

    let resp = TborApiRevResp::decode_response(bytes)
        .expect("maximum-count max-valued trailing entries must be ignored");

    assert_eq!(resp.min_ver, 0x56);
    assert_eq!(resp.max_ver, 0x78);
}

/// Verifies that alternating boundary-valued future fields are ignored at the TOC limit.
#[test]
fn maximum_supported_alternating_trailing_values_are_ignored() {
    const TRAILING_COUNT: usize = 30;

    let trailing: [u8; TRAILING_COUNT] =
        core::array::from_fn(|index| if index % 2 == 0 { u8::MIN } else { u8::MAX });

    let mut buf = [0u8; 512];
    let bytes = encode_api_rev_with_trailing(&mut buf, 0xA5, 0x5A, &trailing);

    let resp = TborApiRevResp::decode_response(bytes)
        .expect("alternating boundary-valued trailing entries must be ignored");

    assert_eq!(resp.min_ver, 0xA5);
    assert_eq!(resp.max_ver, 0x5A);
}

/// Verifies forward compatibility immediately below and at the maximum TOC count.
#[test]
fn forward_compatibility_preserves_known_fields_at_toc_limit_boundary() {
    for trailing_count in [29usize, 30] {
        let trailing: Vec<u8> = (0..trailing_count)
            .map(|index| 0xF0u8.wrapping_add(index as u8))
            .collect();

        let mut buf = [0u8; 512];
        let bytes = encode_api_rev_with_trailing(&mut buf, 0x2A, 0xD5, &trailing);

        let resp = TborApiRevResp::decode_response(bytes).unwrap_or_else(|err| {
            panic!(
                "response with {trailing_count} trailing entries at the TOC boundary \
                 must decode: {err:?}"
            )
        });

        assert_eq!(resp.min_ver, 0x2A);
        assert_eq!(resp.max_ver, 0xD5);
    }
}
