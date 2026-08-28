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
//! Coverage includes representative response layouts:
//!
//! * Inline scalar fields in `TborApiRevResp`.
//! * Typed inline fields (`SessionId` and `KeyId`).
//! * Single variable-length buffers in `TborEccSignResp` and
//!   `TborKeyReportResp`.
//! * Variable-length buffer plus fixed-size array in
//!   `TborAesEncryptDecryptResp`.
//! * Two variable-length buffers in `TborEccGenerateKeyResp`.
//! * Scalar plus two variable-length buffers in `TborUnwrapKeyResp`.
//! * Mixed-width integer and fixed-size buffer fields in
//!   `TborPartInfoResp`.
//! * Session-id plus multiple fixed-size buffer fields in
//!   `TborSessionOpenInitResp`.

use azihsm_ddi_tbor_codec::EncodeError;
use azihsm_ddi_tbor_codec::MAX_TOC_ENTRIES;
use azihsm_ddi_tbor_types::codec::DecodeError;
use azihsm_ddi_tbor_types::codec::ResponseEncoder;
use azihsm_ddi_tbor_types::codec::PROTOCOL_VERSION;
use azihsm_ddi_tbor_types::tbor;
use azihsm_ddi_tbor_types::tbor_int::U32;
use azihsm_ddi_tbor_types::tbor_int::U64;
use azihsm_ddi_tbor_types::tbor_int::U8;
use azihsm_ddi_tbor_types::TborAesEncryptDecryptResp;
use azihsm_ddi_tbor_types::TborApiRevResp;
use azihsm_ddi_tbor_types::TborEccGenerateKeyResp;
use azihsm_ddi_tbor_types::TborEccSignResp;
use azihsm_ddi_tbor_types::TborKeyReportResp;
use azihsm_ddi_tbor_types::TborPartInfoResp;
use azihsm_ddi_tbor_types::TborResp;
use azihsm_ddi_tbor_types::TborSessionOpenInitResp;
use azihsm_ddi_tbor_types::TborUnwrapKeyResp;

#[tbor(response)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeyIdForwardCompatResp {
    #[tbor(key_id)]
    key_id: u16,
    value: u8,
}

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

    for value in trailing.iter().copied() {
        encoder = encoder.uint8(value).unwrap_or_else(|err| {
            panic!(
                "encode trailing future field \
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
    // TborApiRevResp uses two known TOC entries; fill the remaining
    // encoder capacity with trailing future entries.
    const TRAILING_COUNT: usize = MAX_TOC_ENTRIES - 2;

    let trailing: [u8; TRAILING_COUNT] = core::array::from_fn(|index| index as u8);

    let mut buf = [0u8; 512];
    let bytes = encode_api_rev_with_trailing(&mut buf, u8::MIN, u8::MAX, &trailing);

    let resp = TborApiRevResp::decode_response(bytes)
        .expect("maximum-entry response must preserve the known prefix");

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

/// Encode one known buffer field followed by the supplied future fields.
fn encode_buffer_with_trailing<'a>(buf: &'a mut [u8], value: &[u8], trailing: &[u8]) -> &'a [u8] {
    let mut encoder = ResponseEncoder::new(buf, PROTOCOL_VERSION, 0, false)
        .buffer(value)
        .expect("encode known buffer");

    for value in trailing.iter().copied() {
        encoder = encoder.uint8(value).unwrap_or_else(|err| {
            panic!(
                "encode trailing future field \
                 with value {value:#04x}: {err:?}"
            )
        });
    }

    encoder.finish().expect("finish response")
}
/// Verifies exact-count decoding of a variable-length ECDSA signature.
#[test]
fn ecc_sign_exact_toc_count_decodes_signature() {
    let signature: Vec<u8> = (0..96).map(|index| index as u8).collect();
    let mut buf = [0u8; 512];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .buffer(&signature)
        .expect("encode signature")
        .finish()
        .expect("finish response");

    let resp = TborEccSignResp::decode_response(bytes).expect("decode ECC sign response");

    assert_eq!(resp.signature, signature);
}

/// Verifies that an appended field is ignored for a variable-length ECDSA signature.
#[test]
fn ecc_sign_extra_trailing_toc_entry_is_ignored() {
    let signature: Vec<u8> = (0..96).map(|index| index as u8).collect();
    let mut buf = [0u8; 512];

    let bytes = encode_buffer_with_trailing(&mut buf, &signature, &[0xFF]);

    let resp = TborEccSignResp::decode_response(bytes)
        .expect("forward compatibility: trailing entry must not disturb signature");

    assert_eq!(resp.signature, signature);
}

/// Verifies that multiple appended fields are ignored for an ECDSA signature.
#[test]
fn ecc_sign_multiple_trailing_toc_entries_are_ignored() {
    let signature: Vec<u8> = (0..96).map(|index| index as u8).collect();
    let trailing = [0x11, 0x22, 0x33, 0x44];
    let mut buf = [0u8; 512];

    let bytes = encode_buffer_with_trailing(&mut buf, &signature, &trailing);

    let resp = TborEccSignResp::decode_response(bytes)
        .expect("forward compatibility: trailing entries must not disturb signature");

    assert_eq!(resp.signature, signature);
}

/// Verifies forward-compatible decoding of the maximum-size ECDSA signature buffer.
#[test]
fn ecc_sign_maximum_signature_with_trailing_entry_is_preserved() {
    let signature: Vec<u8> = (0..136).map(|index| index as u8).collect();

    let mut buf = [0u8; 512];
    let bytes = encode_buffer_with_trailing(&mut buf, &signature, &[0xA5]);

    let resp = TborEccSignResp::decode_response(bytes)
        .expect("maximum-size signature with trailing entry must decode");

    assert_eq!(resp.signature, signature);
}
/// Verifies exact-count decoding of a variable-length key report.
#[test]
fn key_report_exact_toc_count_decodes_report() {
    let report: Vec<u8> = (0..512).map(|index| (index & 0xFF) as u8).collect();

    let mut buf = [0u8; 2048];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .buffer(&report)
        .expect("encode report")
        .finish()
        .expect("finish response");

    let resp = TborKeyReportResp::decode_response(bytes).expect("decode key report response");

    assert_eq!(resp.report, report);
}

/// Verifies that an appended field is ignored for a variable-length key report.
#[test]
fn key_report_extra_trailing_toc_entry_is_ignored() {
    let report: Vec<u8> = (0..512).map(|index| (index & 0xFF) as u8).collect();

    let mut buf = [0u8; 2048];

    let bytes = encode_buffer_with_trailing(&mut buf, &report, &[0xFF]);

    let resp = TborKeyReportResp::decode_response(bytes)
        .expect("forward compatibility: trailing entry must not disturb report");

    assert_eq!(resp.report, report);
}

/// Verifies that multiple appended fields are ignored for a variable-length key report.
#[test]
fn key_report_multiple_trailing_toc_entries_are_ignored() {
    let report: Vec<u8> = (0..512).map(|index| (index & 0xFF) as u8).collect();

    let trailing = [0x10, 0x20, 0x30, 0x40];
    let mut buf = [0u8; 2048];

    let bytes = encode_buffer_with_trailing(&mut buf, &report, &trailing);

    let resp = TborKeyReportResp::decode_response(bytes)
        .expect("forward compatibility: trailing entries must not disturb report");

    assert_eq!(resp.report, report);
}

/// Verifies forward-compatible decoding of the maximum-size key report buffer.
#[test]
fn key_report_maximum_report_with_trailing_entry_is_preserved() {
    let report: Vec<u8> = (0..1024).map(|index| (index & 0xFF) as u8).collect();

    let mut buf = [0u8; 2048];

    let bytes = encode_buffer_with_trailing(&mut buf, &report, &[0xA5]);

    let resp = TborKeyReportResp::decode_response(bytes)
        .expect("maximum-size report with trailing entry must decode");

    assert_eq!(resp.report, report);
}

/// Verifies that an appended field is ignored for a variable-length
/// message followed by a fixed-size IV.
#[test]
fn aes_encrypt_decrypt_extra_trailing_toc_entry_is_ignored() {
    let msg: Vec<u8> = (0..64).map(|index| index as u8).collect();
    let iv = [0xA5u8; 16];

    let mut buf = [0u8; 512];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .buffer(&msg)
        .expect("encode transformed message")
        .buffer(&iv)
        .expect("encode IV")
        .uint8(0xFF)
        .expect("encode trailing future field")
        .finish()
        .expect("finish response");

    let resp = TborAesEncryptDecryptResp::decode_response(bytes)
        .expect("forward compatibility: trailing entry must not disturb AES response");

    assert_eq!(resp.msg, msg);
    assert_eq!(resp.iv, iv);
}

/// Verifies that an appended field is ignored for a response containing
/// two variable-length buffers.
#[test]
fn ecc_generate_key_extra_trailing_toc_entry_is_ignored() {
    let masked_key: Vec<u8> = (0..180).map(|index| index as u8).collect();
    let pub_key: Vec<u8> = (0..96)
        .map(|index| 0xFFu8.wrapping_sub(index as u8))
        .collect();

    let mut buf = [0u8; 1024];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .buffer(&masked_key)
        .expect("encode masked key")
        .buffer(&pub_key)
        .expect("encode public key")
        .uint8(0xFF)
        .expect("encode trailing future field")
        .finish()
        .expect("finish response");

    let resp = TborEccGenerateKeyResp::decode_response(bytes)
        .expect("forward compatibility: trailing entry must not disturb generated key response");

    assert_eq!(resp.masked_key, masked_key);
    assert_eq!(resp.pub_key, pub_key);
}

/// Verifies that an appended field is ignored for a mixed scalar and
/// multi-buffer response.
#[test]
fn unwrap_key_extra_trailing_toc_entry_is_ignored() {
    let key_kind = 0x03;

    let masked_key: Vec<u8> = (0..256).map(|index| (index & 0xFF) as u8).collect();

    let pub_key: Vec<u8> = (0..136)
        .map(|index| 0xFFu8.wrapping_sub(index as u8))
        .collect();

    let mut buf = [0u8; 1024];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(key_kind)
        .expect("encode key kind")
        .buffer(&masked_key)
        .expect("encode masked key")
        .buffer(&pub_key)
        .expect("encode public key")
        .uint8(0xFF)
        .expect("encode trailing future field")
        .finish()
        .expect("finish response");

    let resp = TborUnwrapKeyResp::decode_response(bytes)
        .expect("forward compatibility: trailing entry must not disturb unwrap response");

    assert_eq!(resp.key_kind, key_kind);
    assert_eq!(resp.masked_key, masked_key);
    assert_eq!(resp.pub_key, pub_key);
}

/// Verifies that multiple appended fields are ignored for a mixed scalar
/// and multi-buffer response.
#[test]
fn unwrap_key_multiple_trailing_toc_entries_are_ignored() {
    let key_kind = 0x03;
    let masked_key = vec![0x11; 256];
    let pub_key = vec![0x22; 136];

    let mut buf = [0u8; 1024];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(key_kind)
        .expect("encode key kind")
        .buffer(&masked_key)
        .expect("encode masked key")
        .buffer(&pub_key)
        .expect("encode public key")
        .uint8(0xA1)
        .expect("encode future field 1")
        .uint8(0xA2)
        .expect("encode future field 2")
        .uint8(0xA3)
        .expect("encode future field 3")
        .finish()
        .expect("finish response");

    let resp = TborUnwrapKeyResp::decode_response(bytes)
        .expect("forward compatibility: trailing entries must not disturb unwrap response");

    assert_eq!(resp.key_kind, key_kind);
    assert_eq!(resp.masked_key, masked_key);
    assert_eq!(resp.pub_key, pub_key);
}

/// Verifies that a mixed response missing its final required field is truncated.
#[test]
fn unwrap_key_missing_required_field_is_message_truncated() {
    let key_kind = 0x03;
    let masked_key = vec![0x11; 256];

    let mut buf = [0u8; 1024];

    // TborUnwrapKeyResp expects:
    //   key_kind, masked_key, pub_key.
    // Encode only the first two.
    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(key_kind)
        .expect("encode key kind")
        .buffer(&masked_key)
        .expect("encode masked key")
        .finish()
        .expect("finish response");

    let err = TborUnwrapKeyResp::decode_response(bytes)
        .expect_err("missing pub_key must produce MessageTruncated");

    assert_eq!(err, DecodeError::MessageTruncated);
}

/// Verifies that an AES response missing its IV is reported as truncated.
#[test]
fn aes_encrypt_decrypt_missing_iv_is_message_truncated() {
    let msg = vec![0x22; 64];
    let mut buf = [0u8; 512];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .buffer(&msg)
        .expect("encode transformed message")
        .finish()
        .expect("finish response");

    let err = TborAesEncryptDecryptResp::decode_response(bytes)
        .expect_err("missing IV must produce MessageTruncated");

    assert_eq!(err, DecodeError::MessageTruncated);
}

/// Verifies forward compatibility for mixed-width integers and
/// fixed-size buffer fields.
#[test]
fn part_info_extra_trailing_toc_entry_is_ignored() {
    let pid = [0xA5u8; 16];
    let pid_pub_key = [0x5Au8; 96];

    let mut buf = [0u8; 512];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(0x02)
        .expect("encode device kind")
        .uint8(0x03)
        .expect("encode partition state")
        .uint32(0x1122_3344)
        .expect("encode generation")
        .uint64(0x1122_3344_5566_7788)
        .expect("encode owner SVN")
        .uint64(0x8877_6655_4433_2211)
        .expect("encode manufacturer SVN")
        .buffer(&pid)
        .expect("encode PID")
        .buffer(&pid_pub_key)
        .expect("encode PID public key")
        .uint8(0xFF)
        .expect("encode trailing future field")
        .finish()
        .expect("finish response");

    let resp = TborPartInfoResp::decode_response(bytes)
        .expect("trailing entry must not disturb PartInfo response");

    assert_eq!(resp.device_kind, U8::from(0x02));
    assert_eq!(resp.part_state, U8::from(0x03));
    assert_eq!(resp.generation, U32::from(0x1122_3344));
    assert_eq!(resp.owner_svn, U64::from(0x1122_3344_5566_7788));
    assert_eq!(resp.mfgr_svn, U64::from(0x8877_6655_4433_2211));
    assert_eq!(resp.pid, pid);
    assert_eq!(resp.pid_pub_key, pid_pub_key);
}

/// Verifies forward compatibility for a session-id scalar followed by
/// multiple fixed-size array fields.
#[test]
fn session_open_init_extra_trailing_toc_entry_is_ignored() {
    let session_id = 0x1234;
    let pk_resp = [0x11u8; 97];
    let mac_resp = [0x22u8; 48];

    let mut buf = [0u8; 512];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .session_id(session_id)
        .expect("encode session id")
        .buffer(&pk_resp)
        .expect("encode response public key")
        .buffer(&mac_resp)
        .expect("encode response MAC")
        .uint8(0xFF)
        .expect("encode trailing future field")
        .finish()
        .expect("finish response");

    let resp = TborSessionOpenInitResp::decode_response(bytes)
        .expect("trailing entry must not disturb session-open response");

    assert_eq!(resp.session_id, session_id);
    assert_eq!(resp.pk_resp, pk_resp);
    assert_eq!(resp.mac_resp, mac_resp);
}

/// Verifies forward compatibility for the typed `KeyId` TOC entry.
#[test]
fn key_id_extra_trailing_toc_entry_is_ignored() {
    let key_id = 0x1234;

    let mut buf = [0u8; 128];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .key_id(key_id)
        .expect("encode key id")
        .uint8(0x56)
        .expect("encode known value")
        .uint8(0xFF)
        .expect("encode trailing future field")
        .finish()
        .expect("finish response");

    let resp = KeyIdForwardCompatResp::decode_response(bytes)
        .expect("trailing entry must not disturb key-id response");

    assert_eq!(resp.key_id, key_id);
    assert_eq!(resp.value, 0x56);
}
