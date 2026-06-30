// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the #[tbor] derive macro.

#![allow(clippy::unwrap_used)]
#![allow(unsafe_code)]

use azihsm_fw_ddi_tbor_api::tbor;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use zerocopy::little_endian::U16 as Le16;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::TryFromBytes;
use zerocopy::Unaligned;

// SAFETY: test-only branding. Host-side tests have no real DMA engine,
// so the DMA-reachability contract is moot; the brand is needed purely
// to satisfy the parse/decode signatures.
fn brand(b: &[u8]) -> &DmaBuf {
    // SAFETY: see fn-level doc comment.
    unsafe { DmaBuf::from_raw(b) }
}

// ── Request with scalar fields ─────────────────────────────────────────

#[tbor(opcode = 0x09)]
pub struct GetCertificateReq {
    slot_id: u8,
    cert_id: u8,
}

#[test]
fn request_scalar_encode_decode() {
    let mut buf = [0u8; 256];
    let frame = GetCertificateReq::encode(&mut buf)
        .unwrap()
        .slot_id(3)
        .unwrap()
        .cert_id(1)
        .unwrap()
        .finish();

    assert_eq!(frame.len(), 12); // 4 header + 2*4 TOC
    assert_eq!(frame.slot_id(), 3);
    assert_eq!(frame.cert_id(), 1);

    let view = GetCertificateReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.slot_id(), 3);
    assert_eq!(view.cert_id(), 1);
    assert_eq!(view.len(), 12);
}

// ── Response with buffer field ─────────────────────────────────────────

#[tbor(response)]
pub struct GetCertificateResp<'a> {
    #[tbor(max_len = 256)]
    certificate: &'a [u8],
}

#[test]
fn response_buffer_encode_decode() {
    let cert_data = b"mock-certificate-data";
    let mut buf = [0u8; 256];
    let frame = GetCertificateResp::encode(&mut buf, 0, false)
        .unwrap()
        .certificate(cert_data.as_slice())
        .unwrap()
        .finish();

    // 8 header + 4 TOC + 21 data = 33
    assert_eq!(frame.len(), 33);
    assert_eq!(frame.certificate(), cert_data);

    let view = GetCertificateResp::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.status(), 0);
    assert!(!view.fips_approved());
    assert_eq!(view.certificate(), cert_data);
}

// ── Request with mixed types ───────────────────────────────────────────

#[tbor(opcode = 0x72)]
pub struct AesEncryptReq<'a> {
    #[tbor(session_id)]
    sess_id: u16,
    #[tbor(key_id)]
    key_id: u16,
    op: u8,
    #[tbor(max_len = 256)]
    iv: &'a [u8],
    #[tbor(max_len = 256)]
    plaintext: &'a [u8],
}

#[test]
fn request_mixed_types_round_trip() {
    let iv = [0u8; 16];
    let plaintext = b"hello world";

    let mut buf = [0u8; 512];
    let frame = AesEncryptReq::encode(&mut buf)
        .unwrap()
        .sess_id(azihsm_fw_ddi_tbor_api::SessionId(43))
        .unwrap()
        .key_id(azihsm_fw_ddi_tbor_api::KeyId(16))
        .unwrap()
        .op(1)
        .unwrap()
        .iv(&iv)
        .unwrap()
        .plaintext(plaintext.as_slice())
        .unwrap()
        .finish();

    let view = AesEncryptReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.sess_id(), azihsm_fw_ddi_tbor_api::SessionId(43));
    assert_eq!(view.key_id(), azihsm_fw_ddi_tbor_api::KeyId(16));
    assert_eq!(view.op(), 1);
    assert_eq!(view.iv().len(), 16);
    assert_eq!(view.plaintext(), b"hello world");
}

// ── Request with u32/u64 fields ────────────────────────────────────────

#[tbor(opcode = 0x10)]
pub struct BigFieldReq {
    count: u32,
    timestamp: u64,
    flags: u8,
}

#[test]
fn request_u32_u64_round_trip() {
    let mut buf = [0u8; 512];
    let frame = BigFieldReq::encode(&mut buf)
        .unwrap()
        .count(0xDEADBEEF)
        .unwrap()
        .timestamp(0x0123456789ABCDEF)
        .unwrap()
        .flags(0x42)
        .unwrap()
        .finish();

    let view = BigFieldReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.count(), 0xDEADBEEF);
    assert_eq!(view.timestamp(), 0x0123456789ABCDEF);
    assert_eq!(view.flags(), 0x42);
}

// ── Response with FIPS flag ────────────────────────────────────────────

#[tbor(response)]
pub struct DeviceInfoResp {
    kind: u8,
    tables: u8,
}

#[test]
fn response_fips_flag() {
    let mut buf = [0u8; 256];
    let frame = DeviceInfoResp::encode(&mut buf, 0, true)
        .unwrap()
        .kind(2)
        .unwrap()
        .tables(5)
        .unwrap()
        .finish();

    let view = DeviceInfoResp::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.status(), 0);
    assert!(view.fips_approved());
    assert_eq!(view.kind(), 2);
    assert_eq!(view.tables(), 5);
}

// ── Enum derive ────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[tbor]
#[repr(u8)]
pub enum DeviceKind {
    Virtual = 1,
    Physical = 2,
}

#[test]
fn enum_try_from_and_into() {
    assert_eq!(DeviceKind::try_from(1u8), Ok(DeviceKind::Virtual));
    assert_eq!(DeviceKind::try_from(2u8), Ok(DeviceKind::Physical));
    assert_eq!(DeviceKind::try_from(3u8), Err(3u8));

    let v: u8 = DeviceKind::Physical.into();
    assert_eq!(v, 2);
}

// ── Display ────────────────────────────────────────────────────────────

#[test]
fn view_display() {
    let mut buf = [0u8; 256];
    let frame = GetCertificateReq::encode(&mut buf)
        .unwrap()
        .slot_id(3)
        .unwrap()
        .cert_id(1)
        .unwrap()
        .finish();

    let view = GetCertificateReq::decode(brand(frame.as_bytes())).unwrap();
    let output = format!("{}", view);
    assert!(output.contains("GetCertificateReq"));
    assert!(output.contains("slot_id"));
    assert!(output.contains("3"));
}

// ── Decode error cases ─────────────────────────────────────────────────

#[test]
fn decode_wrong_opcode() {
    let mut buf = [0u8; 256];
    let msg = azihsm_fw_ddi_tbor::RequestEncoder::new(&mut buf, 0x01, 0xFF)
        .uint8(1)
        .unwrap()
        .uint8(2)
        .unwrap()
        .finish()
        .unwrap();

    let err = GetCertificateReq::decode(brand(msg)).unwrap_err();
    assert_eq!(err, azihsm_fw_hsm_pal_traits::HsmError::TborOpcodeMismatch);
}

#[test]
fn decode_wrong_toc_count() {
    let mut buf = [0u8; 256];
    let msg = azihsm_fw_ddi_tbor::RequestEncoder::new(&mut buf, 0x01, 0x09)
        .uint8(1)
        .unwrap()
        .uint8(2)
        .unwrap()
        .uint8(3)
        .unwrap()
        .finish()
        .unwrap();

    let err = GetCertificateReq::decode(brand(msg)).unwrap_err();
    assert_eq!(
        err,
        azihsm_fw_hsm_pal_traits::HsmError::TborMessageTruncated
    );
}

#[test]
fn decode_wrong_toc_type() {
    let mut buf = [0u8; 256];
    let msg = azihsm_fw_ddi_tbor::RequestEncoder::new(&mut buf, 0x01, 0x09)
        .session_id(1)
        .unwrap()
        .uint8(2)
        .unwrap()
        .finish()
        .unwrap();

    let err = GetCertificateReq::decode(brand(msg)).unwrap_err();
    assert_eq!(
        err,
        azihsm_fw_hsm_pal_traits::HsmError::TborUnexpectedTocType
    );
}

// ── Optional fields ───────────────────────────────────────────────────

#[tbor(opcode = 0x20)]
pub struct OptionalScalarReq {
    required_id: u8,
    opt_value: Option<u16>,
    opt_flags: Option<u8>,
}

#[test]
fn optional_scalar_all_present() {
    let mut buf = [0u8; 256];
    let frame = OptionalScalarReq::encode(&mut buf)
        .unwrap()
        .required_id(5)
        .unwrap()
        .opt_value(Some(1000))
        .unwrap()
        .opt_flags(Some(0xFF))
        .unwrap()
        .finish();

    assert_eq!(frame.required_id(), 5);
    assert_eq!(frame.opt_value(), Some(1000));
    assert_eq!(frame.opt_flags(), Some(0xFF));

    let view = OptionalScalarReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.required_id(), 5);
    assert_eq!(view.opt_value(), Some(1000));
    assert_eq!(view.opt_flags(), Some(0xFF));
}

#[test]
fn optional_scalar_some_absent() {
    let mut buf = [0u8; 256];
    let frame = OptionalScalarReq::encode(&mut buf)
        .unwrap()
        .required_id(3)
        .unwrap()
        .opt_value(None)
        .unwrap()
        .opt_flags(Some(42))
        .unwrap()
        .finish();

    assert_eq!(frame.required_id(), 3);
    assert_eq!(frame.opt_value(), None);
    assert_eq!(frame.opt_flags(), Some(42));

    let view = OptionalScalarReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.required_id(), 3);
    assert_eq!(view.opt_value(), None);
    assert_eq!(view.opt_flags(), Some(42));
}

#[test]
fn optional_scalar_all_absent_early_finish() {
    // Skip trailing optionals by calling finish() early.
    let mut buf = [0u8; 256];
    let frame = OptionalScalarReq::encode(&mut buf)
        .unwrap()
        .required_id(1)
        .unwrap()
        .finish();

    assert_eq!(frame.required_id(), 1);
    assert_eq!(frame.opt_value(), None);
    assert_eq!(frame.opt_flags(), None);

    let view = OptionalScalarReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.required_id(), 1);
    assert_eq!(view.opt_value(), None);
    assert_eq!(view.opt_flags(), None);
}

#[test]
fn optional_skip_intermediate() {
    // Skip opt_value, jump to opt_flags directly.
    let mut buf = [0u8; 256];
    let frame = OptionalScalarReq::encode(&mut buf)
        .unwrap()
        .required_id(7)
        .unwrap()
        .opt_flags(Some(99))
        .unwrap()
        .finish();

    assert_eq!(frame.required_id(), 7);
    assert_eq!(frame.opt_value(), None);
    assert_eq!(frame.opt_flags(), Some(99));
}

// ── Optional buffer fields ────────────────────────────────────────────

#[tbor(opcode = 0x21)]
pub struct OptionalBufferReq<'a> {
    #[tbor(session_id)]
    sess: u16,
    #[tbor(max_len = 256)]
    data: &'a [u8],
    #[tbor(max_len = 256)]
    opt_extra: Option<&'a [u8]>,
}

#[test]
fn optional_buffer_present() {
    let mut buf = [0u8; 512];
    let frame = OptionalBufferReq::encode(&mut buf)
        .unwrap()
        .sess(azihsm_fw_ddi_tbor_api::SessionId(10))
        .unwrap()
        .data(b"hello")
        .unwrap()
        .opt_extra(Some(b"world"))
        .unwrap()
        .finish();

    assert_eq!(frame.sess(), azihsm_fw_ddi_tbor_api::SessionId(10));
    assert_eq!(frame.data(), b"hello");
    assert_eq!(frame.opt_extra(), Some(b"world".as_slice()));

    let view = OptionalBufferReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.sess(), azihsm_fw_ddi_tbor_api::SessionId(10));
    assert_eq!(view.data(), b"hello");
    assert!(view.opt_extra().is_some_and(|d| &**d == b"world"));
}

#[test]
fn optional_buffer_absent_early_finish() {
    let mut buf = [0u8; 512];
    let frame = OptionalBufferReq::encode(&mut buf)
        .unwrap()
        .sess(azihsm_fw_ddi_tbor_api::SessionId(10))
        .unwrap()
        .data(b"hello")
        .unwrap()
        .finish();

    assert_eq!(frame.data(), b"hello");
    assert_eq!(frame.opt_extra(), None);

    let view = OptionalBufferReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.data(), b"hello");
    assert_eq!(view.opt_extra(), None);

    // 4 header + 3*4 TOC + 5 data = 21
    assert_eq!(frame.len(), 21);
}

// ── Optional with offset types: Some/None/Some pattern ────────────────

#[tbor(opcode = 0x22)]
pub struct SomeNoneSomeReq<'a> {
    #[tbor(max_len = 256)]
    first: &'a [u8],
    middle: Option<u32>,
    #[tbor(max_len = 256)]
    last: &'a [u8],
}

#[test]
fn some_none_some_offset_compression() {
    let mut buf = [0u8; 512];
    // Skip middle, jump to last.
    let frame = SomeNoneSomeReq::encode(&mut buf)
        .unwrap()
        .first(b"AAAA")
        .unwrap()
        .last(b"BBBB")
        .unwrap()
        .finish();

    assert_eq!(frame.first(), b"AAAA");
    assert_eq!(frame.middle(), None);
    assert_eq!(frame.last(), b"BBBB");

    // Data section: 4 (first) + 0 (middle absent) + 4 (last) = 8
    // Total: 4 header + 3*4 TOC + 8 data = 24
    assert_eq!(frame.len(), 24);

    let view = SomeNoneSomeReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.first(), b"AAAA");
    assert_eq!(view.middle(), None);
    assert_eq!(view.last(), b"BBBB");
}

#[test]
fn some_some_some_full() {
    let mut buf = [0u8; 512];
    let frame = SomeNoneSomeReq::encode(&mut buf)
        .unwrap()
        .first(b"AAAA")
        .unwrap()
        .middle(Some(0xDEAD))
        .unwrap()
        .last(b"BBBB")
        .unwrap()
        .finish();

    assert_eq!(frame.first(), b"AAAA");
    assert_eq!(frame.middle(), Some(0xDEAD));
    assert_eq!(frame.last(), b"BBBB");

    assert_eq!(frame.len(), 28);
}

// ── Optional response ─────────────────────────────────────────────────

#[tbor(response)]
pub struct OptionalResp<'a> {
    result_code: u8,
    #[tbor(max_len = 256)]
    opt_data: Option<&'a [u8]>,
}

#[test]
fn optional_response_round_trip() {
    let mut buf = [0u8; 256];
    let frame = OptionalResp::encode(&mut buf, 0, true)
        .unwrap()
        .result_code(1)
        .unwrap()
        .opt_data(Some(b"payload"))
        .unwrap()
        .finish();

    let view = OptionalResp::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.status(), 0);
    assert!(view.fips_approved());
    assert_eq!(view.result_code(), 1);
    assert!(view.opt_data().is_some_and(|d| &**d == b"payload"));

    // Without data — early finish
    let mut buf2 = [0u8; 256];
    let frame2 = OptionalResp::encode(&mut buf2, 0x05, false)
        .unwrap()
        .result_code(0)
        .unwrap()
        .finish();

    let view2 = OptionalResp::decode(brand(frame2.as_bytes())).unwrap();
    assert_eq!(view2.status(), 0x05);
    assert_eq!(view2.result_code(), 0);
    assert_eq!(view2.opt_data(), None);
}

// ── Display with optional fields ──────────────────────────────────────

#[test]
fn optional_display() {
    let mut buf = [0u8; 256];
    let frame = OptionalScalarReq::encode(&mut buf)
        .unwrap()
        .required_id(5)
        .unwrap()
        .opt_value(Some(100))
        .unwrap()
        .finish();

    let view = OptionalScalarReq::decode(brand(frame.as_bytes())).unwrap();
    let output = format!("{}", view);
    assert!(output.contains("OptionalScalarReq"));
    assert!(output.contains("required_id"));
    assert!(output.contains("5"));
    assert!(output.contains("100"));
    assert!(output.contains("None"));
}

// ── Typed u8 newtype field (#[tbor(U8)]) ──────────────────────────────

/// Plain single-field newtype over `u8`, used to exercise a typed
/// inline-`u8` schema field. No validation — any byte round-trips.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireTag(pub u8);

#[tbor(opcode = 0x41)]
pub struct TypedU8Req {
    psk_id: u8,
    // Carried as an inline `Uint8` on the wire; the accessor/encoder are
    // typed `WireTag` rather than a bare `u8`. `#[tbor(U8)]` declares the
    // wire width (the macro cannot see that `WireTag` is u8-wide).
    #[tbor(U8)]
    suite_id: WireTag,
}

#[test]
fn typed_u8_newtype_round_trips() {
    let mut buf = [0u8; 256];
    let frame = TypedU8Req::encode(&mut buf)
        .unwrap()
        .psk_id(1)
        .unwrap()
        .suite_id(WireTag(0x07))
        .unwrap()
        .finish();

    // Wire is identical to two inline u8 fields: 4 header + 2*4 TOC.
    assert_eq!(frame.len(), 12);
    // Typed accessor returns the newtype.
    assert_eq!(frame.suite_id(), WireTag(0x07));

    let view = TypedU8Req::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.psk_id(), 1);
    assert_eq!(view.suite_id(), WireTag(0x07));
    // The wire byte is the raw inner value (no validation/transform).
    assert_eq!(view.suite_id().0, 0x07);
}

// ── Alignment padding ─────────────────────────────────────────────────

#[tbor(opcode = 0x30)]
pub struct AlignedReq<'a> {
    #[tbor(max_len = 256)]
    header: &'a [u8],
    #[tbor(align = 4)]
    value: u32,
}

#[test]
fn aligned_field_with_padding_needed() {
    let mut buf = [0u8; 512];
    let frame = AlignedReq::encode(&mut buf)
        .unwrap()
        .header(b"ABCDE")
        .unwrap()
        .value(0xDEADBEEF)
        .unwrap()
        .finish();

    assert_eq!(frame.header(), b"ABCDE");
    assert_eq!(frame.value(), 0xDEADBEEF);

    let view = AlignedReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.header(), b"ABCDE");
    assert_eq!(view.value(), 0xDEADBEEF);
}

#[test]
fn aligned_field_already_aligned() {
    let mut buf = [0u8; 512];
    let frame = AlignedReq::encode(&mut buf)
        .unwrap()
        .header(b"ABCD")
        .unwrap()
        .value(0x12345678)
        .unwrap()
        .finish();

    assert_eq!(frame.header(), b"ABCD");
    assert_eq!(frame.value(), 0x12345678);

    let view = AlignedReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.header(), b"ABCD");
    assert_eq!(view.value(), 0x12345678);
}

// ── 8-byte alignment ─────────────────────────────────────────────────

#[tbor(opcode = 0x31)]
pub struct Aligned8Req<'a> {
    #[tbor(max_len = 256)]
    prefix: &'a [u8],
    #[tbor(align = 8)]
    timestamp: u64,
}

#[test]
fn align_8_with_padding() {
    let mut buf = [0u8; 512];
    let frame = Aligned8Req::encode(&mut buf)
        .unwrap()
        .prefix(b"ABC")
        .unwrap()
        .timestamp(0x0123456789ABCDEF)
        .unwrap()
        .finish();

    assert_eq!(frame.prefix(), b"ABC");
    assert_eq!(frame.timestamp(), 0x0123456789ABCDEF);

    let view = Aligned8Req::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.prefix(), b"ABC");
    assert_eq!(view.timestamp(), 0x0123456789ABCDEF);
}

// ── Multiple aligned fields ───────────────────────────────────────────

#[tbor(opcode = 0x32)]
pub struct MultiAlignReq<'a> {
    #[tbor(max_len = 256)]
    tag: &'a [u8],
    #[tbor(align = 4)]
    count: u32,
    #[tbor(max_len = 256)]
    extra: &'a [u8],
    #[tbor(align = 4)]
    checksum: u32,
}

#[test]
fn multiple_aligned_fields() {
    let mut buf = [0u8; 512];
    let frame = MultiAlignReq::encode(&mut buf)
        .unwrap()
        .tag(b"XYZ")
        .unwrap()
        .count(100)
        .unwrap()
        .extra(b"hello")
        .unwrap()
        .checksum(0xABCD1234)
        .unwrap()
        .finish();

    assert_eq!(frame.tag(), b"XYZ");
    assert_eq!(frame.count(), 100);
    assert_eq!(frame.extra(), b"hello");
    assert_eq!(frame.checksum(), 0xABCD1234);

    let view = MultiAlignReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.tag(), b"XYZ");
    assert_eq!(view.count(), 100);
    assert_eq!(view.extra(), b"hello");
    assert_eq!(view.checksum(), 0xABCD1234);
}

// ── Unaligned typed slice ─────────────────────────────────────────────

/// `#[repr(C)]` POD with `Unaligned` little-endian `U16` fields →
/// alignment 1.  Exercises a typed-slice `&[T]` field: because `T` is
/// `Unaligned`, the derive inserts **no** alignment padding, and the
/// zero-copy `&[Pair]` cast is sound even when the slice lands on an odd
/// data offset.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned,
)]
#[repr(C)]
struct Pair {
    a: Le16,
    b: Le16,
}

#[tbor(opcode = 0x40)]
pub struct TypedSliceReq<'a> {
    // An odd-length leading buffer forces the following typed slice to a
    // misaligned data offset. Because `Pair` is `Unaligned`, the slice
    // still decodes correctly with no padding entry.
    #[tbor(max_len = 64)]
    lead: &'a [u8],
    #[tbor(min_len = 1, max_len = 16)]
    items: &'a [Pair],
}

#[test]
fn typed_slice_unaligned_needs_no_padding() {
    #[repr(align(8))]
    struct AlignedBuf([u8; 512]);

    let pairs = [
        Pair {
            a: Le16::new(0x0102),
            b: Le16::new(0x0304),
        },
        Pair {
            a: Le16::new(0x0506),
            b: Le16::new(0x0708),
        },
    ];

    let mut backing = AlignedBuf([0u8; 512]);
    let frame = TypedSliceReq::encode(&mut backing.0)
        .unwrap()
        // 5 bytes → odd, so `items` lands on an odd offset. An `Unaligned`
        // element type means no padding entry is inserted, yet the cast
        // is still sound.
        .lead(b"ABCDE")
        .unwrap()
        .items(&pairs)
        .unwrap()
        .finish();

    assert_eq!(frame.lead(), b"ABCDE");

    let view = TypedSliceReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.lead(), b"ABCDE");
    // A non-empty, correct slice proves the `Unaligned` cast succeeded at
    // an odd offset with no `#[tbor(align)]` and no padding entry.
    assert_eq!(view.items(), &pairs[..]);
}

#[tbor(opcode = 0x33)]
pub struct OptAlignReq<'a> {
    #[tbor(max_len = 256)]
    prefix: &'a [u8],
    #[tbor(align = 4)]
    opt_value: Option<u32>,
    #[tbor(max_len = 256)]
    suffix: &'a [u8],
}

#[test]
fn optional_aligned_present() {
    let mut buf = [0u8; 512];
    let frame = OptAlignReq::encode(&mut buf)
        .unwrap()
        .prefix(b"AB")
        .unwrap()
        .opt_value(Some(42))
        .unwrap()
        .suffix(b"end")
        .unwrap()
        .finish();

    assert_eq!(frame.prefix(), b"AB");
    assert_eq!(frame.opt_value(), Some(42));
    assert_eq!(frame.suffix(), b"end");

    let view = OptAlignReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.prefix(), b"AB");
    assert_eq!(view.opt_value(), Some(42));
    assert_eq!(view.suffix(), b"end");
}

#[test]
fn optional_aligned_absent_skip_ahead() {
    // Skip opt_value, jump to suffix directly.
    let mut buf = [0u8; 512];
    let frame = OptAlignReq::encode(&mut buf)
        .unwrap()
        .prefix(b"AB")
        .unwrap()
        .suffix(b"end")
        .unwrap()
        .finish();

    assert_eq!(frame.prefix(), b"AB");
    assert_eq!(frame.opt_value(), None);
    assert_eq!(frame.suffix(), b"end");

    let view = OptAlignReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.prefix(), b"AB");
    assert_eq!(view.opt_value(), None);
    assert_eq!(view.suffix(), b"end");
}

// ── Buffer too small ──────────────────────────────────────────────────

#[test]
fn encode_buffer_too_small() {
    let mut buf = [0u8; 4]; // too small for header + TOC
    let result = GetCertificateReq::encode(&mut buf);
    assert!(matches!(
        result,
        Err(azihsm_fw_hsm_pal_traits::HsmError::TborBufferTooSmall)
    ));
}

// ── Fixed-size arrays [u8; N] ─────────────────────────────────────────

#[tbor(opcode = 0x40)]
pub struct FixedArrayReq<'a> {
    nonce: [u8; 12],
    #[tbor(max_len = 256)]
    payload: &'a [u8],
}

#[test]
fn fixed_array_round_trip() {
    let nonce = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    ];
    let mut buf = [0u8; 256];
    let frame = FixedArrayReq::encode(&mut buf)
        .unwrap()
        .nonce(&nonce)
        .unwrap()
        .payload(b"test data")
        .unwrap()
        .finish();

    // Frame accessor returns &[u8; 12]
    assert_eq!(frame.nonce(), &nonce);
    assert_eq!(frame.payload(), b"test data");

    // Decode
    let view = FixedArrayReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.nonce(), &nonce);
    assert_eq!(view.payload(), b"test data");
}

#[test]
fn fixed_array_wrong_length_rejected() {
    // Manually encode with wrong length for the nonce field.
    let mut buf = [0u8; 256];
    let msg = azihsm_fw_ddi_tbor::RequestEncoder::new(&mut buf, 0x01, 0x40)
        .buffer(b"short") // only 5 bytes instead of 12
        .unwrap()
        .buffer(b"payload")
        .unwrap()
        .finish()
        .unwrap();

    let err = FixedArrayReq::decode(brand(msg)).unwrap_err();
    assert_eq!(
        err,
        azihsm_fw_hsm_pal_traits::HsmError::TborInvalidFixedLength
    );
}

// ── Length constraints on slices ──────────────────────────────────────

#[tbor(opcode = 0x41)]
pub struct ConstrainedReq<'a> {
    #[tbor(min_len = 1, max_len = 32)]
    tag: &'a [u8],
    #[tbor(max_len = 128)]
    data: &'a [u8],
}

#[test]
fn len_constraint_valid() {
    let mut buf = [0u8; 512];
    let frame = ConstrainedReq::encode(&mut buf)
        .unwrap()
        .tag(b"hello")
        .unwrap()
        .data(b"world")
        .unwrap()
        .finish();

    assert_eq!(frame.tag(), b"hello");
    assert_eq!(frame.data(), b"world");

    let view = ConstrainedReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.tag(), b"hello");
    assert_eq!(view.data(), b"world");
}

#[test]
fn len_constraint_too_short() {
    let mut buf = [0u8; 512];
    // tag has min_len=1, empty slice should fail.
    let result = ConstrainedReq::encode(&mut buf).unwrap().tag(b"");
    assert!(matches!(
        result,
        Err(azihsm_fw_hsm_pal_traits::HsmError::TborDataTooLarge)
    ));
}

#[test]
fn len_constraint_too_long() {
    let mut buf = [0u8; 512];
    let long_tag = [0u8; 33]; // max_len is 32
    let result = ConstrainedReq::encode(&mut buf).unwrap().tag(&long_tag);
    assert!(matches!(
        result,
        Err(azihsm_fw_hsm_pal_traits::HsmError::TborDataTooLarge)
    ));
}

#[test]
fn len_constraint_decode_too_short() {
    // Manually encode with empty tag (violates min_len=1).
    let mut buf = [0u8; 256];
    let msg = azihsm_fw_ddi_tbor::RequestEncoder::new(&mut buf, 0x01, 0x41)
        .buffer(&[]) // empty tag
        .unwrap()
        .buffer(b"data")
        .unwrap()
        .finish()
        .unwrap();

    let err = ConstrainedReq::decode(brand(msg)).unwrap_err();
    assert_eq!(
        err,
        azihsm_fw_hsm_pal_traits::HsmError::TborInvalidFixedLength
    );
}

// ── All-optional struct (finish from State0) ──────────────────────────

#[tbor(opcode = 0x60)]
pub struct AllOptReq {
    opt_a: Option<u8>,
    opt_b: Option<u16>,
}

#[test]
fn all_optional_immediate_finish() {
    let mut buf = [0u8; 64];
    let frame = AllOptReq::encode(&mut buf).unwrap().finish();

    assert_eq!(frame.opt_a(), None);
    assert_eq!(frame.opt_b(), None);

    let view = AllOptReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.opt_a(), None);
    assert_eq!(view.opt_b(), None);
}

#[test]
fn all_optional_set_first_then_finish() {
    let mut buf = [0u8; 64];
    let frame = AllOptReq::encode(&mut buf)
        .unwrap()
        .opt_a(Some(42))
        .unwrap()
        .finish();

    assert_eq!(frame.opt_a(), Some(42));
    assert_eq!(frame.opt_b(), None);
}

// ── Sealed key derive coverage ────────────────────────────────────────

#[tbor(opcode = 0x61)]
pub struct SealedKeyReq<'a> {
    #[tbor(session_id)]
    session: u16,
    #[tbor(sealed_key, max_len = 256)]
    key_blob: &'a [u8],
}

#[test]
fn derive_sealed_key_round_trip() {
    let blob = b"sealed-key-data-here";
    let mut buf = [0u8; 256];
    let frame = SealedKeyReq::encode(&mut buf)
        .unwrap()
        .session(azihsm_fw_ddi_tbor_api::SessionId(5))
        .unwrap()
        .key_blob(blob.as_slice())
        .unwrap()
        .finish();

    assert_eq!(frame.session(), azihsm_fw_ddi_tbor_api::SessionId(5));
    assert_eq!(frame.key_blob(), blob);

    let view = SealedKeyReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.session(), azihsm_fw_ddi_tbor_api::SessionId(5));
    assert_eq!(view.key_blob(), blob);
}

// ── Optional fixed array ──────────────────────────────────────────────

#[tbor(opcode = 0x62)]
pub struct OptFixedArrayReq {
    required: u8,
    opt_nonce: Option<[u8; 16]>,
}

#[test]
fn optional_fixed_array_present() {
    let nonce = [0xAA; 16];
    let mut buf = [0u8; 256];
    let frame = OptFixedArrayReq::encode(&mut buf)
        .unwrap()
        .required(1)
        .unwrap()
        .opt_nonce(Some(&nonce))
        .unwrap()
        .finish();

    assert_eq!(frame.opt_nonce(), Some(&nonce));

    let view = OptFixedArrayReq::decode(brand(frame.as_bytes())).unwrap();
    assert!(view.opt_nonce().is_some_and(|d| **d == nonce));
}

#[test]
fn optional_fixed_array_absent() {
    let mut buf = [0u8; 256];
    let frame = OptFixedArrayReq::encode(&mut buf)
        .unwrap()
        .required(1)
        .unwrap()
        .finish();

    assert_eq!(frame.opt_nonce(), None);

    let view = OptFixedArrayReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.opt_nonce(), None);
}

// ── Length constraint exact boundaries ────────────────────────────────

#[test]
fn len_constraint_exact_min() {
    let mut buf = [0u8; 512];
    // min_len=1: exactly 1 byte should pass.
    let frame = ConstrainedReq::encode(&mut buf)
        .unwrap()
        .tag(b"x")
        .unwrap()
        .data(b"d")
        .unwrap()
        .finish();
    assert_eq!(frame.tag(), b"x");
}

#[test]
fn len_constraint_exact_max() {
    let mut buf = [0u8; 512];
    let tag32 = [0u8; 32]; // max_len=32: exactly 32 should pass.
    let frame = ConstrainedReq::encode(&mut buf)
        .unwrap()
        .tag(&tag32)
        .unwrap()
        .data(b"d")
        .unwrap()
        .finish();
    assert_eq!(frame.tag().len(), 32);
}

// ── Response encode buffer too small ──────────────────────────────────

#[test]
fn response_encode_buffer_too_small() {
    let mut buf = [0u8; 4]; // too small for response header + TOC
    let result = GetCertificateResp::encode(&mut buf, 0, false);
    assert!(matches!(
        result,
        Err(azihsm_fw_hsm_pal_traits::HsmError::TborBufferTooSmall)
    ));
}

// ── Enum repr(u16) ────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[tbor]
#[repr(u16)]
pub enum StatusCode {
    Ok = 0,
    NotFound = 404,
    Error = 500,
}

#[test]
fn enum_u16_try_from_and_into() {
    assert_eq!(StatusCode::try_from(0u16), Ok(StatusCode::Ok));
    assert_eq!(StatusCode::try_from(404u16), Ok(StatusCode::NotFound));
    assert_eq!(StatusCode::try_from(500u16), Ok(StatusCode::Error));
    assert_eq!(StatusCode::try_from(999u16), Err(999u16));

    let v: u16 = StatusCode::NotFound.into();
    assert_eq!(v, 404);
}

// ── Derive response wrong toc count/type ──────────────────────────────

#[test]
fn derive_response_wrong_toc_count() {
    let mut buf = [0u8; 256];
    let msg = azihsm_fw_ddi_tbor::ResponseEncoder::new(&mut buf, 0x01, 0, false)
        .uint8(1)
        .unwrap()
        .uint8(2)
        .unwrap()
        .uint8(3)
        .unwrap()
        .finish()
        .unwrap();

    // DeviceInfoResp expects 2 TOC entries, not 3.
    let err = DeviceInfoResp::decode(brand(msg)).unwrap_err();
    assert_eq!(
        err,
        azihsm_fw_hsm_pal_traits::HsmError::TborMessageTruncated
    );
}

// ── Include field groups ──────────────────────────────────────────────

#[tbor(fields)]
pub struct CryptoHeader {
    #[tbor(session_id)]
    session: u16,
    #[tbor(key_id)]
    key: u16,
    algorithm: u8,
}

#[tbor(opcode = 0x70)]
pub struct IncludeReq<'a> {
    #[tbor(include)]
    header: CryptoHeader,
    #[tbor(max_len = 256)]
    payload: &'a [u8],
}

#[test]
fn include_group_encode_decode() {
    let mut buf = [0u8; 512];
    let frame = IncludeReq::encode(&mut buf)
        .unwrap()
        .header(|h| {
            h.session(azihsm_fw_ddi_tbor_api::SessionId(7))?
                .key(azihsm_fw_ddi_tbor_api::KeyId(42))?
                .algorithm(3)
        })
        .unwrap()
        .payload(b"test data")
        .unwrap()
        .finish();

    // Verify via raw core decoder.
    let raw = azihsm_fw_ddi_tbor::RequestView::parse(brand(frame.as_bytes())).unwrap();
    assert_eq!(raw.opcode(), 0x70);
    assert_eq!(raw.toc_count(), 4);
    assert!(matches!(
        raw.toc_entry(0),
        azihsm_fw_ddi_tbor::TocEntry::SessionId(7)
    ));
    assert!(matches!(
        raw.toc_entry(1),
        azihsm_fw_ddi_tbor::TocEntry::KeyId(42)
    ));
    assert!(matches!(
        raw.toc_entry(2),
        azihsm_fw_ddi_tbor::TocEntry::Uint8(3)
    ));
    match raw.toc_entry(3) {
        azihsm_fw_ddi_tbor::TocEntry::Buffer(data) => assert_eq!(data, b"test data"),
        other => panic!("expected Buffer, got {:?}", other),
    }
}

#[test]
fn include_group_constants() {
    assert_eq!(CryptoHeader::TOC_COUNT, 3);
    assert_eq!(CryptoHeader::WORST_CASE_DATA_SIZE, 0);
}

// ── Nested include field groups ───────────────────────────────────────

#[tbor(fields)]
pub struct KeyInfo {
    #[tbor(key_id)]
    key: u16,
    key_type: u8,
}

#[tbor(fields)]
pub struct FullHeader {
    #[tbor(session_id)]
    session: u16,
    #[tbor(include)]
    key_info: KeyInfo,
    algorithm: u8,
}

#[tbor(opcode = 0x71)]
pub struct NestedIncludeReq<'a> {
    #[tbor(include)]
    header: FullHeader,
    #[tbor(max_len = 256)]
    payload: &'a [u8],
}

#[test]
fn nested_include_encode_decode() {
    let mut buf = [0u8; 512];
    let frame = NestedIncludeReq::encode(&mut buf)
        .unwrap()
        .header(|h| {
            h.session(azihsm_fw_ddi_tbor_api::SessionId(99))?
                .key_info(|k: KeyInfoEnc<'_, KeyInfoS0>| {
                    k.key(azihsm_fw_ddi_tbor_api::KeyId(5))?.key_type(2)
                })?
                .algorithm(3)
        })
        .unwrap()
        .payload(b"nested!")
        .unwrap()
        .finish();

    // Wire: flat 5 TOC entries + 7 bytes data
    let raw = azihsm_fw_ddi_tbor::RequestView::parse(brand(frame.as_bytes())).unwrap();
    assert_eq!(raw.opcode(), 0x71);
    assert_eq!(raw.toc_count(), 5);
    assert!(matches!(
        raw.toc_entry(0),
        azihsm_fw_ddi_tbor::TocEntry::SessionId(99)
    ));
    assert!(matches!(
        raw.toc_entry(1),
        azihsm_fw_ddi_tbor::TocEntry::KeyId(5)
    ));
    assert!(matches!(
        raw.toc_entry(2),
        azihsm_fw_ddi_tbor::TocEntry::Uint8(2)
    ));
    assert!(matches!(
        raw.toc_entry(3),
        azihsm_fw_ddi_tbor::TocEntry::Uint8(3)
    ));
    match raw.toc_entry(4) {
        azihsm_fw_ddi_tbor::TocEntry::Buffer(data) => assert_eq!(data, b"nested!"),
        other => panic!("expected Buffer, got {:?}", other),
    }
}

#[test]
fn nested_include_constants() {
    assert_eq!(KeyInfo::TOC_COUNT, 2);
    // FullHeader: 1 (session) + KeyInfo::TOC_COUNT (2) + 1 (algorithm) = 4
    assert_eq!(FullHeader::TOC_COUNT, 2 + KeyInfo::TOC_COUNT);
}

// ── Trait-based dispatch ──────────────────────────────────────────────

use azihsm_fw_ddi_tbor_api::TborRequest;

#[test]
fn tbor_request_trait_opcode() {
    // Every #[tbor(opcode = N)] struct implements TborRequest.
    assert_eq!(GetCertificateReq::OPCODE, 0x09);
    assert_eq!(IncludeReq::OPCODE, 0x70);
    assert_eq!(NestedIncludeReq::OPCODE, 0x71);
}

#[test]
fn tbor_request_trait_decode() {
    // Encode via the struct, decode via the trait.
    let mut buf = [0u8; 256];
    let frame = GetCertificateReq::encode(&mut buf)
        .unwrap()
        .slot_id(3)
        .unwrap()
        .cert_id(1)
        .unwrap()
        .finish();

    let view = <GetCertificateReq as TborRequest>::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.slot_id(), 3);
    assert_eq!(view.cert_id(), 1);
}

#[test]
fn trait_based_dispatch() {
    // Simulate receiving a wire message and dispatching by opcode.
    let mut buf = [0u8; 256];
    let frame = GetCertificateReq::encode(&mut buf)
        .unwrap()
        .slot_id(5)
        .unwrap()
        .cert_id(2)
        .unwrap()
        .finish();

    let wire = frame.as_bytes();
    let raw = azihsm_fw_ddi_tbor::RequestView::parse(brand(wire)).unwrap();

    let result = match raw.opcode() {
        GetCertificateReq::OPCODE => {
            let view = GetCertificateReq::decode(brand(wire)).unwrap();
            assert_eq!(view.slot_id(), 5);
            Ok("get_cert")
        }
        BigFieldReq::OPCODE => Ok("big_field"),
        _ => Err("unknown opcode"),
    };
    assert_eq!(result, Ok("get_cert"));
}

// ── ViewMut with mixed scalar + mutable-buffer fields ──────────────────
//
// Regression guard for codegen_view_mut: `Uint32`/`Uint64` are
// data-section types and participate in the `split_at_mut` chain, but
// the destructured `ViewMut` field type is `u32`/`u64`. The codegen
// must convert the split slice to the numeric value at struct-init
// time, not pass the slice through (which would not type-check).
#[tbor(opcode = 0x42)]
pub struct MixedMutableReq<'a> {
    pub epoch: u32,
    pub serial: u64,
    #[tbor(max_len = 32, mutable)]
    pub payload: &'a [u8],
}

#[test]
fn decode_mut_with_uint32_uint64_siblings() {
    let mut buf = [0u8; 256];
    let frame = MixedMutableReq::encode(&mut buf)
        .unwrap()
        .epoch(0xCAFEBABE)
        .unwrap()
        .serial(0x0011_2233_4455_6677)
        .unwrap()
        .payload(b"hello-payload")
        .unwrap()
        .finish();

    let frame_len = frame.len();
    // SAFETY: test-only branding of a heap-resident buffer; see
    // module-level brand() helper.
    let wire_mut: &mut DmaBuf = unsafe { DmaBuf::from_raw_mut(&mut buf[..frame_len]) };
    let view = MixedMutableReq::decode_mut(wire_mut).unwrap();
    assert_eq!(view.epoch, 0xCAFEBABE);
    assert_eq!(view.serial, 0x0011_2233_4455_6677);
    assert_eq!(&**view.payload, b"hello-payload");
}

// ── Field group with typed-slice + buffer fields (include) ────────────

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned,
)]
#[repr(C)]
struct GrpPair {
    a: zerocopy::little_endian::U16,
    b: zerocopy::little_endian::U16,
}

#[tbor(fields)]
pub struct EvidenceLikeGroup<'a> {
    #[tbor(session_id)]
    session: u16,
    #[tbor(buffer, max_len = 64)]
    items: &'a [GrpPair],
    #[tbor(buffer, len = 4)]
    one: &'a GrpPair,
    #[tbor(buffer, max_len = 64)]
    blob: &'a [u8],
}

#[tbor(opcode = 0x7B)]
pub struct GroupBufReq<'a> {
    #[tbor(include)]
    ev: EvidenceLikeGroup<'a>,
    #[tbor(max_len = 32)]
    tail: &'a [u8],
}

#[test]
fn field_group_typed_slice_and_buffer_round_trip() {
    let pairs = [
        GrpPair {
            a: zerocopy::little_endian::U16::new(0x0102),
            b: zerocopy::little_endian::U16::new(0x0304),
        },
        GrpPair {
            a: zerocopy::little_endian::U16::new(0x0506),
            b: zerocopy::little_endian::U16::new(0x0708),
        },
    ];

    let one = GrpPair {
        a: zerocopy::little_endian::U16::new(0xAABB),
        b: zerocopy::little_endian::U16::new(0xCCDD),
    };

    let mut buf = [0u8; 512];
    let frame = GroupBufReq::encode(&mut buf)
        .unwrap()
        .ev(|g| {
            g.session(azihsm_fw_ddi_tbor_api::SessionId(42))?
                .items(&pairs)?
                .one(&one)?
                .blob(b"BLOB")
        })
        .unwrap()
        .tail(b"TAIL")
        .unwrap()
        .finish();

    let view = GroupBufReq::decode(brand(frame.as_bytes())).unwrap();
    let ev = view.ev();
    assert_eq!(ev.session(), azihsm_fw_ddi_tbor_api::SessionId(42));
    assert_eq!(ev.items(), &pairs[..]);
    // Single typed-POD ref (`&GrpPair`) borrowed zero-copy from the group.
    assert_eq!(ev.one(), &one);
    assert_eq!(&**ev.blob(), b"BLOB");
    // The field after the included group must read at the group-adjusted
    // TOC offset.
    assert_eq!(&**view.tail(), b"TAIL");
}

#[tbor(opcode = 0x7C)]
pub struct SinglePodReq<'a> {
    #[tbor(buffer, len = 4)]
    pair: &'a GrpPair,
    #[tbor(max_len = 16)]
    tail: &'a [u8],
}

#[test]
fn single_typed_pod_ref_top_level_round_trip() {
    let p = GrpPair {
        a: zerocopy::little_endian::U16::new(0x1234),
        b: zerocopy::little_endian::U16::new(0x5678),
    };
    let mut buf = [0u8; 256];
    let frame = SinglePodReq::encode(&mut buf)
        .unwrap()
        .pair(&p)
        .unwrap()
        .tail(b"z")
        .unwrap()
        .finish();
    let view = SinglePodReq::decode(brand(frame.as_bytes())).unwrap();
    assert_eq!(view.pair(), &p);
    assert_eq!(&**view.tail(), b"z");
}
