// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared types and helpers for TBOR encoder fuzz targets.

#![allow(dead_code)]

use azihsm_ddi_tbor_codec::Encoder;
use azihsm_ddi_tbor_codec::MAX_DATA_SIZE;
use azihsm_ddi_tbor_codec::MAX_TOC_ENTRIES;
use azihsm_ddi_tbor_codec::TOC_ENTRY_LEN;
use azihsm_ddi_tbor_codec::REQ_HEADER_LEN;
use azihsm_ddi_tbor_codec::RESP_HEADER_LEN;
use azihsm_ddi_tbor_codec::RequestView;
use azihsm_ddi_tbor_codec::ResponseView;
use azihsm_ddi_tbor_codec::TocEntry;
use azihsm_ddi_tbor_codec::header::Header;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;

/// Fuzz operations corresponding to the TOC builder methods on
/// [`Encoder`].
#[derive(Arbitrary, Debug)]
pub enum EncoderTOCBuilders {
    SessionId(u16),
    KeyId(u16),
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Buffer(Vec<u8>),
    BufferReserve(u16),
    SealedKey(Vec<u8>),
    None,
    Padding(u16),
}

/// Buffer size used by request encoder fuzz targets.
///
/// Sized to hold the worst-case request: a full header, the maximum number
/// of TOC entries (each a 4-byte / `u32` wire word), and the maximum data
/// section.
pub const FUZZ_REQ_BUF_SIZE: usize =
    REQ_HEADER_LEN + MAX_TOC_ENTRIES * TOC_ENTRY_LEN + MAX_DATA_SIZE;

/// Buffer size used by response encoder fuzz targets.
pub const FUZZ_RESP_BUF_SIZE: usize =
    RESP_HEADER_LEN + MAX_TOC_ENTRIES * TOC_ENTRY_LEN + MAX_DATA_SIZE;

/// Apply a sequence of TOC builder operations to an encoder, returning
/// the encoded bytes on success or `None` if any step (including
/// [`Encoder::finish`]) fails.
pub fn run_encoder<'a, H: Header>(
    mut encoder: Encoder<'a, H>,
    ops: &[EncoderTOCBuilders],
) -> Option<&'a [u8]> {
    for op in ops {
        let result = match op {
            EncoderTOCBuilders::SessionId(id) => encoder.session_id(*id),
            EncoderTOCBuilders::KeyId(id) => encoder.key_id(*id),
            EncoderTOCBuilders::Uint8(v) => encoder.uint8(*v),
            EncoderTOCBuilders::Uint16(v) => encoder.uint16(*v),
            EncoderTOCBuilders::Uint32(v) => encoder.uint32(*v),
            EncoderTOCBuilders::Uint64(v) => encoder.uint64(*v),
            EncoderTOCBuilders::Buffer(data) => encoder.buffer(data),
            EncoderTOCBuilders::BufferReserve(len) => encoder.buffer_reserve(*len as usize),
            EncoderTOCBuilders::SealedKey(data) => encoder.sealed_key(data),
            EncoderTOCBuilders::None => encoder.none(),
            EncoderTOCBuilders::Padding(len) => encoder.padding(*len as usize),
        };
        match result {
            Ok(enc) => encoder = enc,
            Err(_) => return None,
        }
    }

    encoder.finish().ok()
}

fn validate_toc_entry(op: &EncoderTOCBuilders, entry: TocEntry<'_>) {
    match (op, entry) {
        (EncoderTOCBuilders::SessionId(expected), TocEntry::SessionId(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::KeyId(expected), TocEntry::KeyId(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::Uint8(expected), TocEntry::Uint8(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::Uint16(expected), TocEntry::Uint16(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::Uint32(expected), TocEntry::Uint32(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::Uint64(expected), TocEntry::Uint64(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::Buffer(expected), TocEntry::Buffer(actual)) => {
            assert_eq!(expected, actual);
        }
        (EncoderTOCBuilders::BufferReserve(expected), TocEntry::Buffer(actual)) => {
            assert_eq!(usize::from(*expected), actual.len());
        }
        (EncoderTOCBuilders::SealedKey(expected), TocEntry::SealedKey(actual)) => {
            assert_eq!(expected, actual);
        }
        (EncoderTOCBuilders::None, TocEntry::None) => {}
        (EncoderTOCBuilders::Padding(expected), TocEntry::Padding(actual)) => {
            assert_eq!(usize::from(*expected), actual.len());
            assert!(actual.iter().all(|byte| *byte == 0));
        }
        (expected, actual) => panic!("operation {expected:?} decoded as {actual:?}"),
    }
}

/// Parse and exercise every accessor on a serialised TBOR request.
///
/// A parse failure is treated as expected (the bytes may be invalid).
pub fn run_request_view(data: &[u8]) {
    if let Ok(view) = RequestView::parse(data) {
        let _ = view.version();
        let _ = view.opcode();
        let _ = view.toc_count();
        let _ = view.data_start();
        let _ = view.data_size();
        let _ = view.len();
        let _ = view.is_empty();
        let _ = view.as_bytes();
        let _ = view.data_section();
        for (i, entry) in view.toc_iter().enumerate() {
            let _ = entry;
            let _ = view.toc_entry_type(i);
            let _ = view.toc_entry(i);
        }
    }
}

/// Parse a serialised TBOR request and validate its TOC entries against
/// the operations used to encode it.
///
/// `data` must come from a successful `RequestEncoder::finish`, so a parse
/// failure here means the encoder and decoder disagree and is reported via
/// `expect` rather than discarded.
pub fn validate_request_view(data: &[u8], version: u8, opcode: u8, ops: &[EncoderTOCBuilders]) {
    let view =
        RequestView::parse(data).expect("bytes from a successful RequestEncoder::finish must parse");
    assert_eq!(view.version(), version);
    assert_eq!(view.opcode(), opcode);
    assert_eq!(view.toc_count(), ops.len());
    let _ = view.data_start();
    let _ = view.data_size();
    let _ = view.len();
    let _ = view.is_empty();
    let _ = view.as_bytes();
    let _ = view.data_section();

    for (i, (entry, op)) in view.toc_iter().zip(ops).enumerate() {
        assert_eq!(view.toc_entry(i), entry);
        let _ = view.toc_entry_type(i);

        validate_toc_entry(op, entry);
    }
}

/// Parse and exercise every accessor on a serialised TBOR response.
///
/// A parse failure is treated as expected (the bytes may be invalid).
pub fn run_response_view(data: &[u8]) {
    if let Ok(view) = ResponseView::parse(data) {
        let _ = view.version();
        let _ = view.status();
        let _ = view.flags();
        let _ = view.fips_approved();
        let _ = view.toc_count();
        let _ = view.data_start();
        let _ = view.data_size();
        let _ = view.len();
        let _ = view.is_empty();
        let _ = view.as_bytes();
        let _ = view.data_section();
        for (i, entry) in view.toc_iter().enumerate() {
            let _ = entry;
            let _ = view.toc_entry_type(i);
            let _ = view.toc_entry(i);
        }
    }
}

/// Parse and exercise every accessor on a serialised TBOR response.
///
/// A parse failure is treated as expected (the bytes may be invalid).
pub fn validate_response_view(data: &[u8], ops: &[EncoderTOCBuilders]) {
    if let Ok(view) = ResponseView::parse(data) {
        let _ = view.version();
        let _ = view.status();
        let _ = view.flags();
        let _ = view.fips_approved();
        assert_eq!(view.toc_count(), ops.len());
        let _ = view.data_start();
        let _ = view.data_size();
        let _ = view.len();
        let _ = view.is_empty();
        let _ = view.as_bytes();
        let _ = view.data_section();

        for (i, (entry, op)) in view.toc_iter().zip(ops).enumerate() {
            assert_eq!(view.toc_entry(i), entry);
            let _ = view.toc_entry_type(i);

            validate_toc_entry(op, entry);
        }
    }
}
