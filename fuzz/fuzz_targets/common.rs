// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared types and helpers for TBOR encoder fuzz targets.

#![allow(dead_code)]

use azihsm_ddi_tbor_codec::Encoder;
use azihsm_ddi_tbor_codec::MAX_DATA_SIZE;
use azihsm_ddi_tbor_codec::MAX_TOC_ENTRIES;
use azihsm_ddi_tbor_codec::REQ_HEADER_LEN;
use azihsm_ddi_tbor_codec::RESP_HEADER_LEN;
use azihsm_ddi_tbor_codec::RequestView;
use azihsm_ddi_tbor_codec::ResponseView;
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
/// section. `TOC_ENTRY_LEN` is `pub(crate)` in the codec, so we use
/// `size_of::<u32>()` as an equivalent.
pub const FUZZ_REQ_BUF_SIZE: usize =
    REQ_HEADER_LEN + MAX_TOC_ENTRIES * core::mem::size_of::<u32>() + MAX_DATA_SIZE;

/// Buffer size used by response encoder fuzz targets.
pub const FUZZ_RESP_BUF_SIZE: usize =
    RESP_HEADER_LEN + MAX_TOC_ENTRIES * core::mem::size_of::<u32>() + MAX_DATA_SIZE;

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

/// Parse and exercise every accessor on a serialised TBOR response.
///
/// A parse failure is treated as expected (the bytes may be invalid).
pub fn run_response_view(data: &[u8]) {
    if let Ok(view) = ResponseView::parse(data) {
        let _ = view.version();
        let _ = view.status();
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
