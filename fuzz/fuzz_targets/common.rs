// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared types and helpers for TBOR fuzz targets.

#![allow(dead_code)]

use azihsm_ddi::*;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_tbor_codec::Encoder;
use azihsm_ddi_tbor_codec::MAX_DATA_SIZE;
use azihsm_ddi_tbor_codec::MAX_TOC_ENTRIES;
use azihsm_ddi_tbor_codec::REQ_HEADER_LEN;
use azihsm_ddi_tbor_codec::RESP_HEADER_LEN;
use azihsm_ddi_tbor_codec::TOC_ENTRY_LEN;
use azihsm_ddi_tbor_codec::TocEntry;
use azihsm_ddi_tbor_codec::header::Header;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;

pub type DdiTest = AzihsmDdi;

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

static mut DEVICE_DISPLAY: bool = false;

pub fn common_fuzz_test(test: &dyn Fn(&mut <DdiTest as Ddi>::Dev, &str)) {
    let ddi = DdiTest::default();
    let dev_infos = ddi.dev_info_list();
    if dev_infos.is_empty() {
        panic!("No devices found");
    }

    let path = match std::env::var("FUZZ_DEVICE") {
        Ok(path) => path,
        Err(_) => dev_infos.first().unwrap().path.clone(),
    };

    // Display all device paths and the selected device path if it hasn't been
    // displayed yet.
    unsafe {
        if !DEVICE_DISPLAY {
            for dev_info in &dev_infos {
                println!("Found device: {}", dev_info.path);
            }
            println!("Selected device: {}", path);
            DEVICE_DISPLAY = true;
        }
    }

    let mut dev = ddi.open_dev(&path).expect("Failed to open device");
    test(&mut dev, &path);
}

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

pub fn validate_toc_entry(op: &EncoderTOCBuilders, entry: TocEntry<'_>) {
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
