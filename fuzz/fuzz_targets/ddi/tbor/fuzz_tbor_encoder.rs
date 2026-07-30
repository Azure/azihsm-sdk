// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use azihsm_ddi_tbor_codec::RequestEncoder;

/// Fuzz operations corresponding to the TOC builder methods on
/// [`RequestEncoder`].
#[derive(Arbitrary, Debug)]
enum EncoderTOCBuilders {
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

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    version: u8,
    opcode: u8,
    ops: Vec<EncoderTOCBuilders>,
}

fuzz_target!(|input: FuzzInput| {
    // Use a fixed-size buffer large enough for realistic messages.
    let mut buf = [0u8; 8192];

    let mut encoder = RequestEncoder::new(&mut buf, input.version, input.opcode);

    for op in input.ops {
        let result = match op {
            EncoderTOCBuilders::SessionId(id) => encoder.session_id(id),
            EncoderTOCBuilders::KeyId(id) => encoder.key_id(id),
            EncoderTOCBuilders::Uint8(v) => encoder.uint8(v),
            EncoderTOCBuilders::Uint16(v) => encoder.uint16(v),
            EncoderTOCBuilders::Uint32(v) => encoder.uint32(v),
            EncoderTOCBuilders::Uint64(v) => encoder.uint64(v),
            EncoderTOCBuilders::Buffer(ref data) => encoder.buffer(data),
            EncoderTOCBuilders::BufferReserve(len) => encoder.buffer_reserve(len as usize),
            EncoderTOCBuilders::SealedKey(ref data) => encoder.sealed_key(data),
            EncoderTOCBuilders::None => encoder.none(),
            EncoderTOCBuilders::Padding(len) => encoder.padding(len as usize),
        };
        match result {
            Ok(enc) => encoder = enc,
            Err(_) => return,
        }
    }

    // Attempt to finalize — errors are expected and fine.
    let _ = encoder.finish();
});
