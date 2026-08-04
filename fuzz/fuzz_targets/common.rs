// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared types and helpers for TBOR fuzz targets.

use azihsm_ddi_tbor_codec::Encoder;
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

/// Buffer size used by encoder fuzz targets.
pub const FUZZ_BUF_SIZE: usize = 8192;

/// Apply a sequence of TOC builder operations to an encoder, returning
/// early on error. Calls `finish` at the end.
pub fn run_encoder<H: Header>(mut encoder: Encoder<'_, H>, ops: &[EncoderTOCBuilders]) {
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
            Err(_) => return,
        }
    }

    // Attempt to finalize — errors are expected and fine.
    let _ = encoder.finish();
}

use azihsm_ddi_emu::DdiEmu;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use std::sync::LazyLock;

/// Lazily-initialized emulator DDI and device for fuzz targets that
/// exercise TBOR command round-trips.
static EMU: LazyLock<DdiEmu> = LazyLock::new(DdiEmu::default);

/// Open (or reuse) the emulator device for fuzz targets.
pub fn open_emu_dev() -> <DdiEmu as Ddi>::Dev {
    let devs = EMU.dev_info_list();
    EMU.open_dev(&devs[0].path).expect("open emu device")
}

/// Issue a TBOR request against the emulator, discarding the result.
pub fn fuzz_exec_op_tbor<R: azihsm_ddi_tbor_types::TborOpReq>(
    dev: &<DdiEmu as Ddi>::Dev,
    req: &R,
) {
    let mut cookie = None;
    let _: Result<R::OpResp, _> = dev.exec_op_tbor(req, None, &mut cookie);
}
