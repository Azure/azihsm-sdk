// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cross-compatibility tests between the old `azihsm_ddi_mbor_codec` encoder/decoder
//! and the new `azihsm_fw_ddi_mbor` encoder/decoder. Validates that the wire
//! format is identical.

#![allow(clippy::unwrap_used, unsafe_code)]

use core::ops::Deref;
use std::vec;

// Old crate (dev-dependency)
use azihsm_ddi_mbor_codec as old;
// New crate (this crate)
use azihsm_fw_ddi_mbor as new;
use azihsm_fw_hsm_pal_traits::DmaBuf;

/// Test helper: brand a `&[u8]` as `&DmaBuf`. Safe in tests — no real DMA hw.
fn dma(buf: &mut [u8]) -> &mut DmaBuf {
    // SAFETY: In tests, no real DMA hardware is involved. The
    // `DmaBuf::from_raw_mut` transmute is safe because the data is
    // only read/written by the decoder, not submitted to a DMA engine.
    unsafe { DmaBuf::from_raw_mut(buf) }
}

/// Helper to create an old MborEncoder, supplying the extra `pre_encode` flag
/// that was added to the old crate's API.
fn old_encoder(buf: &mut [u8]) -> old::MborEncoder<'_> {
    old::MborEncoder::new(buf, false)
}

/// Helper to create an old MborDecoder, supplying the extra `post_decode` flag
/// that was added to the old crate's API.
fn old_decoder(buf: &[u8]) -> old::MborDecoder<'_> {
    old::MborDecoder::new(buf, false)
}

/// Helper to create an old MborByteArray from a slice, replacing the removed
/// `new_with_len` constructor.
fn old_byte_array<const N: usize>(data: &[u8]) -> old::MborByteArray<N> {
    old::MborByteArray::from_slice(data).unwrap()
}

// ── Primitives: old encode → new decode ────────────────────────────────

#[test]
fn old_encode_bool_new_decode() {
    let mut buf = vec![0u8; 1];
    let mut enc = old_encoder(&mut buf);
    old::MborEncode::mbor_encode(&true, &mut enc).unwrap();

    let mut dec = new::MborDecoder::new(dma(&mut buf));
    assert!(<bool as new::MborDecode>::mbor_decode(&mut dec).unwrap());
}

#[test]
fn old_encode_u8_new_decode() {
    let mut buf = vec![0u8; 2];
    let mut enc = old_encoder(&mut buf);
    old::MborEncode::mbor_encode(&42u8, &mut enc).unwrap();

    let mut dec = new::MborDecoder::new(dma(&mut buf));
    assert_eq!(<u8 as new::MborDecode>::mbor_decode(&mut dec).unwrap(), 42);
}

#[test]
fn old_encode_u16_new_decode() {
    let mut buf = vec![0u8; 3];
    let mut enc = old_encoder(&mut buf);
    old::MborEncode::mbor_encode(&0x1234u16, &mut enc).unwrap();

    let mut dec = new::MborDecoder::new(dma(&mut buf));
    assert_eq!(
        <u16 as new::MborDecode>::mbor_decode(&mut dec).unwrap(),
        0x1234
    );
}

#[test]
fn old_encode_u32_new_decode() {
    let mut buf = vec![0u8; 5];
    let mut enc = old_encoder(&mut buf);
    old::MborEncode::mbor_encode(&0xDEADBEEFu32, &mut enc).unwrap();

    let mut dec = new::MborDecoder::new(dma(&mut buf));
    assert_eq!(
        <u32 as new::MborDecode>::mbor_decode(&mut dec).unwrap(),
        0xDEADBEEF
    );
}

#[test]
fn old_encode_u64_new_decode() {
    let mut buf = vec![0u8; 9];
    let mut enc = old_encoder(&mut buf);
    old::MborEncode::mbor_encode(&0x0102030405060708u64, &mut enc).unwrap();

    let mut dec = new::MborDecoder::new(dma(&mut buf));
    assert_eq!(
        <u64 as new::MborDecode>::mbor_decode(&mut dec).unwrap(),
        0x0102030405060708
    );
}

#[test]
fn old_encode_map_new_decode() {
    let mut buf = vec![0u8; 1];
    let mut enc = old_encoder(&mut buf);
    old::MborEncode::mbor_encode(&old::MborMap(7), &mut enc).unwrap();

    let mut dec = new::MborDecoder::new(dma(&mut buf));
    let m = <new::MborMap as new::MborDecode>::mbor_decode(&mut dec).unwrap();
    assert_eq!(m.0, 7);
}

// ── Primitives: new encode → old decode ────────────────────────────────

#[test]
fn new_encode_bool_old_decode() {
    let mut buf = vec![0u8; 1];
    let mut enc = new::MborEncoder::new(&mut buf);
    new::MborEncode::mbor_encode(&false, &mut enc).unwrap();

    let mut dec = old_decoder(&buf);
    assert!(!<bool as old::MborDecode>::mbor_decode(&mut dec).unwrap());
}

#[test]
fn new_encode_u32_old_decode() {
    let mut buf = vec![0u8; 5];
    let mut enc = new::MborEncoder::new(&mut buf);
    new::MborEncode::mbor_encode(&0xCAFEBABEu32, &mut enc).unwrap();

    let mut dec = old_decoder(&buf);
    assert_eq!(
        <u32 as old::MborDecode>::mbor_decode(&mut dec).unwrap(),
        0xCAFEBABE
    );
}

// ── Byte slices: old encode (MborByteSlice, no padding) → new decode ──

#[test]
fn old_byte_slice_new_decode_exact() {
    let data = [0xAA, 0xBB, 0xCC, 0xDD];
    let mut buf = vec![0u8; 16];
    let mut enc = old_encoder(&mut buf);
    old::MborEncode::mbor_encode(&old::MborByteSlice(&data), &mut enc).unwrap();
    let pos = enc.position();

    // New exact decode (no padding expected)
    let mut dec = new::MborDecoder::new(&mut dma(&mut buf)[..pos]);
    let slice = dec.decode_byte_slice_exact(4).unwrap();
    let s: &[u8] = slice.deref();
    assert_eq!(s, &data);
}

#[test]
fn old_byte_slice_new_decode_variable() {
    let data = [0x11, 0x22, 0x33];
    let mut buf = vec![0u8; 16];
    let mut enc = old_encoder(&mut buf);
    old::MborEncode::mbor_encode(&old::MborByteSlice(&data), &mut enc).unwrap();
    let pos = enc.position();

    // New variable decode also works (pad=0)
    let mut dec = new::MborDecoder::new(&mut dma(&mut buf)[..pos]);
    let (pad, slice) = dec.decode_byte_slice().unwrap();
    assert_eq!(pad, 0);
    let s: &[u8] = slice.deref();
    assert_eq!(s, &data);
}

// ── Byte arrays: old encode (MborPaddedByteArray, with padding) → new decode ──

#[test]
fn old_padded_array_new_decode_variable() {
    let data_src = [0x55u8; 10];
    let arr = old_byte_array::<10>(&data_src);
    let padded = old::MborPaddedByteArray(&arr, 1);

    let mut acc = old::MborLenAccumulator::default();
    old::MborLen::mbor_len(&padded, &mut acc);
    let mut buf = vec![0u8; acc.len()];

    let mut enc = old_encoder(&mut buf);
    old::MborEncode::mbor_encode(&padded, &mut enc).unwrap();
    let pos = enc.position();

    // New variable decode handles padding
    let mut dec = new::MborDecoder::new(&mut dma(&mut buf)[..pos]);
    let (pad, slice) = dec.decode_byte_slice().unwrap();
    assert_eq!(pad, 1);
    let s: &[u8] = slice.deref();
    assert_eq!(s, &[0x55; 10]);
}

#[test]
fn old_padded_array_new_exact_decode_accepts() {
    // Host SDK encodes `MborByteArray<N>` with 4-byte alignment padding.
    // FW's `decode_byte_slice_exact` must accept that wire shape — it's the
    // exact same encoding used by `[u8; N]` when `pad == 0`, so the decoder
    // tolerates any pad value (0..=3) and asserts the data length.
    let data_src = [0x77u8; 8];
    let arr = old_byte_array::<8>(&data_src);
    let padded = old::MborPaddedByteArray(&arr, 2);

    let mut acc = old::MborLenAccumulator::default();
    old::MborLen::mbor_len(&padded, &mut acc);
    let mut buf = vec![0u8; acc.len()];

    let mut enc = old_encoder(&mut buf);
    old::MborEncode::mbor_encode(&padded, &mut enc).unwrap();
    let pos = enc.position();

    let mut dec = new::MborDecoder::new(&mut dma(&mut buf)[..pos]);
    let slice = dec.decode_byte_slice_exact(8).unwrap();
    let s: &[u8] = slice.deref();
    assert_eq!(s, &data_src);
}

// ── Byte slices: new encode → old decode ──────────────────────────────

#[test]
fn new_byte_slice_old_decode_fixed_array() {
    // New encode with MborByteSlice (no padding) → old decode as [u8; 4]
    let data = [0xDE, 0xAD, 0xBE, 0xEF];
    let mut buf = vec![0u8; 16];
    let mut enc = new::MborEncoder::new(&mut buf);
    new::MborEncode::mbor_encode(&new::MborByteSlice(&data), &mut enc).unwrap();
    let pos = enc.position();

    let mut dec = old_decoder(&buf[..pos]);
    let arr: [u8; 4] = old::MborDecode::mbor_decode(&mut dec).unwrap();
    assert_eq!(arr, data);
}

#[test]
fn new_padded_slice_old_decode_mbor_byte_array() {
    // New encode with MborPaddedByteSlice (pad=1) → old decode as MborByteArray
    let data = [0xAA; 10];
    let mut buf = vec![0u8; 32];
    let mut enc = new::MborEncoder::new(&mut buf);
    new::MborEncode::mbor_encode(&new::MborPaddedByteSlice(&data, 1), &mut enc).unwrap();
    let pos = enc.position();

    let mut dec = old_decoder(&buf[..pos]);
    let arr: old::MborByteArray<10> = old::MborDecode::mbor_decode(&mut dec).unwrap();
    assert_eq!(arr.as_slice(), &data);
}

// ── Map + multiple fields: full struct-like round-trip ─────────────────

#[test]
fn old_encode_struct_new_decode() {
    // Simulate encoding a struct: Map(2) + id(0) + u16(1000) + id(1) + bool(true)
    let mut buf = vec![0u8; 32];
    let mut enc = old_encoder(&mut buf);
    old::MborEncode::mbor_encode(&old::MborMap(2), &mut enc).unwrap();
    old::MborEncode::mbor_encode(&0u8, &mut enc).unwrap();
    old::MborEncode::mbor_encode(&1000u16, &mut enc).unwrap();
    old::MborEncode::mbor_encode(&1u8, &mut enc).unwrap();
    old::MborEncode::mbor_encode(&true, &mut enc).unwrap();
    let pos = enc.position();

    // Decode with new
    let mut dec = new::MborDecoder::new(&mut dma(&mut buf)[..pos]);
    let m = <new::MborMap as new::MborDecode>::mbor_decode(&mut dec).unwrap();
    assert_eq!(m.0, 2);
    assert_eq!(<u8 as new::MborDecode>::mbor_decode(&mut dec).unwrap(), 0);
    assert_eq!(
        <u16 as new::MborDecode>::mbor_decode(&mut dec).unwrap(),
        1000
    );
    assert_eq!(<u8 as new::MborDecode>::mbor_decode(&mut dec).unwrap(), 1);
    assert!(<bool as new::MborDecode>::mbor_decode(&mut dec).unwrap());
}

#[test]
fn new_encode_struct_old_decode() {
    // Encode with new
    let mut buf = vec![0u8; 32];
    let mut enc = new::MborEncoder::new(&mut buf);
    new::MborEncode::mbor_encode(&new::MborMap(2), &mut enc).unwrap();
    new::MborEncode::mbor_encode(&0u8, &mut enc).unwrap();
    new::MborEncode::mbor_encode(&500u16, &mut enc).unwrap();
    new::MborEncode::mbor_encode(&1u8, &mut enc).unwrap();
    new::MborEncode::mbor_encode(&false, &mut enc).unwrap();
    let pos = enc.position();

    // Decode with old
    let mut dec = old_decoder(&buf[..pos]);
    let m = <old::MborMap as old::MborDecode>::mbor_decode(&mut dec).unwrap();
    assert_eq!(m.0, 2);
    assert_eq!(<u8 as old::MborDecode>::mbor_decode(&mut dec).unwrap(), 0);
    assert_eq!(
        <u16 as old::MborDecode>::mbor_decode(&mut dec).unwrap(),
        500
    );
    assert_eq!(<u8 as old::MborDecode>::mbor_decode(&mut dec).unwrap(), 1);
    assert!(!<bool as old::MborDecode>::mbor_decode(&mut dec).unwrap());
}

// ── Byte-level identity: same input produces identical bytes ──────────

#[test]
fn byte_identical_u32_encoding() {
    let val = 0x12345678u32;

    let mut old_buf = vec![0u8; 5];
    let mut old_enc = old_encoder(&mut old_buf);
    old::MborEncode::mbor_encode(&val, &mut old_enc).unwrap();

    let mut new_buf = vec![0u8; 5];
    let mut new_enc = new::MborEncoder::new(&mut new_buf);
    new::MborEncode::mbor_encode(&val, &mut new_enc).unwrap();

    assert_eq!(
        old_buf, new_buf,
        "old and new encoders produce different bytes"
    );
}

#[test]
fn byte_identical_byte_slice_encoding() {
    let data = [1u8, 2, 3, 4, 5];

    let mut old_buf = vec![0u8; 16];
    let mut old_enc = old_encoder(&mut old_buf);
    old::MborEncode::mbor_encode(&old::MborByteSlice(&data), &mut old_enc).unwrap();
    let old_pos = old_enc.position();

    let mut new_buf = vec![0u8; 16];
    let mut new_enc = new::MborEncoder::new(&mut new_buf);
    new::MborEncode::mbor_encode(&new::MborByteSlice(&data), &mut new_enc).unwrap();
    let new_pos = new_enc.position();

    assert_eq!(old_pos, new_pos);
    assert_eq!(
        &old_buf[..old_pos],
        &new_buf[..new_pos],
        "old and new byte slice encodings differ"
    );
}

#[test]
fn byte_identical_padded_encoding() {
    let data = [0xAA; 10];

    // Old: MborPaddedByteArray with pad=1
    let data_src = [0xAAu8; 10];
    let arr = old_byte_array::<10>(&data_src);
    let mut old_acc = old::MborLenAccumulator::default();
    old::MborLen::mbor_len(&old::MborPaddedByteArray(&arr, 1), &mut old_acc);
    let mut old_buf = vec![0u8; old_acc.len()];
    let mut old_enc = old_encoder(&mut old_buf);
    old::MborEncode::mbor_encode(&old::MborPaddedByteArray(&arr, 1), &mut old_enc).unwrap();
    let old_pos = old_enc.position();

    // New: MborPaddedByteSlice with pad=1
    let mut new_acc = new::MborLenAccumulator::default();
    new::MborLen::mbor_len(&new::MborPaddedByteSlice(&data, 1), &mut new_acc);
    let mut new_buf = vec![0u8; new_acc.len()];
    let mut new_enc = new::MborEncoder::new(&mut new_buf);
    new::MborEncode::mbor_encode(&new::MborPaddedByteSlice(&data, 1), &mut new_enc).unwrap();
    let new_pos = new_enc.position();

    assert_eq!(old_pos, new_pos);
    assert_eq!(
        &old_buf[..old_pos],
        &new_buf[..new_pos],
        "old padded array and new padded slice produce different bytes"
    );
}
