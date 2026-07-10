// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the COSE_Sign1 key-report decoder.
//!
//! These build a reference report with an inline [`minicbor`] encoder
//! (independent of the crate's own builder) and exercise the public
//! [`parse_key_report`] API, asserting every field decodes to a
//! zero-copy `&DmaBuf` sub-view of the input buffer.
//!
//! Encoder byte-identity is covered end-to-end by the `part_init`
//! emulator tests (which build a report here and verify it through the
//! AZIHSM simulator's fixed-525 `KeyAttester`).

#![allow(clippy::unwrap_used)]
#![allow(unsafe_code)]

use azihsm_fw_core_crypto_key_report::parse_key_report;
use azihsm_fw_core_crypto_key_report::APP_UUID_LEN;
use azihsm_fw_core_crypto_key_report::PUBLIC_KEY_MAX_SIZE;
use azihsm_fw_core_crypto_key_report::REPORT_DATA_LEN;
use azihsm_fw_core_crypto_key_report::SIGNATURE_LEN;
use azihsm_fw_core_crypto_key_report::VM_LAUNCH_ID_LEN;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use minicbor::Encoder;

const P384_COORD: usize = 48;
const PROTECTED_HEADER: [u8; 22] = [
    0xa2, 0x01, 0x38, 0x22, 0x03, 0x70, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x2f, 0x63, 0x62, 0x6f, 0x72,
];
const COSE_SIGN1_TAG: u8 = 0xD2;

/// Reborrow a `&DmaBuf` as its underlying byte slice.
fn as_bytes(d: &DmaBuf) -> &[u8] {
    d
}

/// Inline EC2 P-384 COSE_Key `{1:2, -1:2, -2:x, -3:y}`.
fn cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 256];
    let n = {
        let mut e = Encoder::new(&mut buf[..]);
        e.map(4)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(2)
            .unwrap()
            .i8(-1)
            .unwrap()
            .i8(2)
            .unwrap()
            .i8(-2)
            .unwrap()
            .bytes(x)
            .unwrap()
            .i8(-3)
            .unwrap()
            .bytes(y)
            .unwrap();
        256 - e.writer().len()
    };
    buf.truncate(n);
    buf
}

/// Inline 7-entry payload map.
fn payload(
    pubkey_525: &[u8],
    cose_len: u16,
    flags: u32,
    uuid: &[u8],
    rd: &[u8],
    vm: &[u8],
) -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
    let n = {
        let mut e = Encoder::new(&mut buf[..]);
        e.map(7)
            .unwrap()
            .u8(0)
            .unwrap()
            .u16(1)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(pubkey_525)
            .unwrap()
            .u8(2)
            .unwrap()
            .u16(cose_len)
            .unwrap()
            .u8(3)
            .unwrap()
            .u32(flags)
            .unwrap()
            .u8(4)
            .unwrap()
            .bytes(uuid)
            .unwrap()
            .u8(5)
            .unwrap()
            .bytes(rd)
            .unwrap()
            .u8(6)
            .unwrap()
            .bytes(vm)
            .unwrap();
        1024 - e.writer().len()
    };
    buf.truncate(n);
    buf
}

/// Inline tagged COSE_Sign1: `D2 84 <protected> <map(0)> <payload> <sig>`.
fn cose_sign1(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2048);
    buf.push(COSE_SIGN1_TAG);
    let mut e = Encoder::new(&mut buf);
    e.array(4)
        .unwrap()
        .bytes(&PROTECTED_HEADER)
        .unwrap()
        .map(0)
        .unwrap()
        .bytes(payload)
        .unwrap()
        .bytes(signature)
        .unwrap();
    buf
}

fn build_report(
    flags: u32,
) -> (
    Vec<u8>,
    Vec<u8>,
    [u8; APP_UUID_LEN],
    Vec<u8>,
    [u8; VM_LAUNCH_ID_LEN],
    [u8; SIGNATURE_LEN],
) {
    let x = [0x11u8; P384_COORD];
    let y = [0x22u8; P384_COORD];
    let uuid = [0xA1u8; APP_UUID_LEN];
    let rd: Vec<u8> = (0..REPORT_DATA_LEN).map(|i| i as u8).collect();
    let vm = [0xC3u8; VM_LAUNCH_ID_LEN];
    let mut sig = [0u8; SIGNATURE_LEN];
    for (i, b) in sig.iter_mut().enumerate() {
        *b = (0x40 + i) as u8;
    }

    let ck = cose_key(&x, &y);
    let mut pubkey_525 = vec![0u8; PUBLIC_KEY_MAX_SIZE];
    pubkey_525[..ck.len()].copy_from_slice(&ck);

    let pl = payload(&pubkey_525, ck.len() as u16, flags, &uuid, &rd, &vm);
    let report = cose_sign1(&pl, &sig);
    (report, pubkey_525, uuid, rd, vm, sig)
}

#[test]
fn parse_decodes_all_fields_zero_copy() {
    let flags = 0x0000_0004u32;
    let (report, pubkey_525, uuid, rd, vm, sig) = build_report(flags);

    // SAFETY: `report` is an ordinary heap buffer used only within this
    // in-process test; branding it as a `DmaBuf` view is sound here.
    let dma = unsafe { DmaBuf::from_raw(&report) };
    let view = parse_key_report(dma).unwrap();

    assert_eq!(view.version, 1);
    assert_eq!(view.flags, flags);
    // public_key_size is the real COSE_Key length within the 525-byte field.
    let expected_cose_len = {
        let x = [0x11u8; P384_COORD];
        let y = [0x22u8; P384_COORD];
        cose_key(&x, &y).len()
    };
    assert_eq!(view.public_key_size as usize, expected_cose_len);

    assert_eq!(as_bytes(view.public_key), &pubkey_525[..]);
    assert_eq!(as_bytes(view.app_uuid), &uuid[..]);
    assert_eq!(as_bytes(view.report_data), &rd[..]);
    assert_eq!(as_bytes(view.vm_launch_id), &vm[..]);
    assert_eq!(as_bytes(view.protected_header), &PROTECTED_HEADER[..]);
    assert_eq!(as_bytes(view.signature), &sig[..]);

    // Every byte view must borrow INTO the report buffer (zero-copy).
    let base = report.as_ptr() as usize;
    let end = base + report.len();
    for p in [
        view.public_key.as_ptr() as usize,
        view.app_uuid.as_ptr() as usize,
        view.report_data.as_ptr() as usize,
        view.vm_launch_id.as_ptr() as usize,
        view.protected_header.as_ptr() as usize,
        view.payload.as_ptr() as usize,
        view.signature.as_ptr() as usize,
    ] {
        assert!(
            p >= base && p < end,
            "view field must borrow the input buffer"
        );
    }
}

#[test]
fn parse_handles_all_flags_widths() {
    for flags in [0u32, 23, 0xAB, 0x1234, 0x0010_0000, u32::MAX] {
        let (report, _, _, _, _, _) = build_report(flags);
        // SAFETY: in-process test heap buffer; branding as a DmaBuf is sound.
        let dma = unsafe { DmaBuf::from_raw(&report) };
        let view = parse_key_report(dma).unwrap();
        assert_eq!(view.flags, flags, "flags={flags:#x}");
    }
}

#[test]
fn parse_rejects_bad_tag() {
    let mut report = build_report(0).0;
    report[0] = 0x00;
    // SAFETY: in-process test heap buffer; branding as a DmaBuf is sound.
    let dma = unsafe { DmaBuf::from_raw(&report) };
    assert!(parse_key_report(dma).is_err());
}

#[test]
fn parse_rejects_truncated() {
    let report = build_report(0).0;
    let short = &report[..report.len() / 2];
    // SAFETY: in-process test heap buffer; branding as a DmaBuf is sound.
    let dma = unsafe { DmaBuf::from_raw(short) };
    assert!(parse_key_report(dma).is_err());
}

/// Encode a payload map with a caller-chosen `public_key` bstr and entry
/// count, for negative testing.
fn payload_custom(pubkey: &[u8], entries: u64) -> Vec<u8> {
    let uuid = [0u8; APP_UUID_LEN];
    let rd = [0u8; REPORT_DATA_LEN];
    let vm = [0u8; VM_LAUNCH_ID_LEN];
    let mut buf = vec![0u8; 2048];
    let n = {
        let mut e = Encoder::new(&mut buf[..]);
        e.map(entries).unwrap();
        e.u8(0).unwrap().u16(1).unwrap();
        e.u8(1).unwrap().bytes(pubkey).unwrap();
        e.u8(2).unwrap().u16(pubkey.len() as u16).unwrap();
        e.u8(3).unwrap().u32(0).unwrap();
        e.u8(4).unwrap().bytes(&uuid).unwrap();
        e.u8(5).unwrap().bytes(&rd).unwrap();
        if entries >= 7 {
            e.u8(6).unwrap().bytes(&vm).unwrap();
        }
        2048 - e.writer().len()
    };
    buf.truncate(n);
    buf
}

#[test]
fn parse_rejects_trailing_bytes() {
    let mut report = build_report(0).0;
    report.push(0xFF);
    // SAFETY: in-process test heap buffer; branding as a DmaBuf is sound.
    let dma = unsafe { DmaBuf::from_raw(&report) };
    assert!(parse_key_report(dma).is_err());
}

#[test]
fn parse_rejects_wrong_public_key_length() {
    // public_key bstr is 524 bytes, not the fixed 525.
    let pubkey = vec![0u8; PUBLIC_KEY_MAX_SIZE - 1];
    let pl = payload_custom(&pubkey, 7);
    let report = cose_sign1(&pl, &[0u8; SIGNATURE_LEN]);
    // SAFETY: in-process test heap buffer; branding as a DmaBuf is sound.
    let dma = unsafe { DmaBuf::from_raw(&report) };
    assert!(parse_key_report(dma).is_err());
}

#[test]
fn parse_rejects_incomplete_payload_map() {
    // Only 6 entries — vm_launch_id (key 6) missing.
    let pubkey = vec![0u8; PUBLIC_KEY_MAX_SIZE];
    let pl = payload_custom(&pubkey, 6);
    let report = cose_sign1(&pl, &[0u8; SIGNATURE_LEN]);
    // SAFETY: in-process test heap buffer; branding as a DmaBuf is sound.
    let dma = unsafe { DmaBuf::from_raw(&report) };
    assert!(parse_key_report(dma).is_err());
}
