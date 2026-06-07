// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Byte-identity tests for the firmware key-report builder.
//!
//! The firmware crate emits CBOR / `COSE_Sign1` reports by patching
//! pre-baked templates so it can stay `no_std` and free of any CBOR
//! library dependency.  These tests build a parallel reference report
//! with [`minicbor`] (scoped to ECC P-384) and assert byte equality
//! against the firmware output for every variable input and every
//! canonical `flags: u32` width.
//!
//! The reference encoder mirrors the wire format used by the AZIHSM
//! simulator's `ddi/mbor/sim` `report` module but is fully inlined
//! here so the firmware crate does not pull in the simulator just to
//! be tested.

#![allow(clippy::unwrap_used)]

use azihsm_fw_core_crypto_key_report::canonical_u32_width;
use azihsm_fw_core_crypto_key_report::write_canonical_u32;
use azihsm_fw_core_crypto_key_report::write_cose_sign1;
use azihsm_fw_core_crypto_key_report::write_payload;
use azihsm_fw_core_crypto_key_report::write_sig_struct;
use azihsm_fw_core_crypto_key_report::KeyFlags;
use azihsm_fw_core_crypto_key_report::KeyReportParams;
use azihsm_fw_core_crypto_key_report::APP_UUID_LEN;
use azihsm_fw_core_crypto_key_report::COSE_SIGN1_MAX_LEN;
use azihsm_fw_core_crypto_key_report::PAYLOAD_MAX_LEN;
use azihsm_fw_core_crypto_key_report::PUBLIC_KEY_COORD_LEN;
use azihsm_fw_core_crypto_key_report::REPORT_DATA_LEN;
use azihsm_fw_core_crypto_key_report::SIGNATURE_LEN;
use azihsm_fw_core_crypto_key_report::SIG_STRUCT_MAX_LEN;
use azihsm_fw_core_crypto_key_report::VM_LAUNCH_ID_LEN;
use minicbor::Encoder;

// -- Wire-format constants (mirror sim's `ddi/mbor/sim/src/report.rs`).
//
// The firmware crate is locked to these sizes by its pre-baked
// templates; if the wire format ever changes, both sides must move
// together.

/// Size in bytes of the `app_uuid` field.
const APP_UUID_SIZE: usize = 16;
/// Size in bytes of the `report_data` field.
const REPORT_DATA_SIZE: usize = 128;
/// Size in bytes of the `vm_launch_id` field.
const VM_LAUNCH_ID_SIZE: usize = 16;
/// Size in bytes of the ECDSA-P384 signature (`r || s`, 48 + 48).
const SIGNATURE_SIZE: usize = 96;
/// Size in bytes of the fixed `public_key` bstr that wraps the inner
/// COSE_Key map.  The firmware preserves the historic container size
/// for wire compatibility; an ECC P-384 COSE_Key occupies only the
/// first ~107 bytes and the remainder is zero-padded.
const PUBLIC_KEY_MAX_SIZE: usize = 525;
/// Size in bytes of the canonical encoded COSE protected header.
const PROTECTED_HEADER_SIZE: usize = 22;
/// Pre-encoded protected header (`{alg: ES384, content_type: "application/cbor"}`).
const PROTECTED_HEADER: [u8; PROTECTED_HEADER_SIZE] = [
    0xa2, 0x01, 0x38, 0x22, 0x03, 0x70, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x2f, 0x63, 0x62, 0x6f, 0x72,
];
/// Major-type byte for a CBOR tag (6) holding tag value 18 (COSE_Sign1).
const COSE_SIGN1_TAG: u8 = 0xd2;
/// CBOR head byte for a length-4 array.
const COSE_SIGN1_ARRAY_4: u8 = 0x84;
/// CBOR head byte for a length-10 text string ("Signature1" context).
const COSE_SIGN1_STR_10: u8 = 0x6a;
/// UTF-8 bytes of the `SigStructure` context literal `"Signature1"`.
const SIG_STRUCTURE_CONTEXT: [u8; 10] =
    [0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31];

const _: () = {
    // Field-size constants on the firmware side must match the wire
    // format exactly; this asserts they have not drifted.
    assert!(APP_UUID_LEN == APP_UUID_SIZE);
    assert!(REPORT_DATA_LEN == REPORT_DATA_SIZE);
    assert!(VM_LAUNCH_ID_LEN == VM_LAUNCH_ID_SIZE);
    assert!(SIGNATURE_LEN == SIGNATURE_SIZE);
};

/// One test vector: caller inputs plus a fixed signature pattern.
struct Vector {
    pk_x: [u8; PUBLIC_KEY_COORD_LEN],
    pk_y: [u8; PUBLIC_KEY_COORD_LEN],
    flags: u32,
    app_uuid: [u8; APP_UUID_LEN],
    report_data: [u8; REPORT_DATA_LEN],
    vm_launch_id: [u8; VM_LAUNCH_ID_LEN],
    /// COSE signature bytes in big-endian wire form (`r || s` BE).
    signature_be: [u8; SIGNATURE_LEN],
}

fn vec_zero() -> Vector {
    Vector {
        pk_x: [0; PUBLIC_KEY_COORD_LEN],
        pk_y: [0; PUBLIC_KEY_COORD_LEN],
        flags: 0,
        app_uuid: [0; APP_UUID_LEN],
        report_data: [0; REPORT_DATA_LEN],
        vm_launch_id: [0; VM_LAUNCH_ID_LEN],
        signature_be: [0; SIGNATURE_LEN],
    }
}

fn vec_max() -> Vector {
    Vector {
        pk_x: [0xFF; PUBLIC_KEY_COORD_LEN],
        pk_y: [0xFE; PUBLIC_KEY_COORD_LEN],
        flags: u32::MAX,
        app_uuid: [0xAA; APP_UUID_LEN],
        report_data: [0xBB; REPORT_DATA_LEN],
        vm_launch_id: [0xCC; VM_LAUNCH_ID_LEN],
        signature_be: [0xDD; SIGNATURE_LEN],
    }
}

fn vec_with_flags(flags: u32) -> Vector {
    Vector {
        pk_x: (0..PUBLIC_KEY_COORD_LEN as u8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        pk_y: (PUBLIC_KEY_COORD_LEN as u8..2 * PUBLIC_KEY_COORD_LEN as u8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        flags,
        app_uuid: [0x10; APP_UUID_LEN],
        report_data: {
            let mut a = [0u8; REPORT_DATA_LEN];
            for (i, b) in a.iter_mut().enumerate() {
                *b = i as u8;
            }
            a
        },
        vm_launch_id: [0x20; VM_LAUNCH_ID_LEN],
        signature_be: {
            let mut a = [0u8; SIGNATURE_LEN];
            for (i, b) in a.iter_mut().enumerate() {
                *b = i as u8;
            }
            a
        },
    }
}

fn params(v: &Vector) -> KeyReportParams<'_> {
    KeyReportParams {
        pk_x: &v.pk_x,
        pk_y: &v.pk_y,
        flags: v.flags,
        app_uuid: &v.app_uuid,
        report_data: &v.report_data,
        vm_launch_id: &v.vm_launch_id,
    }
}

// -- Inline minicbor reference encoder (ECC P-384 only).

/// Encode the inner COSE_Key (P-384 EC2) map: `{1: 2, -1: 2, -2: x, -3: y}`.
fn encode_inner_cose_key_p384(x: &[u8], y: &[u8], out: &mut [u8]) -> usize {
    let out_len = out.len();
    let mut enc = Encoder::new(out);
    enc.map(4)
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
    out_len - enc.writer().len()
}

/// Encode the `KeyAttestationReport` as a 7-entry integer-keyed CBOR
/// map matching the on-wire schema:
///
/// ```text
/// {
///   0: u16 version,
///   1: bstr public_key  (always PUBLIC_KEY_MAX_SIZE bytes),
///   2: u16 public_key_size,
///   3: u32 flags,
///   4: bstr app_uuid    (APP_UUID_SIZE bytes),
///   5: bstr report_data (REPORT_DATA_SIZE bytes),
///   6: bstr vm_launch_id (VM_LAUNCH_ID_SIZE bytes),
/// }
/// ```
fn ref_payload(v: &Vector) -> Vec<u8> {
    let mut public_key = [0u8; PUBLIC_KEY_MAX_SIZE];
    let inner_len = encode_inner_cose_key_p384(&v.pk_x, &v.pk_y, &mut public_key);

    let mut buf = Vec::with_capacity(2048);
    let mut enc = Encoder::new(&mut buf);
    enc.map(7)
        .unwrap()
        .u8(0)
        .unwrap()
        .u16(1)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&public_key)
        .unwrap()
        .u8(2)
        .unwrap()
        .u16(inner_len as u16)
        .unwrap()
        .u8(3)
        .unwrap()
        .u32(v.flags)
        .unwrap()
        .u8(4)
        .unwrap()
        .bytes(&v.app_uuid)
        .unwrap()
        .u8(5)
        .unwrap()
        .bytes(&v.report_data)
        .unwrap()
        .u8(6)
        .unwrap()
        .bytes(&v.vm_launch_id)
        .unwrap();
    buf
}

/// Encode the `SigStructure` (RFC 9052 §4.4):
///
/// ```text
/// [ "Signature1", body_protected bstr, external_aad (empty bstr), payload bstr ]
/// ```
///
/// The fixed leading bytes (array-of-4 header + text-string-10
/// header + "Signature1") are emitted by hand, matching the firmware
/// template byte-for-byte.
fn ref_sig_struct(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2048);
    buf.push(COSE_SIGN1_ARRAY_4);
    buf.push(COSE_SIGN1_STR_10);
    buf.extend_from_slice(&SIG_STRUCTURE_CONTEXT);
    let mut enc = Encoder::new(&mut buf);
    enc.bytes(&PROTECTED_HEADER)
        .unwrap()
        .bytes(&[])
        .unwrap()
        .bytes(payload)
        .unwrap();
    buf
}

/// Encode the tagged `COSE_Sign1` object:
///
/// ```text
/// d2 84 <protected bstr> <unprotected empty map> <payload bstr> <signature bstr>
/// ```
fn ref_cose_sign1(payload: &[u8], signature_be: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2048);
    buf.push(COSE_SIGN1_TAG);
    let mut enc = Encoder::new(&mut buf);
    enc.array(4)
        .unwrap()
        .bytes(&PROTECTED_HEADER)
        .unwrap()
        .map(0)
        .unwrap()
        .bytes(payload)
        .unwrap()
        .bytes(signature_be)
        .unwrap();
    buf
}

// -- Firmware-side wrappers under test.

fn fw_payload(v: &Vector) -> Vec<u8> {
    let width = canonical_u32_width(v.flags);
    let len = PAYLOAD_MAX_LEN - 5 + width;
    let mut buf = vec![0u8; len];
    write_payload(&mut buf, &params(v), width).unwrap();
    buf
}

fn fw_sig_struct(payload: &[u8]) -> Vec<u8> {
    let len = SIG_STRUCT_MAX_LEN - PAYLOAD_MAX_LEN + payload.len();
    let mut buf = vec![0u8; len];
    write_sig_struct(&mut buf, payload, payload.len()).unwrap();
    buf
}

fn fw_cose_sign1(payload: &[u8], signature_be: &[u8]) -> Vec<u8> {
    // Convert BE-by-half (r||s) into LE-by-half — the form the
    // builder expects from PAL ecc_sign.
    let half = SIGNATURE_LEN / 2;
    let mut sig_le = [0u8; SIGNATURE_LEN];
    for i in 0..half {
        sig_le[i] = signature_be[half - 1 - i];
        sig_le[half + i] = signature_be[SIGNATURE_LEN - 1 - i];
    }
    let len = COSE_SIGN1_MAX_LEN - PAYLOAD_MAX_LEN + payload.len();
    let mut buf = vec![0u8; len];
    write_cose_sign1(&mut buf, payload, payload.len(), &sig_le).unwrap();
    buf
}

fn check_vector(v: &Vector) {
    let want_payload = ref_payload(v);
    let got_payload = fw_payload(v);
    assert_eq!(
        got_payload, want_payload,
        "payload mismatch for flags={:#x}",
        v.flags
    );

    let want_ss = ref_sig_struct(&want_payload);
    let got_ss = fw_sig_struct(&got_payload);
    assert_eq!(
        got_ss, want_ss,
        "sig_struct mismatch for flags={:#x}",
        v.flags
    );

    let want_cose = ref_cose_sign1(&want_payload, &v.signature_be);
    let got_cose = fw_cose_sign1(&got_payload, &v.signature_be);
    assert_eq!(
        got_cose, want_cose,
        "cose_sign1 mismatch for flags={:#x}",
        v.flags
    );
}

#[test]
fn flags_width_1_zero() {
    let v = vec_zero();
    assert_eq!(canonical_u32_width(v.flags), 1);
    check_vector(&v);
}

#[test]
fn flags_width_1_max() {
    let mut v = vec_with_flags(23);
    v.signature_be = [0x55; SIGNATURE_LEN];
    assert_eq!(canonical_u32_width(v.flags), 1);
    check_vector(&v);
}

#[test]
fn flags_width_2() {
    let v = vec_with_flags(0xAB);
    assert_eq!(canonical_u32_width(v.flags), 2);
    check_vector(&v);
}

#[test]
fn flags_width_3() {
    let v = vec_with_flags(0x1234);
    assert_eq!(canonical_u32_width(v.flags), 3);
    check_vector(&v);
}

#[test]
fn flags_width_5_mid() {
    let v = vec_with_flags(0x0010_0000);
    assert_eq!(canonical_u32_width(v.flags), 5);
    check_vector(&v);
}

#[test]
fn flags_width_5_max() {
    let v = vec_max();
    assert_eq!(canonical_u32_width(v.flags), 5);
    check_vector(&v);
}

#[test]
fn keyflags_bitfield_matches_reference() {
    // Build a KeyFlags via our crate, route through the reference
    // encoder, and confirm we recover the same bits on the wire.
    let flags = KeyFlags::new()
        .with_is_generated(true)
        .with_can_sign(true)
        .with_can_derive(true);
    let v = vec_with_flags(flags.into());
    check_vector(&v);
}

// Note: the public `key_report` API validates input lengths and
// returns `InvalidArg` for mismatched slices.  Verifying that path
// requires standing up a full async PAL (HsmCrypto + HsmAlloc +
// HsmIo); we leave that to the caller's integration tests where the
// PAL is already wired.  The byte-identity tests above exercise the
// happy path and are sufficient to lock the wire format.

#[test]
fn canonical_u32_widths() {
    let mut buf = [0u8; 5];
    write_canonical_u32(0, &mut buf[..1]).unwrap();
    assert_eq!(buf[..1], [0x00]);
    write_canonical_u32(23, &mut buf[..1]).unwrap();
    assert_eq!(buf[..1], [0x17]);
    write_canonical_u32(24, &mut buf[..2]).unwrap();
    assert_eq!(buf[..2], [0x18, 0x18]);
    write_canonical_u32(0xFF, &mut buf[..2]).unwrap();
    assert_eq!(buf[..2], [0x18, 0xFF]);
    write_canonical_u32(0x100, &mut buf[..3]).unwrap();
    assert_eq!(buf[..3], [0x19, 0x01, 0x00]);
    write_canonical_u32(0xFFFF, &mut buf[..3]).unwrap();
    assert_eq!(buf[..3], [0x19, 0xFF, 0xFF]);
    write_canonical_u32(0x1_0000, &mut buf[..5]).unwrap();
    assert_eq!(buf[..5], [0x1A, 0x00, 0x01, 0x00, 0x00]);
    write_canonical_u32(u32::MAX, &mut buf[..5]).unwrap();
    assert_eq!(buf[..5], [0x1A, 0xFF, 0xFF, 0xFF, 0xFF]);
}
