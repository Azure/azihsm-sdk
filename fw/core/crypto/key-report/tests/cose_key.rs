// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the EC2 `COSE_Key` decoder ([`parse_ec2_cose_key`]).
//!
//! These build reference EC2 `COSE_Key` maps with an inline [`minicbor`]
//! encoder (independent of the crate's own builder) and exercise the
//! public [`parse_ec2_cose_key`] API, asserting the curve and the
//! zero-copy `&DmaBuf` coordinate sub-views, plus its no-panic rejection
//! of malformed input across the trust boundary.

#![allow(clippy::unwrap_used)]
#![allow(unsafe_code)]

use azihsm_fw_core_crypto_key_report::parse_ec2_cose_key;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use minicbor::Encoder;

const COSE_CRV_P256: i8 = 1;
const COSE_CRV_P384: i8 = 2;
const COSE_CRV_P521: i8 = 3;

/// Brand a byte slice as a `DmaBuf` view for the pure decode path.
///
/// # Safety
/// Test-only: the backing slice is ordinary in-process memory, which is
/// valid for the pure CBOR decode path (no real DMA is performed).
fn dma(bytes: &[u8]) -> &DmaBuf {
    // SAFETY: in-process test heap buffer; branding as a DmaBuf is sound.
    unsafe { DmaBuf::from_raw(bytes) }
}

/// Encode a canonical EC2 `COSE_Key` map `{ 1: 2, -1: crv, -2: x, -3: y }`.
fn ec2_cose_key(crv: i8, x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    let remaining = {
        let mut e = Encoder::new(&mut buf[..]);
        e.map(4)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(2)
            .unwrap()
            .i8(-1)
            .unwrap()
            .i8(crv)
            .unwrap()
            .i8(-2)
            .unwrap()
            .bytes(x)
            .unwrap()
            .i8(-3)
            .unwrap()
            .bytes(y)
            .unwrap();
        e.writer().len()
    };
    let n = buf.len() - remaining;
    buf.truncate(n);
    buf
}

fn round_trip(curve: HsmEccCurve, crv: i8, coord: usize) {
    let x: Vec<u8> = (0..coord).map(|i| i as u8).collect();
    let y: Vec<u8> = (0..coord).map(|i| 0xFF - i as u8).collect();
    let bytes = ec2_cose_key(crv, &x, &y);

    let parsed = parse_ec2_cose_key(dma(&bytes)).unwrap();
    assert_eq!(parsed.curve, curve);
    assert_eq!(*parsed.x, x[..]);
    assert_eq!(*parsed.y, y[..]);
}

#[test]
fn round_trips_p256() {
    round_trip(HsmEccCurve::P256, COSE_CRV_P256, 32);
}

#[test]
fn round_trips_p384() {
    round_trip(HsmEccCurve::P384, COSE_CRV_P384, 48);
}

#[test]
fn round_trips_p521() {
    round_trip(HsmEccCurve::P521, COSE_CRV_P521, 66);
}

#[test]
fn rejects_empty_and_non_map() {
    assert!(parse_ec2_cose_key(dma(&[])).is_err());
    // A CBOR unsigned integer, not a map.
    assert!(parse_ec2_cose_key(dma(&[0x00])).is_err());
}

#[test]
fn rejects_trailing_bytes() {
    let mut bytes = ec2_cose_key(COSE_CRV_P384, &[0x11u8; 48], &[0x22u8; 48]);
    bytes.push(0xFF);
    assert!(parse_ec2_cose_key(dma(&bytes)).is_err());
}

#[test]
fn rejects_wrong_map_arity() {
    // A 3-entry map (missing one canonical label) must be rejected.
    let mut buf = vec![0u8; 256];
    let remaining = {
        let mut e = Encoder::new(&mut buf[..]);
        e.map(3)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(2)
            .unwrap()
            .i8(-1)
            .unwrap()
            .i8(COSE_CRV_P384)
            .unwrap()
            .i8(-2)
            .unwrap()
            .bytes(&[0x11u8; 48])
            .unwrap();
        e.writer().len()
    };
    let n = buf.len() - remaining;
    buf.truncate(n);
    assert!(parse_ec2_cose_key(dma(&buf)).is_err());
}

#[test]
fn rejects_non_ec2_key_type() {
    // kty = 3 (RSA) instead of 2 (EC2).
    let mut buf = vec![0u8; 256];
    let remaining = {
        let mut e = Encoder::new(&mut buf[..]);
        e.map(4)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(3)
            .unwrap()
            .i8(-1)
            .unwrap()
            .i8(COSE_CRV_P384)
            .unwrap()
            .i8(-2)
            .unwrap()
            .bytes(&[0x11u8; 48])
            .unwrap()
            .i8(-3)
            .unwrap()
            .bytes(&[0x22u8; 48])
            .unwrap();
        e.writer().len()
    };
    let n = buf.len() - remaining;
    buf.truncate(n);
    assert!(parse_ec2_cose_key(dma(&buf)).is_err());
}

#[test]
fn rejects_unknown_curve() {
    let bytes = ec2_cose_key(9, &[0x11u8; 48], &[0x22u8; 48]);
    assert!(parse_ec2_cose_key(dma(&bytes)).is_err());
}

#[test]
fn rejects_wrong_coordinate_length() {
    // P-384 selected but coordinates are 32 bytes (P-256 size).
    let bytes = ec2_cose_key(COSE_CRV_P384, &[0x11u8; 32], &[0x22u8; 32]);
    assert!(parse_ec2_cose_key(dma(&bytes)).is_err());
}

#[test]
fn rejects_duplicate_label() {
    // Two `-2` (x) labels, no `-3` (y): duplicate must be rejected.
    let mut buf = vec![0u8; 256];
    let remaining = {
        let mut e = Encoder::new(&mut buf[..]);
        e.map(4)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(2)
            .unwrap()
            .i8(-1)
            .unwrap()
            .i8(COSE_CRV_P384)
            .unwrap()
            .i8(-2)
            .unwrap()
            .bytes(&[0x11u8; 48])
            .unwrap()
            .i8(-2)
            .unwrap()
            .bytes(&[0x33u8; 48])
            .unwrap();
        e.writer().len()
    };
    let n = buf.len() - remaining;
    buf.truncate(n);
    assert!(parse_ec2_cose_key(dma(&buf)).is_err());
}
