// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire-compatibility tests against the AZIHSM simulator's report codec.
//!
//! These build report bytes with the **actual** `azihsm_ddi_mbor_sim`
//! encoder (the host verifier's own types — not an inline copy) and then
//! decode them with this crate's [`parse_key_report`], asserting every
//! field round-trips. This pins the firmware decoder to the exact wire
//! format the host simulator produces and consumes.
//!
//! The encode direction (firmware builder → sim decoder) is covered
//! end-to-end by the `part_init` emulator tests, which verify a real
//! firmware-built report through `azihsm_ddi_mbor_sim::KeyAttester`.

#![allow(clippy::unwrap_used)]
#![allow(unsafe_code)]

use azihsm_ddi_mbor_sim::report::encode_ecc_public;
use azihsm_ddi_mbor_sim::report::CoseSign1Object;
use azihsm_ddi_mbor_sim::report::KeyAttestationReport;
use azihsm_ddi_mbor_sim::report::UnprotectedHeader;
use azihsm_ddi_mbor_sim::report::PROTECTED_HEADER;
use azihsm_ddi_mbor_sim::report::PUBLIC_KEY_MAX_SIZE as SIM_PUBLIC_KEY_MAX_SIZE;
use azihsm_ddi_mbor_sim::report::REPORT_VERSION as SIM_REPORT_VERSION;
use azihsm_fw_core_crypto_key_report::parse_key_report;
use azihsm_fw_core_crypto_key_report::KEY_REPORT_MAX_LEN;
use azihsm_fw_core_crypto_key_report::PUBLIC_KEY_MAX_SIZE;
use azihsm_fw_hsm_pal_traits::DmaBuf;

const P384_COORD: usize = 48;
/// COSE elliptic-curve identifier for P-384 (RFC 9053 Table 18).
const COSE_CRV_P384: i8 = 2;

/// Reborrow a `&DmaBuf` as its underlying byte slice.
fn as_bytes(d: &DmaBuf) -> &[u8] {
    d
}

/// The firmware and simulator must agree on the fixed `public_key` size.
#[test]
fn public_key_max_size_matches_sim() {
    assert_eq!(PUBLIC_KEY_MAX_SIZE, SIM_PUBLIC_KEY_MAX_SIZE);
}

/// The worst-case report — every CBOR integer field at its maximum
/// encoded width — must fit within the advertised [`KEY_REPORT_MAX_LEN`]
/// upper bound (which the PartInit handler `const`-asserts its response
/// cap against). Built with the byte-identical simulator encoder.
#[test]
fn report_fits_max_len() {
    let x = [0x11u8; P384_COORD];
    let y = [0x22u8; P384_COORD];
    let mut public_key = [0u8; SIM_PUBLIC_KEY_MAX_SIZE];
    encode_ecc_public(COSE_CRV_P384, &x, &y, &mut public_key).unwrap();

    // Max-width integers: version / public_key_size (`u16::MAX` → 3 B),
    // flags (`u32::MAX` → 5 B); the byte fields are already maximal.
    let report = KeyAttestationReport {
        version: u16::MAX,
        public_key,
        public_key_size: u16::MAX,
        flags: u32::MAX,
        app_uuid: [0xFF; 16],
        report_data: [0xFF; 128],
        vm_launch_id: [0xFF; 16],
    };
    let mut payload = vec![0u8; 2048];
    let payload_len = report.encode(&mut payload).unwrap();
    payload.truncate(payload_len);

    let cose = CoseSign1Object {
        protected_header: PROTECTED_HEADER,
        unprotected_header: UnprotectedHeader {},
        payload: &payload,
        signature: [0xFF; 96],
    };
    let mut out = vec![0u8; payload_len + 256];
    let total = cose.encode(&mut out).unwrap();

    assert!(
        total <= KEY_REPORT_MAX_LEN,
        "worst-case report {total} exceeds KEY_REPORT_MAX_LEN {KEY_REPORT_MAX_LEN}"
    );
}

/// Build a tagged COSE_Sign1 report entirely with the simulator's codec,
/// returning the encoded bytes plus the inputs for later assertions.
fn sim_build(
    flags: u32,
) -> (
    Vec<u8>,
    [u8; SIM_PUBLIC_KEY_MAX_SIZE],
    u16,
    [u8; 16],
    [u8; 128],
    [u8; 16],
    [u8; 96],
) {
    let x = [0x11u8; P384_COORD];
    let y = [0x22u8; P384_COORD];
    let app_uuid = [0xA1u8; 16];
    let mut report_data = [0u8; 128];
    for (i, b) in report_data.iter_mut().enumerate() {
        *b = i as u8;
    }
    let vm_launch_id = [0xC3u8; 16];
    let mut signature = [0u8; 96];
    for (i, b) in signature.iter_mut().enumerate() {
        *b = (0x40 + i) as u8;
    }

    // Inner COSE_Key (EC2 P-384), zero-padded to the fixed field size.
    let mut public_key = [0u8; SIM_PUBLIC_KEY_MAX_SIZE];
    let cose_len = encode_ecc_public(COSE_CRV_P384, &x, &y, &mut public_key).unwrap() as u16;

    // Payload map.
    let report = KeyAttestationReport {
        version: SIM_REPORT_VERSION,
        public_key,
        public_key_size: cose_len,
        flags,
        app_uuid,
        report_data,
        vm_launch_id,
    };
    let mut payload = vec![0u8; 2048];
    let payload_len = report.encode(&mut payload).unwrap();
    payload.truncate(payload_len);

    // Tagged COSE_Sign1 envelope.
    let cose = CoseSign1Object {
        protected_header: PROTECTED_HEADER,
        unprotected_header: UnprotectedHeader {},
        payload: &payload,
        signature,
    };
    let mut out = vec![0u8; payload_len + 256];
    let total = cose.encode(&mut out).unwrap();
    out.truncate(total);

    (
        out,
        public_key,
        cose_len,
        app_uuid,
        report_data,
        vm_launch_id,
        signature,
    )
}

/// A sim-encoded report decodes field-for-field through the firmware
/// [`parse_key_report`].
#[test]
fn fw_decodes_sim_encoded_report() {
    let flags = 0x0000_0004u32;
    let (bytes, public_key, cose_len, app_uuid, report_data, vm_launch_id, signature) =
        sim_build(flags);

    // SAFETY: in-process test heap buffer; branding as a DmaBuf is sound.
    let dma = unsafe { DmaBuf::from_raw(&bytes) };
    let view = parse_key_report(dma).unwrap();

    assert_eq!(view.version, SIM_REPORT_VERSION);
    assert_eq!(view.public_key_size, cose_len);
    assert_eq!(view.flags, flags);
    assert_eq!(as_bytes(view.public_key), &public_key[..]);
    assert_eq!(as_bytes(view.app_uuid), &app_uuid[..]);
    assert_eq!(as_bytes(view.report_data), &report_data[..]);
    assert_eq!(as_bytes(view.vm_launch_id), &vm_launch_id[..]);
    assert_eq!(as_bytes(view.protected_header), &PROTECTED_HEADER[..]);
    assert_eq!(as_bytes(view.signature), &signature[..]);
}

/// The firmware decoder and the simulator decoder agree on the same
/// sim-encoded bytes (both are exercised against one another).
#[test]
fn fw_and_sim_decoders_agree() {
    for flags in [0u32, 23, 0xAB, 0x1234, 0x0010_0000, u32::MAX] {
        let (bytes, _, _, _, _, _, _) = sim_build(flags);

        // Firmware decode.
        // SAFETY: in-process test heap buffer; branding as a DmaBuf is sound.
        let dma = unsafe { DmaBuf::from_raw(&bytes) };
        let fw = parse_key_report(dma).unwrap();

        // Simulator decode.
        let cose = CoseSign1Object::decode(&bytes).unwrap();
        let sim: KeyAttestationReport = minicbor::decode(cose.payload).unwrap();

        assert_eq!(fw.version, sim.version, "flags={flags:#x}");
        assert_eq!(fw.public_key_size, sim.public_key_size, "flags={flags:#x}");
        assert_eq!(fw.flags, sim.flags, "flags={flags:#x}");
        assert_eq!(
            as_bytes(fw.public_key),
            &sim.public_key[..],
            "flags={flags:#x}"
        );
        assert_eq!(as_bytes(fw.app_uuid), &sim.app_uuid[..], "flags={flags:#x}");
        assert_eq!(
            as_bytes(fw.report_data),
            &sim.report_data[..],
            "flags={flags:#x}"
        );
        assert_eq!(
            as_bytes(fw.vm_launch_id),
            &sim.vm_launch_id[..],
            "flags={flags:#x}"
        );
        assert_eq!(
            as_bytes(fw.signature),
            &cose.signature[..],
            "flags={flags:#x}"
        );
    }
}
