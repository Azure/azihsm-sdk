// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `KeyReport` command.
//!
//! `KeyReport` takes a **masked key** (as produced by `SdSealingKeyGen`),
//! unmasks it, derives its public component on-device, and returns a
//! PID-signed COSE_Sign1 key-attestation report over it.  The
//! Ephemeral/Local masking keys are provisioned by `PartFinal`, so the
//! happy-path tests first drive `PartInit → PartFinal → SdSealingKeyGen`
//! to obtain a masked key.
//!
//! Coverage:
//! * Happy path (Ephemeral + Local) — the report is a COSE_Sign1 that
//!   verifies under the PID pubkey, its embedded COSE_Key re-derives the
//!   sealed key's public point, and its `report_data` round-trips.
//! * Tampered masked key (flipped AEAD tag) → `AesGcmDecryptTagDoesNotMatch`.
//! * Before finalize (partition not `Initialized`) → `InvalidArg`.
//! * Crypto-User session → `InvalidPermissions`.
//! * Default-PSK gate → `DefaultPskMustRotate` (dispatcher, pre-handler).

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborKeyReportReq;
use azihsm_ddi_tbor_types::TborSdSealingKeyGenReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use azihsm_ddi_tbor_types::PSK_LEN;

use crate::commands::part_init::bootstrap_rotated_co;
use crate::commands::part_init::ROTATED_CO_PSK;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;

/// `KeyScope` discriminants (wire mirror of the firmware `HsmKeyScope`).
const SCOPE_EPHEMERAL: u8 = 0b010;
const SCOPE_LOCAL: u8 = 0b011;

/// P-384 coordinate length (raw, big-endian) — the sealed key is a P-384
/// keypair, so each attested COSE_Key coordinate is 48 bytes.
const P384_COORD_LEN: usize = 48;

/// Crypto-User PSK id.
const CU: u8 = 1;

/// Crypto-Officer PSK id (the default-PSK gate test opens under the
/// public default CO PSK).
const CO_DEFAULT: u8 = 0;

/// Non-default 32-byte CU PSK, used to clear the default-PSK gate so the
/// CU-role reject path — not the default-PSK gate — is exercised.
const ROTATED_CU_PSK: [u8; PSK_LEN] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
];

/// Sample caller-supplied report data bound into the report payload.
fn sample_report_data() -> [u8; KEY_REPORT_DATA_LEN] {
    let mut data = [0u8; KEY_REPORT_DATA_LEN];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i as u8) ^ 0xA5;
    }
    data
}

/// Mint a masked sealing key under `scope` on a finalized CO session,
/// returning `(masked_key, sealing_pub_le)`.  The public key is in the
/// little-endian DDI wire form (`x_le ‖ y_le`).
fn masked_sealing_key(ctx: &TestCtx, session_id: u16, scope: u8) -> (Vec<u8>, Vec<u8>) {
    let seal = ctx
        .tbor(&TborSdSealingKeyGenReq { session_id, scope })
        .expect("SdSealingKeyGen");
    (seal.masked_key.to_vec(), seal.pub_key.to_vec())
}

/// Verify a `KeyReport` COSE_Sign1: (1) the envelope verifies under the
/// PID pubkey; (2) the embedded COSE_Key re-derives `sealing_pub_le`; and
/// (3) the report's `report_data` matches what the caller supplied.
fn verify_key_report(
    ctx: &TestCtx,
    report: &[u8],
    sealing_pub_le: &[u8],
    expected_report_data: &[u8; KEY_REPORT_DATA_LEN],
) {
    use azihsm_ddi_mbor_sim::attestation::KeyAttester;
    use azihsm_ddi_mbor_sim::crypto::ecc::EccOp;
    use azihsm_ddi_mbor_sim::crypto::ecc::EccPublicKey as SimEccPublicKey;
    use azihsm_ddi_mbor_sim::report::CoseSign1Object;
    use azihsm_ddi_mbor_sim::report::KeyAttestationReport;
    use x509::X509Certificate;
    use x509::X509CertificateOp;

    // 1. PID pubkey from the slot-0 chain leaf.
    let info = ctx.cert_chain_info().expect("GetCertChainInfo");
    let n = info.data.num_certs;
    assert!(
        n >= 1,
        "slot-0 cert chain must contain the PID leaf, got {n}"
    );
    let leaf_resp = ctx.get_certificate(n - 1).expect("GetCertificate(leaf)");
    let leaf_bytes = leaf_resp.data.certificate.as_slice();
    let leaf = X509Certificate::from_der(leaf_bytes).expect("PID leaf parses as X.509 certificate");
    let pid_spki = leaf.get_public_key_der().expect("PID leaf SPKI extracts");
    let pid_pub =
        SimEccPublicKey::from_der(&pid_spki, None).expect("PID pubkey loads from leaf SPKI");

    // 2. COSE_Sign1 signature verify under PID pubkey.
    let attester = KeyAttester::parse(report).expect("report parses as COSE_Sign1");
    attester
        .verify(&pid_pub)
        .expect("KeyReport COSE_Sign1 must verify under PID pubkey");

    // 3. Decode the payload and cross-bind the embedded COSE_Key to the
    //    sealed public point.
    let cose = CoseSign1Object::decode(report).expect("re-decode COSE_Sign1 envelope");
    let decoded: KeyAttestationReport =
        minicbor::decode(cose.payload).expect("report payload decodes as KeyAttestationReport");

    assert_eq!(
        &decoded.report_data[..],
        &expected_report_data[..],
        "report_data must round-trip into the report payload",
    );

    let cose_key = &decoded.public_key[..decoded.public_key_size as usize];
    let (x_be, y_be) = cose_key_xy(cose_key);

    // The COSE_Key holds big-endian coordinates; the sealing pubkey is
    // little-endian `x_le ‖ y_le`, so reverse each COSE_Key coordinate
    // and compare against the corresponding wire half.
    assert_eq!(x_be.len(), P384_COORD_LEN, "COSE_Key pk_x is a P-384 coord");
    assert_eq!(y_be.len(), P384_COORD_LEN, "COSE_Key pk_y is a P-384 coord");
    let x_le: Vec<u8> = x_be.iter().rev().copied().collect();
    let y_le: Vec<u8> = y_be.iter().rev().copied().collect();
    assert_eq!(
        x_le.as_slice(),
        &sealing_pub_le[..P384_COORD_LEN],
        "attested COSE_Key pk_x must re-derive the sealed key's X",
    );
    assert_eq!(
        y_le.as_slice(),
        &sealing_pub_le[P384_COORD_LEN..],
        "attested COSE_Key pk_y must re-derive the sealed key's Y",
    );
}

/// Walk a COSE_Key CBOR map and return its `(x, y)` byte strings
/// (labels -2 / -3).
fn cose_key_xy(cose_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use minicbor::data::Type as CborType;

    let mut decoder = minicbor::Decoder::new(cose_key);
    let entries = decoder
        .map()
        .expect("COSE_Key is a CBOR map")
        .expect("COSE_Key map length is known");
    let (mut x_bytes, mut y_bytes): (Option<Vec<u8>>, Option<Vec<u8>>) = (None, None);
    for _ in 0..entries {
        let label_ty = decoder.datatype().expect("COSE_Key entry has datatype");
        let label = match label_ty {
            CborType::I8 | CborType::I16 | CborType::I32 | CborType::I64 => {
                decoder.i64().expect("COSE_Key label decodes as int")
            }
            CborType::U8 | CborType::U16 | CborType::U32 | CborType::U64 => {
                decoder.u64().expect("COSE_Key label decodes as uint") as i64
            }
            other => panic!("unexpected COSE_Key label type {other:?}"),
        };
        match label {
            -2 => x_bytes = Some(decoder.bytes().expect("pk_x bytes").to_vec()),
            -3 => y_bytes = Some(decoder.bytes().expect("pk_y bytes").to_vec()),
            _ => decoder.skip().expect("skip non-XY label value"),
        }
    }
    (
        x_bytes.expect("COSE_Key carries pk_x (label -2)"),
        y_bytes.expect("COSE_Key carries pk_y (label -3)"),
    )
}

/// Happy path for a supported `scope`: `SdSealingKeyGen` mints a masked
/// key, `KeyReport` attests it, and the report verifies + cross-binds.
fn report_roundtrip_for_scope(scope: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, sealing_pub) = masked_sealing_key(&ctx, session.session_id, scope);
    let report_data = sample_report_data();

    let req = TborKeyReportReq {
        session_id: session.session_id,
        masked_key,
        report_data,
    };
    let resp = ctx.tbor(&req).expect("KeyReport roundtrip");

    // Tagged COSE_Sign1: CBOR tag 18 (0xD2) opening byte.
    assert_eq!(
        resp.report.first(),
        Some(&0xD2),
        "report must begin with the COSE_Sign1 CBOR tag (0xD2)",
    );
    verify_key_report(&ctx, &resp.report, &sealing_pub, &report_data);
}

#[test]
fn key_report_ephemeral_roundtrip_emu() {
    report_roundtrip_for_scope(SCOPE_EPHEMERAL);
}

#[test]
fn key_report_local_roundtrip_emu() {
    report_roundtrip_for_scope(SCOPE_LOCAL);
}

#[test]
fn key_report_rejects_tampered_masked_key_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (mut masked_key, _pub) = masked_sealing_key(&ctx, session.session_id, SCOPE_EPHEMERAL);

    // Flip the last byte (inside the AEAD tag) so unmask's tag check fails
    // — the peeked cleartext scope is untouched, so the reject is the
    // authenticity failure, not a scope/state gate.
    let last = masked_key.len() - 1;
    masked_key[last] ^= 0xFF;

    let req = TborKeyReportReq {
        session_id: session.session_id,
        masked_key,
        report_data: sample_report_data(),
    };
    ctx.expect_fw_reject(&req, TborStatus::AesGcmDecryptTagDoesNotMatch);
}

#[test]
fn key_report_rejects_before_finalize_emu() {
    let ctx = TestCtx::new();
    // Rotated CO session but no PartInit/PartFinal → the partition is not
    // Initialized, so the handler rejects before it ever unmasks.  The
    // masked_key is a well-formed-length dummy; the state gate fires first.
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let req = TborKeyReportReq {
        session_id: session.session_id,
        masked_key: vec![0u8; 180],
        report_data: sample_report_data(),
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

#[test]
fn key_report_rejected_on_cu_session_emu() {
    let ctx = TestCtx::new();

    // Rotate the CU PSK out of the default so the dispatcher's default-PSK
    // gate does not fire first; then reopen a CU session under it.  CU
    // sessions are pinned to `SessionType::PlainText`.
    let bootstrap = ctx.open_session(CU, SessionType::PlainText);
    ctx.psk_change(bootstrap.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");
    bootstrap.close().expect("close bootstrap CU session");

    let opts = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_CU_PSK);
    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("CU session_open_init under rotated PSK");
    let session = ctx
        .session_open_finish(pending)
        .expect("CU session_open_finish under rotated PSK");

    // KeyReport is Crypto-Officer-only: the handler's role gate (checked
    // before the state/scope gates) rejects a CU session.
    let req = TborKeyReportReq {
        session_id: session.session_id,
        masked_key: vec![0u8; 180],
        report_data: sample_report_data(),
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidPermissions);
}

#[test]
fn key_report_rejected_on_default_psk_emu() {
    let ctx = TestCtx::new();
    // Open a CO session WITHOUT rotating the PSK (still the public
    // default) — the dispatcher's default-PSK gate must reject the command
    // before the handler runs.
    let session = ctx.open_session(CO_DEFAULT, SessionType::Authenticated);

    let req = TborKeyReportReq {
        session_id: session.session_id(),
        masked_key: vec![0u8; 180],
        report_data: sample_report_data(),
    };
    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}
