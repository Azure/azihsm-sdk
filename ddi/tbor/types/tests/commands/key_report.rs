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
//! * Report-data patterns and repeated requests preserve signed key binding.
//! * Ordinary ECC keys on all curves, including P-521 wire padding.
//! * Imported ECC keys retain their public points and imported/sign/verify
//!   flags (emu); generated keys carry generated/sign/derive flags.
//! * CU rejection with a valid key on a finalized partition.
//! * All supported symmetric key classes are rejected (emu); session-scoped ECC keys are rejected.
//! * Oversized envelopes and invalid sessions are rejected.
//! * IV/ciphertext tampering fails authentication; the original key still works.
//! * Default-PSK gate → `DefaultPskMustRotate` (dispatcher, pre-handler).

use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_cu;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::CO_PSK_ID;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::ROTATED_CU_PSK;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborKeyReportReq;
use azihsm_ddi_tbor_types::TborSdSealingKeyGenReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use azihsm_ddi_tbor_types::KEY_REPORT_MASKED_KEY_MAX_LEN;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope` discriminants (wire mirror of the firmware `HsmKeyScope`).
const SCOPE_SESSION: u8 = 0b001;
const SCOPE_EPHEMERAL: u8 = 0b010;
const SCOPE_LOCAL: u8 = 0b011;

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
) -> azihsm_ddi_mbor_sim::report::KeyAttestationReport {
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
    let (coord_len, wire_len) = match sealing_pub_le.len() {
        64 => (32, 32),
        96 => (48, 48),
        136 => (66, 68), // P-521 wire coordinates include two padding bytes.
        other => panic!("unexpected public-key length {other}"),
    };
    assert_eq!(x_be.len(), coord_len, "COSE_Key X coordinate length");
    assert_eq!(y_be.len(), coord_len, "COSE_Key Y coordinate length");
    let x_le: Vec<u8> = x_be.iter().rev().copied().collect();
    let y_le: Vec<u8> = y_be.iter().rev().copied().collect();
    assert_eq!(
        x_le.as_slice(),
        &sealing_pub_le[..coord_len],
        "attested COSE_Key pk_x must re-derive the sealed key's X",
    );
    assert_eq!(
        y_le.as_slice(),
        &sealing_pub_le[wire_len..wire_len + coord_len],
        "attested COSE_Key pk_y must re-derive the sealed key's Y",
    );
    assert_eq!(decoded.version, 2, "TBOR reports use version 2");
    decoded
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
fn key_report_ephemeral_roundtrip() {
    report_roundtrip_for_scope(SCOPE_EPHEMERAL);
}

#[test]
fn key_report_local_roundtrip() {
    report_roundtrip_for_scope(SCOPE_LOCAL);
}

#[test]
fn key_report_rejects_tampered_masked_key() {
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
fn key_report_rejects_before_finalize() {
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
fn key_report_rejected_on_cu_session() {
    let ctx = TestCtx::new();

    // Rotate the CU PSK out of the default so the dispatcher's default-PSK
    // gate does not fire first; then reopen a CU session under it.  CU
    // sessions are pinned to `SessionType::PlainText`.
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

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
fn key_report_rejected_on_default_psk() {
    let ctx = TestCtx::new();
    // Open a CO session WITHOUT rotating the PSK (still the public
    // default) — the dispatcher's default-PSK gate must reject the command
    // before the handler runs.
    let session = ctx
        .open_session(CO_PSK_ID, SessionType::Authenticated)
        .expect("open_session must succeed");

    let req = TborKeyReportReq {
        session_id: session.session_id(),
        masked_key: vec![0u8; 180],
        report_data: sample_report_data(),
    };
    ctx.expect_fw_reject(&req, TborStatus::DefaultPskMustRotate);
}

#[test]
fn key_report_report_data_patterns() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for scope in [SCOPE_EPHEMERAL, SCOPE_LOCAL] {
        let (masked_key, public_key) = masked_sealing_key(&ctx, session.session_id, scope);
        for report_data in [
            [0; KEY_REPORT_DATA_LEN],
            [0xFF; KEY_REPORT_DATA_LEN],
            sample_report_data(),
            [0; KEY_REPORT_DATA_LEN],
        ] {
            let resp = ctx
                .tbor(&TborKeyReportReq {
                    session_id: session.session_id,
                    masked_key: masked_key.clone(),
                    report_data,
                })
                .expect("KeyReport with report-data pattern");
            // Verify the signed payload, rather than comparing randomized signatures.
            verify_key_report(&ctx, &resp.report, &public_key, &report_data);
        }
    }
}

#[test]
fn key_report_generated_ecc_all_curves() {
    use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
    use azihsm_ddi_tbor_types::ECC_CURVE_P256;
    use azihsm_ddi_tbor_types::ECC_CURVE_P384;
    use azihsm_ddi_tbor_types::ECC_CURVE_P521;
    use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;

    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for curve in [ECC_CURVE_P256, ECC_CURVE_P384, ECC_CURVE_P521] {
        for scope in [SCOPE_EPHEMERAL, SCOPE_LOCAL] {
            let key = ctx
                .tbor(&TborEccGenerateKeyReq {
                    session_id: session.session_id,
                    scope,
                    curve,
                    key_usage: KEY_USAGE_SIGN,
                    key_label: Vec::new(),
                })
                .expect("generate ECC key");
            let report_data = sample_report_data();
            let report = ctx
                .tbor(&TborKeyReportReq {
                    session_id: session.session_id,
                    masked_key: key.masked_key,
                    report_data,
                })
                .expect("attest ordinary ECC key");
            let decoded = verify_key_report(&ctx, &report.report, &key.pub_key, &report_data);
            // Generated (bit 2) + sign (bit 5); no other usages.
            assert_eq!(decoded.flags, (1 << 2) | (1 << 5));
        }
    }
}

/// Rejects every supported symmetric key class because KeyReport only
/// attests asymmetric keys that have a public component.
#[test]
#[cfg(feature = "emu")]
fn key_report_rejects_all_symmetric_key_classes_emu() {
    use azihsm_ddi_tbor_types::KEY_CLASS_AES;
    use azihsm_ddi_tbor_types::KEY_CLASS_HMAC_SHA256;
    use azihsm_ddi_tbor_types::KEY_CLASS_HMAC_SHA384;
    use azihsm_ddi_tbor_types::KEY_CLASS_HMAC_SHA512;

    use crate::commands::unwrap_key::unwrap;

    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for (class, key_len) in [
        (KEY_CLASS_AES, 32usize),
        (KEY_CLASS_HMAC_SHA256, 32usize),
        (KEY_CLASS_HMAC_SHA384, 48usize),
        (KEY_CLASS_HMAC_SHA512, 64usize),
    ] {
        // Use a valid key length for each class so the key imports
        // successfully and the test isolates KeyReport's key-type gate.
        let key_material = vec![0x37; key_len];
        let key = unwrap(&ctx, session.session_id, class, &key_material);

        ctx.expect_fw_reject(
            &TborKeyReportReq {
                session_id: session.session_id,
                masked_key: key.masked_key,
                report_data: sample_report_data(),
            },
            TborStatus::UnsupportedKeyType,
        );
    }
}

#[test]
fn key_report_rejects_session_scope() {
    use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
    use azihsm_ddi_tbor_types::ECC_CURVE_P384;
    use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;

    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SESSION,
            curve: ECC_CURVE_P384,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("generate session-scoped ECC key");
    ctx.expect_fw_reject(
        &TborKeyReportReq {
            session_id: session.session_id,
            masked_key: key.masked_key,
            report_data: sample_report_data(),
        },
        TborStatus::UnsupportedKeyScope,
    );
}

#[test]
fn key_report_rejects_oversized_masked_key() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    ctx.expect_fw_reject(
        &TborKeyReportReq {
            session_id: session.session_id,
            masked_key: vec![0; KEY_REPORT_MASKED_KEY_MAX_LEN + 1],
            report_data: sample_report_data(),
        },
        TborStatus::TborInvalidFixedLength,
    );
}

#[test]
fn key_report_rejects_invalid_session() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _) = masked_sealing_key(&ctx, session.session_id, SCOPE_LOCAL);
    ctx.expect_fw_reject(
        &TborKeyReportReq {
            session_id: u16::MAX,
            masked_key,
            report_data: sample_report_data(),
        },
        TborStatus::FileHandleSessionIdDoesNotMatch,
    );
}

#[test]
fn key_report_rejects_tampered_iv_and_ciphertext() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, public_key) = masked_sealing_key(&ctx, session.session_id, SCOPE_LOCAL);
    let report_data = sample_report_data();
    // The IV begins at offset 8, so tampering it preserves the envelope
    // structure but fails GCM authentication. The legacy `8 + 12 + 96`
    // offset now falls inside the expanded masked-key metadata/AAD region,
    // so corrupting it fails masked-key decoding.
    for (offset, expected_status) in [
        (8, TborStatus::AesGcmDecryptTagDoesNotMatch),
        (8 + 12 + 96, TborStatus::MaskedKeyDecodeFailed),
    ] {
        let mut tampered = masked_key.clone();
        tampered[offset] ^= 1;
        ctx.expect_fw_reject(
            &TborKeyReportReq {
                session_id: session.session_id,
                masked_key: tampered,
                report_data,
            },
            expected_status,
        );
        let resp = ctx
            .tbor(&TborKeyReportReq {
                session_id: session.session_id,
                masked_key: masked_key.clone(),
                report_data,
            })
            .expect("original key remains attestable after rejection");
        verify_key_report(&ctx, &resp.report, &public_key, &report_data);
    }
}

#[test]
#[cfg(feature = "emu")]
fn key_report_imported_ecc_all_curves_emu() {
    use azihsm_crypto::EccPrivateKey;
    use azihsm_crypto::ExportableKey;
    use azihsm_crypto::KeyGenerationOp;
    use azihsm_ddi_tbor_types::KEY_CLASS_ECC;

    use crate::commands::unwrap_key::unwrap;

    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for key_len in [32, 48, 66] {
        let key = EccPrivateKey::generate(key_len).expect("host ECC key generation");
        let der = key.to_vec().expect("export PKCS#8 key");
        let imported = unwrap(&ctx, session.session_id, KEY_CLASS_ECC, &der);
        let report_data = sample_report_data();
        let report = ctx
            .tbor(&TborKeyReportReq {
                session_id: session.session_id,
                masked_key: imported.masked_key,
                report_data,
            })
            .expect("attest imported ECC key");
        let decoded = verify_key_report(&ctx, &report.report, &imported.pub_key, &report_data);
        // Imported (bit 0), sign (bit 5), verify (bit 6). In particular,
        // an imported key must not claim that it was generated on-device.
        assert_eq!(
            decoded.flags,
            1 | (1 << 5) | (1 << 6),
            "key length {key_len}"
        );
    }
}

#[test]
fn key_report_rejects_cu_with_valid_key_after_finalize() {
    let ctx = TestCtx::new();
    let co = finalized_co_session(&ctx);
    let (masked_key, _) = masked_sealing_key(&ctx, co.session_id, SCOPE_LOCAL);
    ctx.session_close(co.session_id).expect("close CO session");
    let cu = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    // Every other prerequisite is valid, isolating the CO-only role gate.
    ctx.expect_fw_reject(
        &TborKeyReportReq {
            session_id: cu.session_id,
            masked_key,
            report_data: sample_report_data(),
        },
        TborStatus::InvalidPermissions,
    );
    ctx.session_close(cu.session_id).expect("close CU session");
}

/// Attests a generated ECC key carrying a non-empty key label.
#[test]
fn key_report_generated_ecc_non_empty_label() {
    use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
    use azihsm_ddi_tbor_types::ECC_CURVE_P256;
    use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;

    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: b"key-report-test".to_vec(),
        })
        .expect("generate labeled ECC key");

    let report_data = sample_report_data();

    let report = ctx
        .tbor(&TborKeyReportReq {
            session_id: session.session_id,
            masked_key: key.masked_key,
            report_data,
        })
        .expect("KeyReport accepts labeled ECC key");

    let decoded = verify_key_report(&ctx, &report.report, &key.pub_key, &report_data);

    // Generated + sign.
    assert_eq!(decoded.flags, (1 << 2) | (1 << 5));
}

/// Attests an ECC key carrying the maximum-length key label.
#[test]
fn key_report_generated_ecc_max_label() {
    use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
    use azihsm_ddi_tbor_types::ECC_CURVE_P256;
    use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;
    use azihsm_ddi_tbor_types::TBOR_KEY_LABEL_MAX_LEN;

    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: vec![b'L'; TBOR_KEY_LABEL_MAX_LEN],
        })
        .expect("generate ECC key with max label");

    let report_data = sample_report_data();

    let report = ctx
        .tbor(&TborKeyReportReq {
            session_id: session.session_id,
            masked_key: key.masked_key,
            report_data,
        })
        .expect("KeyReport accepts max-label ECC key");

    let decoded = verify_key_report(&ctx, &report.report, &key.pub_key, &report_data);

    assert_eq!(decoded.flags, (1 << 2) | (1 << 5));
}

/// Preserves DERIVE usage from generated-key metadata into KeyReport flags.
#[test]
fn key_report_generated_ecc_derive_usage() {
    use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
    use azihsm_ddi_tbor_types::ECC_CURVE_P256;
    use azihsm_ddi_tbor_types::KEY_USAGE_DERIVE;

    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_DERIVE,
            key_label: Vec::new(),
        })
        .expect("generate derive-only ECC key");

    let report_data = sample_report_data();

    let report = ctx
        .tbor(&TborKeyReportReq {
            session_id: session.session_id,
            masked_key: key.masked_key,
            report_data,
        })
        .expect("attest derive-only ECC key");

    let decoded = verify_key_report(&ctx, &report.report, &key.pub_key, &report_data);

    // Generated + derive.
    assert_eq!(decoded.flags, (1 << 2) | (1 << 9));
}

/// Rejects combined SIGN | DERIVE usage for generated ECC keys.
#[test]
fn key_report_generated_ecc_sign_and_derive_usage_rejected() {
    use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
    use azihsm_ddi_tbor_types::ECC_CURVE_P256;
    use azihsm_ddi_tbor_types::KEY_USAGE_DERIVE;
    use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;

    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    ctx.expect_fw_reject(
        &TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN | KEY_USAGE_DERIVE,
            key_label: Vec::new(),
        },
        TborStatus::InvalidPermissions,
    );
}

/// Attests a DERIVE-only ECC key carrying a non-empty label.
#[test]
fn key_report_generated_ecc_derive_with_label() {
    use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
    use azihsm_ddi_tbor_types::ECC_CURVE_P256;
    use azihsm_ddi_tbor_types::KEY_USAGE_DERIVE;

    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_DERIVE,
            key_label: b"derive-key-report".to_vec(),
        })
        .expect("generate labeled DERIVE ECC key");

    let report_data = sample_report_data();

    let report = ctx
        .tbor(&TborKeyReportReq {
            session_id: session.session_id,
            masked_key: key.masked_key,
            report_data,
        })
        .expect("attest labeled DERIVE ECC key");

    let decoded = verify_key_report(&ctx, &report.report, &key.pub_key, &report_data);

    // Generated + derive.
    assert_eq!(decoded.flags, (1 << 2) | (1 << 9));
}

/// Attests a generated ECC key carrying a binary key label.
#[test]
fn key_report_generated_ecc_binary_label() {
    use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
    use azihsm_ddi_tbor_types::ECC_CURVE_P256;
    use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;

    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_SIGN,
            key_label: vec![0x00, 0x80, 0xff, 0x41],
        })
        .expect("generate ECC key with binary label");

    let report_data = sample_report_data();

    let report = ctx
        .tbor(&TborKeyReportReq {
            session_id: session.session_id,
            masked_key: key.masked_key,
            report_data,
        })
        .expect("attest ECC key with binary label");

    let decoded = verify_key_report(&ctx, &report.report, &key.pub_key, &report_data);

    assert_eq!(decoded.flags, (1 << 2) | (1 << 5));
}

/// Attests the largest supported ECC key with the maximum key-label length.
#[test]
fn key_report_p521_with_max_label() {
    use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
    use azihsm_ddi_tbor_types::ECC_CURVE_P521;
    use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;
    use azihsm_ddi_tbor_types::TBOR_KEY_LABEL_MAX_LEN;

    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P521,
            key_usage: KEY_USAGE_SIGN,
            key_label: vec![b'L'; TBOR_KEY_LABEL_MAX_LEN],
        })
        .expect("generate P-521 ECC key with maximum label");

    let report_data = sample_report_data();

    let report = ctx
        .tbor(&TborKeyReportReq {
            session_id: session.session_id,
            masked_key: key.masked_key,
            report_data,
        })
        .expect("attest P-521 ECC key with maximum label");

    let decoded = verify_key_report(&ctx, &report.report, &key.pub_key, &report_data);

    assert_eq!(decoded.flags, (1 << 2) | (1 << 5));
}
