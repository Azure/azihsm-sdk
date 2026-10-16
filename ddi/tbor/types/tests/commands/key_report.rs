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
//! * All supported symmetric key classes are rejected (emu).
//! * Session-scoped P-384 ECC keys successfully produce signed reports;
//!   the PID signature, public-key binding, and report data are verified.
//! * Oversized envelopes and invalid sessions are rejected.
//! * IV/ciphertext tampering fails authentication; the original key still works.
//! * Default-PSK gate → `DefaultPskMustRotate` (dispatcher, pre-handler).

#[cfg(feature = "emu")]
use azihsm_crypto::EccKeyOp;
#[cfg(feature = "emu")]
use azihsm_crypto::EccPrivateKey;
#[cfg(feature = "emu")]
use azihsm_crypto::ExportableKey;
#[cfg(feature = "emu")]
use azihsm_crypto::KeyGenerationOp;
#[cfg(feature = "emu")]
use azihsm_crypto::RsaKeyOp;
#[cfg(feature = "emu")]
use azihsm_crypto::RsaPrivateKey;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_cu;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::CO_PSK_ID;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::ROTATED_CU_PSK;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::TborKeyReportReq;
use azihsm_ddi_tbor_types::TborSdSealingKeyGenReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::ECC_CURVE_P384;
use azihsm_ddi_tbor_types::ECC_CURVE_P521;
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::KEY_CLASS_AES;
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::KEY_CLASS_ECC;
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::KEY_CLASS_HMAC_SHA256;
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::KEY_CLASS_HMAC_SHA384;
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::KEY_CLASS_HMAC_SHA512;
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::KEY_CLASS_RSA;
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::KEY_CLASS_RSA_CRT;
use azihsm_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use azihsm_ddi_tbor_types::KEY_REPORT_MASKED_KEY_MAX_LEN;
use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;
use azihsm_ddi_tbor_types::MASKED_SEALING_KEY_LEN;

use crate::commands::common::ENVELOPE_AAD_LEN;
use crate::commands::common::ENVELOPE_HEADER_LEN;
use crate::commands::common::ENVELOPE_IV_LEN;
use crate::commands::common::SCOPE_EPHEMERAL;
use crate::commands::common::SCOPE_LOCAL;
use crate::commands::common::SCOPE_SESSION;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
#[cfg(feature = "emu")]
use crate::commands::unwrap_key::unwrap;

/// Verifies an imported RSA or RSA-CRT key report against the host public key.
#[cfg(feature = "emu")]
fn imported_rsa_report_roundtrip(class: u8, modulus_bytes: usize) {
    use azihsm_ddi_mbor_sim::attestation::KeyAttester;
    use azihsm_ddi_mbor_sim::crypto::ecc::EccOp;
    use azihsm_ddi_mbor_sim::crypto::ecc::EccPublicKey as SimEccPublicKey;
    use azihsm_ddi_mbor_sim::report::CoseSign1Object;
    use azihsm_ddi_mbor_sim::report::KeyAttestationReport;
    use x509::X509Certificate;
    use x509::X509CertificateOp;

    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = RsaPrivateKey::generate(modulus_bytes).expect("generate host RSA key");

    // Obtain public components independently from the host key.
    let expected_n = key.n_vec().expect("host RSA modulus");
    let expected_e = key.e_vec().expect("host RSA exponent");

    let der = key.to_vec().expect("export host RSA private key");

    let imported = unwrap(&ctx, session.session_id, class, &der);

    let report_data = sample_report_data();

    let report = ctx
        .tbor(&TborKeyReportReq {
            session_id: session.session_id,
            masked_key: imported.masked_key,
            report_data,
        })
        .expect("KeyReport accepts imported RSA key");

    // Verify the PID signature.
    let info = ctx.cert_chain_info().expect("GetCertChainInfo");
    assert!(info.data.num_certs > 0);

    let leaf_resp = ctx
        .get_certificate(info.data.num_certs - 1)
        .expect("GetCertificate PID leaf");

    let leaf = X509Certificate::from_der(leaf_resp.data.certificate.as_slice())
        .expect("parse PID certificate");

    let spki = leaf.get_public_key_der().expect("extract PID public key");

    let pid_pub = SimEccPublicKey::from_der(&spki, None).expect("load PID public key");

    KeyAttester::parse(&report.report)
        .expect("parse COSE_Sign1")
        .verify(&pid_pub)
        .expect("verify PID signature");

    // Decode the signed attestation payload.
    let cose = CoseSign1Object::decode(&report.report).expect("decode COSE_Sign1");

    let decoded: KeyAttestationReport =
        minicbor::decode(cose.payload).expect("decode key attestation report");

    assert_eq!(decoded.version, 2);
    assert_eq!(&decoded.report_data[..], &report_data[..]);

    // Verify imported + sign + verify flags.
    assert_eq!(decoded.flags, 1 | (1 << 5) | (1 << 6),);

    // Parse the RSA COSE_Key: { 1: 3, -1: n, -2: e }.
    let cose_key = &decoded.public_key[..decoded.public_key_size as usize];

    let mut decoder = minicbor::Decoder::new(cose_key);
    let entries = decoder
        .map()
        .expect("COSE_Key map")
        .expect("definite COSE_Key map");

    let mut n = None;
    let mut e = None;
    let mut kty = None;

    for _ in 0..entries {
        let label = decoder.i64().expect("COSE key label");

        match label {
            1 => kty = Some(decoder.u8().expect("COSE kty")),
            -1 => n = Some(decoder.bytes().expect("RSA n")),
            -2 => e = Some(decoder.bytes().expect("RSA e")),
            _ => {
                decoder.skip().expect("skip unknown COSE field");
            }
        }
    }

    assert_eq!(kty, Some(3), "COSE key type must be RSA");

    let report_n = n.expect("RSA modulus in report");
    let report_e = e.expect("RSA exponent in report");

    assert_eq!(
        report_n,
        expected_n.as_slice(),
        "attested RSA modulus must match host key",
    );

    // The firmware stores the exponent in a four-byte field.
    // Remove any leading zero padding before comparing.
    let report_e_trimmed = report_e
        .iter()
        .position(|&b| b != 0)
        .map_or(&report_e[report_e.len()..], |i| &report_e[i..]);

    assert_eq!(
        report_e_trimmed,
        expected_e.as_slice(),
        "attested RSA exponent must match host key",
    );
}

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
    let expected_curve = match sealing_pub_le.len() {
        64 => 1,  // P-256
        96 => 2,  // P-384
        136 => 3, // P-521
        other => panic!("unexpected public-key length {other}"),
    };

    let (x_be, y_be) = cose_key_xy(cose_key, expected_curve);
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

/// Parses an EC2 COSE_Key and verifies its key type and curve.
fn cose_key_xy(cose_key: &[u8], expected_curve: u8) -> (Vec<u8>, Vec<u8>) {
    use minicbor::data::Type as CborType;

    let mut decoder = minicbor::Decoder::new(cose_key);
    let entries = decoder
        .map()
        .expect("COSE_Key is a CBOR map")
        .expect("COSE_Key map length is known");

    let mut kty = None;
    let mut crv = None;
    let mut x_bytes = None;
    let mut y_bytes = None;

    for _ in 0..entries {
        let label = match decoder.datatype().expect("COSE_Key label datatype") {
            CborType::I8 | CborType::I16 | CborType::I32 | CborType::I64 => {
                decoder.i64().expect("signed COSE label")
            }

            CborType::U8 | CborType::U16 | CborType::U32 | CborType::U64 => {
                decoder.u64().expect("unsigned COSE label") as i64
            }

            other => panic!("unexpected COSE_Key label type {other:?}"),
        };

        match label {
            1 => kty = Some(decoder.u8().expect("COSE key type")),
            -1 => crv = Some(decoder.u8().expect("COSE curve")),
            -2 => x_bytes = Some(decoder.bytes().expect("COSE X coordinate").to_vec()),
            -3 => y_bytes = Some(decoder.bytes().expect("COSE Y coordinate").to_vec()),
            _ => decoder.skip().expect("skip unknown COSE field"),
        }
    }

    assert_eq!(kty, Some(2), "COSE key type must be EC2");
    assert_eq!(
        crv,
        Some(expected_curve),
        "COSE curve must match the expected ECC public key",
    );

    (
        x_bytes.expect("COSE_Key carries X coordinate"),
        y_bytes.expect("COSE_Key carries Y coordinate"),
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

/// Verifies a signed key report for an ephemeral sealing key.
#[test]
fn key_report_ephemeral_roundtrip() {
    report_roundtrip_for_scope(SCOPE_EPHEMERAL);
}

/// Verifies a signed key report for a local sealing key.
#[test]
fn key_report_local_roundtrip() {
    report_roundtrip_for_scope(SCOPE_LOCAL);
}

/// Rejects a masked key with a tampered authentication tag.
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

/// Rejects KeyReport requests before partition finalization.
#[test]
fn key_report_rejects_before_finalize() {
    let ctx = TestCtx::new();
    // Rotated CO session but no PartInit/PartFinal → the partition is not
    // Initialized, so the handler rejects before it ever unmasks.  The
    // masked_key is a well-formed-length dummy; the state gate fires first.
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let req = TborKeyReportReq {
        session_id: session.session_id,
        masked_key: vec![0u8; MASKED_SEALING_KEY_LEN],
        report_data: sample_report_data(),
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Rejects KeyReport requests from a Crypto-User session.
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

/// Rejects KeyReport requests while the default CO PSK is in use.
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

/// Verifies report-data binding across patterns and repeated requests.
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

/// Attests generated ECC keys on all supported curves and persistent scopes.
#[test]
fn key_report_generated_ecc_all_curves() {
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
#[cfg(feature = "emu")]
#[test]
fn key_report_rejects_all_symmetric_key_classes() {
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

/// Verifies a signed key report for a session-scoped P-384 ECC key.
#[test]
fn key_report_session_scope_roundtrip() {
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

    let report_data = sample_report_data();

    let report = ctx
        .tbor(&TborKeyReportReq {
            session_id: session.session_id,
            masked_key: key.masked_key,
            report_data,
        })
        .expect("KeyReport accepts session-scoped ECC key");

    let decoded = verify_key_report(&ctx, &report.report, &key.pub_key, &report_data);

    // Generated + sign.
    // Session + Generated + Sign.
    assert_eq!(decoded.flags, (1 << 2) | (1 << 5));
}

/// Rejects masked keys exceeding the KeyReport maximum length.
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

/// Rejects KeyReport requests with an invalid session ID.
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

/// Rejects tampered IVs and ciphertext while preserving the original key.
#[test]
fn key_report_rejects_tampered_iv_and_ciphertext() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, public_key) = masked_sealing_key(&ctx, session.session_id, SCOPE_LOCAL);
    let report_data = sample_report_data();

    // The IV begins at offset 8, while ciphertext begins after the
    // 8-byte header, 12-byte IV, and 192-byte metadata/AAD region.
    // Tampering either encrypted field must fail GCM authentication.
    for offset in [
        ENVELOPE_HEADER_LEN,
        ENVELOPE_HEADER_LEN + ENVELOPE_IV_LEN + ENVELOPE_AAD_LEN,
    ] {
        let mut tampered = masked_key.clone();
        tampered[offset] ^= 1;

        ctx.expect_fw_reject(
            &TborKeyReportReq {
                session_id: session.session_id,
                masked_key: tampered,
                report_data,
            },
            TborStatus::AesGcmDecryptTagDoesNotMatch,
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

/// Attests imported ECC keys across P-256, P-384, and P-521 using platform-appropriate key sizes.
/// Verifies imported ECC key reports against independently generated host public keys.

#[cfg(feature = "emu")]
#[test]
fn key_report_imported_ecc_all_curves() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for (curve, key_len) in [
        (azihsm_crypto::EccCurve::P256, 32usize),
        (azihsm_crypto::EccCurve::P384, 48),
        (azihsm_crypto::EccCurve::P521, 66),
    ] {
        let key = EccPrivateKey::from_curve(curve).expect("host ECC key generation");

        // Extract the host public coordinates before importing.
        let (x_be, y_be) = key
            .coord_vec()
            .expect("extract host ECC public coordinates");

        assert_eq!(x_be.len(), key_len);
        assert_eq!(y_be.len(), key_len);

        // Convert host big-endian coordinates to TBOR wire format.
        // P-521 uses 68-byte wire coordinates with two padding bytes.
        let wire_len = if key_len == 66 { 68 } else { key_len };

        let mut host_pub_key = Vec::with_capacity(2 * wire_len);

        host_pub_key.extend(x_be.iter().rev().copied());
        host_pub_key.resize(wire_len, 0);

        host_pub_key.extend(y_be.iter().rev().copied());
        host_pub_key.resize(2 * wire_len, 0);

        // Import the host private key into the firmware.
        let der = key.to_vec().expect("export PKCS#8 key");

        let imported = unwrap(&ctx, session.session_id, KEY_CLASS_ECC, &der);

        // Independently check the public key returned by UnwrapKey.
        assert_eq!(
            imported.pub_key, host_pub_key,
            "UnwrapKey public key must match host key (len={key_len})",
        );

        let report_data = sample_report_data();

        let report = ctx
            .tbor(&TborKeyReportReq {
                session_id: session.session_id,
                masked_key: imported.masked_key,
                report_data,
            })
            .expect("attest imported ECC key");

        // Verify against the host-generated public key,
        // not the firmware's UnwrapKey public key.
        let decoded = verify_key_report(&ctx, &report.report, &host_pub_key, &report_data);

        // Imported + Sign + Verify.
        assert_eq!(
            decoded.flags,
            1 | (1 << 5) | (1 << 6),
            "key length {key_len}",
        );
    }
}

/// Rejects a CU request even with a valid key after partition finalization.
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

/// Verifies a signed report for an imported RSA-2048 private key.
#[test]
#[cfg(feature = "emu")]
fn key_report_imported_rsa_roundtrip() {
    imported_rsa_report_roundtrip(KEY_CLASS_RSA, 256);
}

/// Verifies a signed report for an imported RSA-CRT-2048 private key.
#[test]
#[cfg(feature = "emu")]
fn key_report_imported_rsa_crt_roundtrip() {
    imported_rsa_report_roundtrip(KEY_CLASS_RSA_CRT, 256);
}

/// Verifies a signed report for an imported RSA-3072 private key.
#[test]
#[cfg(feature = "emu")]
fn key_report_imported_rsa_3072_roundtrip() {
    imported_rsa_report_roundtrip(KEY_CLASS_RSA, 384);
}

/// Verifies a signed report for an imported RSA-4096 private key.
#[test]
#[cfg(feature = "emu")]
fn key_report_imported_rsa_4096_roundtrip() {
    imported_rsa_report_roundtrip(KEY_CLASS_RSA, 512);
}

/// Verifies a signed report for an imported RSA-CRT-3072 private key.
#[test]
#[cfg(feature = "emu")]
fn key_report_imported_rsa_crt_3072_roundtrip() {
    imported_rsa_report_roundtrip(KEY_CLASS_RSA_CRT, 384);
}

/// Verifies a signed report for an imported RSA-CRT-4096 private key.
#[test]
#[cfg(feature = "emu")]
fn key_report_imported_rsa_crt_4096_roundtrip() {
    imported_rsa_report_roundtrip(KEY_CLASS_RSA_CRT, 512);
}

/// Verifies that tampering with an imported RSA/RSA-CRT masked key
/// is rejected without invalidating the original key.
#[cfg(feature = "emu")]
fn imported_rsa_tampering_rejected(class: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = RsaPrivateKey::generate(256).expect("generate RSA-2048 key");

    let der = key.to_vec().expect("export RSA DER");

    let imported = unwrap(&ctx, session.session_id, class, &der);

    let masked_key = imported.masked_key;
    let report_data = sample_report_data();

    let ciphertext_offset = ENVELOPE_HEADER_LEN + ENVELOPE_IV_LEN + ENVELOPE_AAD_LEN;

    // Tamper with IV, ciphertext, and authentication tag.
    for offset in [ENVELOPE_HEADER_LEN, ciphertext_offset, masked_key.len() - 1] {
        assert!(offset < masked_key.len());

        let mut tampered = masked_key.clone();
        tampered[offset] ^= 0x01;

        ctx.expect_fw_reject(
            &TborKeyReportReq {
                session_id: session.session_id,
                masked_key: tampered,
                report_data,
            },
            TborStatus::AesGcmDecryptTagDoesNotMatch,
        );

        // The original key must remain usable after rejection.
        let resp = ctx
            .tbor(&TborKeyReportReq {
                session_id: session.session_id,
                masked_key: masked_key.clone(),
                report_data,
            })
            .expect("original RSA key remains attestable");

        assert_eq!(
            resp.report.first(),
            Some(&0xD2),
            "expected tagged COSE_Sign1 report",
        );
    }
}

/// Rejects tampered imported RSA masked keys.
#[test]
#[cfg(feature = "emu")]
fn key_report_imported_rsa_tampering_rejected() {
    imported_rsa_tampering_rejected(KEY_CLASS_RSA);
}

/// Rejects tampered imported RSA-CRT masked keys.
#[test]
#[cfg(feature = "emu")]
fn key_report_imported_rsa_crt_tampering_rejected() {
    imported_rsa_tampering_rejected(KEY_CLASS_RSA_CRT);
}

/// Verifies RSA/RSA-CRT authenticated metadata tampering fails GCM verification.
#[cfg(feature = "emu")]
fn imported_rsa_metadata_tampering_rejected(class: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = RsaPrivateKey::generate(256).expect("generate host RSA-2048 key");

    let der = key.to_vec().expect("export RSA private DER");

    let imported = unwrap(&ctx, session.session_id, class, &der);

    let masked_key = imported.masked_key;
    let report_data = sample_report_data();

    // Modify authenticated metadata while preserving its valid encoding.
    // This should reach the AES-GCM authentication check.
    let aad_offset = ENVELOPE_HEADER_LEN + ENVELOPE_IV_LEN + 26;

    assert!(aad_offset < masked_key.len());

    let mut tampered = masked_key.clone();
    tampered[aad_offset] ^= 0x01;

    ctx.expect_fw_reject(
        &TborKeyReportReq {
            session_id: session.session_id,
            masked_key: tampered,
            report_data,
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );

    // The original key remains valid after the rejected request.
    let report = ctx
        .tbor(&TborKeyReportReq {
            session_id: session.session_id,
            masked_key,
            report_data,
        })
        .expect("original RSA key remains attestable");

    assert_eq!(report.report.first(), Some(&0xD2));
}

/// Rejects authenticated metadata tampering on an imported RSA key.
#[test]
#[cfg(feature = "emu")]
fn key_report_imported_rsa_metadata_tampering_rejected() {
    imported_rsa_metadata_tampering_rejected(KEY_CLASS_RSA);
}

/// Rejects authenticated metadata tampering on an imported RSA-CRT key.
#[test]
#[cfg(feature = "emu")]
fn key_report_imported_rsa_crt_metadata_tampering_rejected() {
    imported_rsa_metadata_tampering_rejected(KEY_CLASS_RSA_CRT);
}

/// Rejects an RSA/RSA-CRT KeyReport request with an invalid session ID.
#[cfg(feature = "emu")]
fn imported_rsa_invalid_session_rejected(class: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key = RsaPrivateKey::generate(256).expect("generate host RSA-2048 key");

    let der = key.to_vec().expect("export RSA private DER");

    let imported = unwrap(&ctx, session.session_id, class, &der);

    let masked_key = imported.masked_key;
    let report_data = sample_report_data();

    ctx.expect_fw_reject(
        &TborKeyReportReq {
            session_id: u16::MAX,
            masked_key: masked_key.clone(),
            report_data,
        },
        TborStatus::FileHandleSessionIdDoesNotMatch,
    );

    // An invalid-session request must not affect the valid session.
    let report = ctx
        .tbor(&TborKeyReportReq {
            session_id: session.session_id,
            masked_key,
            report_data,
        })
        .expect("valid session remains usable after rejection");

    assert_eq!(report.report.first(), Some(&0xD2));
}

/// Rejects an imported RSA KeyReport request with an invalid session.
#[test]
#[cfg(feature = "emu")]
fn key_report_imported_rsa_invalid_session_rejected() {
    imported_rsa_invalid_session_rejected(KEY_CLASS_RSA);
}

/// Rejects an imported RSA-CRT KeyReport request with an invalid session.
#[test]
#[cfg(feature = "emu")]
fn key_report_imported_rsa_crt_invalid_session_rejected() {
    imported_rsa_invalid_session_rejected(KEY_CLASS_RSA_CRT);
}
