// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Happy-path `PartInit` tests:
//!
//! * [`part_init_smoke_roundtrip_emu`] — `OpenSession → PskChange →
//!   PartInit` returns a parseable PKCS#10 CSR and a verifiable
//!   COSE_Sign1 PTAReport that cross-binds to the CSR pubkey; a
//!   second `PartInit` on a fresh session surfaces the one-shot
//!   `PtaKeyAlreadySet` guard.
//! * [`part_init_determinism_emu`] — across two cold restarts (via
//!   `ctx.erase()`), the derived PTA pubkey is byte-identical given
//!   the same `(UDS, MachineSeed, Policy, POTA thumb)` inputs.

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PTA_CSR_MAX_LEN;
use azihsm_ddi_tbor_types::PTA_REPORT_MAX_LEN;

use super::bootstrap_rotated_co;
use super::known_good_part_policy;
use super::mach_seed;
use super::open_co_with;
use super::pota_thumbprint;
use super::CO;
use super::ROTATED_CO_PSK;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::TestCtx;

#[test]
fn part_init_smoke_roundtrip_emu() {
    let ctx = TestCtx::new();

    // 1. Bootstrap: rotate CO PSK so PartInit clears the
    //    default-PSK reject arm, then open under the rotated PSK.
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let resp = ctx
        .part_init(&session, &seed, &policy, &thumb)
        .expect("PartInit roundtrip");

    // CSR — DER `SEQUENCE` (0x30) tag, length fits the FW max.
    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(
        resp.pta_csr.len() <= PTA_CSR_MAX_LEN,
        "PTACSR len {} exceeds wire max {}",
        resp.pta_csr.len(),
        PTA_CSR_MAX_LEN,
    );
    assert_eq!(
        resp.pta_csr[0], 0x30,
        "PTACSR must begin with DER SEQUENCE tag",
    );

    // Full PKCS#10 parse + ECDSA-P384 self-signature verification.
    // Confirms the FW's CSR builder produced a syntactically valid,
    // self-consistent CertificationRequest signed by the embedded
    // PTA pubkey.
    use x509::X509Csr;
    use x509::X509CsrOp;
    let csr = X509Csr::from_der(&resp.pta_csr).unwrap_or_else(|e| {
        panic!(
            "PTACSR parses as PKCS#10: {e:?}\nlen={} first16={:02x?}",
            resp.pta_csr.len(),
            &resp.pta_csr[..resp.pta_csr.len().min(16)],
        )
    });
    let v = csr.verify();
    if !matches!(v, Ok(true)) {
        panic!(
            "PTACSR verify expected Ok(true), got {v:?}\nDER (len={}): {}",
            resp.pta_csr.len(),
            resp.pta_csr
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        );
    }
    let pta_spki = csr
        .get_public_key_der()
        .expect("PTA SubjectPublicKeyInfo extracts");
    assert!(!pta_spki.is_empty(), "PTA SPKI must be non-empty");

    // PTAReport — CBOR tag 18 (COSE_Sign1) opening byte 0xD2.
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
    assert!(
        resp.pta_report.len() <= PTA_REPORT_MAX_LEN,
        "PTAReport len {} exceeds wire max {}",
        resp.pta_report.len(),
        PTA_REPORT_MAX_LEN,
    );
    assert_eq!(
        resp.pta_report[0], 0xD2,
        "PTAReport must begin with COSE_Sign1 CBOR tag (0xD2)",
    );

    // Full COSE_Sign1 verification of the PTAReport under the PID
    // pubkey.  The PID pubkey is the SubjectPublicKeyInfo of the
    // slot-0 cert-chain leaf (idx = num_certs - 1; signed by the
    // Alias CA in the std PAL emu cert store).  Cross-binds the
    // report by also asserting its embedded COSE_Key `pk_x`/`pk_y`
    // matches the PTA pubkey we just extracted from the CSR.
    verify_pta_report(&ctx, &resp.pta_report, &pta_spki);

    // 2. Second PartInit on a freshly-opened session must be rejected
    //    by the one-shot `part_set_pta_key` guard with
    //    `TborStatus::PtaKeyAlreadySet`.
    ctx.session_close(session.session_id)
        .expect("close first PartInit session");
    let session2 = open_co_with(&ctx, &ROTATED_CO_PSK);
    let err = ctx
        .part_init(&session2, &seed, &policy, &thumb)
        .expect_err("second PartInit must be rejected by one-shot state guard");
    assert_fw_rejects(&err, TborStatus::PtaKeyAlreadySet);
}

/// Verify the PTAReport COSE_Sign1 envelope and cross-bind its
/// embedded COSE_Key payload to the PTA pubkey carried in
/// `pta_spki_der`.
///
/// Steps:
///
/// 1. Fetch the partition's slot-0 cert chain via the existing MBOR
///    `GetCertChainInfo` + `GetCertificate` helpers and treat the
///    last cert (idx = `num_certs - 1`) as the PID leaf signed by
///    the Alias CA.  Parse it with [`x509::X509Certificate`] and
///    pull the SubjectPublicKeyInfo as the PID pubkey.
///
/// 2. Verify the COSE_Sign1 signature with
///    [`azihsm_ddi_mbor_sim::attestation::KeyAttester::verify`],
///    which rebuilds the COSE `Sig_structure`, hashes it with
///    SHA-384, and runs ECDSA-P384 verify under the PID pubkey.
///
/// 3. Cross-bind: re-decode the COSE_Sign1 to recover the raw
///    payload, parse it as a [`KeyAttestationReport`], and walk
///    the embedded COSE_Key map to recover the attested `pk_x` /
///    `pk_y`.  These must match the X/Y coordinates parsed out of
///    the CSR's SubjectPublicKeyInfo — proving the report
///    actually attests the same key the CSR is requesting a cert
///    for.
fn verify_pta_report(ctx: &TestCtx, pta_report: &[u8], pta_spki_der: &[u8]) {
    use azihsm_crypto::DerEccPublicKey;
    use azihsm_ddi_mbor_sim::attestation::KeyAttester;
    use azihsm_ddi_mbor_sim::crypto::ecc::EccOp;
    use azihsm_ddi_mbor_sim::crypto::ecc::EccPublicKey as SimEccPublicKey;
    use azihsm_ddi_mbor_sim::report::CoseSign1Object;
    use azihsm_ddi_mbor_sim::report::KeyAttestationReport;
    use minicbor::data::Type as CborType;
    use x509::X509Certificate;
    use x509::X509CertificateOp;

    // 1. PID pubkey from the slot-0 chain leaf.
    let info = ctx.cert_chain_info().expect("GetCertChainInfo");
    let n = info.data.num_certs;
    assert!(
        n >= 1,
        "slot-0 cert chain must contain at least the PID leaf, got {n}",
    );
    let leaf_resp = ctx.get_certificate(n - 1).expect("GetCertificate(leaf)");
    let leaf_bytes = leaf_resp.data.certificate.as_slice();
    let leaf = X509Certificate::from_der(leaf_bytes).expect("PID leaf parses as X.509 certificate");
    let pid_spki = leaf.get_public_key_der().expect("PID leaf SPKI extracts");
    let pid_pub =
        SimEccPublicKey::from_der(&pid_spki, None).expect("PID pubkey loads from leaf SPKI");

    // 2. COSE_Sign1 signature verify under PID pubkey.
    let attester = KeyAttester::parse(pta_report).expect("PTAReport parses as COSE_Sign1");
    attester
        .verify(&pid_pub)
        .expect("PTAReport COSE_Sign1 must verify under PID pubkey");

    // 3. Cross-binding: report's embedded COSE_Key matches CSR pub.
    let cose = CoseSign1Object::decode(pta_report).expect("re-decode COSE_Sign1 envelope");
    let report: KeyAttestationReport =
        minicbor::decode(cose.payload).expect("report payload decodes as KeyAttestationReport");
    let cose_key = &report.public_key[..report.public_key_size as usize];

    // Walk the COSE_Key CBOR map and pull labels -2 (`x`) and -3
    // (`y`).  We could call `CoseKey::EccPublic { ... }` if there
    // were a `Decode` impl, but only `encode` is exposed; a manual
    // walk keeps the test independent of sim-side CBOR plumbing.
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
            -2 => {
                x_bytes = Some(decoder.bytes().expect("pk_x bytes").to_vec());
            }
            -3 => {
                y_bytes = Some(decoder.bytes().expect("pk_y bytes").to_vec());
            }
            _ => {
                // Skip kty / crv / any future labels.
                decoder.skip().expect("skip non-XY label value");
            }
        }
    }
    let x_rep = x_bytes.expect("COSE_Key carries pk_x (label -2)");
    let y_rep = y_bytes.expect("COSE_Key carries pk_y (label -3)");

    let csr_pub =
        DerEccPublicKey::from_der(pta_spki_der).expect("CSR SubjectPublicKeyInfo decodes");
    assert_eq!(
        x_rep.as_slice(),
        csr_pub.x(),
        "PTAReport COSE_Key pk_x must equal the PTA pubkey X carried in the CSR",
    );
    assert_eq!(
        y_rep.as_slice(),
        csr_pub.y(),
        "PTAReport COSE_Key pk_y must equal the PTA pubkey Y carried in the CSR",
    );
}

/// Run the canonical CO bootstrap → rotate PSK → reopen → PartInit
/// flow with the supplied inputs and return the PTA SubjectPublicKeyInfo
/// extracted from the CSR.
fn run_part_init_capture_pta_pub(
    ctx: &TestCtx,
    seed: &[u8; MACH_SEED_LEN],
    policy: &[u8; PART_POLICY_LEN],
    thumb: &[u8; POTA_THUMBPRINT_LEN],
) -> Vec<u8> {
    use x509::X509Csr;
    use x509::X509CsrOp;

    let bootstrap = ctx
        .open_session_raw(CO, SessionType::Authenticated)
        .expect("open CO default");
    ctx.psk_change(&bootstrap, &ROTATED_CO_PSK)
        .expect("rotate CO PSK");
    let _ = ctx.session_close(bootstrap.session_id);

    let session = open_co_with(ctx, &ROTATED_CO_PSK);
    let resp = ctx
        .part_init(&session, seed, policy, thumb)
        .expect("PartInit roundtrip");
    let _ = ctx.session_close(session.session_id);

    let csr = X509Csr::from_der(&resp.pta_csr).expect("PTACSR parses");
    csr.get_public_key_der().expect("CSR SPKI extracts")
}

/// Cold-start determinism: derive the PTA keypair twice with the
/// same `(UDS, MachineSeed, Policy, POTA thumbprint)` inputs (UDS
/// being deterministic per `pid` under the std/emu PAL) and assert
/// the two PTA pubkeys are byte-identical.
///
/// The emu device's `erase()` performs `part_disable` + `part_enable`,
/// matching what real hardware does on NSSR: it wipes the rotated
/// PSKs, the prior PTA key material, the partition policy, and the
/// POTA thumbprint, and re-derives a fresh-but-deterministic UDS via
/// `derive_sim_uds(pid)`.  Each run therefore starts from a pristine
/// `Enabled` partition with the canonical default PSKs and the
/// same UDS, which means PTA = f(UDS, MachineSeed, Policy, POTA
/// thumb) must collapse to the same bytes both times.
///
/// We compare the X.509 SubjectPublicKeyInfo carried in the CSR
/// rather than the CSR bytes themselves: the CSR's ECDSA signature
/// and the COSE_Sign1 PTAReport signature both contain
/// non-deterministic ECDSA nonces, but the PTA public key is the
/// canonical determinism invariant under test.
#[test]
fn part_init_determinism_emu() {
    let ctx = TestCtx::new();

    // `TestCtx::new` already left the partition factory-reset; this
    // first `erase` is redundant but documents the run-1 precondition.
    ctx.erase().expect("erase to pristine Enabled before run 1");

    let seed = mach_seed();
    let policy = known_good_part_policy();
    let thumb = pota_thumbprint();

    let pta_pub_run1 = run_part_init_capture_pta_pub(&ctx, &seed, &policy, &thumb);

    // Cold restart: wipe partition state (including PTA key material
    // and rotated PSKs) and re-provision a fresh-but-deterministic
    // UDS via `part_enable_internal` → `derive_sim_uds(pid)`.
    ctx.erase().expect("erase between runs");

    let pta_pub_run2 = run_part_init_capture_pta_pub(&ctx, &seed, &policy, &thumb);

    assert_eq!(
        pta_pub_run1, pta_pub_run2,
        "PTA pubkey must be byte-identical across cold restarts with the \
         same (UDS, MachineSeed, Policy, POTA thumb) inputs",
    );
}
