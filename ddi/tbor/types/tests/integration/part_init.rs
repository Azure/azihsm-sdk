// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 6 e2e integration tests for the TBOR `PartInit` command.
//!
//! Every test runs against the `emu` backend.  PartInit is a one-shot
//! transition (`Enabled → Initializing`) on a process-global
//! partition, so the happy-path smoke test consumes the *only*
//! pristine-`Enabled` window the emulator offers per process; tests
//! that need to observe rejection from a fresh `Enabled` state must
//! either run before the smoke test on the same partition or live in
//! their own dedicated test binary.  For this checkpoint we keep all
//! happy-path coverage in a single test that also asserts the
//! second-PartInit rejection arm.
//!
//! Coverage:
//! * `PartInit` after `OpenSession → ChangePsk` succeeds and returns
//!   a non-empty PTACSR (DER-tagged `0x30`) and PTAReport (CBOR tag
//!   18 = COSE_Sign1, opening byte `0xD2`).
//! * A second `PartInit` on a freshly-opened CO session surfaces
//!   `HsmError::PtaKeyAlreadySet` (one-shot enforcement via
//!   `part_mark_initializing`).
//! * Negative gates that reject **before** any partition-state
//!   mutation — order-independent vs the smoke test:
//!   * Default-PSK CO session → `DefaultPskMustRotate` (dispatcher).
//!   * CU session under rotated PSK → `InvalidPermissions`
//!     (handler role gate).
//!   * Rotated CO session with a malformed `PartPolicy` →
//!     `InvalidArg` (handler `policy::from_bytes`).

#![cfg(feature = "emu")]

use azihsm_ddi::DdiDev;
use azihsm_ddi_tbor_test_helpers::change_psk;
use azihsm_ddi_tbor_test_helpers::close_session;
use azihsm_ddi_tbor_test_helpers::open_session;
use azihsm_ddi_tbor_test_helpers::open_session_finish;
use azihsm_ddi_tbor_test_helpers::open_session_init_with_options;
use azihsm_ddi_tbor_test_helpers::part_init;
use azihsm_ddi_tbor_test_helpers::OpenSessionInitOptions;
use azihsm_ddi_tbor_types::TborPartInitReq;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PTA_CSR_MAX_LEN;
use azihsm_ddi_tbor_types::PTA_REPORT_MAX_LEN;
use azihsm_fw_ddi_tbor_types::policy::PolicyKeyKind;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::SessionType;
use azihsm_fw_hsm_pal_traits::PSK_LEN;
use serial_test::serial;

use crate::integration::common::assertions::assert_fw_rejects;
use crate::integration::common::fixture::open_dev;

const CO: u8 = 0;

/// Non-default 32-byte CO PSK used so PartInit clears the
/// default-PSK-gate.  Pinned to a fixed value so the smoke test is
/// fully deterministic.
const ROTATED_CO_PSK: [u8; PSK_LEN] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
];

/// Build a 167-byte `PartPolicy` blob that passes
/// `azihsm_fw_hsm_core::ddi::tbor::policy::from_bytes`.  Layout mirrors
/// the canonical wire format defined in
/// `fw/core/ddi/tbor/types/src/policy.rs`.
fn known_good_part_policy() -> [u8; PART_POLICY_LEN] {
    const OFF_VERSION_MAJOR: usize = 0;
    const OFF_VERSION_MINOR: usize = 1;
    const OFF_KIND: usize = 2;
    const OFF_LEN: usize = 4;
    const OFF_DATA: usize = 6;
    const OFF_INFO: usize = 103;

    let mut bytes = [0u8; PART_POLICY_LEN];
    bytes[OFF_VERSION_MAJOR] = 1;
    bytes[OFF_VERSION_MINOR] = 0;
    bytes[OFF_KIND..OFF_KIND + 2].copy_from_slice(&PolicyKeyKind::Ecc384.0.to_le_bytes());
    bytes[OFF_LEN..OFF_LEN + 2].copy_from_slice(&97u16.to_le_bytes());
    bytes[OFF_DATA] = 0x04;
    for (i, b) in bytes[OFF_DATA + 1..OFF_DATA + 97].iter_mut().enumerate() {
        *b = (0x10 + (i as u8)) | 0x80;
    }
    for b in bytes[OFF_INFO..OFF_INFO + 64].iter_mut() {
        *b = 0xAB;
    }
    bytes
}

fn mach_seed() -> [u8; MACH_SEED_LEN] {
    let mut v = [0u8; MACH_SEED_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x40 + i as u8;
    }
    v
}

fn pota_thumbprint() -> [u8; POTA_THUMBPRINT_LEN] {
    let mut v = [0u8; POTA_THUMBPRINT_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x80 ^ i as u8;
    }
    v
}

/// Open a CO session under the supplied PSK (bypassing the partition
/// default).
fn open_co_with(
    dev: &<azihsm_ddi::AzihsmDdi as azihsm_ddi_interface::Ddi>::Dev,
    psk: &[u8; PSK_LEN],
) -> azihsm_ddi_tbor_test_helpers::SessionHandshake {
    let opts = OpenSessionInitOptions::new(CO, SessionType::Authenticated).with_psk(psk);
    let pending = open_session_init_with_options(dev, opts).expect("open_session_init under PSK");
    open_session_finish(dev, pending).expect("open_session_finish under PSK")
}

#[test]
#[serial]
fn part_init_smoke_roundtrip_emu() {
    let dev = open_dev();

    // 1. Open CO under default PSK and rotate to a non-default value
    //    so the PartInit handler clears the default-PSK reject arm.
    let bootstrap = open_session(&dev, CO, SessionType::Authenticated).expect("open CO default");
    change_psk(&dev, &bootstrap, &ROTATED_CO_PSK).expect("rotate CO PSK");
    let _ = close_session(&dev, bootstrap.session_id);

    // 2. Reopen CO under the rotated PSK and run PartInit.
    let session = open_co_with(&dev, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let resp = part_init(&dev, &session, &seed, &policy, &thumb).expect("PartInit roundtrip");

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
    verify_pta_report(&dev, &resp.pta_report, &pta_spki);

    // 3. Second PartInit on a freshly-opened session must be rejected
    //    by the one-shot `part_set_pta_key` guard with
    //    `HsmError::PtaKeyAlreadySet`.  Closing this session before
    //    rotating the PSK back keeps the rest of the matrix clean.
    let _ = close_session(&dev, session.session_id);
    let session2 = open_co_with(&dev, &ROTATED_CO_PSK);
    let err = part_init(&dev, &session2, &seed, &policy, &thumb)
        .expect_err("second PartInit must be rejected by one-shot state guard");
    assert_fw_rejects(&err, HsmError::PtaKeyAlreadySet);
    let _ = close_session(&dev, session2.session_id);

    // 4. Restore the default CO PSK so any later test in this binary
    //    that opens CO under the canonical default still works.
    let restore = open_co_with(&dev, &ROTATED_CO_PSK);
    change_psk(&dev, &restore, &azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CO).expect("restore CO PSK");
    let _ = close_session(&dev, restore.session_id);
}

const CU: u8 = 1;

/// Non-default 32-byte CU PSK, used to clear the default-PSK gate
/// before exercising the CU role-reject path.  Distinct bytes from
/// [`ROTATED_CO_PSK`] so a copy/paste swap is loud.
const ROTATED_CU_PSK: [u8; PSK_LEN] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
];

/// Open a session of `role` + `sty` under the supplied PSK
/// (bypassing the partition default).
fn open_role_with(
    dev: &<azihsm_ddi::AzihsmDdi as azihsm_ddi_interface::Ddi>::Dev,
    role: u8,
    sty: SessionType,
    psk: &[u8; PSK_LEN],
) -> azihsm_ddi_tbor_test_helpers::SessionHandshake {
    let opts = OpenSessionInitOptions::new(role, sty).with_psk(psk);
    let pending =
        open_session_init_with_options(dev, opts).expect("open_session_init under custom PSK");
    open_session_finish(dev, pending).expect("open_session_finish under custom PSK")
}

/// Default-PSK CO session: the TBOR dispatcher must reject `PartInit`
/// with [`HsmError::DefaultPskMustRotate`] **before** the handler
/// runs.  Independent of partition state: the rejection lives in the
/// dispatcher gate, not in any setter.
#[test]
#[serial]
fn part_init_reject_default_psk_co_emu() {
    let dev = open_dev();

    let session = open_session(&dev, CO, SessionType::Authenticated).expect("open CO default PSK");
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = part_init(&dev, &session, &seed, &policy, &thumb)
        .expect_err("PartInit under default CO PSK must be rejected");
    assert_fw_rejects(&err, HsmError::DefaultPskMustRotate);

    let _ = close_session(&dev, session.session_id);
}

/// CU session under a rotated PSK: the handler's CO-only role gate
/// must surface [`HsmError::InvalidPermissions`].  The CU PSK is
/// rotated up-front so the dispatcher's default-PSK gate does not
/// fire first, and restored at the end so other tests still observe
/// the canonical default.
#[test]
#[serial]
fn part_init_reject_cu_session_emu() {
    let dev = open_dev();

    // Rotate CU PSK out of the default so we exercise the role gate,
    // not the default-PSK gate.  CU sessions are pinned to
    // `SessionType::PlainText` (CO-only is `Authenticated`).
    let bootstrap = open_session(&dev, CU, SessionType::PlainText).expect("open CU default");
    change_psk(&dev, &bootstrap, &ROTATED_CU_PSK).expect("rotate CU PSK");
    let _ = close_session(&dev, bootstrap.session_id);

    let session = open_role_with(&dev, CU, SessionType::PlainText, &ROTATED_CU_PSK);
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = part_init(&dev, &session, &seed, &policy, &thumb)
        .expect_err("PartInit on CU session must be rejected");
    assert_fw_rejects(&err, HsmError::InvalidPermissions);

    let _ = close_session(&dev, session.session_id);

    // Restore default CU PSK so the rest of the matrix is unaffected.
    let restore = open_role_with(&dev, CU, SessionType::PlainText, &ROTATED_CU_PSK);
    change_psk(&dev, &restore, &azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CU).expect("restore CU PSK");
    let _ = close_session(&dev, restore.session_id);
}

/// Rotated CO session with a syntactically invalid `PartPolicy`
/// (all-zero bytes — `version.major == 0` fails the canonical decode
/// gate in `policy::from_bytes`): the handler must reject with
/// [`HsmError::InvalidArg`] **before** any setter runs, leaving
/// partition state untouched.
#[test]
#[serial]
fn part_init_reject_bad_policy_emu() {
    let dev = open_dev();

    let bootstrap = open_session(&dev, CO, SessionType::Authenticated).expect("open CO default");
    change_psk(&dev, &bootstrap, &ROTATED_CO_PSK).expect("rotate CO PSK");
    let _ = close_session(&dev, bootstrap.session_id);

    let session = open_role_with(&dev, CO, SessionType::Authenticated, &ROTATED_CO_PSK);
    let bad_policy = [0u8; PART_POLICY_LEN];
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = part_init(&dev, &session, &seed, &bad_policy, &thumb)
        .expect_err("PartInit with malformed PartPolicy must be rejected");
    assert_fw_rejects(&err, HsmError::InvalidArg);

    let _ = close_session(&dev, session.session_id);

    // Restore default CO PSK.
    let restore = open_role_with(&dev, CO, SessionType::Authenticated, &ROTATED_CO_PSK);
    change_psk(&dev, &restore, &azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CO).expect("restore CO PSK");
    let _ = close_session(&dev, restore.session_id);
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
fn verify_pta_report(
    dev: &<azihsm_ddi::AzihsmDdi as azihsm_ddi_interface::Ddi>::Dev,
    pta_report: &[u8],
    pta_spki_der: &[u8],
) {
    use azihsm_crypto::DerEccPublicKey;
    use azihsm_ddi_mbor_sim::attestation::KeyAttester;
    use azihsm_ddi_mbor_sim::crypto::ecc::EccOp;
    use azihsm_ddi_mbor_sim::crypto::ecc::EccPublicKey as SimEccPublicKey;
    use azihsm_ddi_mbor_sim::report::CoseSign1Object;
    use azihsm_ddi_mbor_sim::report::KeyAttestationReport;
    use azihsm_ddi_mbor_test_helpers::helper_get_cert_chain_info;
    use azihsm_ddi_mbor_test_helpers::helper_get_certificate;
    use minicbor::data::Type as CborType;
    use x509::X509Certificate;
    use x509::X509CertificateOp;

    // 1. PID pubkey from the slot-0 chain leaf.
    let info = helper_get_cert_chain_info(dev).expect("GetCertChainInfo");
    let n = info.data.num_certs;
    assert!(
        n >= 1,
        "slot-0 cert chain must contain at least the PID leaf, got {n}",
    );
    let leaf_resp = helper_get_certificate(dev, n - 1).expect("GetCertificate(leaf)");
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
    dev: &<azihsm_ddi::AzihsmDdi as azihsm_ddi_interface::Ddi>::Dev,
    seed: &[u8; MACH_SEED_LEN],
    policy: &[u8; PART_POLICY_LEN],
    thumb: &[u8; POTA_THUMBPRINT_LEN],
) -> Vec<u8> {
    use x509::X509Csr;
    use x509::X509CsrOp;

    let bootstrap = open_session(dev, CO, SessionType::Authenticated).expect("open CO default");
    change_psk(dev, &bootstrap, &ROTATED_CO_PSK).expect("rotate CO PSK");
    let _ = close_session(dev, bootstrap.session_id);

    let session = open_co_with(dev, &ROTATED_CO_PSK);
    let resp = part_init(dev, &session, seed, policy, thumb).expect("PartInit roundtrip");
    let _ = close_session(dev, session.session_id);

    let csr = X509Csr::from_der(&resp.pta_csr).expect("PTACSR parses");
    let spki = csr.get_public_key_der().expect("CSR SPKI extracts");

    // Restore the default CO PSK so the next incarnation can bootstrap
    // identically.
    let restore = open_co_with(dev, &ROTATED_CO_PSK);
    change_psk(dev, &restore, &azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CO).expect("restore CO PSK");
    let _ = close_session(dev, restore.session_id);

    spki
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
#[serial]
fn part_init_determinism_emu() {
    let dev = open_dev();

    // Start from a known-pristine partition so we control all four
    // inputs to the derivation.
    dev.erase().expect("erase to pristine Enabled before run 1");

    let seed = mach_seed();
    let policy = known_good_part_policy();
    let thumb = pota_thumbprint();

    let pta_pub_run1 = run_part_init_capture_pta_pub(&dev, &seed, &policy, &thumb);

    // Cold restart: wipe partition state (including PTA key material
    // and rotated PSKs) and re-provision a fresh-but-deterministic
    // UDS via `part_enable_internal` → `derive_sim_uds(pid)`.
    dev.erase().expect("erase between runs");

    let pta_pub_run2 = run_part_init_capture_pta_pub(&dev, &seed, &policy, &thumb);

    assert_eq!(
        pta_pub_run1, pta_pub_run2,
        "PTA pubkey must be byte-identical across cold restarts with the \
         same (UDS, MachineSeed, Policy, POTA thumb) inputs",
    );

    // Leave the partition in a pristine `Enabled` state with default
    // PSKs so any later test in this binary sees the canonical
    // starting condition.
    dev.erase().expect("erase to leave pristine state behind");
}

// ===========================================================================
// `mach_seed` envelope tampering
//
// These tests run BEFORE the smoke test on the same partition would
// otherwise burn PartInit's one-shot slot, but they always reject the
// envelope BEFORE any partition-state mutation, so they leave the
// partition in `Enabled`.  Each test rotates the CO PSK out of the
// default for its own session (so the default-PSK gate doesn't fire
// first) and restores the canonical default at the end so the test
// matrix stays clean.
// ===========================================================================

/// Bit-flip the ciphertext of a valid `mach_seed_envelope`.  AEAD-GCM
/// tag verification must fail before any plaintext is exposed, and
/// the handler surfaces [`HsmError::AeadEnvelopeAuthFailed`].
#[test]
#[serial]
fn part_init_envelope_tampered_emu() {
    use azihsm_ddi_tbor_test_helpers::encrypt_mach_seed_envelope;

    let dev = open_dev();

    let bootstrap = open_session(&dev, CO, SessionType::Authenticated).expect("open CO default");
    change_psk(&dev, &bootstrap, &ROTATED_CO_PSK).expect("rotate CO PSK");
    let _ = close_session(&dev, bootstrap.session_id);

    let session = open_co_with(&dev, &ROTATED_CO_PSK);
    let seed = mach_seed();
    let mut envelope =
        encrypt_mach_seed_envelope(&session, &seed).expect("seal mach_seed envelope");
    // Envelope layout matches `change_psk`'s ciphertext-tamper test:
    // HEADER(4) ‖ IV(12) ‖ AAD(32) ‖ CT(32) ‖ TAG(16).  Flip a byte in
    // the middle so AEAD tag verification fails.
    let target = envelope.len() / 2;
    envelope[target] ^= 0x01;

    let mut req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy.copy_from_slice(&known_good_part_policy());
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    let mut cookie = None;
    let res: azihsm_ddi_interface::DdiResult<azihsm_ddi_tbor_types::TborPartInitResp> =
        dev.exec_op_tbor(&req, &mut cookie);
    let err = res.expect_err("tampered envelope must be rejected");
    assert_fw_rejects(&err, HsmError::AeadEnvelopeAuthFailed);

    let _ = close_session(&dev, session.session_id);

    let restore = open_co_with(&dev, &ROTATED_CO_PSK);
    change_psk(&dev, &restore, &azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CO).expect("restore CO PSK");
    let _ = close_session(&dev, restore.session_id);
}

/// Build a `mach_seed_envelope` whose AAD encodes a different session
/// id than the request carries.  AEAD-GCM tag verifies (the FW
/// recomputes the tag over *these* AAD bytes), but the FW then
/// constant-compares the AAD against
/// `build_part_init_mach_seed_aad(req.session_id)` and rejects with
/// [`HsmError::AeadEnvelopeAuthFailed`].
#[test]
#[serial]
fn part_init_wrong_session_id_in_aad_emu() {
    use azihsm_crypto::aead_envelope;
    use azihsm_crypto::aead_envelope::AeadAlg;
    use azihsm_crypto::Rng;
    use azihsm_ddi_tbor_types::build_part_init_mach_seed_aad;

    let dev = open_dev();

    let bootstrap = open_session(&dev, CO, SessionType::Authenticated).expect("open CO default");
    change_psk(&dev, &bootstrap, &ROTATED_CO_PSK).expect("rotate CO PSK");
    let _ = close_session(&dev, bootstrap.session_id);

    let session = open_co_with(&dev, &ROTATED_CO_PSK);
    let seed = mach_seed();

    let bogus_aad = build_part_init_mach_seed_aad(session.session_id ^ 0x1234);
    let mut iv = [0u8; 12];
    Rng::rand_bytes(&mut iv).expect("rng iv");
    let total = aead_envelope::seal(
        AeadAlg::AesGcm256,
        &session.param_key,
        &iv,
        &bogus_aad,
        &seed,
        None,
    )
    .expect("aead size");
    let mut envelope = vec![0u8; total];
    let written = aead_envelope::seal(
        AeadAlg::AesGcm256,
        &session.param_key,
        &iv,
        &bogus_aad,
        &seed,
        Some(&mut envelope),
    )
    .expect("aead seal");
    envelope.truncate(written);

    let mut req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy.copy_from_slice(&known_good_part_policy());
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());

    let mut cookie = None;
    let res: azihsm_ddi_interface::DdiResult<azihsm_ddi_tbor_types::TborPartInitResp> =
        dev.exec_op_tbor(&req, &mut cookie);
    let err = res.expect_err("AAD encoding the wrong session id must be rejected");
    assert_fw_rejects(&err, HsmError::AeadEnvelopeAuthFailed);

    let _ = close_session(&dev, session.session_id);

    let restore = open_co_with(&dev, &ROTATED_CO_PSK);
    change_psk(&dev, &restore, &azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CO).expect("restore CO PSK");
    let _ = close_session(&dev, restore.session_id);
}
