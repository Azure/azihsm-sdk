// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hardware end-to-end tests for the TBOR `PartInit` command.
//!
//! Mirrors the emu suite in `commands::part_init`. Cross-test
//! isolation comes from
//! [`hw_test_reset`](crate::hw::harness::hw_test_reset) — NSSR
//! before + after each test body via `dev.erase()` — so every test
//! starts with the partition at pristine defaults (PSKs at
//! `DEFAULT_PSK_*`, partition `Enabled`, session table empty, no
//! prior PTA key) and leaves it that way even on panic.
//!
//! Each test that reaches the handler must first rotate the CO PSK
//! out of the default so the dispatcher's default-PSK gate does not
//! fire before the code path under test — see the emu suite's
//! `bootstrap_rotated_co` helper for the same convention. The
//! default-PSK gate itself is exercised by
//! [`hw::default_psk_gate::part_init_rejected_under_default_psk`].
//!
//! What is intentionally *not* verified here (compared to the emu
//! suite):
//!
//! * **Full COSE_Sign1 PTAReport verify** — that needs the sim-only
//!   `azihsm_ddi_mbor_sim` verifier and the MBOR cert-chain fetch
//!   helpers, which the hw harness does not wire up. We assert the
//!   report's outer CBOR shape and cap here; the cryptographic
//!   verify is covered by the emu smoke test.
//!
//! Cold-restart determinism *is* exercised here — see
//! [`part_init_determinism_hw`] — because NSSR on real silicon
//! re-materialises the same fuse-derived UDS, so
//! `PTA = f(UDS, MachineSeed, Policy, POTA thumb)` must be
//! byte-stable across resets when the four inputs are held fixed.
//!
//! Invoke with:
//!
//! ```text
//! cargo test --no-default-features --features hw-tests \
//!     -p azihsm_ddi_tbor_types \
//!     --test azihsm_ddi_tbor_tests hw::part_init
//! ```

use azihsm_crypto::aead_envelope;
use azihsm_crypto::aead_envelope::AeadAlg;
use azihsm_crypto::AesKey;
use azihsm_crypto::Rng;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborPartInitReq;
use azihsm_ddi_tbor_types::TborPartInitResp;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PSK_LEN;
use azihsm_ddi_tbor_types::PTA_CSR_MAX_LEN;
use azihsm_ddi_tbor_types::PTA_REPORT_MAX_LEN;
use azihsm_ddi_tbor_types::SATA_THUMBPRINT_LEN;

use crate::hw::assertions::assert_fw_rejects;
use crate::hw::harness::hw_test_reset;
use crate::hw::harness::HwDevInner;
use crate::hw::session_helper::build_part_init_mach_seed_aad;
use crate::hw::session_helper::encrypt_mach_seed_envelope;
use crate::hw::session_helper::open_session;
use crate::hw::session_helper::part_init;
use crate::hw::session_helper::psk_change;
use crate::hw::session_helper::session_close;
use crate::hw::session_helper::session_open_finish;
use crate::hw::session_helper::session_open_init_with_options;
use crate::hw::session_helper::SessionHandshake;
use crate::hw::session_helper::SessionOpenInitOptions;

const CO: u8 = 0;
const CU: u8 = 1;

/// Non-default 32-byte CO PSK used so PartInit clears the
/// default-PSK gate. Same value as the emu suite''s `ROTATED_CO_PSK`
/// so a byte-for-byte comparison across the two runs is easy.
const ROTATED_CO_PSK: [u8; PSK_LEN] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
];

/// Non-default 32-byte CU PSK used to clear the default-PSK gate
/// before exercising the CU role-reject path. Distinct from
/// [`ROTATED_CO_PSK`] so a copy/paste swap is loud.
const ROTATED_CU_PSK: [u8; PSK_LEN] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
];

// -- Fixtures --------------------------------------------------------------

/// Build a 484-byte `PartPolicy` blob that passes
/// `azihsm_fw_hsm_core::ddi::tbor::policy::from_bytes`. Layout mirrors
/// the canonical wire format and the emu helper
/// `commands::part_init::known_good_part_policy`.
fn known_good_part_policy() -> [u8; PART_POLICY_LEN] {
    const OFF_POTA: usize = 2;
    const OFF_SATA: usize = 102;
    const OFF_FLAGS: usize = 418;
    const OFF_INFO: usize = 419;

    fn write_pubkey(bytes: &mut [u8], off: usize, fill: u8) {
        bytes[off..off + 2].copy_from_slice(&PolicyKeyKind::Ecc384.0.to_le_bytes());
        bytes[off + 2..off + 4].copy_from_slice(&96u16.to_le_bytes());
        for (i, b) in bytes[off + 4..off + 4 + 96].iter_mut().enumerate() {
            *b = (fill.wrapping_add(i as u8)) | 0x80;
        }
    }

    let mut bytes = [0u8; PART_POLICY_LEN];
    bytes[0] = 1;
    bytes[1] = 0;
    write_pubkey(&mut bytes, OFF_POTA, 0x10);
    write_pubkey(&mut bytes, OFF_SATA, 0x20);
    bytes[OFF_FLAGS] = 0;
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

fn sata_thumbprint() -> [u8; SATA_THUMBPRINT_LEN] {
    let mut v = [0u8; SATA_THUMBPRINT_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x40 ^ i as u8;
    }
    v
}

/// Seal an AEAD-GCM envelope under `param_key` with caller-controlled
/// AAD + plaintext. Used by envelope-shape negatives to build
/// envelopes the canonical `encrypt_mach_seed_envelope` helper cannot
/// produce (wrong AAD length, mismatched session id, wrong plaintext
/// length). Mirrors the `build_envelope` helper in `hw/psk_change.rs`.
fn build_envelope(param_key: &AesKey, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let iv = Rng::rand_vec(12).expect("rng iv");
    let total = aead_envelope::seal(AeadAlg::AesGcm256, param_key, &iv, aad, plaintext, None)
        .expect("aead size");
    let mut out = vec![0u8; total];
    let n = aead_envelope::seal(
        AeadAlg::AesGcm256,
        param_key,
        &iv,
        aad,
        plaintext,
        Some(&mut out),
    )
    .expect("aead seal");
    out.truncate(n);
    out
}

/// Open a CO/Authenticated session under the supplied PSK (bypassing
/// the partition default). Mirrors the emu suite''s `open_co_with`.
fn open_co_with(dev: &HwDevInner, psk: &[u8; PSK_LEN]) -> SessionHandshake {
    let opts = SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(psk);
    let pending = session_open_init_with_options(dev, opts).expect("CO init under rotated PSK");
    session_open_finish(dev, pending).expect("CO finish under rotated PSK")
}

/// Open CO under default -> rotate PSK to `target_psk` -> close
/// bootstrap -> reopen fresh CO under the rotated PSK. Mirrors the
/// emu suite''s `bootstrap_rotated_co`.
fn bootstrap_rotated_co(dev: &HwDevInner, target_psk: &[u8; PSK_LEN]) -> SessionHandshake {
    let bootstrap = open_session(dev, CO, SessionType::Authenticated).expect("open CO default");
    psk_change(dev, &bootstrap, target_psk).expect("rotate CO PSK");
    session_close(dev, bootstrap.session_id).expect("close bootstrap CO");
    open_co_with(dev, target_psk)
}

/// Ship a raw `TborPartInitReq` (already carrying the caller''s
/// envelope + policy + thumbprints). Envelope-shape negatives use this
/// to bypass the `part_init` helper''s client-side re-seal.
fn exec_part_init_raw(
    dev: &HwDevInner,
    req: &TborPartInitReq,
) -> Result<TborPartInitResp, DdiError> {
    dev.exec_op_tbor::<TborPartInitReq>(req, None, &mut None)
}

/// Build a `TborPartInitReq` whose only non-default fields are the
/// caller''s `session_id` + `mach_seed_envelope`, plus a known-good
/// policy and POTA/SATA thumbprints. Cuts boilerplate out of the
/// envelope-shape negatives.
fn make_req_with_envelope(session_id: u16, envelope: Vec<u8>) -> TborPartInitReq {
    let mut req = TborPartInitReq {
        session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy =
        <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&known_good_part_policy())
            .expect("known-good policy parses");
    req.pota_thumbprint.copy_from_slice(&pota_thumbprint());
    req.sata_thumbprint.copy_from_slice(&sata_thumbprint());
    req
}

// -- Happy path + one-shot guard ------------------------------------------

/// End-to-end `OpenSession -> PskChange -> PartInit` on real silicon.
///
/// Asserts the wire-shape invariants the FW guarantees for a
/// successful PartInit:
///
/// * `pta_csr` starts with the PKCS#10 SEQUENCE tag (`0x30`), fits
///   `PTA_CSR_MAX_LEN`, parses as an [`x509::X509Csr`], and
///   self-verifies under its embedded SubjectPublicKeyInfo (proves
///   the FW''s CSR builder produced a syntactically valid CSR signed
///   by the correct PTA private key).
/// * `pta_report` is COSE_Sign1 (starts with the CBOR tag 18 opening
///   byte `0xD2`) and fits `PTA_REPORT_MAX_LEN`. Full COSE_Sign1 +
///   PID cross-binding verify lives in the emu smoke test.
///
/// Then a second `PartInit` on a freshly-opened session must be
/// rejected by the write-once `part_set_pta_key` guard with
/// [`TborStatus::PtaKeyAlreadySet`]. Cross-tests the one-shot state
/// machine independently of the wire path.
#[test]
fn part_init_smoke_roundtrip_hw() {
    use x509::X509Csr;
    use x509::X509CsrOp;

    hw_test_reset(|dev| {
        let session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let session_id = session.session_id;
        let policy = known_good_part_policy();
        let seed = mach_seed();
        let pota = pota_thumbprint();
        let sata = sata_thumbprint();

        let resp = part_init(dev, &session, &seed, &policy, &pota, &sata, None)
            .expect("PartInit roundtrip on hardware");

        // -- PTACSR wire-shape --------------------------------------
        assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
        assert!(
            resp.pta_csr.len() <= PTA_CSR_MAX_LEN,
            "PTACSR len {} exceeds wire max {}",
            resp.pta_csr.len(),
            PTA_CSR_MAX_LEN,
        );
        assert_eq!(
            resp.pta_csr[0], 0x30,
            "PTACSR must begin with the DER SEQUENCE tag (0x30)",
        );

        // -- PTACSR PKCS#10 parse + self-signature verify -----------
        let csr = X509Csr::from_der(&resp.pta_csr).unwrap_or_else(|e| {
            panic!(
                "PTACSR parses as PKCS#10: {e:?}\nlen={} first16={:02x?}",
                resp.pta_csr.len(),
                &resp.pta_csr[..resp.pta_csr.len().min(16)],
            )
        });
        let v = csr.verify();
        assert!(
            matches!(v, Ok(true)),
            "PTACSR self-signature must verify (got {v:?})",
        );

        // -- PTAReport wire-shape -----------------------------------
        assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
        assert!(
            resp.pta_report.len() <= PTA_REPORT_MAX_LEN,
            "PTAReport len {} exceeds wire max {}",
            resp.pta_report.len(),
            PTA_REPORT_MAX_LEN,
        );
        assert_eq!(
            resp.pta_report[0], 0xD2,
            "PTAReport must begin with the COSE_Sign1 CBOR tag byte (0xD2)",
        );

        // Free the first session slot before opening the second.
        session_close(dev, session_id).expect("close first PartInit session");

        // Second PartInit must hit the one-shot write-once guard.
        let session2 = open_co_with(dev, &ROTATED_CO_PSK);
        let session2_id = session2.session_id;
        let err = part_init(dev, &session2, &seed, &policy, &pota, &sata, None)
            .expect_err("second PartInit must be rejected by the one-shot state guard");
        assert_fw_rejects(&err, TborStatus::PtaKeyAlreadySet);

        session_close(dev, session2_id).expect("close second session");
    });
}

// -- Pre-commit rejects ---------------------------------------------------

/// CU session under a rotated CU PSK: the handler''s CO-only role
/// gate must surface [`TborStatus::InvalidPermissions`]. CU PSK is
/// rotated up-front so the default-PSK gate does not fire first (CU
/// is pinned to `SessionType::PlainText`).
#[test]
fn part_init_cu_role_rejected_hw() {
    hw_test_reset(|dev| {
        let bootstrap = open_session(dev, CU, SessionType::PlainText).expect("open CU default");
        psk_change(dev, &bootstrap, &ROTATED_CU_PSK).expect("rotate CU PSK");
        session_close(dev, bootstrap.session_id).expect("close bootstrap CU");

        let opts =
            SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_CU_PSK);
        let pending = session_open_init_with_options(dev, opts).expect("CU init under rotated PSK");
        let session = session_open_finish(dev, pending).expect("CU finish under rotated PSK");
        let session_id = session.session_id;

        let err = part_init(
            dev,
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            None,
        )
        .expect_err("PartInit on a CU session must be rejected by the role gate");
        assert_fw_rejects(&err, TborStatus::InvalidPermissions);

        session_close(dev, session_id).expect("close CU session");
    });
}

/// Rotated CO session with a syntactically invalid `PartPolicy`
/// (all-zero bytes — `version.major == 0` fails `policy::from_bytes`)
/// must be rejected with [`TborStatus::InvalidArg`] **before** any
/// setter runs, leaving partition state untouched.
#[test]
fn part_init_malformed_policy_rejected_hw() {
    hw_test_reset(|dev| {
        let session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let session_id = session.session_id;
        let bad_policy = [0u8; PART_POLICY_LEN];

        let err = part_init(
            dev,
            &session,
            &mach_seed(),
            &bad_policy,
            &pota_thumbprint(),
            &sata_thumbprint(),
            None,
        )
        .expect_err("PartInit with all-zero PartPolicy must be rejected");
        assert_fw_rejects(&err, TborStatus::InvalidArg);

        session_close(dev, session_id).expect("close CO session");
    });
}

// -- mach_seed_envelope AEAD rejects --------------------------------------

/// Bit-flip the ciphertext of an otherwise-valid `mach_seed_envelope`.
/// AEAD-GCM tag verification must fail before any plaintext is
/// exposed, and the handler surfaces
/// [`TborStatus::AeadEnvelopeAuthFailed`].
#[test]
fn part_init_envelope_ciphertext_bit_flip_rejected_hw() {
    hw_test_reset(|dev| {
        let session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let session_id = session.session_id;

        let mut envelope =
            encrypt_mach_seed_envelope(&session, &mach_seed()).expect("seal mach_seed envelope");
        // Envelope layout: HEADER(4) || IV(12) || AAD(32) || CT(32) || TAG(16);
        // flipping a byte in the middle lands in the ciphertext region
        // so AEAD tag verification fails.
        let target = envelope.len() / 2;
        envelope[target] ^= 0x01;

        let req = make_req_with_envelope(session_id, envelope);
        let err = exec_part_init_raw(dev, &req)
            .expect_err("bit-flipped mach_seed envelope must be rejected");
        assert_fw_rejects(&err, TborStatus::AeadEnvelopeAuthFailed);

        session_close(dev, session_id).expect("close CO session");
    });
}

/// AAD encoding a *different* `session_id` than the request carries:
/// AEAD-GCM tag verifies over these AAD bytes (FW recomputes the tag
/// from the wire AAD), but the FW then constant-compares the AAD
/// against `build_part_init_mach_seed_aad(req.session_id)` and rejects
/// with [`TborStatus::AeadEnvelopeAuthFailed`].
#[test]
fn part_init_envelope_wrong_session_id_in_aad_rejected_hw() {
    hw_test_reset(|dev| {
        let session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let session_id = session.session_id;

        let bogus_aad = build_part_init_mach_seed_aad(session_id ^ 0x1234);
        let envelope = build_envelope(&session.param_key, &bogus_aad, &mach_seed());

        let req = make_req_with_envelope(session_id, envelope);
        let err = exec_part_init_raw(dev, &req)
            .expect_err("mismatched session_id in AAD must be rejected");
        assert_fw_rejects(&err, TborStatus::AeadEnvelopeAuthFailed);

        session_close(dev, session_id).expect("close CO session");
    });
}

/// `mach_seed` plaintext length != [`MACH_SEED_LEN`] (32) inflates the
/// envelope past the fixed `MACH_SEED_ENVELOPE_LEN` (100 B); the wire
/// decoder catches the length mismatch and surfaces it as
/// [`TborStatus::DdiDecodeFailed`] before the handler''s
/// `TborInvalidFixedLength` branch is reached. Emu decoder returns the
/// more specific `TborInvalidFixedLength`; the hw vs emu split matches
/// what `hw::psk_change::envelope_wrong_plaintext_length_rejected`
/// documents for `PskChange`. Loop over +/- 1 to cover both
/// excursions.
#[test]
fn part_init_envelope_wrong_mach_seed_length_rejected_hw() {
    hw_test_reset(|dev| {
        // PartInit''s length check rejects before any partition-state
        // mutation, so a single rotated-CO session drives both
        // iterations.
        let session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let session_id = session.session_id;
        let aad = build_part_init_mach_seed_aad(session_id);

        for len in [MACH_SEED_LEN - 1, MACH_SEED_LEN + 1] {
            let bogus_seed = vec![0xCDu8; len];
            let envelope = build_envelope(&session.param_key, &aad, &bogus_seed);
            let req = make_req_with_envelope(session_id, envelope);
            let err = exec_part_init_raw(dev, &req).expect_err(&format!(
                "mach_seed length {len} (!= MACH_SEED_LEN={MACH_SEED_LEN}) must be rejected",
            ));
            assert_fw_rejects(&err, TborStatus::DdiDecodeFailed);
        }

        session_close(dev, session_id).expect("close CO session");
    });
}

/// AAD of arbitrary but wrong length (64 bytes — double the canonical
/// `PART_INIT_MACH_SEED_AAD_LEN` of 32) inflates the envelope past
/// `MACH_SEED_ENVELOPE_LEN` (100 B), so the wire decoder rejects it
/// with [`TborStatus::DdiDecodeFailed`] before any AEAD work. Same
/// hw-vs-emu split as the wrong-plaintext-length test.
#[test]
fn part_init_envelope_wrong_aad_length_rejected_hw() {
    hw_test_reset(|dev| {
        let session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let session_id = session.session_id;

        let long_aad = vec![0u8; 64];
        let envelope = build_envelope(&session.param_key, &long_aad, &mach_seed());

        let req = make_req_with_envelope(session_id, envelope);
        let err = exec_part_init_raw(dev, &req)
            .expect_err("wrong AAD length must inflate the envelope past its fixed size");
        assert_fw_rejects(&err, TborStatus::DdiDecodeFailed);

        session_close(dev, session_id).expect("close CO session");
    });
}

/// Empty `mach_seed_envelope` hits the same wire-decode path as the
/// wrong-length cases: [`TborStatus::DdiDecodeFailed`] before the
/// handler runs.
#[test]
fn part_init_envelope_empty_rejected_hw() {
    hw_test_reset(|dev| {
        let session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let session_id = session.session_id;

        let req = make_req_with_envelope(session_id, Vec::new());
        let err = exec_part_init_raw(dev, &req).expect_err("empty envelope must be rejected");
        assert_fw_rejects(&err, TborStatus::DdiDecodeFailed);

        session_close(dev, session_id).expect("close CO session");
    });
}

// -- Cold-restart determinism ---------------------------------------------

/// Run the canonical `bootstrap-rotated-CO -> PartInit` flow with the
/// supplied inputs, close the session, and return the PTA
/// SubjectPublicKeyInfo (DER) extracted from the returned CSR.
///
/// Mirrors the emu suite's `run_part_init_capture_pta_pub`. Comparing
/// the CSR SPKI rather than the CSR bytes themselves side-steps the
/// non-deterministic ECDSA nonce baked into the CSR signature and the
/// COSE_Sign1 signature on the PTAReport: the PTA public key is the
/// canonical determinism invariant under test.
fn run_part_init_capture_pta_pub_hw(
    dev: &HwDevInner,
    seed: &[u8; MACH_SEED_LEN],
    policy: &[u8; PART_POLICY_LEN],
    pota: &[u8; POTA_THUMBPRINT_LEN],
    sata: &[u8; SATA_THUMBPRINT_LEN],
) -> Vec<u8> {
    use x509::X509Csr;
    use x509::X509CsrOp;

    let session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
    let session_id = session.session_id;
    let resp = part_init(dev, &session, seed, policy, pota, sata, None)
        .expect("PartInit roundtrip on hardware");
    session_close(dev, session_id).expect("close CO session after PartInit");

    let csr = X509Csr::from_der(&resp.pta_csr).expect("PTACSR parses as PKCS#10");
    csr.get_public_key_der().expect("CSR SPKI extracts")
}

/// Cold-restart determinism on real silicon: derive the PTA keypair
/// twice with the same `(MachineSeed, Policy, POTA thumb, SATA thumb)`
/// inputs, separated by a mid-test NSSR (`dev.erase()`), and assert
/// the two PTA pubkeys are byte-identical.
///
/// NSSR re-materialises UDS from the on-die fuses (constant per
/// device) and wipes all soft state — rotated PSKs, the prior PTA
/// key material, the partition policy, the POTA/SATA thumbprints, and
/// the one-shot PTA-already-set latch. With UDS held constant and all
/// four externally-supplied inputs held constant, the derivation
/// `PTA = f(UDS, MachineSeed, Policy, POTA thumb)` must collapse to
/// the same public key across both runs.
///
/// We compare the X.509 SubjectPublicKeyInfo carried in the CSR
/// rather than the CSR bytes: the ECDSA signature on the CSR and the
/// COSE_Sign1 signature on the PTAReport both contain
/// non-deterministic nonces. The PTA public key itself is the
/// determinism invariant.
#[test]
fn part_init_determinism_hw() {
    hw_test_reset(|dev| {
        let seed = mach_seed();
        let policy = known_good_part_policy();
        let pota = pota_thumbprint();
        let sata = sata_thumbprint();

        // Run 1 — pristine after `hw_test_reset` setup NSSR.
        let pta_pub_run1 = run_part_init_capture_pta_pub_hw(dev, &seed, &policy, &pota, &sata);

        // Cold restart: NSSR wipes soft state (rotated PSKs, PTA
        // key material, policy, thumbprints, one-shot latch) but
        // fuse-backed UDS is preserved.
        dev.erase().expect("mid-test NSSR between determinism runs");

        // Run 2 — same inputs, fresh partition.
        let pta_pub_run2 = run_part_init_capture_pta_pub_hw(dev, &seed, &policy, &pota, &sata);

        assert_eq!(
            pta_pub_run1, pta_pub_run2,
            "PTA pubkey must be byte-identical across NSSR with the same              (UDS, MachineSeed, Policy, POTA thumb) inputs — got              run1 len={} run2 len={}",
            pta_pub_run1.len(),
            pta_pub_run2.len(),
        );
    });
}
