// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hardware end-to-end tests for the TBOR `PskChange` command.
//!
//! Mirrors the emu suite in `commands::psk_change`. Cross-test
//! isolation comes from [`hw_test_reset`](crate::hw::harness::hw_test_reset)
//! (NSSR before + after each `execute` body via `dev.erase()`), so
//! every test starts with the partition at pristine defaults and
//! leaves it that way even on panic.
//!
//! Invoke with:
//!
//! ```text
//! cargo test --no-default-features \
//!     -p azihsm_ddi_tbor_types \
//!     --test azihsm_ddi_tbor_tests hw::psk_change
//! ```

use azihsm_crypto::aead_envelope;
use azihsm_crypto::aead_envelope::AeadAlg;
use azihsm_crypto::AesKey;
use azihsm_crypto::Rng;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_tbor_types::build_psk_change_aad;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborPskChangeReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CO;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CU;
use azihsm_ddi_tbor_types::PSK_LEN;

use crate::hw::assertions::assert_fw_rejects;
use crate::hw::harness::hw_test_reset;
use crate::hw::session_helper::open_session;
use crate::hw::session_helper::psk_change;
use crate::hw::session_helper::session_close;
use crate::hw::session_helper::session_open_finish;
use crate::hw::session_helper::session_open_init_with_options;
use crate::hw::session_helper::SessionOpenInitOptions;

const CO: u8 = 0;
const CU: u8 = 1;

/// Non-default PSK used as the rotation target. Distinct per-role.
const ROTATED_PSK_CO: [u8; PSK_LEN] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
];
const ROTATED_PSK_CU: [u8; PSK_LEN] = [
    0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0,
    0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
];

/// Build an AEAD-GCM envelope under `param_key` with caller-supplied
/// AAD + plaintext. Negatives use this to construct envelopes the FW
/// must reject.
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

// ---------------------------------------------------------------------------
// Happy-path lifecycle: open under default -> rotate -> close ->
// reopen under new PSK succeeds -> reopen under default fails.
// ---------------------------------------------------------------------------

fn run_lifecycle(role: u8, sty: SessionType, default_psk: &[u8; PSK_LEN], rotated: &[u8; PSK_LEN]) {
    hw_test_reset(|dev| {
        let session = open_session(dev, role, sty).expect("open under default PSK");
        let session_id = session.session_id;
        psk_change(dev, &session, rotated).expect("rotate to new PSK");
        session_close(dev, session_id).expect("close rotating session");

        let opts = SessionOpenInitOptions::new(role, sty).with_psk(rotated);
        let pending = session_open_init_with_options(dev, opts).expect("reopen under rotated PSK");
        let resumed = session_open_finish(dev, pending).expect("finish reopen under rotated PSK");
        session_close(dev, resumed.session_id).expect("close resumed session");

        let opts_default = SessionOpenInitOptions::new(role, sty).with_psk(default_psk);
        let result = session_open_init_with_options(dev, opts_default)
            .and_then(|p| session_open_finish(dev, p));
        assert!(
            result.is_err(),
            "reopen with old default PSK must fail after rotation",
        );
    });
}

#[test]
fn lifecycle_co() {
    run_lifecycle(
        CO,
        SessionType::Authenticated,
        &DEFAULT_PSK_CO,
        &ROTATED_PSK_CO,
    );
}

#[test]
fn lifecycle_cu() {
    run_lifecycle(CU, SessionType::PlainText, &DEFAULT_PSK_CU, &ROTATED_PSK_CU);
}

/// After a successful rotation, a second `PskChange` on the same
/// session must fail with `InvalidPermissions` (one-shot budget).
#[test]
fn second_attempt_same_session_fails() {
    hw_test_reset(|dev| {
        let session = open_session(dev, CU, SessionType::PlainText).expect("open under default CU");
        let session_id = session.session_id;

        psk_change(dev, &session, &ROTATED_PSK_CU).expect("first rotate");
        let err = psk_change(dev, &session, &DEFAULT_PSK_CU)
            .expect_err("second PskChange on same session must fail");
        assert_fw_rejects(&err, TborStatus::InvalidPermissions);

        session_close(dev, session_id).expect("close");
    });
}

// ---------------------------------------------------------------------------
// Envelope-shape negatives (pre-commit rejects).
// ---------------------------------------------------------------------------

#[test]
fn envelope_ciphertext_bit_flip_rejected() {
    hw_test_reset(|dev| {
        let session = open_session(dev, CU, SessionType::PlainText).expect("open");
        let session_id = session.session_id;

        let aad = build_psk_change_aad(session_id);
        let mut envelope = build_envelope(&session.param_key, &aad, &ROTATED_PSK_CU);
        let target = envelope.len() / 2;
        envelope[target] ^= 0x01;

        let req = TborPskChangeReq {
            session_id,
            psk_envelope: envelope,
        };
        let mut cookie = None;
        let err = dev
            .exec_op_tbor::<TborPskChangeReq>(&req, None, &mut cookie)
            .expect_err("bit-flipped ciphertext must be rejected");
        assert_fw_rejects(&err, TborStatus::AeadEnvelopeAuthFailed);

        session_close(dev, session_id).expect("close");
    });
}

#[test]
fn envelope_wrong_session_id_in_aad_rejected() {
    hw_test_reset(|dev| {
        let session = open_session(dev, CU, SessionType::PlainText).expect("open");
        let session_id = session.session_id;

        let bogus_aad = build_psk_change_aad(session_id ^ 0x1234);
        let envelope = build_envelope(&session.param_key, &bogus_aad, &ROTATED_PSK_CU);
        let req = TborPskChangeReq {
            session_id,
            psk_envelope: envelope,
        };
        let mut cookie = None;
        let err = dev
            .exec_op_tbor::<TborPskChangeReq>(&req, None, &mut cookie)
            .expect_err("mismatched session_id in AAD must be rejected");
        assert_fw_rejects(&err, TborStatus::AeadEnvelopeAuthFailed);

        session_close(dev, session_id).expect("close");
    });
}

#[test]
fn envelope_wrong_plaintext_length_rejected() {
    hw_test_reset(|dev| {
        for len in [PSK_LEN - 1, PSK_LEN + 1] {
            let session = open_session(dev, CU, SessionType::PlainText).expect("open");
            let session_id = session.session_id;
            let bogus_psk = vec![0xCDu8; len];
            let aad = build_psk_change_aad(session_id);
            let envelope = build_envelope(&session.param_key, &aad, &bogus_psk);
            let req = TborPskChangeReq {
                session_id,
                psk_envelope: envelope,
            };
            let mut cookie = None;
            let err = dev
                .exec_op_tbor::<TborPskChangeReq>(&req, None, &mut cookie)
                .expect_err("wrong plaintext length must be rejected");
            // Hardware: wire decoder catches length mismatch (schema pins
            // `psk_envelope` at 100 B via `#[tbor(buffer, len = 100)]`) and
            // surfaces it as `DdiDecodeFailed` before the handler's defensive
            // `TborInvalidFixedLength` branch is reached. Emu decoder returns
            // the more specific `TborInvalidFixedLength`.
            assert_fw_rejects(&err, TborStatus::DdiDecodeFailed);
            session_close(dev, session_id).expect("close");
        }
    });
}

#[test]
fn envelope_empty_rejected() {
    hw_test_reset(|dev| {
        let session = open_session(dev, CU, SessionType::PlainText).expect("open");
        let session_id = session.session_id;

        let req = TborPskChangeReq {
            session_id,
            psk_envelope: Vec::new(),
        };
        let mut cookie = None;
        let err = dev
            .exec_op_tbor::<TborPskChangeReq>(&req, None, &mut cookie)
            .expect_err("empty envelope must be rejected");
        // See `envelope_wrong_plaintext_length_rejected` for the hw-vs-emu
        // decode-order rationale — empty envelope hits the same decoder path.
        assert_fw_rejects(&err, TborStatus::DdiDecodeFailed);

        session_close(dev, session_id).expect("close");
    });
}
