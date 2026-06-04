// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Smoke test for the host-side session-establishment helpers.
//!
//! This file exists to catch protocol mismatches between the host
//! HPKE/MAC math in `azihsm_ddi_tbor_test_helpers::session` and the
//! FW handlers as early as possible. The full coverage matrix (CO,
//! CU, role/type mismatch, MAC tampering, resume, etc.) lives in
//! `open_session.rs` (Phase 4); this file just runs one happy-path
//! handshake to fail loud if the wire transcript or key schedule
//! drifts.

#![cfg(any(feature = "emu", feature = "mock"))]

#[cfg_attr(
    not(all(feature = "mock", not(feature = "emu"))),
    allow(unused_imports)
)]
use crate::integration::common::assertions::assert_unsupported_encoding;
use crate::integration::common::fixture::open_dev;

#[cfg(feature = "emu")]
#[test]
fn open_session_round_trip_cu_plaintext_emu() {
    use azihsm_ddi_tbor_test_helpers::open_session;
    use azihsm_fw_hsm_pal_traits::SessionType;

    let dev = open_dev();
    let session = open_session(&dev, 1, SessionType::PlainText)
        .expect("CU PlainText session must complete the full handshake");
    assert_eq!(session.psk_id, 1, "session must remember its psk_id");
    assert!(
        !session.bmk_session.is_empty(),
        "FW must return a non-empty bmk_session envelope",
    );
}

#[cfg(all(feature = "mock", not(feature = "emu")))]
#[test]
fn open_session_unsupported_on_mock() {
    use azihsm_ddi_tbor_test_helpers::open_session_init;
    use azihsm_fw_hsm_pal_traits::SessionType;

    let dev = open_dev();
    let err = open_session_init(&dev, 1, SessionType::PlainText)
        .expect_err("mock backend must not implement exec_op_tbor");
    assert_unsupported_encoding(&err);
}
