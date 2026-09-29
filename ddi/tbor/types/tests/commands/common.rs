// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Common constants and helpers for TBOR command tests.

use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;

/// `KeyScope::Session` discriminant.
pub(crate) const SCOPE_SESSION: u8 = 0b001;

/// `KeyScope::Ephemeral` discriminant.
pub(crate) const SCOPE_EPHEMERAL: u8 = 0b010;

/// `KeyScope::Local` discriminant.
pub(crate) const SCOPE_LOCAL: u8 = 0b011;

/// `KeyScope::SecurityDomain` discriminant.
pub(crate) const SCOPE_SECURITY_DOMAIN: u8 = 0b100;

/// `SessionType` role identifier for Crypto-Officer sessions.
pub(crate) const CO: u8 = 0;

/// `SessionType` role identifier for Crypto-User sessions.
pub(crate) const CU: u8 = 1;

/// Creates a Crypto-Officer session, generates a session-scoped ECC signing key,
/// and keeps the session alive while `test` runs.
pub(crate) fn with_generated_ecc_key(
    curve: u8,
    test: impl FnOnce(&TestCtx, u16, Vec<u8>, Vec<u8>),
) {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SESSION,
            curve,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");

    test(&ctx, session.session_id, resp.masked_key, resp.pub_key);
}
