// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SecureInitBk3 / SetInitBk3Pin smoke tests for mock and hardware backends.
//!
//! - `test_secure_init_bk3_smoke` mirrors `helper_get_or_init_bk3`, but on the
//!   secure BK3 path:
//!   - Skips when a sealed BK3 is already present (secure provisioning is
//!     one-shot and persistent, so a re-run is a no-op).
//!   - Otherwise securely provisions (`set_init_bk3_pin` + `secure_init_bk3`)
//!     and seals the resulting masked BK3 (MOBK).
//! - `test_secure_init_bk3_requires_pin` is the negative case: on a fresh
//!   partition, `secure_init_bk3` before `set_init_bk3_pin` must be rejected
//!   with `Bk3PinNotSet`.
//! - `test_secure_init_bk3_transport_tag_mismatch`,
//!   `test_secure_init_bk3_pin_tag_mismatch`, and
//!   `test_secure_init_bk3_pin_already_set` cover the remaining authentication
//!   and one-shot guards. These are mock-only: they set the one-shot Phase-2 PIN
//!   without completing Phase 4, which on real HW persists until reboot (NSSR
//!   won't clear it) and would block the other PIN-setting tests.

#![cfg(not(feature = "emu"))]
#![cfg(test)]

use azihsm_crypto::Rng;
use azihsm_ddi::*;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

pub fn setup(_dev: &mut <DdiTest as Ddi>::Dev, _ddi: &DdiTest, _path: &str) -> u16 {
    0
}

pub fn cleanup(
    _dev: &mut <DdiTest as Ddi>::Dev,
    _ddi: &DdiTest,
    _path: &str,
    _setup_session_id: Option<u16>,
) {
}

/// Secure BK3 smoke: provision (`set_init_bk3_pin` + `secure_init_bk3`) and seal,
/// mirroring `helper_get_or_init_bk3` but over the secure BK3 path.
///
/// - If a sealed BK3 is already present, secure provisioning is one-shot and
///   persistent, so it's a no-op (idempotent on re-runs).
/// - Otherwise securely provision, then seal the resulting masked BK3 (MOBK).
#[test]
fn test_secure_init_bk3_smoke() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        // Provision + seal can only run on a genuinely fresh partition. Any
        // other known state (sealed, provisioned-but-unsealed, unsupported) is
        // skipped; an unexpected GetSealedBk3 status fails loudly in bk3_state.
        if bk3_state(dev) != Bk3State::Fresh {
            return;
        }

        let mut bk3 = [0u8; 48];
        Rng::rand_bytes(&mut bk3).expect("rand_bytes failed");

        // Not provisioned yet: securely provision, then seal the masked BK3 (MOBK).
        let result = secure_bk3_provision_and_seal(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);
        assert!(result.is_ok(), "provision + seal {result:?}");
    });
}

/// Negative smoke: `secure_init_bk3` before `set_init_bk3_pin` must be rejected.
///
/// On a fresh partition the in-flight provisioning PIN is unset, so a
/// `secure_init_bk3` attempt must fail `Bk3PinNotSet`. This is the basic
/// ordering guard, independent of any live-migration semantics. It fails
/// cleanly without advancing the (process-global, monotonic) mock BK3 store, so
/// it is kept as a separate test and run one-at-a-time via an exact filter.
#[test]
fn test_secure_init_bk3_requires_pin() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        // The negative check needs a genuinely fresh partition; any other known
        // state is skipped and an unexpected status fails loudly in bk3_state.
        if bk3_state(dev) != Bk3State::Fresh {
            return;
        }

        let mut bk3 = [0u8; 48];
        Rng::rand_bytes(&mut bk3).expect("rand_bytes failed");

        // Build the encrypted-BK3 payload, then attempt secure_init_bk3 without
        // having set the provisioning PIN: it must be rejected as Bk3PinNotSet.
        let payload = build_secure_init_bk3_payload(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);
        assert!(payload.is_ok(), "payload {payload:?}");
        let (eb, pk) = payload.unwrap();
        let result = helper_secure_init_bk3(dev, eb, pk);
        assert!(
            matches!(result, Err(DdiError::DdiStatus(DdiStatus::Bk3PinNotSet))),
            "secure_init before set_pin: {result:?}"
        );
    });
}

/// Negative smoke: a corrupted transport tag must be rejected.
///
/// After `set_init_bk3_pin`, flipping a bit in `tag_transport` fails the
/// transport HMAC check (verified before the PIN tag), so `secure_init_bk3` must
/// return `Bk3TransportTagMismatch`. The failure happens before the one-shot
/// state advances, so the partition stays fresh.
///
/// Mock-only: it sets the one-shot Phase-2 PIN without completing Phase 4, which
/// on real HW persists until reboot (NSSR won't clear it) and would block the
/// other PIN-setting tests.
#[cfg(feature = "mock")]
#[test]
fn test_secure_init_bk3_transport_tag_mismatch() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        if bk3_state(dev) != Bk3State::Fresh {
            return;
        }

        let mut bk3 = [0u8; 48];
        Rng::rand_bytes(&mut bk3).expect("rand_bytes failed");

        set_init_bk3_pin(dev, TEST_CRED_ID, TEST_CRED_PIN).expect("set_init_bk3_pin");
        let (mut eb, pk) = build_secure_init_bk3_payload(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3)
            .expect("build payload");
        eb.tag_transport[0] ^= 1;
        let result = helper_secure_init_bk3(dev, eb, pk);
        assert!(
            matches!(
                result,
                Err(DdiError::DdiStatus(DdiStatus::Bk3TransportTagMismatch))
            ),
            "corrupted transport tag: {result:?}"
        );
    });
}

/// Negative smoke: a corrupted PIN tag must be rejected.
///
/// After `set_init_bk3_pin`, flipping a bit in `tag_pin` (leaving `tag_transport`
/// valid) passes the transport check and fails the PIN HMAC check, so
/// `secure_init_bk3` must return `Bk3PinTagMismatch`.
///
/// Mock-only: same one-shot Phase-2 PIN reason as
/// `test_secure_init_bk3_transport_tag_mismatch`.
#[cfg(feature = "mock")]
#[test]
fn test_secure_init_bk3_pin_tag_mismatch() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        if bk3_state(dev) != Bk3State::Fresh {
            return;
        }

        let mut bk3 = [0u8; 48];
        Rng::rand_bytes(&mut bk3).expect("rand_bytes failed");

        set_init_bk3_pin(dev, TEST_CRED_ID, TEST_CRED_PIN).expect("set_init_bk3_pin");
        let (mut eb, pk) = build_secure_init_bk3_payload(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3)
            .expect("build payload");
        eb.tag_pin[0] ^= 1;
        let result = helper_secure_init_bk3(dev, eb, pk);
        assert!(
            matches!(
                result,
                Err(DdiError::DdiStatus(DdiStatus::Bk3PinTagMismatch))
            ),
            "corrupted pin tag: {result:?}"
        );
    });
}

/// Negative smoke: `set_init_bk3_pin` is one-shot per partition.
///
/// A second `set_init_bk3_pin`, before `secure_init_bk3` consumes the stored PIN,
/// must be rejected with `Bk3PinAlreadySet`.
///
/// Mock-only: the first `set_init_bk3_pin` leaves a one-shot Phase-2 PIN that on
/// real HW persists until reboot (NSSR won't clear it).
#[cfg(feature = "mock")]
#[test]
fn test_secure_init_bk3_pin_already_set() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        if bk3_state(dev) != Bk3State::Fresh {
            return;
        }

        set_init_bk3_pin(dev, TEST_CRED_ID, TEST_CRED_PIN).expect("first set_init_bk3_pin");
        let result = set_init_bk3_pin(dev, TEST_CRED_ID, TEST_CRED_PIN);
        assert!(
            matches!(
                result,
                Err(DdiError::DdiStatus(DdiStatus::Bk3PinAlreadySet))
            ),
            "second set_init_bk3_pin: {result:?}"
        );
    });
}
