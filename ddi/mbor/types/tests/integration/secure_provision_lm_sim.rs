// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Secure-provisioning live-migration simulation tests for mock and hardware backends.
//!
//! `migrate_sim` (NSSR) reproduces what a live migration does to a
//! partition: the volatile state (the ECDH tunnel key and the in-flight
//! provisioning PIN) is dropped, while the sealed/persistent store is carried
//! to the target. These tests confirm the two halves of that contract:
//!
//! 1. A migration in the MIDDLE of secure provisioning lands no partial
//!    persistent state on the target, and a clean flow still provisions
//!    afterwards (`test_secure_provision_lm_midflow_restart`).
//! 2. A COMPLETED, sealed provisioning survives a migration byte-identical,
//!    with FIPS status preserved and a re-seal rejected
//!    (`test_secure_provision_lm_completed_survives`).

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

const API_REV: DdiApiRev = DdiApiRev { major: 1, minor: 0 };

/// Simulate a live migration onto a fresh target
fn migrate_sim(dev: &<DdiTest as Ddi>::Dev) {
    let resp = dev.erase();
    assert!(resp.is_ok(), "migrate_sim (NSSR) {resp:?}");
}

/// Reads the module FIPS-approval status the host observes via `GetDeviceInfo`.
fn fips_approved(dev: &<DdiTest as Ddi>::Dev) -> bool {
    let resp = helper_get_device_info(dev, None, Some(API_REV));
    assert!(resp.is_ok(), "GetDeviceInfo {resp:?}");
    resp.unwrap().data.fips_approved
}

/// Assert that `err` is the pin-not-set status.
fn assert_pin_not_set(err: &DdiError, ctx: &str) {
    assert!(
        matches!(err, DdiError::DdiStatus(DdiStatus::Bk3PinNotSet)),
        "{ctx}: expected Bk3PinNotSet, got {err:?}"
    );
}

/// A live migration in the MIDDLE of secure provisioning must leave no partial
/// persistent state on the target, and a clean flow must still provision
/// afterwards.
///
/// `migrate_sim` (NSSR) drops the volatile ECDH tunnel key and the in-flight
/// provisioning PIN while carrying the persistent store across:
///
/// - mint-then-migrate: migrate right after minting the establish key (no PIN
///   set) — `secure_init_bk3` must fail `Bk3PinNotSet`.
/// - setpin-then-migrate: migrate after `set_init_bk3_pin` (the volatile PIN is
///   lost) — `secure_init_bk3` over a fresh tunnel is rejected as pin-not-set.
/// - prebuild-then-migrate: pre-build the encrypted-BK3 payload over a second
///   tunnel, THEN migrate (both the tunnel key and the volatile PIN are lost and
///   NSSR regenerates the tunnel nonce) — the pre-built payload now carries a
///   stale nonce. `secure_init_bk3` verifies the nonce before the PIN (firmware
///   `on_start`, which the mock mirrors), so the stale/replayed payload is
///   rejected with `NonceMismatch`.
/// - no-partial-state: `get_sealed_bk3` stays gated and `fips_approved` stays
///   false, confirming no partial persistent state landed.
///
/// Recovery then runs a clean full flow (provision + seal) and confirms the
/// completed provisioning migrates intact, with a one-shot re-seal rejected
/// (`SealedBk3AlreadySet`).
#[test]
fn test_secure_provision_lm_midflow_restart() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        // Guard: mid-flow scenarios need a genuinely fresh partition. Proceed
        // only on Fresh (Bk3NotSecurelyProvisioned); any sealed /
        // provisioned-but-unsealed (secure or legacy) / unsupported state can't
        // be re-provisioned (SecureInitBk3 is one-shot and the MOBK can't be
        // re-minted), so skip. An unexpected status fails loudly in bk3_state.
        if bk3_state(dev) != Bk3State::Fresh {
            println!("skipping: partition not fresh (AC-cycle to reset)");
            return;
        }

        let mut bk3 = [0u8; 48];
        let rng = Rng::rand_bytes(&mut bk3);
        assert!(rng.is_ok(), "rand_bytes failed: {rng:?}");

        // mint-then-migrate: migrate after minting the establish key (no PIN
        // set). With the volatile prov-cred empty, secure_init_bk3 must fail
        // Bk3PinNotSet.
        let resp = helper_get_establish_cred_encryption_key(dev, None, Some(API_REV));
        assert!(resp.is_ok(), "resp {resp:?}");
        migrate_sim(dev);
        let payload = build_secure_init_bk3_payload(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);
        assert!(payload.is_ok(), "payload {payload:?}");
        let (eb, pk) = payload.unwrap();
        let result = helper_secure_init_bk3(dev, eb, pk);
        assert!(
            matches!(result, Err(DdiError::DdiStatus(DdiStatus::Bk3PinNotSet))),
            "mint-then-migrate: {result:?}"
        );

        // setpin-then-migrate: set the PIN, migrate (volatile prov-cred lost),
        // then secure_init_bk3 over a fresh tunnel is rejected as if landing on a
        // fresh target.
        let pin_resp = set_init_bk3_pin(dev, TEST_CRED_ID, TEST_CRED_PIN);
        assert!(pin_resp.is_ok(), "pin_resp {pin_resp:?}");
        migrate_sim(dev);
        let payload = build_secure_init_bk3_payload(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);
        assert!(payload.is_ok(), "payload {payload:?}");
        let (eb, pk) = payload.unwrap();
        let result = helper_secure_init_bk3(dev, eb, pk);
        assert!(result.is_err(), "setpin-then-migrate: {result:?}");
        assert_pin_not_set(&result.unwrap_err(), "setpin-then-migrate");

        // prebuild-then-migrate: re-set the volatile PIN, pre-build an
        // encrypted-BK3 payload over a second tunnel, THEN migrate so both the
        // tunnel key and PIN are lost and the tunnel nonce is regenerated. The
        // pre-built payload now carries a stale nonce, and secure_init_bk3
        // verifies the nonce before the PIN (firmware `on_start`; the mock
        // mirrors this), so the stale/replayed payload is rejected with
        // NonceMismatch.
        let pin_resp = set_init_bk3_pin(dev, TEST_CRED_ID, TEST_CRED_PIN);
        assert!(pin_resp.is_ok(), "pin_resp {pin_resp:?}");
        let payload = build_secure_init_bk3_payload(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);
        assert!(payload.is_ok(), "payload {payload:?}");
        let (eb, pk) = payload.unwrap();
        migrate_sim(dev);
        let result = helper_secure_init_bk3(dev, eb, pk);
        assert!(
            matches!(result, Err(DdiError::DdiStatus(DdiStatus::NonceMismatch))),
            "prebuild-then-migrate: expected NonceMismatch for stale payload, got {result:?}"
        );

        // no-partial-state: no partial persistent state landed on the target.
        assert!(
            matches!(
                helper_get_sealed_bk3(dev),
                Err(DdiError::DdiStatus(DdiStatus::Bk3NotSecurelyProvisioned))
            ),
            "get_sealed_bk3 must stay gated while un-provisioned"
        );
        assert!(!fips_approved(dev), "fips_approved must be false");

        // Recovery: a clean full flow provisions and seals end to end.
        let result = secure_bk3_provision_and_seal(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);
        assert!(result.is_ok(), "provision + seal {result:?}");
        let sealed_before = result.unwrap();

        // `fips_approved` reflects the module's FIPS provisioning status: the
        // mock marks it approved once secure provisioning completes, while real
        // firmware ties it to the power-on image measurement (so it stays false
        // on a debug/non-FIPS image). Its value is therefore backend-dependent;
        // capture it once here and assert only that migration preserves it.
        let image_is_fips = fips_approved(dev);

        // persist-identical: the completed provisioning migrates intact.
        migrate_sim(dev);
        let sealed_after = helper_get_sealed_bk3(dev);
        assert!(sealed_after.is_ok(), "sealed_after {sealed_after:?}");
        let sealed_after = sealed_after.unwrap().data.sealed_bk3.as_slice().to_vec();
        assert_eq!(
            sealed_after, sealed_before,
            "persist-identical: sealed_bk3 changed"
        );
        assert_eq!(
            fips_approved(dev),
            image_is_fips,
            "persist-identical: fips changed"
        );
        assert!(
            !sealed_after.is_empty(),
            "fips-implies-sealed: sealed_bk3 empty"
        );

        // One-shot: re-sealing the migrated partition is rejected.
        let reseal = helper_set_sealed_bk3(dev, sealed_after.clone());
        assert!(
            matches!(
                reseal,
                Err(DdiError::DdiStatus(DdiStatus::SealedBk3AlreadySet))
            ),
            "reseal {reseal:?}"
        );
    });
}

/// A COMPLETED, sealed secure provisioning must survive a live migration
/// byte-identical.
///
/// Starting from a securely-provisioned + sealed partition (provisioning it
/// in-test if the device is fresh), `migrate_sim` (NSSR) is applied and the
/// persistent contract is asserted on the target:
///
/// - persist-identical: `get_sealed_bk3` returns the same bytes before and
///   after migration, and the FIPS-approval status is preserved.
/// - One-shot: re-sealing the migrated partition is rejected with
///   `SealedBk3AlreadySet`.
/// - fips-implies-sealed: a FIPS-approved partition never carries an empty
///   sealed BK3.
#[test]
fn test_secure_provision_lm_completed_survives() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        // Obtain a securely-provisioned + sealed partition. If the device is not
        // already sealed, complete a full secure provisioning + seal here so the
        // test does not depend on prior firmware/test state. An unexpected
        // GetSealedBk3 status fails loudly in bk3_state.
        let sealed_before = match bk3_state(dev) {
            Bk3State::Sealed => helper_get_sealed_bk3(dev)
                .expect("sealed BK3 present")
                .data
                .sealed_bk3
                .as_slice()
                .to_vec(),
            Bk3State::Fresh => {
                // Fresh: securely provision + seal.
                let mut bk3 = [0u8; 48];
                let rng = Rng::rand_bytes(&mut bk3);
                assert!(rng.is_ok(), "rand_bytes failed: {rng:?}");
                let result = secure_bk3_provision_and_seal(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);
                assert!(result.is_ok(), "provision + seal {result:?}");
                result.unwrap()
            }
            // Provisioned-but-unsealed or unsupported: can't recover here.
            Bk3State::Unsealed | Bk3State::Unsupported => {
                println!("skipping: partition not fresh or sealed (AC-cycle to reset)");
                return;
            }
        };
        let fips_before = fips_approved(dev);

        migrate_sim(dev);

        // persist-identical: the persistent store survives the migration byte-identical.
        let sealed_after = helper_get_sealed_bk3(dev);
        assert!(sealed_after.is_ok(), "sealed_after {sealed_after:?}");
        let sealed_after = sealed_after.unwrap().data.sealed_bk3.as_slice().to_vec();
        assert_eq!(
            sealed_after, sealed_before,
            "persist-identical: sealed_bk3 changed"
        );
        assert_eq!(
            fips_approved(dev),
            fips_before,
            "persist-identical: fips changed"
        );

        // One-shot: re-sealing the migrated partition is rejected.
        let reseal = helper_set_sealed_bk3(dev, sealed_after.clone());
        assert!(
            matches!(
                reseal,
                Err(DdiError::DdiStatus(DdiStatus::SealedBk3AlreadySet))
            ),
            "reseal {reseal:?}"
        );

        // fips-implies-sealed: FIPS-approved implies a non-empty sealed BK3.
        if fips_approved(dev) {
            assert!(
                !sealed_after.is_empty(),
                "fips-implies-sealed: sealed_bk3 empty"
            );
        }
    });
}
