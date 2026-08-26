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

use azihsm_cred_encrypt::Bk3EncryptionKey;
use azihsm_cred_encrypt::DeviceCredKey;
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
    assert!(
        resp.is_ok(),
        "live-migration simulation (NSSR) must succeed, resp {resp:?}"
    );
}

/// Reads the module FIPS-approval status the host observes via `GetDeviceInfo`.
fn fips_approved(dev: &<DdiTest as Ddi>::Dev) -> bool {
    let resp = helper_get_device_info(dev, None, Some(API_REV));
    assert!(resp.is_ok(), "GetDeviceInfo must succeed, resp {resp:?}");
    resp.unwrap().data.fips_approved
}

/// `SetInitBk3Pin`: store the encrypted `(id, pin)` provisioning credential.
fn set_init_bk3_pin(
    dev: &<DdiTest as Ddi>::Dev,
    id: [u8; 16],
    pin: [u8; 16],
) -> Result<(), DdiError> {
    let resp = helper_get_establish_cred_encryption_key(dev, None, Some(API_REV))?;
    let nonce = resp.data.nonce;
    let dev_key = DeviceCredKey::new(&resp.data.pub_key, nonce);
    assert!(dev_key.is_ok(), "DeviceCredKey::new failed: {dev_key:?}");
    let cred = dev_key
        .unwrap()
        .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY);
    assert!(
        cred.is_ok(),
        "create_credential_key_from_der failed: {:?}",
        cred.as_ref().err()
    );
    let (cred_key, pub_key) = cred.unwrap();
    let ecred = cred_key.encrypt_establish_credential(id, pin, nonce);
    assert!(
        ecred.is_ok(),
        "encrypt_establish_credential failed: {ecred:?}"
    );
    helper_set_init_bk3_pin(dev, ecred.unwrap(), pub_key)?;
    Ok(())
}

/// Build the encrypted, PIN-authenticated BK3 payload for `SecureInitBk3`.
fn build_encrypted_bk3(
    dev: &<DdiTest as Ddi>::Dev,
    id: [u8; 16],
    pin: [u8; 16],
    bk3: &[u8; 48],
) -> Result<(DdiEncryptedBk3, DdiDerPublicKey), DdiError> {
    let resp = helper_get_establish_cred_encryption_key(dev, None, Some(API_REV))?;
    let nonce = resp.data.nonce;
    let dev_key = DeviceCredKey::new(&resp.data.pub_key, nonce);
    assert!(dev_key.is_ok(), "DeviceCredKey::new failed: {dev_key:?}");
    let bk3_res = dev_key
        .unwrap()
        .create_bk3_key_from_der(&TEST_ECC_384_PRIVATE_KEY);
    assert!(
        bk3_res.is_ok(),
        "create_bk3_key_from_der failed: {:?}",
        bk3_res.as_ref().err()
    );
    let (bk3_key, pub_key): (Bk3EncryptionKey, DdiDerPublicKey) = bk3_res.unwrap();
    let encrypted_bk3 = bk3_key.encrypt_bk3(bk3, id, pin, nonce);
    assert!(
        encrypted_bk3.is_ok(),
        "encrypt_bk3 failed: {encrypted_bk3:?}"
    );
    Ok((encrypted_bk3.unwrap(), pub_key))
}

/// Full secure provisioning: set PIN, then inject BK3.
fn secure_provision_bk3(
    dev: &<DdiTest as Ddi>::Dev,
    id: [u8; 16],
    pin: [u8; 16],
    bk3: &[u8; 48],
) -> Result<DdiSecureInitBk3CmdResp, DdiError> {
    set_init_bk3_pin(dev, id, pin)?;
    let (encrypted_bk3, pub_key) = build_encrypted_bk3(dev, id, pin, bk3)?;
    helper_secure_init_bk3(dev, encrypted_bk3, pub_key)
}

fn assert_pin_not_set(err: &DdiError, ctx: &str) {
    assert!(
        matches!(err, DdiError::DdiStatus(DdiStatus::Bk3PinNotSet)),
        "{ctx}: expected Bk3PinNotSet (141557993), got {err:?}"
    );
}

/// True if the device already carries persistent BK3 provisioning state
/// (`Bk3AlreadyInitialized` / `Bk3PinAlreadySet`), which the seal-op gate alone
/// cannot detect. These statuses only signal that provisioning state is present;
/// they do not indicate which API (legacy `init_bk3` or secure) produced it.
fn not_truly_fresh(err: &DdiError) -> bool {
    matches!(
        err,
        DdiError::DdiStatus(DdiStatus::Bk3AlreadyInitialized)
            | DdiError::DdiStatus(DdiStatus::Bk3PinAlreadySet)
    )
}

/// A live migration in the MIDDLE of secure provisioning must leave no partial
/// persistent state on the target, and a clean flow must still provision
/// afterwards.
///
/// `migrate_sim` (NSSR) drops the volatile ECDH tunnel key and the in-flight
/// provisioning PIN while carrying the persistent store across:
///
/// - A1: migrate right after minting the establish key (no PIN set) —
///   `secure_init_bk3` must fail `Bk3PinNotSet`.
/// - A2: migrate after `set_init_bk3_pin` (the volatile PIN is lost) —
///   `secure_init_bk3` over a fresh tunnel is rejected as pin-not-set.
/// - A3: pre-build the encrypted-BK3 payload, THEN migrate (both tunnel key and
///   PIN lost) — `secure_init_bk3` fails the pin-set guard (the persistent nonce
///   survives migration, so the nonce check passes first) with `Bk3PinNotSet`.
/// - A4: no partial persistent state landed — `get_sealed_bk3` stays gated and
///   `is_fips_approved` stays false.
///
/// Recovery then runs a clean full flow (provision + seal) and confirms the
/// completed provisioning migrates intact (B5/B6), with a one-shot re-seal
/// rejected (`SealedBk3AlreadySet`).
#[test]
fn test_secure_provision_lm_midflow_restart() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        // Guard: mid-flow scenarios need a fresh partition, detected via the
        // seal-op gate rejecting `GetSealedBk3` while un-provisioned.
        match helper_get_sealed_bk3(dev) {
            Err(DdiError::DdiStatus(DdiStatus::Bk3NotSecurelyProvisioned)) => {}
            Err(err) if is_unsupported_cmd(&err) => {
                println!("skipping: ops unsupported (emu backend)");
                return;
            }
            other => {
                println!("skipping: partition already provisioned (AC-cycle to reset): {other:?}");
                return;
            }
        }

        let mut bk3 = [0u8; 48];
        let rng = Rng::rand_bytes(&mut bk3);
        assert!(rng.is_ok(), "rand_bytes failed: {rng:?}");

        // A1: migrate after minting the establish key (no PIN set). With the
        // volatile prov-cred empty, secure_init_bk3 must fail Bk3PinNotSet;
        // pre-existing persistent BK3 means the device isn't truly fresh, so skip.
        let resp = helper_get_establish_cred_encryption_key(dev, None, Some(API_REV));
        assert!(
            resp.is_ok(),
            "minting the establish key must succeed, resp {resp:?}"
        );
        migrate_sim(dev);
        let payload = build_encrypted_bk3(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);
        assert!(
            payload.is_ok(),
            "encrypted-BK3 payload build (fresh tunnel) must succeed, resp {payload:?}"
        );
        let (eb, pk) = payload.unwrap();
        let result = helper_secure_init_bk3(dev, eb, pk);
        if let Err(err) = &result {
            if not_truly_fresh(err) {
                println!("skipping: device already provisioned (persistent BK3 present)");
                return;
            }
        }
        assert!(
            matches!(result, Err(DdiError::DdiStatus(DdiStatus::Bk3PinNotSet))),
            "A1: cold secure_init_bk3 (no PIN) must be Bk3PinNotSet, got {result:?}"
        );

        // A2: set the PIN, migrate (volatile prov-cred lost), then secure_init_bk3
        // over a fresh tunnel is rejected as if landing on a fresh target.
        let pin_resp = set_init_bk3_pin(dev, TEST_CRED_ID, TEST_CRED_PIN);
        assert!(
            pin_resp.is_ok(),
            "set_init_bk3_pin must succeed on a fresh partition, resp {pin_resp:?}"
        );
        migrate_sim(dev);
        let payload = build_encrypted_bk3(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);
        assert!(
            payload.is_ok(),
            "encrypted-BK3 payload build must succeed after migration, resp {payload:?}"
        );
        let (eb, pk) = payload.unwrap();
        let result = helper_secure_init_bk3(dev, eb, pk);
        assert!(
            result.is_err(),
            "A2: secure_init_bk3 after mid-flow migration must be rejected, got {result:?}"
        );
        assert_pin_not_set(&result.unwrap_err(), "A2: migrate after set_init_bk3_pin");

        // A3: re-set the volatile PIN, pre-build an encrypted-BK3 payload over a
        // second tunnel, THEN migrate so both the tunnel key and PIN are lost;
        // secure_init_bk3 must not decrypt-succeed against the stale state.
        let pin_resp = set_init_bk3_pin(dev, TEST_CRED_ID, TEST_CRED_PIN);
        assert!(
            pin_resp.is_ok(),
            "set_init_bk3_pin must succeed again after migration (PIN was volatile), resp {pin_resp:?}"
        );
        let payload = build_encrypted_bk3(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);
        assert!(
            payload.is_ok(),
            "encrypted-BK3 payload over the second tunnel must build, resp {payload:?}"
        );
        let (eb, pk) = payload.unwrap();
        migrate_sim(dev);
        let result = helper_secure_init_bk3(dev, eb, pk);
        assert!(
            result.is_err(),
            "A3: secure_init_bk3 after mid-flow migration must be rejected, got {result:?}"
        );
        assert_pin_not_set(&result.unwrap_err(), "A3: migrate after pre-building the payload");

        // A4: no partial persistent state landed on the target.
        assert!(
            matches!(
                helper_get_sealed_bk3(dev),
                Err(DdiError::DdiStatus(DdiStatus::Bk3NotSecurelyProvisioned))
            ),
            "A4: get_sealed_bk3 must stay gated while un-provisioned"
        );
        assert!(
            !fips_approved(dev),
            "A4/C9: is_fips_approved must be false while un-provisioned"
        );

        // Recovery: a clean full flow provisions end to end.
        let resp = secure_provision_bk3(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);
        assert!(
            resp.is_ok(),
            "full provisioning after a clean restart must succeed, resp {resp:?}"
        );
        let resp = resp.unwrap();
        assert_eq!(resp.hdr.status, DdiStatus::Success);
        let masked_bk3 = resp.data.masked_bk3.as_slice().to_vec();
        assert!(
            (MIN_MASKED_BK3_LEN..=MAX_MASKED_BK3_LEN).contains(&masked_bk3.len()),
            "masked_bk3 length {} is outside the expected range",
            masked_bk3.len()
        );
        assert_eq!(resp.data.vm_launch_guid.len(), 16);

        // is_fips_approved reflects whether the firmware IMAGE is FIPS-approved
        // (a power-on measurement), so it is legitimately false on a debug image.
        // Capture it once here; it is invariant across the test and is used below
        // to assert preservation across migration.
        let image_is_fips = fips_approved(dev);

        // Seal the MOBK.
        let seal_resp = helper_set_sealed_bk3(dev, masked_bk3.clone());
        assert!(
            seal_resp.is_ok(),
            "set_sealed_bk3 seal must succeed, resp {seal_resp:?}"
        );

        // B5/B6: the completed provisioning migrates intact.
        let sealed_before = helper_get_sealed_bk3(dev);
        assert!(
            sealed_before.is_ok(),
            "get_sealed_bk3 must succeed after sealing, resp {sealed_before:?}"
        );
        let sealed_before = sealed_before.unwrap().data.sealed_bk3.as_slice().to_vec();
        migrate_sim(dev);
        let sealed_after = helper_get_sealed_bk3(dev);
        assert!(
            sealed_after.is_ok(),
            "get_sealed_bk3 must succeed after a completed-provisioning migration, resp {sealed_after:?}"
        );
        let sealed_after = sealed_after.unwrap().data.sealed_bk3.as_slice().to_vec();
        assert_eq!(
            sealed_after, sealed_before,
            "C7: sealed_bk3 must be byte-identical across migration"
        );
        assert_eq!(
            fips_approved(dev),
            image_is_fips,
            "C7: fips status must be preserved across migration"
        );
        assert!(
            !sealed_after.is_empty(),
            "C9: a sealed partition must never have an empty sealed BK3"
        );

        // One-shot: re-sealing the migrated partition is rejected.
        let reseal = helper_set_sealed_bk3(dev, sealed_after.clone());
        assert!(
            matches!(
                reseal,
                Err(DdiError::DdiStatus(DdiStatus::SealedBk3AlreadySet))
            ),
            "re-seal after migration must be rejected with SealedBk3AlreadySet, got {reseal:?}"
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
/// - C7: `get_sealed_bk3` returns the same bytes before and after migration,
///   and the FIPS-approval status is preserved.
/// - One-shot: re-sealing the migrated partition is rejected with
///   `SealedBk3AlreadySet`.
/// - C9: a FIPS-approved partition never carries an empty sealed BK3.
#[test]
fn test_secure_provision_lm_completed_survives() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        // Obtain a securely-provisioned + sealed partition. If the device is
        // currently fresh, complete a full secure provisioning + seal here so
        // the test does not depend on prior firmware/test state.
        let initial = helper_get_sealed_bk3(dev);
        // Skip on backends that don't implement the sealed-BK3 ops.
        if let Err(err) = &initial {
            if is_unsupported_cmd(err) {
                println!("skipping: ops unsupported (emu backend)");
                return;
            }
        }
        let needs_provision = matches!(
            &initial,
            Err(DdiError::DdiStatus(
                DdiStatus::Bk3NotSecurelyProvisioned | DdiStatus::SealedBk3NotPresent,
            ))
        );
        assert!(
            initial.is_ok() || needs_provision,
            "unexpected get_sealed_bk3 error: {initial:?}"
        );
        let sealed_before = if let Ok(resp) = initial {
            resp.data.sealed_bk3.as_slice().to_vec()
        } else {
            // Fresh partition: complete a full secure provisioning + seal here so
            // the test does not depend on prior firmware/test state.
            let mut bk3 = [0u8; 48];
            let rng = Rng::rand_bytes(&mut bk3);
            assert!(rng.is_ok(), "rand_bytes failed: {rng:?}");
            let result = secure_provision_bk3(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);
            if let Err(err) = &result {
                if is_unsupported_cmd(err) {
                    println!("skipping: ops unsupported (emu backend)");
                    return;
                }
                if not_truly_fresh(err) {
                    println!("skipping: device already provisioned (persistent BK3 present)");
                    return;
                }
            }
            assert!(result.is_ok(), "resp {:?}", result);
            let resp = result.unwrap();
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            let masked_bk3 = resp.data.masked_bk3.as_slice().to_vec();
            assert!(
                (MIN_MASKED_BK3_LEN..=MAX_MASKED_BK3_LEN).contains(&masked_bk3.len()),
                "masked_bk3 length {} is outside the expected range",
                masked_bk3.len()
            );
            let seal_resp = helper_set_sealed_bk3(dev, masked_bk3);
            assert!(
                seal_resp.is_ok(),
                "in-test seal must succeed, resp {seal_resp:?}"
            );
            let get_resp = helper_get_sealed_bk3(dev);
            assert!(
                get_resp.is_ok(),
                "get_sealed_bk3 must succeed after in-test sealing, resp {get_resp:?}"
            );
            get_resp.unwrap().data.sealed_bk3.as_slice().to_vec()
        };
        let fips_before = fips_approved(dev);

        migrate_sim(dev);

        // C7: the persistent store survives the migration byte-identical.
        let sealed_after = helper_get_sealed_bk3(dev);
        assert!(
            sealed_after.is_ok(),
            "get_sealed_bk3 must succeed after migration, resp {sealed_after:?}"
        );
        let sealed_after = sealed_after.unwrap().data.sealed_bk3.as_slice().to_vec();
        assert_eq!(
            sealed_after, sealed_before,
            "C7: sealed_bk3 must be identical before/after migration"
        );
        assert_eq!(
            fips_approved(dev),
            fips_before,
            "C7: fips status must be preserved across migration"
        );

        // One-shot: re-sealing the migrated partition is rejected.
        let reseal = helper_set_sealed_bk3(dev, sealed_after.clone());
        assert!(
            matches!(
                reseal,
                Err(DdiError::DdiStatus(DdiStatus::SealedBk3AlreadySet))
            ),
            "re-seal after migration must be rejected with SealedBk3AlreadySet, got {reseal:?}"
        );

        // C9 invariant: FIPS-approved implies a non-empty sealed BK3.
        if fips_approved(dev) {
            assert!(
                !sealed_after.is_empty(),
                "C9: a FIPS-approved partition must never have an empty sealed BK3"
            );
        }
    });
}
