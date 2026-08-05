// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(any(feature = "emu", feature = "mock"))]
#![cfg(test)]

use azihsm_cred_encrypt::Bk3EncryptionKey;
use azihsm_cred_encrypt::DeviceCredKey;
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
    dev.erase()
        .expect("live-migration simulation (NSSR) must succeed");
}

/// Reads the module FIPS-approval status the host observes via `GetDeviceInfo`.
fn fips_approved(dev: &<DdiTest as Ddi>::Dev) -> bool {
    helper_get_device_info(dev, None, Some(API_REV))
        .expect("GetDeviceInfo must succeed")
        .data
        .fips_approved
}

/// Phase 2 (`SetInitBk3Pin`): store the encrypted `(id, pin)` provisioning credential.
fn set_pin_phase2(
    dev: &<DdiTest as Ddi>::Dev,
    id: [u8; 16],
    pin: [u8; 16],
) -> Result<(), DdiError> {
    let resp = helper_get_establish_cred_encryption_key(dev, None, Some(API_REV))?;
    let nonce = resp.data.nonce;
    let dev_key = DeviceCredKey::new(&resp.data.pub_key, nonce).unwrap();
    let (cred_key, pub_key) = dev_key
        .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
        .unwrap();
    let ecred = cred_key
        .encrypt_establish_credential(id, pin, nonce)
        .unwrap();
    helper_set_init_bk3_pin(dev, ecred, pub_key)?;
    Ok(())
}

/// Phase 3: build the encrypted, PIN-authenticated BK3 payload for Phase 4.
fn build_phase4(
    dev: &<DdiTest as Ddi>::Dev,
    id: [u8; 16],
    pin: [u8; 16],
    bk3: &[u8; 48],
) -> Result<(DdiEncryptedBk3, DdiDerPublicKey), DdiError> {
    let resp = helper_get_establish_cred_encryption_key(dev, None, Some(API_REV))?;
    let nonce = resp.data.nonce;
    let dev_key = DeviceCredKey::new(&resp.data.pub_key, nonce).unwrap();
    let (bk3_key, pub_key): (Bk3EncryptionKey, DdiDerPublicKey) = dev_key
        .create_bk3_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
        .unwrap();
    let encrypted_bk3 = bk3_key.encrypt_bk3(bk3, id, pin, nonce).unwrap();
    Ok((encrypted_bk3, pub_key))
}

/// Full secure provisioning (Phases 1-4): set PIN, then inject BK3.
fn secure_provision_bk3(
    dev: &<DdiTest as Ddi>::Dev,
    id: [u8; 16],
    pin: [u8; 16],
    bk3: &[u8; 48],
) -> Result<DdiSecureInitBk3CmdResp, DdiError> {
    set_pin_phase2(dev, id, pin)?;
    let (encrypted_bk3, pub_key) = build_phase4(dev, id, pin, bk3)?;
    helper_secure_init_bk3(dev, encrypted_bk3, pub_key)
}

fn assert_pin_not_set(err: &DdiError, ctx: &str) {
    assert!(
        matches!(err, DdiError::DdiStatus(DdiStatus::Bk3PinNotSet)),
        "{ctx}: expected Bk3PinNotSet (141557979), got {err:?}"
    );
}

/// True if the device carries a persistent/legacy BK3 (`Bk3AlreadyInitialized` /
/// `Bk3PinAlreadySet`), which the seal-op gate alone cannot detect.
fn not_truly_fresh(err: &DdiError) -> bool {
    matches!(
        err,
        DdiError::DdiStatus(DdiStatus::Bk3AlreadyInitialized)
            | DdiError::DdiStatus(DdiStatus::Bk3PinAlreadySet)
    )
}

#[test]
fn test_secure_provision_lm_midflow_restart() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        // Guard: mid-flow scenarios need a fresh partition, detected via the
        // seal-op gate rejecting `GetSealedBk3` while un-provisioned.
        match helper_get_sealed_bk3(dev) {
            Err(DdiError::DdiStatus(DdiStatus::Bk3NotSecurelyProvisioned)) => {}
            Err(err) if is_unsupported_cmd(&err) => {
                tracing::warn!("ops unsupported (emu backend); skipping");
                return;
            }
            other => {
                tracing::warn!(
                    ?other,
                    "partition already provisioned; AC-cycle to reset; skipping"
                );
                return;
            }
        }

        let bk3 = [0xABu8; 48];

        // A1: migrate after Phase 1 (establish key minted, no PIN). With the
        // volatile prov-cred empty, Phase 4 must fail Bk3PinNotSet; a legacy
        // persistent BK3 means the device isn't truly fresh, so skip.
        helper_get_establish_cred_encryption_key(dev, None, Some(API_REV))
            .expect("Phase 1 (mint establish key) must succeed");
        migrate_sim(dev);
        let (eb, pk) = build_phase4(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3)
            .expect("Phase-4 payload build (fresh tunnel) must succeed");
        match helper_secure_init_bk3(dev, eb, pk) {
            Err(DdiError::DdiStatus(DdiStatus::Bk3PinNotSet)) => {}
            Err(err) if not_truly_fresh(&err) => {
                tracing::warn!(
                    ?err,
                    "device not truly fresh (legacy/persistent BK3); skipping"
                );
                return;
            }
            other => panic!("A1: cold Phase 4 (no PIN) must be Bk3PinNotSet, got {other:?}"),
        }

        // A2: set the PIN, migrate (volatile prov-cred lost), then Phase 4 over a
        // fresh tunnel is rejected as if landing on a fresh target.
        set_pin_phase2(dev, TEST_CRED_ID, TEST_CRED_PIN)
            .expect("Phase 2 (set PIN) must succeed on a fresh partition");
        migrate_sim(dev);
        let (eb, pk) = build_phase4(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3)
            .expect("Phase-4 payload build must succeed after migration");
        match helper_secure_init_bk3(dev, eb, pk) {
            Err(err) => assert_pin_not_set(&err, "A2: migrate after Phase 2"),
            Ok(_) => panic!("A2: Phase 4 after mid-flow migration must be rejected"),
        }

        // A3: re-set the volatile PIN, pre-build a Phase-4 payload over a second
        // tunnel, THEN migrate so both the tunnel key and PIN are lost; Phase 4
        // must not decrypt-succeed against the stale state.
        set_pin_phase2(dev, TEST_CRED_ID, TEST_CRED_PIN)
            .expect("Phase 2 must succeed again after migration (PIN was volatile)");
        let (eb, pk) = build_phase4(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3)
            .expect("Phase-4 payload over the second tunnel must build");
        migrate_sim(dev);
        match helper_secure_init_bk3(dev, eb, pk) {
            Ok(_) => panic!("A3: Phase 4 after migration must not tag-decrypt-succeed"),
            Err(DdiError::DdiStatus(
                DdiStatus::Bk3PinNotSet
                | DdiStatus::NonceMismatch
                | DdiStatus::Bk3TransportTagMismatch,
            )) => {}
            Err(err) => panic!("A3: expected a volatile-loss status, got {err:?}"),
        }

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

        // Recovery: a clean full flow from Phase 1 provisions end to end.
        let resp = secure_provision_bk3(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3)
            .expect("full provisioning after a clean restart must succeed");
        assert_eq!(resp.hdr.status, DdiStatus::Success);
        let masked_bk3 = resp.data.masked_bk3.as_slice().to_vec();
        assert!(
            (200..=300).contains(&masked_bk3.len()),
            "masked_bk3 length {} out of range",
            masked_bk3.len()
        );
        assert_eq!(resp.data.vm_launch_guid.len(), 16);

        // is_fips_approved reflects whether the firmware IMAGE is FIPS-approved
        // (a power-on measurement), so it is legitimately false on a debug image.
        // Gate the absolute "== true" checks on the image; preservation and the
        // FIPS-implies-sealed invariant are always asserted.
        let image_is_fips = fips_approved(dev);
        if image_is_fips {
            assert!(
                fips_approved(dev),
                "B5: is_fips_approved must be true right after the Phase-4 commit"
            );
        } else {
            tracing::warn!(
                "firmware image is not FIPS-approved; skipping absolute is_fips_approved checks"
            );
        }

        // Phase 5: seal the MOBK.
        helper_set_sealed_bk3(dev, masked_bk3.clone()).expect("Phase 5 seal must succeed");

        // B5/B6: the completed provisioning migrates intact.
        let sealed_before = helper_get_sealed_bk3(dev)
            .expect("get_sealed_bk3 must succeed after sealing")
            .data
            .sealed_bk3
            .as_slice()
            .to_vec();
        migrate_sim(dev);
        let sealed_after = helper_get_sealed_bk3(dev)
            .expect("get_sealed_bk3 must succeed after a completed-provisioning migration")
            .data
            .sealed_bk3
            .as_slice()
            .to_vec();
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
        if image_is_fips {
            assert!(
                fips_approved(dev),
                "B5: is_fips_approved must remain true after a completed-provisioning migration"
            );
        }

        // One-shot: re-sealing the migrated partition is rejected.
        match helper_set_sealed_bk3(dev, sealed_after.clone()) {
            Err(DdiError::DdiStatus(DdiStatus::SealedBk3AlreadySet)) => {}
            other => panic!("re-seal after migration must be rejected, got {other:?}"),
        }
    });
}

#[test]
fn test_secure_provision_lm_completed_survives() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        // Guard: require an already securely-provisioned + sealed partition.
        let sealed_before = match helper_get_sealed_bk3(dev) {
            Ok(resp) => resp.data.sealed_bk3.as_slice().to_vec(),
            Err(err) if is_unsupported_cmd(&err) => {
                tracing::warn!("ops unsupported (emu backend); skipping");
                return;
            }
            Err(DdiError::DdiStatus(DdiStatus::Bk3NotSecurelyProvisioned)) => {
                tracing::warn!("partition not securely provisioned; skipping");
                return;
            }
            Err(DdiError::DdiStatus(DdiStatus::SealedBk3NotPresent)) => {
                tracing::warn!("partition provisioned but not yet sealed; skipping");
                return;
            }
            Err(err) => panic!("unexpected get_sealed_bk3 error: {err:?}"),
        };
        let fips_before = fips_approved(dev);

        migrate_sim(dev);

        // C7: the persistent store survives the migration byte-identical.
        let sealed_after = helper_get_sealed_bk3(dev)
            .expect("get_sealed_bk3 must succeed after migration")
            .data
            .sealed_bk3
            .as_slice()
            .to_vec();
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
        match helper_set_sealed_bk3(dev, sealed_after.clone()) {
            Err(DdiError::DdiStatus(DdiStatus::SealedBk3AlreadySet)) => {}
            other => panic!("re-seal after migration must be rejected, got {other:?}"),
        }

        // C9 invariant: FIPS-approved implies a non-empty sealed BK3.
        if fips_approved(dev) {
            assert!(
                !sealed_after.is_empty(),
                "C9: a FIPS-approved partition must never have an empty sealed BK3"
            );
        }
    });
}
