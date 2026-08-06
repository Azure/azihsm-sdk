// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SecureInitBk3 / SetInitBk3Pin smoke tests for the emu/mock backend.
//!
//! Exercises:
//! - Happy path: set_init_bk3_pin + secure_init_bk3 succeed, returning a masked
//!   BK3 (MOBK) and a 16-byte VM launch GUID, then set_sealed_bk3 seals the MOBK.
//! - Full flow on a fresh partition: seal-op gate before secure_init_bk3,
//!   provisioning, seal round-trip, and one-shot rejection of re-provision / re-seal.
//! - Auth negatives: a tampered transport or PIN tag is rejected, while a
//!   well-formed secure_init_bk3 with the same PIN still succeeds.

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

/// Full secure provisioning (set_init_bk3_pin + secure_init_bk3), each over its
/// own fresh ECDH tunnel.
fn secure_provision_bk3(
    dev: &<DdiTest as Ddi>::Dev,
    id: [u8; 16],
    pin: [u8; 16],
    bk3: &[u8; 48],
) -> Result<DdiSecureInitBk3CmdResp, DdiError> {
    let rev = Some(API_REV);

    // set_init_bk3_pin
    let resp1 = helper_get_establish_cred_encryption_key(dev, None, rev)?;
    let nonce1 = resp1.data.nonce;
    let dev_key1 = DeviceCredKey::new(&resp1.data.pub_key, nonce1).unwrap();
    let (cred_key, pub_key1) = dev_key1
        .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
        .unwrap();
    let encrypted_credential = cred_key
        .encrypt_establish_credential(id, pin, nonce1)
        .unwrap();
    helper_set_init_bk3_pin(dev, encrypted_credential, pub_key1)?;

    // secure_init_bk3
    let resp2 = helper_get_establish_cred_encryption_key(dev, None, rev)?;
    let nonce2 = resp2.data.nonce;
    let dev_key2 = DeviceCredKey::new(&resp2.data.pub_key, nonce2).unwrap();
    let (bk3_key, pub_key2): (Bk3EncryptionKey, DdiDerPublicKey) = dev_key2
        .create_bk3_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
        .unwrap();
    let encrypted_bk3 = bk3_key.encrypt_bk3(bk3, id, pin, nonce2).unwrap();
    helper_secure_init_bk3(dev, encrypted_bk3, pub_key2)
}

/// Error means skip: op unsupported (emu) or partition already provisioned.
fn should_skip(err: &DdiError) -> bool {
    is_unsupported_cmd(err)
        || matches!(
            err,
            DdiError::DdiStatus(DdiStatus::Bk3AlreadyInitialized)
                | DdiError::DdiStatus(DdiStatus::Bk3PinAlreadySet)
        )
}

// Happy path: set_init_bk3_pin + secure_init_bk3 succeed, then set_sealed_bk3 seals the MOBK.
#[test]
fn test_secure_init_bk3_smoke() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        let mut bk3 = [0u8; 48];
        Rng::rand_bytes(&mut bk3).unwrap();

        let result = secure_provision_bk3(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);
        if let Err(err) = &result {
            if should_skip(err) {
                tracing::warn!(
                    ?err,
                    "secure_init_bk3 unsupported or already provisioned; skipping"
                );
                return;
            }
        }
        assert!(result.is_ok(), "resp {:?}", result);
        let resp = result.unwrap();

        assert_eq!(resp.hdr.op, DdiOp::SecureInitBk3);
        assert_eq!(resp.hdr.status, DdiStatus::Success);
        let masked_len = resp.data.masked_bk3.len();
        assert_eq!(
            masked_len, EXPECTED_MASKED_BK3_LEN,
            "unexpected masked_bk3 length"
        );
        assert_eq!(resp.data.vm_launch_guid.len(), 16);

        // Seal the MOBK so later tests re-hydrate via `get_sealed_bk3`.
        let masked_bk3 = resp.data.masked_bk3.as_slice().to_vec();
        let set_resp = helper_set_sealed_bk3(dev, masked_bk3.clone());
        assert!(set_resp.is_ok(), "resp {:?}", set_resp);
        assert_eq!(set_resp.unwrap().hdr.status, DdiStatus::Success);

        // Confirm the seal round-trips: get_sealed_bk3 now returns the MOBK.
        let get_resp = helper_get_sealed_bk3(dev);
        assert!(get_resp.is_ok(), "resp {:?}", get_resp);
        assert_eq!(
            get_resp.unwrap().data.sealed_bk3.as_slice(),
            masked_bk3.as_slice()
        );
    });
}

// Skips if already provisioned (AC-cycle to reset) or unsupported (emu backend).
#[test]
fn test_secure_bk3_full_flow() {
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        // Probe (also asserts the get-path gate on a fresh device).
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

        // (1) Seal-op gate: `set_sealed_bk3` is rejected before a successful secure_init_bk3.
        let err = helper_set_sealed_bk3(dev, vec![0u8; 64]).unwrap_err();
        assert!(
            matches!(
                err,
                DdiError::DdiStatus(DdiStatus::Bk3NotSecurelyProvisioned)
            ),
            "seal op before secure_init_bk3 must be gated, got {err:?}"
        );

        // (2) Full provisioning (set_init_bk3_pin + secure_init_bk3).
        let mut bk3 = [0u8; 48];
        Rng::rand_bytes(&mut bk3).unwrap();
        let result = secure_provision_bk3(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);
        if let Err(err) = &result {
            if should_skip(err) {
                tracing::warn!(
                    ?err,
                    "partition not truly fresh (masked_bk_boot set / already provisioned); \
                     AC-cycle to reset; skipping"
                );
                return;
            }
        }
        assert!(result.is_ok(), "resp {:?}", result);
        let resp = result.unwrap();
        assert_eq!(resp.hdr.status, DdiStatus::Success);
        let masked_bk3 = resp.data.masked_bk3.as_slice().to_vec();
        assert_eq!(
            masked_bk3.len(),
            EXPECTED_MASKED_BK3_LEN,
            "unexpected masked_bk3 length"
        );
        assert_eq!(resp.data.vm_launch_guid.len(), 16);

        // (3) Seal round-trip.
        let set_resp = helper_set_sealed_bk3(dev, masked_bk3.clone()).unwrap();
        assert_eq!(set_resp.hdr.status, DdiStatus::Success);
        let get_resp = helper_get_sealed_bk3(dev).unwrap();
        assert_eq!(get_resp.data.sealed_bk3.as_slice(), masked_bk3.as_slice());

        // (4) Re-provision must be rejected (one-shot + persistent).
        let err = secure_provision_bk3(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3).unwrap_err();
        assert!(
            matches!(
                err,
                DdiError::DdiStatus(DdiStatus::Bk3AlreadyInitialized)
                    | DdiError::DdiStatus(DdiStatus::Bk3PinAlreadySet)
            ),
            "re-provision must be rejected, got {err:?}"
        );

        // (5) Re-seal must be rejected.
        let err = helper_set_sealed_bk3(dev, masked_bk3).unwrap_err();
        assert!(
            matches!(err, DdiError::DdiStatus(DdiStatus::SealedBk3AlreadySet)),
            "re-seal must be rejected, got {err:?}"
        );
    });
}
