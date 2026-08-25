// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SecureInitBk3 / SetInitBk3Pin smoke test for mock and hardware backends.
//!
//! `test_secure_init_bk3_smoke` mirrors `helper_get_or_init_bk3`, but on the
//! secure BK3 path:
//! - Skips when a sealed BK3 is already present (secure provisioning is one-shot
//!   and persistent, so a re-run is a no-op).
//! - Otherwise securely provisions (`set_init_bk3_pin` + `secure_init_bk3`) and
//!   seals the resulting masked BK3 (MOBK).

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
    let dev_key1 = DeviceCredKey::new(&resp1.data.pub_key, nonce1);
    assert!(dev_key1.is_ok(), "DeviceCredKey::new failed: {dev_key1:?}");
    let cred = dev_key1
        .unwrap()
        .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY);
    assert!(
        cred.is_ok(),
        "create_credential_key_from_der failed: {:?}",
        cred.as_ref().err()
    );
    let (cred_key, pub_key1) = cred.unwrap();
    let encrypted_credential = cred_key.encrypt_establish_credential(id, pin, nonce1);
    assert!(
        encrypted_credential.is_ok(),
        "encrypt_establish_credential failed: {encrypted_credential:?}"
    );
    helper_set_init_bk3_pin(dev, encrypted_credential.unwrap(), pub_key1)?;

    // secure_init_bk3
    let resp2 = helper_get_establish_cred_encryption_key(dev, None, rev)?;
    let nonce2 = resp2.data.nonce;
    let dev_key2 = DeviceCredKey::new(&resp2.data.pub_key, nonce2);
    assert!(dev_key2.is_ok(), "DeviceCredKey::new failed: {dev_key2:?}");
    let bk3_res = dev_key2
        .unwrap()
        .create_bk3_key_from_der(&TEST_ECC_384_PRIVATE_KEY);
    assert!(
        bk3_res.is_ok(),
        "create_bk3_key_from_der failed: {:?}",
        bk3_res.as_ref().err()
    );
    let (bk3_key, pub_key2): (Bk3EncryptionKey, DdiDerPublicKey) = bk3_res.unwrap();
    let encrypted_bk3 = bk3_key.encrypt_bk3(bk3, id, pin, nonce2);
    assert!(
        encrypted_bk3.is_ok(),
        "encrypt_bk3 failed: {encrypted_bk3:?}"
    );
    helper_secure_init_bk3(dev, encrypted_bk3.unwrap(), pub_key2)
}

/// Validate whether the device already has a sealed BK3.
///
/// Secure provisioning is one-shot and persistent, so a present sealed BK3 means
/// the partition is already provisioned and callers can skip (re)provisioning.
/// `helper_get_sealed_bk3` returns `Ok` only when a sealed BK3 is present;
/// otherwise it errors (`Bk3NotSecurelyProvisioned` / `SealedBk3NotPresent`).
fn is_bk3_sealed(dev: &<DdiTest as Ddi>::Dev) -> bool {
    helper_get_sealed_bk3(dev).is_ok()
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
        // If the sealed BK3 is already set, there is nothing to do.
        if is_bk3_sealed(dev) {
            return;
        }

        let mut bk3 = [0u8; 48];
        Rng::rand_bytes(&mut bk3).expect("rand_bytes failed");

        // Not provisioned yet: securely provision, then seal the masked BK3 (MOBK).
        let result = secure_provision_bk3(dev, TEST_CRED_ID, TEST_CRED_PIN, &bk3);
        assert!(result.is_ok(), "result {:?}", result);
        let masked_bk3 = result.unwrap().data.masked_bk3;

        let result = helper_set_sealed_bk3(dev, masked_bk3.as_slice().to_vec());
        assert!(result.is_ok(), "result {:?}", result);
    });
}
