// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! EstablishCredential smoke tests for the emu backend.
//!
//! Exercises the EstablishCredential firmware command from the host
//! side end-to-end:
//!
//! - Happy path: ECDH + HKDF + HMAC verify + AES-CBC decrypt succeed,
//!   the user credential is persisted, BK3 is unmasked, the partition
//!   masking key is generated, and the response includes a non-empty
//!   `bmk` blob (the freshly generated masking key wrapped under the
//!   partition BK).
//! - Null user ID is rejected with `InvalidAppCredentials` after the
//!   crypto succeeds (matches the reference firmware's credential
//!   manager invariant).
//! - Null user PIN is symmetrically rejected with
//!   `InvalidAppCredentials`.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

pub fn setup(dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str) -> u16 {
    common_cleanup(dev, ddi, path, None);

    // EstablishCredential is a no-session command; the harness ignores
    // the returned id so any sentinel value is fine.
    0
}

fn helper_smoke_establish_credential(
    dev: &<DdiTest as Ddi>::Dev,
    encrypted_credential: DdiEncryptedEstablishCredential,
    pub_key: DdiDerPublicKey,
) -> Result<DdiEstablishCredentialCmdResp, DdiError> {
    let masked_bk3 = helper_get_or_init_bk3(dev);
    let (signature, pota_pub_key) = helper_get_pota_endorsement(dev);

    helper_establish_credential(
        dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        encrypted_credential,
        pub_key,
        masked_bk3,
        MborByteArray::from_slice(&[]).expect("Failed to create empty BMK"),
        MborByteArray::from_slice(&[]).expect("Failed to create empty masked unwrapping key"),
        MborByteArray::from_slice(&signature).expect("Failed to create signed PID"),
        DdiDerPublicKey {
            der: MborByteArray::from_slice(&pota_pub_key)
                .expect("Failed to create MborByteArray from POTA ECC public key"),
            key_kind: DdiKeyType::Ecc384Public,
        },
    )
}

#[test]
fn test_establish_credential_smoke() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _| {
        let (encrypted_credential, pub_key) =
            encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);

        let resp = helper_smoke_establish_credential(dev, encrypted_credential, pub_key).unwrap();

        assert!(resp.hdr.sess_id.is_none());
        assert_eq!(resp.hdr.op, DdiOp::EstablishCredential);
        assert_eq!(resp.hdr.status, DdiStatus::Success);

        // Step 13 of the firmware handler always emits a freshly
        // generated masking key wrapped under BK; the blob must be
        // non-empty so the host can persist it as the partition BMK
        // for later re-imports.
        assert!(
            !resp.data.bmk.is_empty(),
            "EstablishCredential response should carry a non-empty BMK"
        );
    });
}

#[test]
fn test_establish_credential_null_id_smoke() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _| {
        let (encrypted_credential, pub_key) =
            encrypt_userid_pin_for_establish_cred(dev, [0; 16], TEST_CRED_PIN);

        let err = helper_smoke_establish_credential(dev, encrypted_credential, pub_key)
            .expect_err("null user ID must be rejected");

        assert!(
            matches!(err, DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)),
            "expected InvalidAppCredentials, got {:?}",
            err
        );
    });
}

#[test]
fn test_establish_credential_null_pin_smoke() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _| {
        let (encrypted_credential, pub_key) =
            encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, [0; 16]);

        let err = helper_smoke_establish_credential(dev, encrypted_credential, pub_key)
            .expect_err("null user PIN must be rejected");

        assert!(
            matches!(err, DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)),
            "expected InvalidAppCredentials, got {:?}",
            err
        );
    });
}
