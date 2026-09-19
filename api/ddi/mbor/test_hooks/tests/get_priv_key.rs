// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the `GetPrivKey` FIPS-validation hook
//! (`DdiOp` 2005).
//!
//! These generate a key on the device and read its private material back
//! with `GetPrivKey`. They only run on a physical device whose firmware
//! is built with `fips_validation_hooks`; otherwise they skip.
//!
//! Requires the `helpers` feature for the host send helpers.

#![cfg(feature = "helpers")]
#![allow(clippy::unwrap_used)]

mod common;
#[path = "helper/get_priv_key.rs"]
mod helper;

use azihsm_crypto::EccCurve;
use azihsm_crypto::HashAlgo;
use azihsm_ddi::Ddi;
use azihsm_ddi::DdiError;
use azihsm_ddi_mbor_test_hooks::helper_get_priv_key;
use azihsm_ddi_mbor_types::DdiAesKeySize;
use azihsm_ddi_mbor_types::DdiApiRev;
use azihsm_ddi_mbor_types::DdiDeviceKind;
use azihsm_ddi_mbor_types::DdiKeyType;
use azihsm_ddi_mbor_types::DdiStatus;
use common::*;
use helper::*;
use test_with_tracing::test;

#[test]
fn test_aes_get_and_validate_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                return;
            }

            let key_id = create_aes_key(dev, session_id);
            let Some((key_type, raw_key)) = retrieve_private_key(dev, session_id, key_id) else {
                return;
            };
            assert_eq!(key_type, DdiKeyType::Aes128);
            assert_eq!(raw_key.len(), 16);

            let plaintext = [0x5a; 32];
            let ciphertext = aes_encrypt_hardware(dev, session_id, key_id, &plaintext);
            assert_eq!(aes_decrypt_local(&raw_key, &ciphertext), plaintext);
        },
    );
}

#[test]
fn test_aes_bulk_get_privkey_rejected() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                return;
            }

            let resp =
                generate_aes_bulk_256_key(dev, session_id, DdiAesKeySize::AesGcmBulk256Unapproved)
                    .unwrap();
            let get_resp = helper_get_priv_key(dev, Some(session_id), resp.data.key_id);

            assert!(matches!(
                get_resp,
                Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType))
            ));
        },
    );
}

#[test]
fn test_secret_get_and_validate_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                return;
            }

            let (secret_key_id1, secret_key_id2) =
                create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);
            let Some((key_type1, secret1)) = retrieve_private_key(dev, session_id, secret_key_id1)
            else {
                return;
            };
            let (key_type2, secret2) =
                retrieve_private_key(dev, session_id, secret_key_id2).unwrap();

            assert_eq!(key_type1, DdiKeyType::Secret256);
            assert_eq!(key_type2, DdiKeyType::Secret256);
            assert_eq!(secret1, secret2);
        },
    );
}

#[test]
fn test_ecc_get_privkey() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                return;
            }

            let (private_key_id, public_key) = generate_ecc_key(dev, session_id);
            let Some((key_type, mut private_key)) =
                retrieve_private_key(dev, session_id, private_key_id)
            else {
                return;
            };
            assert_eq!(key_type, DdiKeyType::Ecc256Private);
            assert_eq!(private_key.len(), 32);

            private_key.reverse();
            let signature = ecc_sign_local(private_key, EccCurve::P256, &DIGEST);
            assert!(ecc_verify_local(&signature, &public_key, &DIGEST));
        },
    );
}

#[test]
fn test_ecc_get_privkey_key_not_found() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                return;
            }

            let probe_key = generate_ecc_key(dev, session_id).0;
            if let Err(err) = helper_get_priv_key(dev, Some(session_id), probe_key) {
                if is_unsupported_cmd(&err) {
                    return;
                }
                panic!("Unexpected GetPrivKey probe error: {err:?}");
            }

            let resp = helper_get_priv_key(dev, Some(session_id), 9999);
            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::KeyNotFound))
            ));
        },
    );
}

#[test]
fn test_ecc_get_privkey_deleted_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                return;
            }

            let private_key_id = generate_ecc_key(dev, session_id).0;
            let probe = helper_get_priv_key(dev, Some(session_id), private_key_id);
            if let Err(err) = &probe {
                if is_unsupported_cmd(err) {
                    return;
                }
            }
            probe.unwrap();

            helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                private_key_id,
            )
            .unwrap();
            let resp = helper_get_priv_key(dev, Some(session_id), private_key_id);
            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::KeyNotFound))
            ));
        },
    );
}

#[test]
fn test_ecc_get_privkey_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let private_key_id = generate_ecc_key(dev, session_id).0;
            let probe = helper_get_priv_key(dev, Some(session_id), private_key_id);
            if let Err(err) = &probe {
                if is_unsupported_cmd(err) {
                    return;
                }
            }
            probe.unwrap();

            let resp = helper_get_priv_key(dev, None, private_key_id);

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(
                matches!(
                    resp.as_ref().unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
                ),
                "Expected FileHandleSessionIdDoesNotMatch error, got {:?}",
                resp
            );
        },
    );
}

#[test]
fn test_ecc_get_privkey_incorrect_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                return;
            }

            let private_key_id = generate_ecc_key(dev, session_id).0;
            let probe = helper_get_priv_key(dev, Some(session_id), private_key_id);
            if let Err(err) = &probe {
                if is_unsupported_cmd(err) {
                    return;
                }
            }
            probe.unwrap();

            let resp = helper_get_priv_key(dev, Some(20), private_key_id);
            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(
                    DdiStatus::FileHandleSessionIdDoesNotMatch
                ))
            ));
        },
    );
}

#[test]
fn test_get_privkey_rejects_other_live_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                return;
            }

            let key_id = create_hmac_key(session_id, DdiKeyType::VarHmac256, dev, Some(32));

            let other_dev = ddi.open_dev(path).unwrap();
            let (encrypted_credential, public_key) = encrypt_userid_pin_for_open_session(
                &other_dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );
            let open_resp = helper_open_session(
                &other_dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                public_key,
            )
            .unwrap();
            let other_session_id = open_resp.data.sess_id;

            let resp = helper_get_priv_key(&other_dev, Some(other_session_id), key_id);
            close_app_session(&other_dev, other_session_id);

            assert!(matches!(
                resp,
                Err(DdiError::DdiStatus(DdiStatus::KeyNotFound))
            ));
        },
    );
}

#[test]
fn test_var_hmac_sha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                return;
            }

            validate_variable_hmac_key(
                dev,
                session_id,
                DdiKeyType::VarHmac256,
                32,
                33,
                HashAlgo::sha256(),
            );
        },
    );
}

#[test]
fn test_var_hmac_sha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                return;
            }

            validate_variable_hmac_key(
                dev,
                session_id,
                DdiKeyType::VarHmac384,
                48,
                81,
                HashAlgo::sha384(),
            );
        },
    );
}

#[test]
fn test_var_hmac_sha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                return;
            }

            validate_variable_hmac_key(
                dev,
                session_id,
                DdiKeyType::VarHmac512,
                64,
                65,
                HashAlgo::sha512(),
            );
        },
    );
}
