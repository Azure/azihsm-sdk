// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HKDF derivation smoke tests.
//!
//! - **AES output** (both backends): generate two ECC key pairs,
//!   ECDH them into a shared secret, derive an `Aes256` key from each
//!   secret, then encrypt with one and decrypt with the other and
//!   confirm the message round-trips — proving the derived AES key is
//!   usable and the derivation is deterministic.
//! - **Variable-length HMAC output** (emu only — the sim does not
//!   support the var-len HMAC output kind): derive `VarHmac256` /
//!   `VarHmac384` / `VarHmac512` keys and confirm the handler accepts
//!   in-range lengths and rejects a missing / out-of-range
//!   `key_length`.
//!
//! The masked-key contents and a follow-up `Hmac` MAC over a derived
//! HMAC key are out of scope here — masking and the `Hmac` handler
//! are implemented separately.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_hkdf_aes_derive_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (secret1, secret2) = create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);
            let rev = Some(DdiApiRev { major: 1, minor: 0 });
            let salt = Some(MborByteArray::from_slice("salt".as_bytes()).unwrap());
            let info = Some(MborByteArray::from_slice("info".as_bytes()).unwrap());
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            // Derive the same AES-256 key from each (equal) shared secret.
            let derive = |dev: &mut <DdiTest as Ddi>::Dev, secret_id| {
                helper_hkdf_derive(
                    dev,
                    Some(session_id),
                    rev,
                    secret_id,
                    DdiHashAlgorithm::Sha256,
                    salt,
                    info,
                    DdiKeyType::Aes256,
                    None,
                    key_props,
                    None,
                )
                .expect("HKDF AES-256 derive should succeed")
                .data
                .key_id
            };
            let key1 = derive(dev, secret1);
            let key2 = derive(dev, secret2);

            // Encrypt with key1, decrypt with key2 — recovers the input
            // iff both derivations produced the same usable AES key.
            let plaintext = [0xABu8; 32];
            let iv = MborByteArray::from_slice(&[0u8; 16]).unwrap();
            let enc = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                rev,
                key1,
                DdiAesOp::Encrypt,
                MborByteArray::from_slice(&plaintext).unwrap(),
                iv,
            )
            .expect("encrypt with derived AES key");
            let dec = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                rev,
                key2,
                DdiAesOp::Decrypt,
                enc.data.msg,
                iv,
            )
            .expect("decrypt with derived AES key");
            assert_eq!(
                dec.data.msg.as_slice(),
                plaintext,
                "HKDF-derived AES key must round-trip encrypt/decrypt"
            );
        },
    );
}

/// Run an ECDH → HKDF derivation into a sign/verify HMAC-family key
/// (`HmacSha*` or `VarHmac*`) and return the result.
fn hkdf_hmac_derive(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    key_type: DdiKeyType,
    key_length: Option<u8>,
) -> Result<DdiHkdfDeriveCmdResp, DdiError> {
    let (secret_key_id, _) = create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);
    let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::Session);
    helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id,
        DdiHashAlgorithm::Sha256,
        Some(MborByteArray::from_slice("salt".as_bytes()).unwrap()),
        Some(MborByteArray::from_slice("info".as_bytes()).unwrap()),
        key_type,
        None,
        key_props,
        key_length,
    )
}

#[test]
fn test_hkdf_hmac_derive_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Fixed-length HMAC output types are supported by both
            // backends.  A follow-up `Hmac` MAC over the key needs the
            // `Hmac` handler (not yet implemented), so assert only that
            // the derive succeeds.
            for key_type in [
                DdiKeyType::HmacSha256,
                DdiKeyType::HmacSha384,
                DdiKeyType::HmacSha512,
            ] {
                let resp = hkdf_hmac_derive(dev, session_id, key_type, None);
                assert!(resp.is_ok(), "HKDF {key_type:?} should derive: {resp:?}");
                let resp = resp.unwrap();
                assert_eq!(resp.hdr.op, DdiOp::HkdfDerive);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
            }
        },
    );
}

#[cfg(not(feature = "mock"))]
#[test]
fn test_hkdf_var_hmac_derive_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // (key_type, in-range key_length) for each var-HMAC variant.
            let cases = [
                (DdiKeyType::VarHmac256, 32u8),
                (DdiKeyType::VarHmac256, 64),
                (DdiKeyType::VarHmac384, 48),
                (DdiKeyType::VarHmac384, 128),
                (DdiKeyType::VarHmac512, 64),
                (DdiKeyType::VarHmac512, 128),
            ];
            for (key_type, key_len) in cases {
                let resp = hkdf_hmac_derive(dev, session_id, key_type, Some(key_len));
                assert!(
                    resp.is_ok(),
                    "HKDF {key_type:?} len {key_len} should derive: {resp:?}"
                );
                let resp = resp.unwrap();
                assert_eq!(resp.hdr.op, DdiOp::HkdfDerive);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
            }
        },
    );
}

#[cfg(not(feature = "mock"))]
#[test]
fn test_hkdf_var_hmac_missing_length_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // A var-len HMAC output requires an explicit key_length.
            let err = hkdf_hmac_derive(dev, session_id, DdiKeyType::VarHmac256, None)
                .expect_err("missing key_length must be rejected");
            assert!(
                matches!(err, DdiError::DdiStatus(DdiStatus::InvalidKeyType)),
                "expected InvalidKeyType, got {err:?}"
            );
        },
    );
}

#[cfg(not(feature = "mock"))]
#[test]
fn test_hkdf_var_hmac_out_of_range_length_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // 16 is below VarHmac256's 32-byte minimum.
            let err = hkdf_hmac_derive(dev, session_id, DdiKeyType::VarHmac256, Some(16))
                .expect_err("out-of-range key_length must be rejected");
            assert!(
                matches!(err, DdiError::DdiStatus(DdiStatus::InvalidKeyLength)),
                "expected InvalidKeyLength, got {err:?}"
            );
        },
    );
}
