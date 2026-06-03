// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RsaUnwrap smoke tests for the emu backend.
//!
//! Exercises the RsaUnwrap firmware command end-to-end:
//!
//! - Happy path (AES-256): wrap a fresh AES-256 key under the
//!   partition's unwrap key, send `RsaUnwrap`, and verify the
//!   imported key shows up as `Aes256` with no `pub_key` (symmetric)
//!   and no `bulk_key_id` (non-bulk).  Then cross-check the imported
//!   bytes by encrypting locally with the known key and decrypting
//!   on the device with the imported key id.
//! - Happy path (RSA-2K / RSA-3K / RSA-4K private): wrap a known
//!   non-CRT PKCS#8 DER private key under the partition's unwrap
//!   key, send `RsaUnwrap` with `DdiKeyClass::Rsa`, and verify the
//!   response declares the matching `Rsa*Private` kind.  Bytewise
//!   import correctness is verified by comparing the returned
//!   `pub_key` against the public key derived locally from the known
//!   private DER — no `RsaModExp` round-trip required.
//! - RSA-3K CRT private: CRT import is not yet supported and is
//!   deferred to a follow-up (the crypto crate's CRT HSM layout does
//!   not yet match the canonical vault CRT blob size); not exercised
//!   here.
//! - Happy path (ECC P-256 / P-384 / P-521 private): wrap a known
//!   ECC PKCS#8 DER private key under the partition's unwrap key,
//!   send `RsaUnwrap` with `DdiKeyClass::Ecc`, and verify the
//!   response declares the matching `Ecc*Private` kind and surfaces
//!   the wire-format public key.
//! - Without a session: rejected with
//!   `FileHandleSessionIdDoesNotMatch` (enforced by the emu's
//!   session-validation layer).
//!
//! `masked_key` is emitted as an empty placeholder by the firmware
//! handler until the masking infrastructure lands; we don't assert
//! on its contents here.

#![cfg(test)]

use azihsm_crypto::AesCbcAlgo;
use azihsm_crypto::AesKey;
use azihsm_crypto::EccKeyOp;
use azihsm_crypto::Encrypter;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::PrivateKey;
use azihsm_crypto::RsaKeyOp;
use azihsm_crypto::RsaPrivateKey;
use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_rsa_unwrap_aes_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Pull the partition's unwrap pub key directly via the
            // low-level helper — the shared `get_unwrapping_key`
            // wrapper asserts `!masked_key.is_empty()` which our
            // handler does not yet satisfy (empty placeholder until
            // masking lands).
            let unwrap_resp = helper_get_unwrapping_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            )
            .expect("get_unwrapping_key");
            let unwrap_key_id = unwrap_resp.data.key_id;
            let unwrap_pub_key_der = unwrap_resp.data.pub_key.der.as_slice().to_vec();

            // Wrap a fresh AES-256 key with the partition's unwrap key.
            let wrapped = wrap_data(unwrap_pub_key_der, TEST_AES_256.as_slice());

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::from_slice(&wrapped).expect("wrapped blob fits in 3072"),
                DdiKeyClass::Aes,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                key_props,
            )
            .expect("rsa_unwrap AES-256 should succeed");

            assert_eq!(resp.hdr.op, DdiOp::RsaUnwrap);
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            assert_eq!(resp.hdr.sess_id, Some(session_id));
            assert_eq!(resp.data.kind, DdiKeyType::Aes256);
            assert!(
                resp.data.pub_key.is_none(),
                "symmetric AES import must not return a pub_key"
            );
            assert!(
                resp.data.bulk_key_id.is_none(),
                "non-bulk AES import must not return a bulk_key_id"
            );

            // End-to-end check: encrypt locally with the KNOWN AES
            // key bytes the host wrapped, decrypt on the device with
            // the imported key id, and verify we recover the
            // plaintext.  A device-only encrypt+decrypt round-trip
            // would silently pass if the device imported the wrong
            // bytes (both halves would use the same wrong key) — the
            // local-vs-device cross-check actually proves the
            // imported key bytes match the wrapped bytes.
            let imported_key_id = resp.data.key_id;
            // Use distinct, non-palindromic byte patterns so any
            // byte-reversal / endianness flip in the device path
            // produces a visibly different decryption (vs a constant
            // pattern like [0xa5; 16] which would silently pass a
            // reversed-plaintext bug).
            let plaintext: [u8; 16] = [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ];
            let iv: [u8; 16] = [
                0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef,
            ];

            let aes_key = AesKey::from_bytes(TEST_AES_256.as_slice())
                .expect("import known AES-256 key locally");
            let ciphertext_local =
                Encrypter::encrypt_vec(&mut AesCbcAlgo::with_no_padding(&iv), &aes_key, &plaintext)
                    .expect("local AES-CBC encrypt");
            assert_eq!(ciphertext_local.len(), 16);

            let dec_resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                imported_key_id,
                DdiAesOp::Decrypt,
                MborByteArray::from_slice(&ciphertext_local).unwrap(),
                MborByteArray::from_slice(&iv).unwrap(),
            )
            .expect("device decrypt with imported AES key");
            assert_eq!(dec_resp.hdr.status, DdiStatus::Success);
            assert_eq!(
                dec_resp.data.msg.as_slice(),
                plaintext,
                "device-decrypted plaintext must match the local input — \
                 if this fails, the imported key bytes don't match the wrapped bytes"
            );
        },
    );
}

fn rsa_import_smoke(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    priv_der: &[u8],
    key_class: DdiKeyClass,
    expected_kind: DdiKeyType,
) {
    let unwrap_resp = helper_get_unwrapping_key(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
    )
    .expect("get_unwrapping_key");
    let unwrap_key_id = unwrap_resp.data.key_id;
    let unwrap_pub_key_der = unwrap_resp.data.pub_key.der.as_slice().to_vec();

    // Wrap the known RSA DER private key under the partition's unwrap
    // key.  The host-side `wrap_data` constructs
    // `OAEP(ephemeral_AES) || AES-KWP(payload)` exactly as
    // `DdiRsaUnwrapReq.wrapped_blob` expects.
    let wrapped = wrap_data(unwrap_pub_key_der, priv_der);

    let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

    let resp = helper_rsa_unwrap(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        unwrap_key_id,
        MborByteArray::from_slice(&wrapped).expect("wrapped blob fits in 3072"),
        key_class,
        DdiRsaCryptoPadding::Oaep,
        DdiHashAlgorithm::Sha256,
        None,
        key_props,
    )
    .expect("rsa_unwrap RSA should succeed");

    assert_eq!(resp.hdr.op, DdiOp::RsaUnwrap);
    assert_eq!(resp.hdr.status, DdiStatus::Success);
    assert_eq!(resp.hdr.sess_id, Some(session_id));
    assert_eq!(
        resp.data.kind, expected_kind,
        "expected the requested RSA kind, got {:?}",
        resp.data.kind
    );

    // Verify the imported key bytewise by comparing the returned
    // `pub_key` against the public key derived locally from the
    // KNOWN private DER we wrapped.  If the device imported even
    // one wrong byte of n/e, this comparison fails — without
    // needing an `RsaModExp` round-trip.
    let returned_pub = resp
        .data
        .pub_key
        .as_ref()
        .expect("RSA import must return pub_key");
    let local_priv = RsaPrivateKey::from_bytes(priv_der).expect("parse known RSA priv DER locally");
    let local_pub = local_priv.public_key().expect("derive pub from local priv");
    let expected_n = local_pub.n_vec().expect("local n");
    let expected_e = local_pub.e_vec().expect("local e");

    // The returned pub_key.der is the post-decoded SPKI DER form
    // (post_decode = true under the Physical emu device kind), so
    // parse it back to compare n/e directly.
    let returned_rsa = azihsm_crypto::RsaPublicKey::from_bytes(returned_pub.der.as_slice())
        .expect("parse returned pub SPKI DER");
    let returned_n = returned_rsa.n_vec().expect("returned n");
    let returned_e = returned_rsa.e_vec().expect("returned e");
    assert_eq!(
        returned_n, expected_n,
        "returned pub_key modulus must match the wrapped private key's modulus"
    );
    assert_eq!(
        returned_e, expected_e,
        "returned pub_key exponent must match the wrapped private key's exponent"
    );
}

#[test]
fn test_rsa_unwrap_rsa_2k_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            rsa_import_smoke(
                dev,
                session_id,
                TEST_RSA_2K_PRIVATE_KEY.as_slice(),
                DdiKeyClass::Rsa,
                DdiKeyType::Rsa2kPrivate,
            );
        },
    );
}

#[test]
fn test_rsa_unwrap_rsa_3k_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            rsa_import_smoke(
                dev,
                session_id,
                TEST_RSA_3K_PRIVATE_KEY.as_slice(),
                DdiKeyClass::Rsa,
                DdiKeyType::Rsa3kPrivate,
            );
        },
    );
}

#[test]
fn test_rsa_unwrap_rsa_4k_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            rsa_import_smoke(
                dev,
                session_id,
                TEST_RSA_4K_PRIVATE_KEY.as_slice(),
                DdiKeyClass::Rsa,
                DdiKeyType::Rsa4kPrivate,
            );
        },
    );
}

fn ecc_import_smoke(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    priv_der: &[u8],
    expected_kind: DdiKeyType,
    expected_pub_kind: DdiKeyType,
) {
    let unwrap_resp = helper_get_unwrapping_key(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
    )
    .expect("get_unwrapping_key");
    let unwrap_key_id = unwrap_resp.data.key_id;
    let unwrap_pub_key_der = unwrap_resp.data.pub_key.der.as_slice().to_vec();

    // ECC keys are imported in PKCS#8 DER on the wire (same as RSA);
    // the firmware re-encodes to its raw HSM scalar vault form
    // internally.  Wrap the known DER test vector directly.
    let wrapped = wrap_data(unwrap_pub_key_der, priv_der);

    let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);

    let resp = helper_rsa_unwrap(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        unwrap_key_id,
        MborByteArray::from_slice(&wrapped).expect("wrapped blob fits in 3072"),
        DdiKeyClass::Ecc,
        DdiRsaCryptoPadding::Oaep,
        DdiHashAlgorithm::Sha256,
        None,
        key_props,
    )
    .expect("rsa_unwrap ECC should succeed");

    assert_eq!(resp.hdr.op, DdiOp::RsaUnwrap);
    assert_eq!(resp.hdr.status, DdiStatus::Success);
    assert_eq!(resp.hdr.sess_id, Some(session_id));
    assert_eq!(
        resp.data.kind, expected_kind,
        "expected the requested ECC kind, got {:?}",
        resp.data.kind
    );

    // Cross-check the returned public key against the public key
    // derived locally from the known private DER we wrapped.  The
    // returned `pub_key.der` is in the host-side post-decoded SPKI
    // DER form (Physical emu device kind), so parse it back and
    // compare the uncompressed `0x04 || x || y` representation.
    let returned_pub = resp
        .data
        .pub_key
        .as_ref()
        .expect("ECC import must return pub_key");
    assert_eq!(
        returned_pub.key_kind, expected_pub_kind,
        "expected the matching ECC public key kind, got {:?}",
        returned_pub.key_kind
    );

    let local_priv = azihsm_crypto::EccPrivateKey::from_bytes(priv_der)
        .expect("parse known ECC priv DER locally");
    let local_pub = local_priv.public_key().expect("derive pub from local priv");
    let returned_ecc = azihsm_crypto::EccPublicKey::from_bytes(returned_pub.der.as_slice())
        .expect("parse returned pub SPKI DER");

    let coord_len: usize = local_pub.curve().into();
    let mut local_x = vec![0u8; coord_len];
    let mut local_y = vec![0u8; coord_len];
    let mut returned_x = vec![0u8; coord_len];
    let mut returned_y = vec![0u8; coord_len];
    local_pub
        .coord(Some((local_x.as_mut_slice(), local_y.as_mut_slice())))
        .expect("local coord");
    returned_ecc
        .coord(Some((returned_x.as_mut_slice(), returned_y.as_mut_slice())))
        .expect("returned coord");
    assert_eq!(
        returned_x, local_x,
        "returned pub_key X coord must match the wrapped private key"
    );
    assert_eq!(
        returned_y, local_y,
        "returned pub_key Y coord must match the wrapped private key"
    );

    // Round-trip: sign a digest with the imported key and verify it
    // against the returned public key.  The pub-key cross-check above
    // only proves the import DER was parsed correctly; this exercises
    // the stored HSM scalar via `from_hsm_bytes`, catching a bad
    // DER → HSM-scalar conversion (`ecc_priv_to_hsm`) or storage.
    let imported_key_id = resp.data.key_id;
    let digest = [0xC7u8; 32];
    let sign_resp = helper_ecc_sign(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        imported_key_id,
        MborByteArray::from_slice(&digest).unwrap(),
        DdiHashAlgorithm::Sha256,
    )
    .expect("EccSign with the imported key must succeed");
    let sig_len = sign_resp.data.signature.len();
    let mut digest_padded = [0u8; 96];
    digest_padded[..digest.len()].copy_from_slice(&digest);
    assert!(
        ecc_verify_local_openssl(
            &sign_resp.data.signature.data()[..sig_len],
            returned_pub,
            digest_padded,
            digest.len(),
        ),
        "signature from the imported key must verify — proves the \
         stored HSM scalar matches the wrapped private key"
    );
}

#[test]
fn test_rsa_unwrap_ecc_256_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            ecc_import_smoke(
                dev,
                session_id,
                TEST_ECC_256_PRIVATE_KEY.as_slice(),
                DdiKeyType::Ecc256Private,
                DdiKeyType::Ecc256Public,
            );
        },
    );
}

#[test]
fn test_rsa_unwrap_ecc_384_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            ecc_import_smoke(
                dev,
                session_id,
                TEST_ECC_384_PRIVATE_KEY.as_slice(),
                DdiKeyType::Ecc384Private,
                DdiKeyType::Ecc384Public,
            );
        },
    );
}

#[test]
fn test_rsa_unwrap_ecc_521_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            ecc_import_smoke(
                dev,
                session_id,
                TEST_ECC_521_PRIVATE_KEY.as_slice(),
                DdiKeyType::Ecc521Private,
                DdiKeyType::Ecc521Public,
            );
        },
    );
}

#[test]
fn test_rsa_unwrap_no_session_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let unwrap_resp = helper_get_unwrapping_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            )
            .expect("get_unwrapping_key");
            let unwrap_key_id = unwrap_resp.data.key_id;
            let unwrap_pub_key_der = unwrap_resp.data.pub_key.der.as_slice().to_vec();

            let wrapped = wrap_data(unwrap_pub_key_der, TEST_AES_256.as_slice());

            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let err = helper_rsa_unwrap(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrap_key_id,
                MborByteArray::from_slice(&wrapped).expect("wrapped blob fits in 3072"),
                DdiKeyClass::Aes,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                key_props,
            )
            .expect_err("must be rejected without a session");

            assert!(
                matches!(
                    err,
                    DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
                ),
                "expected FileHandleSessionIdDoesNotMatch, got {:?}",
                err
            );
        },
    );
}
