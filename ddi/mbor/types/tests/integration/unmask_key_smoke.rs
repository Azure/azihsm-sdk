// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `UnmaskKey` round-trip smoke tests.
//!
//! Run on every backend, including the firmware emulator, so CI's emu
//! smoke run exercises the full mask → unmask path end to end for two
//! representative shapes:
//!
//! * a **symmetric, partition-scoped** AES key — generate, encrypt,
//!   re-import via `UnmaskKey`, decrypt with the re-imported key, and
//!   confirm the original plaintext is recovered;
//! * an **asymmetric, session-scoped** ECC key — generate a session-only
//!   P-256 pair, re-import via `UnmaskKey`, and confirm the re-imported
//!   public key matches the original and verifies a signature made with
//!   the re-imported private key (exercising the public-key re-derivation
//!   path and the session-scoped masking-key selection).
//!
//! Per-handler masked-key *return* coverage (envelope populated, IV
//! randomized) lives in each key handler's own smoke test:
//! `aes_generate_smoke`, `ecc_generate_smoke`, `hkdf_smoke`,
//! `kbkdf_smoke`, `ecdh_smoke`, `get_unwrapping_key_smoke`, and
//! `rsa_unwrap_smoke`.

#![cfg(test)]

use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

/// Round-trip for a **symmetric, partition-scoped** key: generate an AES
/// (App-availability) key and encrypt a message, re-import the key from
/// its masked envelope via `UnmaskKey`, then decrypt with the re-imported
/// key and confirm the original plaintext is recovered.
#[test]
fn test_unmask_aes_app_key_roundtrip_smoke() {
    const MSG: [u8; 64] = [0x5a; 64];

    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let rev = Some(DdiApiRev { major: 1, minor: 0 });

            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                rev,
                DdiAesKeySize::Aes256,
                Some(1),
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            )
            .expect("aes generate should succeed");

            let key_id = resp.data.key_id;
            let masked_key = resp.data.masked_key;

            // Encrypt with the original key under a fixed IV.
            let iv = MborByteArray::new([0x8; 16], 16).expect("failed to create iv");
            let encrypted = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                rev,
                key_id,
                DdiAesOp::Encrypt,
                MborByteArray::from_slice(&MSG).expect("failed to create byte array"),
                iv,
            )
            .expect("encrypt should succeed");
            let ciphertext = encrypted.data.msg.as_slice().to_vec();
            assert_ne!(
                MSG.as_slice(),
                ciphertext.as_slice(),
                "ciphertext must differ"
            );

            // Delete the original key and re-import it from its masked
            // envelope; the helper asserts the UnmaskKey call succeeds.
            let (new_key_id, _, _) = helper_get_new_key_id_from_unmask(
                dev,
                Some(session_id),
                rev,
                key_id,
                false,
                masked_key,
            )
            .expect("unmask round-trip should succeed");

            // Decrypt with the re-imported key: recovering the original
            // plaintext proves the exact key material round-tripped.
            let decrypted = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                rev,
                new_key_id,
                DdiAesOp::Decrypt,
                MborByteArray::from_slice(ciphertext.as_slice())
                    .expect("failed to create byte array"),
                iv,
            )
            .expect("decrypt should succeed");

            assert_eq!(
                decrypted.data.msg.as_slice(),
                MSG.as_slice(),
                "unmasked key must recover the original plaintext",
            );
        },
    );
}

/// Round-trip for an **asymmetric, session-scoped** key: generate a
/// session-only ECC P-256 key pair in the harness session, re-import it
/// from its masked envelope via `UnmaskKey`, and confirm the re-imported
/// public key matches the original and verifies a signature made with the
/// re-imported private key.  Complements the AES/partition case by
/// exercising the public-key re-derivation path and the session-scoped
/// masking-key selection.
#[test]
fn test_unmask_ecc_session_key_roundtrip_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let rev = Some(DdiApiRev { major: 1, minor: 0 });

            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                rev,
                DdiEccCurve::P256,
                None,
                helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::Session),
            )
            .expect("ecc generate should succeed");
            let private_key_id = resp.data.private_key_id;
            let pub_key = resp.data.pub_key;
            let masked_key = resp.data.masked_key;

            // Delete the original key and re-import it via UnmaskKey; the
            // re-imported public key must match the original, proving the
            // private key round-tripped and its public key re-derived.
            let (new_key_id, _, new_pub_key) = helper_get_new_key_id_from_unmask(
                dev,
                Some(session_id),
                rev,
                private_key_id,
                false,
                masked_key,
            )
            .expect("unmask round-trip should succeed");
            let new_pub_key = new_pub_key.expect("asymmetric unmask must return a public key");
            assert_eq!(
                new_pub_key.key_kind, pub_key.key_kind,
                "re-imported pub_key kind must match",
            );
            assert_eq!(
                new_pub_key.der.as_slice(),
                pub_key.der.as_slice(),
                "re-imported pub_key must match the original",
            );

            // Functionally verify: sign a digest with the re-imported key
            // and check the signature against the recovered public key.
            let digest = [1u8; 96];
            let digest_len = 20;
            let resp = helper_ecc_sign(
                dev,
                Some(session_id),
                rev,
                new_key_id,
                MborByteArray::new(digest, digest_len).expect("failed to create byte array"),
                DdiHashAlgorithm::Sha256,
            )
            .expect("ecc sign should succeed");
            let signature_len = resp.data.signature.len();
            assert!(
                ecc_verify_local_openssl(
                    &resp.data.signature.data()[..signature_len],
                    &new_pub_key,
                    digest,
                    digest_len,
                ),
                "signature from the re-imported key must verify",
            );
        },
    );
}
