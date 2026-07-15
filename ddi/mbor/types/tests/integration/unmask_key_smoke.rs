// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `UnmaskKey` round-trip smoke tests.
//!
//! Run on every backend, including the firmware emulator, so CI's emu
//! smoke run exercises the full mask → unmask path end to end for three
//! representative shapes:
//!
//! * a **symmetric, partition-scoped** AES key — generate, encrypt,
//!   re-import via `UnmaskKey`, then re-import *again* from the fresh
//!   envelope `UnmaskKey` itself returns, and confirm decrypting with the
//!   twice-round-tripped key recovers the original plaintext;
//! * an **asymmetric, session-scoped** ECC key — generate a session-only
//!   P-256 pair, re-import via `UnmaskKey` and again from the envelope it
//!   returns, and confirm the re-imported public key matches the original
//!   and verifies a signature made with the re-imported private key
//!   (exercising the public-key re-derivation path, the session-scoped
//!   masking-key selection, and the re-mask of the returned envelope);
//! * a **large asymmetric, partition-scoped** RSA-4096 CRT key — import via
//!   `RsaUnwrap`, then 10× delete and re-import it from the fresh envelope
//!   each `UnmaskKey` returns, confirming a raw `RsaModExp` output and the
//!   re-derived public key stay bit-identical every round and the metadata
//!   is preserved (exercising the DMA-tight in-place re-mask of the largest
//!   key type).
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

            // Re-import twice: first from the generate envelope, then from
            // the *re-masked* envelope UnmaskKey itself returns, deleting the
            // prior key each time.  Decrypting with the twice-round-tripped
            // key proves the returned envelope carries the exact key material.
            assert!(
                helper_delete_key(dev, Some(session_id), rev, key_id).is_ok(),
                "delete original key",
            );
            let resp = helper_unmask_key(dev, Some(session_id), rev, masked_key)
                .expect("unmask (generate envelope) should succeed");
            assert_eq!(resp.data.kind, DdiKeyType::Aes256);
            let key_id_2 = resp.data.key_id;
            let masked_key_2 = resp.data.masked_key;

            assert!(
                helper_delete_key(dev, Some(session_id), rev, key_id_2).is_ok(),
                "delete first re-imported key",
            );
            let resp = helper_unmask_key(dev, Some(session_id), rev, masked_key_2)
                .expect("unmask (re-masked envelope) should succeed");
            assert_eq!(resp.data.kind, DdiKeyType::Aes256);
            let new_key_id = resp.data.key_id;

            // Decrypt with the twice-round-tripped key: recovering the
            // original plaintext proves the exact key material round-tripped.
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

            // Re-import twice: first from the generate envelope, then from
            // the *re-masked* envelope UnmaskKey returns, deleting the prior
            // (session-scoped) key each time.  The re-imported public key must
            // match the original throughout, proving the private key
            // round-trips through the session-scoped re-mask and its public
            // key re-derives.
            assert!(
                helper_delete_key(dev, Some(session_id), rev, private_key_id).is_ok(),
                "delete original key",
            );
            let resp = helper_unmask_key(dev, Some(session_id), rev, masked_key)
                .expect("unmask (generate envelope) should succeed");
            let key_id_2 = resp.data.key_id;
            let masked_key_2 = resp.data.masked_key;
            let pub_2 = resp
                .data
                .pub_key
                .expect("asymmetric unmask must return a public key");
            assert_eq!(
                pub_2.der.as_slice(),
                pub_key.der.as_slice(),
                "re-imported pub_key must match the original",
            );

            assert!(
                helper_delete_key(dev, Some(session_id), rev, key_id_2).is_ok(),
                "delete first re-imported key",
            );
            let resp = helper_unmask_key(dev, Some(session_id), rev, masked_key_2)
                .expect("unmask (re-masked envelope) should succeed");
            let new_key_id = resp.data.key_id;
            let new_pub_key = resp
                .data
                .pub_key
                .expect("asymmetric unmask must return a public key");
            assert_eq!(
                new_pub_key.key_kind, pub_key.key_kind,
                "re-imported pub_key kind must match",
            );
            assert_eq!(
                new_pub_key.der.as_slice(),
                pub_key.der.as_slice(),
                "re-imported pub_key must match the original after re-mask",
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

/// Round-trip for the **largest asymmetric, partition-scoped** key across
/// *repeated* re-masks: import an RSA-4096 CRT private key via `RsaUnwrap`,
/// then 10× delete it and re-import it via `UnmaskKey`, each round feeding
/// back the fresh envelope the previous `UnmaskKey` returned.  Because the
/// same fixed input is fed to every raw `RsaModExp`, the exponentiation
/// output — and the re-derived public key — must be bit-identical on every
/// round iff the private key survives unchanged, and the masked-key metadata
/// (type, attributes, label, length) must be preserved through every mask /
/// re-mask cycle.  Guards the DMA-tight in-place re-mask of the largest key.
#[test]
fn test_unmask_rsa_4k_crt_reunmask_roundtrip_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let rev = Some(DdiApiRev { major: 1, minor: 0 });
            // Non-empty label to prove label preservation across re-masks.
            let label_bytes: &[u8] = b"rsa4k-crt-role";

            // --- Import an RSA-4096 CRT private key via RsaUnwrap. ---
            let (unwrap_key_id, unwrap_pub_key_der, _) = get_unwrapping_key(dev, session_id);
            let wrapped = wrap_data(unwrap_pub_key_der, TEST_RSA_4K_PRIVATE_KEY.as_slice());
            let mut der = [0u8; 3072];
            der[..wrapped.len()].copy_from_slice(&wrapped);
            let der_len = wrapped.len();

            let resp = helper_rsa_unwrap(
                dev,
                Some(session_id),
                rev,
                unwrap_key_id,
                MborByteArray::new(der, der_len).expect("failed to create byte array"),
                DdiKeyClass::RsaCrt,
                DdiRsaCryptoPadding::Oaep,
                DdiHashAlgorithm::Sha256,
                None,
                helper_key_properties_with_label(
                    DdiKeyUsage::EncryptDecrypt,
                    DdiKeyAvailability::App,
                    MborByteArray::from_slice(label_bytes).expect("failed to create label"),
                ),
            )
            .expect("rsa_unwrap");
            assert_eq!(resp.data.kind, DdiKeyType::Rsa4kPrivateCrt);
            // Baseline captured from the unwrap: key id, envelope, public key,
            // metadata, and the raw mod-exp output.  Every subsequent unmask of
            // the (re-masked) envelope must reproduce these exactly.
            let mut current_key = resp.data.key_id;
            let mut current_env = resp.data.masked_key;
            let base_pub = resp.data.pub_key.expect("unwrap must return a public key");
            let base_pub_kind = base_pub.key_kind;
            let base_pub_der = base_pub.der.as_slice().to_vec();
            let base_meta =
                extract_metadata_from_masked_key(current_env.as_slice()).expect("M1 metadata");
            let base_key_type = base_meta.key_type;
            let base_attrs = base_meta.key_attributes.clone();
            let base_label = base_meta.key_label.as_slice().to_vec();
            let base_key_len = base_meta.key_length;

            // Fixed mod-exp input reused for every key so the raw private-key
            // exponentiation output must match iff the key material is preserved.
            let orig_x = [0x1u8; 512];
            let data_len = 190;
            let y_vec = rsa_encrypt_local_openssl(
                &TEST_RSA_4K_PUBLIC_KEY,
                &orig_x,
                data_len,
                DdiRsaCryptoPadding::Oaep,
                Some(DdiHashAlgorithm::Sha256),
            );
            let mut y = [0u8; 512];
            y[..y_vec.len()].copy_from_slice(y_vec.as_slice());
            let y_arr = MborByteArray::new(y, y_vec.len()).expect("failed to create byte array");

            let mod_exp_raw = |key_id: u16| -> MborByteArray<512> {
                helper_rsa_mod_exp(
                    dev,
                    Some(session_id),
                    rev,
                    key_id,
                    y_arr,
                    DdiRsaOpType::Decrypt,
                )
                .expect("rsa mod-exp")
                .data
                .x
            };
            let base_x = mod_exp_raw(current_key);

            // Sanity: the raw output OAEP-decodes back to the original data.
            let mut padded = [0u8; 512];
            let x_len = base_x.len();
            padded[..x_len].copy_from_slice(&base_x.data()[..x_len]);
            let decoded = RsaEncoding::decode_oaep(
                &mut padded[..x_len],
                None,
                4096 / 8,
                RsaDigestKind::Sha256,
                crypto_sha256,
            )
            .expect("oaep decode");
            assert_eq!(orig_x[..data_len], decoded[..]);

            // The firmware embeds the caller's label into the envelope; the sim
            // (mock) backend does not model labels, so assert the exact value on
            // every backend except the sim.
            #[cfg(not(feature = "mock"))]
            assert_eq!(
                base_meta.key_label.as_slice(),
                label_bytes,
                "label not carried into the unwrap envelope"
            );

            // Re-import the key from its own envelope 10 times, each round
            // feeding back the fresh envelope the previous UnmaskKey returned.
            // The firmware re-masks on every call (fresh IV) so the envelope
            // differs byte-wise each round, yet the recovered key never changes
            // — proven by identical raw mod-exp and public key — and the
            // metadata (type, attributes, label, length) is preserved.
            for round in 0..10 {
                assert!(
                    helper_delete_key(dev, Some(session_id), rev, current_key).is_ok(),
                    "delete key (round {round})"
                );
                let resp = helper_unmask_key(dev, Some(session_id), rev, current_env);
                assert!(resp.is_ok(), "unmask (round {round}): {resp:?}");
                let resp = resp.unwrap();
                assert_eq!(
                    resp.data.kind,
                    DdiKeyType::Rsa4kPrivateCrt,
                    "kind changed (round {round})"
                );
                let new_key = resp.data.key_id;
                let new_env = resp.data.masked_key;
                let new_pub = resp.data.pub_key.expect("unmask must return a public key");
                let new_meta =
                    extract_metadata_from_masked_key(new_env.as_slice()).expect("metadata");

                // Key material preserved: raw mod-exp + public key are identical.
                assert_eq!(
                    mod_exp_raw(new_key).as_slice(),
                    base_x.as_slice(),
                    "mod-exp changed (round {round})"
                );
                assert_eq!(
                    new_pub.key_kind, base_pub_kind,
                    "pub key kind changed (round {round})"
                );
                assert_eq!(
                    new_pub.der.as_slice(),
                    base_pub_der.as_slice(),
                    "pub key changed (round {round})"
                );

                // Key properties + label preserved through the mask / re-mask.
                assert_eq!(
                    new_meta.key_type, base_key_type,
                    "key_type changed (round {round})"
                );
                assert_eq!(
                    new_meta.key_attributes, base_attrs,
                    "attributes changed (round {round})"
                );
                assert_eq!(
                    new_meta.key_label.as_slice(),
                    base_label.as_slice(),
                    "label changed (round {round})"
                );
                assert_eq!(
                    new_meta.key_length, base_key_len,
                    "key_length changed (round {round})"
                );

                // The firmware re-masks (fresh IV) rather than echoing, so each
                // envelope differs byte-wise from the one it unmasked; the sim
                // (mock) echoes the input, so this holds on every backend but it.
                #[cfg(not(feature = "mock"))]
                assert_ne!(
                    new_env.as_slice(),
                    current_env.as_slice(),
                    "envelope must be a fresh re-mask (round {round})"
                );

                current_key = new_key;
                current_env = new_env;
            }
        },
    );
}
