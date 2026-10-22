// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Known-answer tests for the platform AES-GCM implementation, run through the
//! `TestAction::AesGcm` test hook.
//!
//! The vectors split the text differently into whole 16-byte blocks and a
//! partial last block, so a wrong keystream for the partial block fails here
//! even when the device's own encrypt and decrypt agree with each other. The
//! tests run only on a physical device whose firmware is built with
//! `azihsm_test_hooks`; otherwise they skip.

#![allow(clippy::unwrap_used)]

mod common;

use azihsm_crypto::AesGcmAlgo;
use azihsm_crypto::AesKey;
use azihsm_crypto::EncryptOp;
use azihsm_crypto::ImportableKey;
use azihsm_ddi::Ddi;
use azihsm_ddi::DdiError;
use azihsm_ddi_mbor_test_hooks::helper_aes_gcm;
use azihsm_ddi_mbor_test_hooks::DdiAesGcmOp;
use azihsm_ddi_mbor_test_hooks::DdiAesGcmResp;
use azihsm_ddi_mbor_types::DdiDeviceKind;
use azihsm_ddi_mbor_types::DdiStatus;
use common::*;
use test_with_tracing::test;

/// One AES-GCM known-answer vector, in hex.
struct GcmVector {
    key: &'static str,
    iv: &'static str,
    aad: &'static str,
    pt: &'static str,
    ct: &'static str,
    tag: &'static str,
}

/// A 48-byte whole-block prefix and a 3-byte partial last block.
///
/// NIST CAVP `gcmEncryptExtIV256.rsp` ([Keylen = 256] [IVlen = 96]
/// [PTlen = 408] [AADlen = 128] [Taglen = 128], Count = 0), from
/// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip>.
const PREFIX_AND_TAIL: GcmVector = GcmVector {
    key: "5fe01c4baf01cbe07796d5aaef6ec1f45193a98a223594ae4f0ef4952e82e330",
    iv: "bd587321566c7f1a5dd8652d",
    aad: "9013617817dda947e135ee6dd3653382",
    pt: "881dc6c7a5d4509f3c4bd2daab08f165ddc204489aa8134562a4eac3d0bcad79\
         65847b102733bb63d1e5c598ece0c3e5dadddd",
    ct: "16e375b4973b339d3f746c1c5a568bc7526e909ddff1e19c95c94a6ccff210c9\
         a4a40679de5760c396ac0e2ceb1234f9f5fe26",
    tag: "abd3d26d65a6275f7a4f56b422acab49",
};

/// A 13-byte partial block and no whole-block prefix.
///
/// NIST CAVP `gcmEncryptExtIV256.rsp` ([Keylen = 256] [IVlen = 96]
/// [PTlen = 104] [AADlen = 128] [Taglen = 128], Count = 0), from the same
/// archive as [`PREFIX_AND_TAIL`].
const TAIL_ONLY: GcmVector = GcmVector {
    key: "dad89d9be9bba138cdcf8752c45b579d7e27c3dbb40f53e771dd8cfd500aa2d5",
    iv: "cfb2aec82cfa6c7d89ee72ff",
    aad: "6e43784a91851a77667a02198e28dc32",
    pt: "b526ba1050177d05b0f72f8d67",
    ct: "8b29e66e924ecae84f6d8f7d68",
    tag: "1e365805c8f28b2ed8a5cadfd9079158",
};

/// One whole block and no partial block, with 32 bytes of AAD.
///
/// Generated with OpenSSL AES-256-GCM.
const PREFIX_ONLY: GcmVector = GcmVector {
    key: "0204050d06010d08050807030400040404050e050306070b00080804090b0705",
    iv: "111111111111111111111111",
    aad: "16e375b4973b339d3f746c1c5a568bc7526e909ddff1e19c95c94a6ccff210c9",
    pt: "881dc6c7a5d4509f3c4bd2daab08f165",
    ct: "1c6dc15820831844c457ff2ca094068e",
    tag: "7ddd7f927ba093d062b421b692337100",
};

const ENCRYPT_OPS: [DdiAesGcmOp; 2] = [DdiAesGcmOp::Encrypt, DdiAesGcmOp::EncryptInPlace];
const DECRYPT_OPS: [DdiAesGcmOp; 2] = [DdiAesGcmOp::Decrypt, DdiAesGcmOp::DecryptInPlace];

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Run one operation, or return `None` when the firmware lacks the hook.
#[allow(clippy::too_many_arguments)]
fn run(
    dev: &<DdiTest as Ddi>::Dev,
    session_id: u16,
    op: DdiAesGcmOp,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    text: &[u8],
    tag: Option<&[u8]>,
) -> Option<DdiAesGcmResp> {
    match helper_aes_gcm(dev, session_id, op, key, iv, aad, text, tag) {
        Ok(resp) => Some(resp.data),
        Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
            println!("Firmware is not built with azihsm_test_hooks; skipping.");
            None
        }
        Err(err) => panic!("{op:?} failed: {err:?}"),
    }
}

/// Check every PAL GCM method against one known-answer vector.
fn check_vector(dev: &mut <DdiTest as Ddi>::Dev, session_id: u16, vector: &GcmVector) {
    if get_device_kind(dev) != DdiDeviceKind::Physical {
        return;
    }
    let (key, iv, aad) = (hex(vector.key), hex(vector.iv), hex(vector.aad));
    let (pt, ct, tag) = (hex(vector.pt), hex(vector.ct), hex(vector.tag));

    for op in ENCRYPT_OPS {
        let Some(resp) = run(dev, session_id, op, &key, &iv, &aad, &pt, None) else {
            return;
        };
        assert_eq!(resp.text.as_slice(), ct, "{op:?} ciphertext");
        assert_eq!(
            resp.tag.as_ref().map(|tag| tag.as_slice()),
            Some(tag.as_slice()),
            "{op:?} tag"
        );
    }
    for op in DECRYPT_OPS {
        let Some(resp) = run(dev, session_id, op, &key, &iv, &aad, &ct, Some(&tag)) else {
            return;
        };
        assert_eq!(resp.text.as_slice(), pt, "{op:?} plaintext");
        assert!(resp.tag.is_none(), "{op:?} returned a tag");
    }
}

/// Encrypt with the host's software AES-GCM.
fn software_gcm_encrypt(key: &[u8], iv: &[u8], aad: &[u8], pt: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let key = AesKey::from_bytes(key).unwrap();
    let aad = if aad.is_empty() { None } else { Some(aad) };
    let mut algo = AesGcmAlgo::for_encrypt(iv, aad).unwrap();
    let mut ct = vec![0u8; pt.len()];
    let written = algo.encrypt(&key, pt, Some(&mut ct)).unwrap();
    assert_eq!(written, pt.len());
    (ct, algo.tag().to_vec())
}

/// Checks the vectors and the sweep's software reference against each other,
/// without a device.
#[test]
fn software_gcm_matches_vectors() {
    for vector in [&PREFIX_AND_TAIL, &TAIL_ONLY, &PREFIX_ONLY] {
        let (ct, tag) = software_gcm_encrypt(
            &hex(vector.key),
            &hex(vector.iv),
            &hex(vector.aad),
            &hex(vector.pt),
        );
        assert_eq!(ct, hex(vector.ct));
        assert_eq!(tag, hex(vector.tag));
    }
}

#[test]
fn aes_gcm_kat_prefix_and_tail() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            check_vector(dev, session_id, &PREFIX_AND_TAIL);
        },
    );
}

#[test]
fn aes_gcm_kat_tail_only() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            check_vector(dev, session_id, &TAIL_ONLY);
        },
    );
}

#[test]
fn aes_gcm_kat_prefix_only() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            check_vector(dev, session_id, &PREFIX_ONLY);
        },
    );
}

#[test]
fn aes_gcm_kat_rejects_bad_tag() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                return;
            }
            for vector in [&PREFIX_AND_TAIL, &TAIL_ONLY] {
                let (key, iv, aad, ct) = (
                    hex(vector.key),
                    hex(vector.iv),
                    hex(vector.aad),
                    hex(vector.ct),
                );
                let mut tag = hex(vector.tag);
                tag[0] ^= 0x01;
                for op in DECRYPT_OPS {
                    match helper_aes_gcm(dev, session_id, op, &key, &iv, &aad, &ct, Some(&tag)) {
                        Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                            println!("Firmware is not built with azihsm_test_hooks; skipping.");
                            return;
                        }
                        Err(DdiError::DdiStatus(status)) => {
                            assert_eq!(status, DdiStatus::AesGcmDecryptTagDoesNotMatch, "{op:?}")
                        }
                        other => panic!("{op:?}: expected a tag mismatch, got {other:?}"),
                    }
                }
            }
        },
    );
}

#[test]
fn aes_gcm_length_sweep_matches_software() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                return;
            }
            let key: Vec<u8> = (0u8..32).collect();
            for aad_len in [0usize, 16, 20] {
                let aad: Vec<u8> = (0..aad_len).map(|i| (i as u8) ^ 0x5a).collect();
                for text_len in 1usize..=64 {
                    let iv = [aad_len as u8, text_len as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
                    let pt: Vec<u8> = (0..text_len)
                        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(aad_len as u8))
                        .collect();
                    let (ct, tag) = software_gcm_encrypt(&key, &iv, &aad, &pt);
                    let case = format!("text_len {text_len}, aad_len {aad_len}");

                    for op in ENCRYPT_OPS {
                        let Some(resp) = run(dev, session_id, op, &key, &iv, &aad, &pt, None)
                        else {
                            return;
                        };
                        assert_eq!(resp.text.as_slice(), ct, "{op:?} ciphertext, {case}");
                        assert_eq!(
                            resp.tag.as_ref().map(|tag| tag.as_slice()),
                            Some(tag.as_slice()),
                            "{op:?} tag, {case}"
                        );
                    }
                    for op in DECRYPT_OPS {
                        let Some(resp) = run(dev, session_id, op, &key, &iv, &aad, &ct, Some(&tag))
                        else {
                            return;
                        };
                        assert_eq!(resp.text.as_slice(), pt, "{op:?} plaintext, {case}");
                    }
                }
            }
        },
    );
}

/// Malformed requests fail with `InvalidArg`, and the session still works
/// after each one.
#[test]
fn aes_gcm_rejects_malformed_requests() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                return;
            }
            let (key, iv, aad) = (hex(TAIL_ONLY.key), hex(TAIL_ONLY.iv), hex(TAIL_ONLY.aad));
            let (pt, ct, tag) = (hex(TAIL_ONLY.pt), hex(TAIL_ONLY.ct), hex(TAIL_ONLY.tag));
            if run(
                dev,
                session_id,
                DdiAesGcmOp::Encrypt,
                &key,
                &iv,
                &aad,
                &pt,
                None,
            )
            .is_none()
            {
                return;
            }

            let mut cases: Vec<(&str, DdiAesGcmOp, &[u8], &[u8], Option<&[u8]>)> = vec![
                ("unknown operation", DdiAesGcmOp(0), &iv[..], &pt[..], None),
                ("empty IV", DdiAesGcmOp::Encrypt, &iv[..0], &pt[..], None),
                ("11-byte IV", DdiAesGcmOp::Encrypt, &iv[..11], &pt[..], None),
            ];
            for op in DECRYPT_OPS {
                cases.push(("no tag", op, &iv[..], &ct[..], None));
                cases.push(("empty tag", op, &iv[..], &ct[..], Some(&tag[..0])));
                cases.push(("15-byte tag", op, &iv[..], &ct[..], Some(&tag[..15])));
            }
            for op in ENCRYPT_OPS {
                cases.push(("tag on encrypt", op, &iv[..], &pt[..], Some(&tag[..])));
            }

            for (case, op, case_iv, text, case_tag) in cases {
                let result =
                    helper_aes_gcm(dev, session_id, op, &key, case_iv, &aad, text, case_tag);
                assert!(
                    matches!(result, Err(DdiError::DdiStatus(DdiStatus::InvalidArg))),
                    "{case}, {op:?}: expected InvalidArg, got {result:?}"
                );

                let resp = helper_aes_gcm(
                    dev,
                    session_id,
                    DdiAesGcmOp::Encrypt,
                    &key,
                    &iv,
                    &aad,
                    &pt,
                    None,
                )
                .unwrap_or_else(|err| panic!("encrypt after {case}, {op:?} failed: {err:?}"))
                .data;
                assert_eq!(resp.text.as_slice(), ct, "ciphertext after {case}, {op:?}");
                assert_eq!(
                    resp.tag.as_ref().map(|tag| tag.as_slice()),
                    Some(tag.as_slice()),
                    "tag after {case}, {op:?}"
                );
            }
        },
    );
}
