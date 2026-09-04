// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `Hash` command.
//!
//! `Hash` computes a SHA-256 / 384 / 512 digest of a host-supplied
//! message.  These tests hash several messages on-device and verify the
//! result byte-for-byte against the digest computed on the host with
//! `azihsm_crypto` (natural big-endian output), for every algorithm.

#![cfg(feature = "emu")]

use azihsm_crypto::HashAlgo as CryptoHashAlgo;
use azihsm_crypto::Hasher;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborHashReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::HASH_ALGO_SHA256;
use azihsm_ddi_tbor_types::HASH_ALGO_SHA384;
use azihsm_ddi_tbor_types::HASH_ALGO_SHA512;

use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::harness::bootstrap_rotated_cu;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CU_PSK;

/// Hash `msg` on-device with `algo`, returning the digest.
fn device_digest(ctx: &TestCtx, session_id: u16, algo: u8, msg: Vec<u8>) -> Vec<u8> {
    ctx.tbor(&TborHashReq {
        session_id,
        algo,
        msg,
    })
    .expect("Hash")
    .digest
}

/// Compute the expected digest on the host with `azihsm_crypto`.
fn host_digest(algo: u8, msg: &[u8]) -> Vec<u8> {
    let mut crypto_algo = match algo {
        HASH_ALGO_SHA256 => CryptoHashAlgo::sha256(),
        HASH_ALGO_SHA384 => CryptoHashAlgo::sha384(),
        HASH_ALGO_SHA512 => CryptoHashAlgo::sha512(),
        _ => unreachable!("unknown hash algo"),
    };
    Hasher::hash_vec(&mut crypto_algo, msg).expect("host hash")
}

/// Expected digest length for a mode.
fn digest_len(algo: u8) -> usize {
    match algo {
        HASH_ALGO_SHA256 => 32,
        HASH_ALGO_SHA384 => 48,
        HASH_ALGO_SHA512 => 64,
        _ => unreachable!(),
    }
}

/// Verifies SHA-256, SHA-384, and SHA-512 digests match the host for varied inputs.
#[test]
fn hash_matches_host_all_algos() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // A few messages: short, empty, and a longer non-trivial buffer.
    let short = b"abc".to_vec();
    let empty: Vec<u8> = Vec::new();
    let long: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();

    for msg in [short, empty, long] {
        for mode in [HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512] {
            let dev = device_digest(&ctx, session.session_id, mode, msg.clone());
            assert_eq!(
                dev.len(),
                digest_len(mode),
                "digest length must match the algorithm (mode {mode}, msg {} B)",
                msg.len(),
            );
            assert_eq!(
                dev,
                host_digest(mode, &msg),
                "device digest must match host SHA (mode {mode}, msg {} B)",
                msg.len(),
            );
        }
    }
}

/// Rejects an unsupported hash algorithm.
#[test]
fn hash_unknown_algo_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // Mode discriminant `0` is not one of SHA-256 / 384 / 512.
    ctx.expect_fw_reject(
        &TborHashReq {
            session_id: session.session_id,
            algo: 0,
            msg: b"abc".to_vec(),
        },
        TborStatus::InvalidArg,
    );
}

/// Rejects a Hash request that references a nonexistent session.
#[test]
fn hash_invalid_session_id_rejected() {
    let ctx = TestCtx::new();

    ctx.expect_fw_reject(
        &TborHashReq {
            session_id: u16::MAX,
            algo: HASH_ALGO_SHA256,
            msg: b"abc".to_vec(),
        },
        TborStatus::SessionNotFound,
    );
}

/// Rejects multiple invalid hash algorithm discriminants.
#[test]
fn hash_invalid_algos_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for algo in [
        0,
        HASH_ALGO_SHA256.wrapping_sub(1),
        HASH_ALGO_SHA512.wrapping_add(1),
        u8::MAX,
    ] {
        if [HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512].contains(&algo) {
            continue;
        }

        ctx.expect_fw_reject(
            &TborHashReq {
                session_id: session.session_id,
                algo,
                msg: b"abc".to_vec(),
            },
            TborStatus::InvalidArg,
        );
    }
}

/// Verifies binary input containing arbitrary byte values hashes correctly.
#[test]
fn hash_binary_message_matches_host() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let msg = vec![
        0x00, 0xff, 0x80, 0x7f, 0x00, 0x01, 0xfe, 0xaa, 0x55, 0x00, 0xff,
    ];

    for algo in [HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512] {
        let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

        assert_eq!(dev, host_digest(algo, &msg));
    }
}

/// Verifies different messages produce different digests for every supported algorithm.
#[test]
fn hash_different_messages_produce_different_digests() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for algo in [HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512] {
        let digest_a = device_digest(&ctx, session.session_id, algo, b"abc".to_vec());
        let digest_b = device_digest(&ctx, session.session_id, algo, b"abd".to_vec());

        assert_ne!(
            digest_a, digest_b,
            "different messages should produce different hashes for algo {algo}",
        );
    }
}

/// Verifies hashing across SHA padding and compression-block boundaries.
#[test]
fn hash_block_boundary_lengths_match_host() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // SHA-256 block = 64 bytes.
    // SHA-384/SHA-512 block = 128 bytes.
    for len in [1usize, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129] {
        let msg: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

        for algo in [HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512] {
            let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

            assert_eq!(
                dev,
                host_digest(algo, &msg),
                "hash mismatch for algo {algo}, message length {len}",
            );
        }
    }
}

/// Rejects a Hash request made with a previously closed session.
#[test]
fn hash_closed_session_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let session_id = session.session_id;

    ctx.session_close(session_id).expect("close CO session");

    ctx.expect_fw_reject(
        &TborHashReq {
            session_id,
            algo: HASH_ALGO_SHA256,
            msg: b"abc".to_vec(),
        },
        TborStatus::SessionNotFound,
    );
}

/// Verifies the same message hashes correctly with every supported algorithm.
#[test]
fn hash_same_message_different_algos() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let msg = b"same message".to_vec();

    let sha256 = device_digest(&ctx, session.session_id, HASH_ALGO_SHA256, msg.clone());
    let sha384 = device_digest(&ctx, session.session_id, HASH_ALGO_SHA384, msg.clone());
    let sha512 = device_digest(&ctx, session.session_id, HASH_ALGO_SHA512, msg.clone());

    assert_eq!(sha256, host_digest(HASH_ALGO_SHA256, &msg));
    assert_eq!(sha384, host_digest(HASH_ALGO_SHA384, &msg));
    assert_eq!(sha512, host_digest(HASH_ALGO_SHA512, &msg));

    assert_eq!(sha256.len(), 32);
    assert_eq!(sha384.len(), 48);
    assert_eq!(sha512.len(), 64);
}

/// Verifies a one-bit input change produces a different digest.
#[test]
fn hash_one_bit_message_change_changes_digest() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let msg_a = vec![0x00; 64];
    let mut msg_b = msg_a.clone();
    msg_b[31] ^= 0x01;

    for algo in [HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512] {
        let digest_a = device_digest(&ctx, session.session_id, algo, msg_a.clone());
        let digest_b = device_digest(&ctx, session.session_id, algo, msg_b.clone());

        assert_ne!(
            digest_a, digest_b,
            "one-bit input change must change digest for algo {algo}",
        );

        assert_eq!(digest_a, host_digest(algo, &msg_a));
        assert_eq!(digest_b, host_digest(algo, &msg_b));
    }
}

/// Verifies a rotated Crypto-User session can hash with every supported algorithm.
#[test]
fn hash_crypto_user_session_matches_host() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    let msg = b"crypto-user hash".to_vec();

    for algo in [HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512] {
        let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

        assert_eq!(
            dev,
            host_digest(algo, &msg),
            "CU hash must match host for algo {algo}",
        );
    }
}

/// Verifies SHA-256, SHA-384, and SHA-512 against known-answer vectors.
#[test]
fn hash_known_answer_vectors() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let msg = b"abc".to_vec();

    let sha256_expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    let sha384_expected = [
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50,
        0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff,
        0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34,
        0xc8, 0x25, 0xa7,
    ];

    let sha512_expected = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41,
        0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
        0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3,
        0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
        0xa5, 0x4c, 0xa4, 0x9f,
    ];

    assert_eq!(
        device_digest(&ctx, session.session_id, HASH_ALGO_SHA256, msg.clone()),
        sha256_expected,
    );

    assert_eq!(
        device_digest(&ctx, session.session_id, HASH_ALGO_SHA384, msg.clone()),
        sha384_expected,
    );

    assert_eq!(
        device_digest(&ctx, session.session_id, HASH_ALGO_SHA512, msg),
        sha512_expected,
    );
}

/// Rejects hashing from a Crypto-User session that still uses the default PSK.
#[test]
fn hash_default_psk_cu_rejected() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(1, SessionType::PlainText)
        .expect("open default-PSK CU session");

    ctx.expect_fw_reject(
        &TborHashReq {
            session_id: session.session_id(),
            algo: HASH_ALGO_SHA256,
            msg: b"abc".to_vec(),
        },
        TborStatus::DefaultPskMustRotate,
    );
}

/// Verifies repeated identical Hash requests return the same digest.
#[test]
fn hash_same_request_is_deterministic() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let msg = b"deterministic hash input".to_vec();

    for algo in [HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512] {
        let first = device_digest(&ctx, session.session_id, algo, msg.clone());

        let second = device_digest(&ctx, session.session_id, algo, msg.clone());

        assert_eq!(
            first, second,
            "same input must produce same digest for algo {algo}",
        );
    }
}

/// Hashing the full range of byte values must match the host implementation.
#[test]
fn hash_all_byte_values_matches_host() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let msg: Vec<u8> = (0u8..=u8::MAX).collect();

    for algo in [HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512] {
        let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

        assert_eq!(
            dev,
            host_digest(algo, &msg),
            "all-byte-values hash mismatch for algo {algo}",
        );
    }
}

/// A rejected Hash request must not invalidate or poison the session.
#[test]
fn hash_session_usable_after_invalid_algo() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    ctx.expect_fw_reject(
        &TborHashReq {
            session_id: session.session_id,
            algo: u8::MAX,
            msg: b"invalid request".to_vec(),
        },
        TborStatus::InvalidArg,
    );

    let msg = b"valid request after rejection".to_vec();

    for algo in [HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512] {
        let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

        assert_eq!(
            dev,
            host_digest(algo, &msg),
            "session must remain usable after rejected request for algo {algo}",
        );
    }
}

/// Verifies consecutive requests of different lengths do not retain hash state.
#[test]
fn hash_consecutive_different_length_messages_match_host() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let messages = [
        vec![0x5a],
        vec![0xa5; 1000],
        Vec::new(),
        vec![0x3c; 17],
        vec![0xc3; 513],
    ];

    for algo in [HASH_ALGO_SHA256, HASH_ALGO_SHA384, HASH_ALGO_SHA512] {
        for msg in &messages {
            let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

            assert_eq!(
                dev,
                host_digest(algo, msg),
                "hash mismatch for algo {algo}, message length {}",
                msg.len(),
            );
        }
    }
}
