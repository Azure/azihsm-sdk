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
use azihsm_ddi_tbor_types::TborHashReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::HASH_ALGO_SHA256;
use azihsm_ddi_tbor_types::HASH_ALGO_SHA384;
use azihsm_ddi_tbor_types::HASH_ALGO_SHA512;

use crate::commands::sd_sealing_key_gen::finalized_co_session;
use azihsm_ddi_tbor_test_harness::TestCtx;

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

#[test]
fn hash_matches_host_all_algos_emu() {
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

#[test]
fn hash_unknown_algo_rejected_emu() {
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
