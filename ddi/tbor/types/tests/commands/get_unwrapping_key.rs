// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `GetUnwrappingKey` command.
//!
//! The command returns the partition's RSA-2048 unwrapping public key
//! (HSM wire format `n_le(256) ‖ e_le(4)` = 260 bytes), which the host
//! uses to RSA-AES key-wrap a payload for a future `UnwrapKey` import.
//! The std (emulator) PAL materialises the key lazily on first read.
//!
//! Coverage:
//! * Happy path — returns a full, non-zero 260-byte public key.
//! * Stability — a second call returns the same (stable) key.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::TborGetUnwrappingKeyReq;
use azihsm_ddi_tbor_types::UNWRAPPING_PUB_KEY_LEN;

use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::harness::TestCtx;

#[test]
fn get_unwrapping_key_returns_rsa_pub_key_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let req = TborGetUnwrappingKeyReq {
        session_id: session.session_id,
    };
    let resp = ctx.tbor(&req).expect("GetUnwrappingKey");

    assert_eq!(
        resp.pub_key.len(),
        UNWRAPPING_PUB_KEY_LEN,
        "unwrapping pub key must be the pinned length",
    );
    // The RSA modulus (first 256 bytes) must be a full, non-zero value.
    assert!(
        resp.pub_key[..256].iter().any(|&b| b != 0),
        "RSA modulus must not be all-zero",
    );
    // The public exponent (last 4 bytes) must be non-zero.
    assert!(
        resp.pub_key[256..].iter().any(|&b| b != 0),
        "RSA public exponent must not be all-zero",
    );
}

#[test]
fn get_unwrapping_key_is_stable_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let req = TborGetUnwrappingKeyReq {
        session_id: session.session_id,
    };
    let first = ctx.tbor(&req).expect("first GetUnwrappingKey");
    let second = ctx.tbor(&req).expect("second GetUnwrappingKey");

    // The unwrapping key is a stable partition key — not regenerated.
    assert_eq!(
        first.pub_key, second.pub_key,
        "the unwrapping key must be stable across calls",
    );
}
