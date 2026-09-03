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
//! * Happy path — returns a well-formed RSA-2048 public key.
//! * Stability — a second call returns the same (stable) key.
//! * Role access — Crypto-User sessions can also fetch the key.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborGetUnwrappingKeyReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::PSK_LEN;
use azihsm_ddi_tbor_types::UNWRAPPING_PUB_KEY_LEN;

use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;

use crate::harness::CO_PSK_ID;
use crate::harness::ROTATED_CO_PSK;

const CU: u8 = 1;
const RSA_2048_MODULUS_LEN: usize = 256;
const RSA_PUBLIC_EXPONENT: u32 = 65_537;

/// Non-default CU PSK used to pass the dispatcher's default-PSK gate.
const ROTATED_CU_PSK: [u8; PSK_LEN] = [0xA5; PSK_LEN];
/// Second non-default CO PSK used to verify credential rotation does not change the key.
const SECOND_ROTATED_CO_PSK: [u8; PSK_LEN] = [0x5A; PSK_LEN];

/// Returns a well-formed RSA-2048 partition unwrapping public key.
#[test]
fn get_unwrapping_key_returns_rsa_pub_key() {
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
    let (modulus, exponent) = resp.pub_key.split_at(RSA_2048_MODULUS_LEN);

    // A generated RSA-2048 modulus has exactly 2048 significant bits and
    // is odd. The HSM wire format is little-endian, so those properties
    // live in the last and first modulus bytes respectively.
    assert!(
        modulus[RSA_2048_MODULUS_LEN - 1] & 0x80 != 0,
        "RSA modulus must have exactly 2048 significant bits",
    );
    assert!(modulus[0] & 1 != 0, "RSA modulus must be odd",);

    let exponent = u32::from_le_bytes(exponent.try_into().expect("four-byte RSA exponent"));
    assert_eq!(
        exponent, RSA_PUBLIC_EXPONENT,
        "unwrapping key must use the standard RSA public exponent",
    );
}

/// Returns the same stable partition unwrapping key across repeated calls.
#[test]
fn get_unwrapping_key_is_stable() {
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

/// Allows a Crypto-User with a rotated PSK to fetch the unwrapping key.
#[test]
fn get_unwrapping_key_available_to_crypto_user() {
    let ctx = TestCtx::new();

    // Rotate the CU PSK so GetUnwrappingKey reaches its handler instead of
    // being rejected by the dispatcher's default-PSK gate.
    let bootstrap = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open bootstrap CU session");

    ctx.psk_change(bootstrap.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");

    bootstrap.close().expect("close bootstrap CU session");

    let opts = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_CU_PSK);

    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("open CU session under rotated PSK");

    let session = ctx.session_open_finish(pending).expect("finish CU session");

    let resp = ctx
        .tbor(&TborGetUnwrappingKeyReq {
            session_id: session.session_id,
        })
        .expect("GetUnwrappingKey must be available to Crypto-User sessions");

    assert_eq!(
        resp.pub_key.len(),
        UNWRAPPING_PUB_KEY_LEN,
        "unwrapping pub key must be the pinned length",
    );

    let (modulus, exponent) = resp.pub_key.split_at(RSA_2048_MODULUS_LEN);

    assert!(
        modulus.iter().any(|&byte| byte != 0),
        "RSA modulus must not be all zero",
    );

    assert!(
        modulus[RSA_2048_MODULUS_LEN - 1] & 0x80 != 0,
        "RSA modulus must have exactly 2048 significant bits",
    );

    assert!(modulus[0] & 1 != 0, "RSA modulus must be odd",);

    let exponent = u32::from_le_bytes(exponent.try_into().expect("four-byte RSA exponent"));

    assert_eq!(
        exponent, RSA_PUBLIC_EXPONENT,
        "unwrapping key must use the standard RSA public exponent",
    );
}

/// Rejects a request that references a closed session.
#[test]
fn get_unwrapping_key_closed_session_rejected() {
    let ctx = TestCtx::new();

    let session = finalized_co_session(&ctx);
    let session_id = session.session_id;

    ctx.session_close(session_id).expect("close CO session");

    ctx.expect_fw_reject(
        &TborGetUnwrappingKeyReq { session_id },
        TborStatus::SessionNotFound,
    );
}

/// Preserves the same partition unwrapping key across separate CO sessions.
#[test]
fn get_unwrapping_key_stable_across_co_sessions() {
    let ctx = TestCtx::new();

    // Provision/finalize the partition once.
    let first_session = finalized_co_session(&ctx);

    let first = ctx
        .tbor(&TborGetUnwrappingKeyReq {
            session_id: first_session.session_id,
        })
        .expect("GetUnwrappingKey from first CO session");

    ctx.session_close(first_session.session_id)
        .expect("close first CO session");

    // Reopen CO under the PSK already rotated by finalized_co_session().
    let opts = SessionOpenInitOptions::new(CO_PSK_ID, SessionType::Authenticated)
        .with_psk(&ROTATED_CO_PSK);

    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("reopen CO session under rotated PSK");

    let second_session = ctx
        .session_open_finish(pending)
        .expect("finish second CO session");

    let second = ctx
        .tbor(&TborGetUnwrappingKeyReq {
            session_id: second_session.session_id,
        })
        .expect("GetUnwrappingKey from second CO session");

    assert_eq!(
        first.pub_key, second.pub_key,
        "partition unwrapping key must remain stable across CO sessions",
    );
}

/// Returns the same partition unwrapping key to CO and CU sessions.
#[test]
fn get_unwrapping_key_same_for_co_and_crypto_user() {
    let ctx = TestCtx::new();

    // Finalize the partition and read the unwrapping key as CO.
    let co_session = finalized_co_session(&ctx);

    let co_resp = ctx
        .tbor(&TborGetUnwrappingKeyReq {
            session_id: co_session.session_id,
        })
        .expect("GetUnwrappingKey from CO session");

    // Close CO before opening the CU bootstrap session.
    ctx.session_close(co_session.session_id)
        .expect("close CO session");

    // Rotate the CU PSK so GetUnwrappingKey reaches its handler instead
    // of being rejected by the dispatcher's default-PSK gate.
    let bootstrap = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open bootstrap CU session");

    ctx.psk_change(bootstrap.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");

    bootstrap.close().expect("close bootstrap CU session");

    // Reopen CU under the rotated PSK.
    let opts = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_CU_PSK);

    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("open CU session under rotated PSK");

    let cu_session = ctx.session_open_finish(pending).expect("finish CU session");

    let cu_resp = ctx
        .tbor(&TborGetUnwrappingKeyReq {
            session_id: cu_session.session_id,
        })
        .expect("GetUnwrappingKey from CU session");

    assert_eq!(
        co_resp.pub_key, cu_resp.pub_key,
        "CO and CU must observe the same partition unwrapping key",
    );
}

/// Rejects a Crypto-User request while the CU PSK is still the default.
#[test]
fn get_unwrapping_key_default_cu_psk_rejected() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open CU session under default PSK");

    ctx.expect_fw_reject(
        &TborGetUnwrappingKeyReq {
            session_id: session.handshake().session_id,
        },
        TborStatus::DefaultPskMustRotate,
    );
}

/// Rejects a request that references an unknown session ID.
#[test]
fn get_unwrapping_key_unknown_session_rejected() {
    let ctx = TestCtx::new();

    ctx.expect_fw_reject(
        &TborGetUnwrappingKeyReq {
            session_id: u16::MAX,
        },
        TborStatus::SessionNotFound,
    );
}

/// Preserves the same partition unwrapping key across separate CU sessions.
#[test]
fn get_unwrapping_key_stable_across_cu_sessions() {
    let ctx = TestCtx::new();

    // Rotate the CU PSK.
    let bootstrap = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open bootstrap CU session");

    ctx.psk_change(bootstrap.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");

    bootstrap.close().expect("close bootstrap CU session");

    // First CU session.
    let opts = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_CU_PSK);

    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("open first CU session");

    let first_session = ctx
        .session_open_finish(pending)
        .expect("finish first CU session");

    let first = ctx
        .tbor(&TborGetUnwrappingKeyReq {
            session_id: first_session.session_id,
        })
        .expect("GetUnwrappingKey from first CU session");

    ctx.session_close(first_session.session_id)
        .expect("close first CU session");

    // Second CU session.
    let opts = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_CU_PSK);

    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("open second CU session");

    let second_session = ctx
        .session_open_finish(pending)
        .expect("finish second CU session");

    let second = ctx
        .tbor(&TborGetUnwrappingKeyReq {
            session_id: second_session.session_id,
        })
        .expect("GetUnwrappingKey from second CU session");

    assert_eq!(
        first.pub_key, second.pub_key,
        "partition unwrapping key must remain stable across CU sessions",
    );
}

/// Preserves the partition unwrapping key across a CO PSK rotation.
#[test]
fn get_unwrapping_key_stable_across_co_psk_rotation() {
    let ctx = TestCtx::new();

    let session = finalized_co_session(&ctx);

    let before = ctx
        .tbor(&TborGetUnwrappingKeyReq {
            session_id: session.session_id,
        })
        .expect("GetUnwrappingKey before CO PSK rotation");

    ctx.psk_change(&session, &SECOND_ROTATED_CO_PSK)
        .expect("rotate CO PSK a second time");

    let after = ctx
        .tbor(&TborGetUnwrappingKeyReq {
            session_id: session.session_id,
        })
        .expect("GetUnwrappingKey after CO PSK rotation");

    assert_eq!(
        before.pub_key, after.pub_key,
        "CO PSK rotation must not change the partition unwrapping key",
    );
}
