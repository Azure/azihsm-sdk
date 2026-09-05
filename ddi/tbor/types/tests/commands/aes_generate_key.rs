// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `AesGenerateKey` command.
//!
//! The command generates a random AES key of the requested size and
//! returns it **masked** under the requested scope's masking key — nothing
//! is stored on-device.  Like the other general crypto commands,
//! `AesGenerateKey` is available to both Crypto-Officer and Crypto-User
//! sessions.
//!
//! Coverage:
//! * Happy path per key size (128/192/256) — the masked key has the
//!   expected length (148/156/164 B) and is non-zero; a second call yields
//!   a distinct key.
//! * Every masking-key scope: `Session` (works pre-finalize), `Ephemeral`
//!   / `Local` (provisioned by `PartFinal`).
//! * `SecurityDomain` scope before `CreateSD` → `UnsupportedKeyScope`.
//! * `Ephemeral` scope before `PartFinal` → `InvalidArg`.
//! * Unknown key size → `InvalidArg`.

#![cfg(any(feature = "emu", feature = "mock", feature = "sock"))]
// The shared masked-key helpers/constants below stay available under any
// backend (so the module isn't emu-limited), but only the emu-gated tests
// exercise them today; suppress dead-code noise in non-emu builds.
#![cfg_attr(not(feature = "emu"), allow(dead_code))]

use azihsm_ddi_tbor_types::TborAesGenerateKeyReq;
// The reject/scope tests need the emu FW handler and its partition
// bootstrap helpers; keep those imports emu-only so the shared masked-key
// helpers below stay available under any backend.
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::AES_KEY_SIZE_128;
use azihsm_ddi_tbor_types::AES_KEY_SIZE_192;
use azihsm_ddi_tbor_types::AES_KEY_SIZE_256;
use azihsm_ddi_tbor_types::KEY_USAGE_DECRYPT;
use azihsm_ddi_tbor_types::KEY_USAGE_ENCRYPT;

#[cfg(feature = "emu")]
use crate::commands::sd_sealing_key_gen::finalized_co_session;
#[cfg(feature = "emu")]
use crate::harness::bootstrap_rotated_co;
use crate::harness::TestCtx;
#[cfg(feature = "emu")]
use crate::harness::ROTATED_CO_PSK;

/// `KeyScope` discriminants (wire mirror of the firmware `HsmKeyScope`).
pub(crate) const SCOPE_SESSION: u8 = 0b001;
pub(crate) const SCOPE_EPHEMERAL: u8 = 0b010;
pub(crate) const SCOPE_LOCAL: u8 = 0b011;
pub(crate) const SCOPE_SECURITY_DOMAIN: u8 = 0b100;

/// Masked-key envelope length for a given AES key length: `header(8) ‖
/// iv(12) ‖ aad(96) ‖ pt(key) ‖ tag(16)`.
fn masked_len(key_len: usize) -> usize {
    8 + 12 + 96 + key_len + 16
}

/// Expected AES key length (bytes) for a wire key-size discriminant.
pub(crate) fn key_len_for_size(size: u8) -> usize {
    match size {
        AES_KEY_SIZE_128 => 16,
        AES_KEY_SIZE_192 => 24,
        AES_KEY_SIZE_256 => 32,
        other => panic!("unexpected key-size discriminant {other}"),
    }
}

/// Generate a masked AES key of `(scope, size)` on `session_id`.
pub(crate) fn generate_key(ctx: &TestCtx, session_id: u16, scope: u8, size: u8) -> Vec<u8> {
    let req = TborAesGenerateKeyReq {
        session_id,
        scope,
        key_size: size,
        key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        key_label: "AES Key".as_bytes().to_vec(),
    };
    ctx.tbor(&req).expect("AesGenerateKey").masked_key
}

/// Happy path for a `(scope, size)` pair: the masked key has the expected
/// length, is non-zero, and a second call yields a distinct blob.
fn roundtrip(ctx: &TestCtx, session_id: u16, scope: u8, size: u8) {
    let masked = generate_key(ctx, session_id, scope, size);
    assert_eq!(
        masked.len(),
        masked_len(key_len_for_size(size)),
        "masked key length must match the key size",
    );
    assert!(
        masked.iter().any(|&b| b != 0),
        "masked_key must not be all-zero",
    );

    // Each call samples fresh randomness → a distinct masked blob.
    let masked2 = generate_key(ctx, session_id, scope, size);
    assert_ne!(
        masked, masked2,
        "each generation must yield a distinct masked key",
    );
}

#[cfg(feature = "emu")]
#[test]
fn aes_generate_key_roundtrip_all_sizes_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    for size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
        roundtrip(&ctx, session.session_id, SCOPE_EPHEMERAL, size);
    }
}

#[cfg(feature = "emu")]
#[test]
fn aes_generate_key_roundtrip_all_scopes_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    // Session / Ephemeral / Local masking keys all exist on an Initialized
    // partition with an Active session.
    for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
        roundtrip(&ctx, session.session_id, scope, AES_KEY_SIZE_256);
    }
}

#[cfg(feature = "emu")]
#[test]
fn aes_generate_key_session_scope_before_finalize_emu() {
    // Session-scoped keys are masked under the per-session masking key, so
    // they do not require a finalized partition — only an Active session.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    roundtrip(&ctx, session.session_id, SCOPE_SESSION, AES_KEY_SIZE_256);
}

#[cfg(feature = "emu")]
#[test]
fn aes_generate_key_rejects_security_domain_scope_emu() {
    // The SecurityDomain masking key (SDMK) is only provisioned by
    // CreateSD, so the scope is rejected with the dedicated error.
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let req = TborAesGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_SECURITY_DOMAIN,
        key_size: AES_KEY_SIZE_256,
        key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        key_label: "AES Key".as_bytes().to_vec(),
    };
    ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
}

#[cfg(feature = "emu")]
#[test]
fn aes_generate_key_rejects_ephemeral_before_finalize_emu() {
    // Ephemeral / Local masking keys are provisioned at PartFinal, so a
    // non-Session scope before finalize is rejected with InvalidArg.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let req = TborAesGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_EPHEMERAL,
        key_size: AES_KEY_SIZE_256,
        key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        key_label: "AES Key".as_bytes().to_vec(),
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

#[cfg(feature = "emu")]
#[test]
fn aes_generate_key_rejects_unknown_size_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let req = TborAesGenerateKeyReq {
        session_id: session.session_id,
        scope: SCOPE_EPHEMERAL,
        // 0 is not a valid AesKeySize discriminant.
        key_size: 0,
        key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        key_label: "AES Key".as_bytes().to_vec(),
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}
