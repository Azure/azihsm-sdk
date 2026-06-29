// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `PartInit` command.
//!
//! Every test runs against the `emu` backend.  Cross-test isolation
//! comes from [`TestCtx::new`] (factory-reset + process-global lock
//! held for the ctx's lifetime, see [`crate::harness::fixture`]) so
//! each test starts from a pristine `Enabled` partition with the
//! canonical default PSKs.
//!
//! Submodules group tests by what is being exercised:
//! * [`happy_path`] — the full `OpenSession → ChangePsk → PartInit`
//!   flow, plus the cold-restart determinism test.
//! * [`fw_rejects`] — dispatcher/handler gates that reject **before**
//!   any partition-state mutation (default PSK, role, malformed
//!   policy).
//! * [`crypto_rejects`] — `mach_seed_envelope` AEAD-GCM tag and
//!   AAD-binding rejects.
//!
//! Shared bootstrap helpers (`open_co_with`, `bootstrap_rotated_co`,
//! the wire-correct `known_good_part_policy`/`mach_seed`/
//! `pota_thumbprint` fixtures, and the rotated CO PSK constant)
//! live in this module and are `pub(super)` so each submodule can
//! reach them via `super::*`.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PSK_LEN;

use crate::harness::OpenSessionInitOptions;
use crate::harness::SessionHandshake;
use crate::harness::TestCtx;

mod crypto_rejects;
mod fw_rejects;
mod happy_path;

pub(crate) const CO: u8 = 0;

/// Non-default 32-byte CO PSK used so PartInit clears the
/// default-PSK-gate.  Pinned to a fixed value so the smoke test is
/// fully deterministic.
pub(crate) const ROTATED_CO_PSK: [u8; PSK_LEN] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
];

/// Build a 167-byte `PartPolicy` blob that passes
/// `azihsm_fw_hsm_core::ddi::tbor::policy::from_bytes`.  Layout mirrors
/// the canonical wire format defined in
/// `fw/core/ddi/tbor/types/src/policy.rs`.
pub(crate) fn known_good_part_policy() -> [u8; PART_POLICY_LEN] {
    const OFF_VERSION_MAJOR: usize = 0;
    const OFF_VERSION_MINOR: usize = 1;
    const OFF_KIND: usize = 2;
    const OFF_LEN: usize = 4;
    const OFF_DATA: usize = 6;
    const OFF_INFO: usize = 103;

    let mut bytes = [0u8; PART_POLICY_LEN];
    bytes[OFF_VERSION_MAJOR] = 1;
    bytes[OFF_VERSION_MINOR] = 0;
    bytes[OFF_KIND..OFF_KIND + 2].copy_from_slice(&PolicyKeyKind::Ecc384.0.to_le_bytes());
    bytes[OFF_LEN..OFF_LEN + 2].copy_from_slice(&97u16.to_le_bytes());
    bytes[OFF_DATA] = 0x04;
    for (i, b) in bytes[OFF_DATA + 1..OFF_DATA + 97].iter_mut().enumerate() {
        *b = (0x10 + (i as u8)) | 0x80;
    }
    for b in bytes[OFF_INFO..OFF_INFO + 64].iter_mut() {
        *b = 0xAB;
    }
    bytes
}

pub(crate) fn mach_seed() -> [u8; MACH_SEED_LEN] {
    let mut v = [0u8; MACH_SEED_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x40 + i as u8;
    }
    v
}

pub(crate) fn pota_thumbprint() -> [u8; POTA_THUMBPRINT_LEN] {
    let mut v = [0u8; POTA_THUMBPRINT_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x80 ^ i as u8;
    }
    v
}

/// Seal an AEAD-GCM envelope under `param_key` with a caller-controlled
/// AAD and plaintext. Used by `crypto_rejects` to build envelopes the
/// canonical `encrypt_mach_seed_envelope` helper can't produce (wrong
/// AAD length, wrong plaintext length, mismatched session id, etc.).
/// Mirrors the `build_envelope` helper in `commands/change_psk.rs`.
pub(super) fn build_envelope(
    param_key: &azihsm_crypto::AesKey,
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    use azihsm_crypto::aead_envelope;
    use azihsm_crypto::aead_envelope::AeadAlg;
    use azihsm_crypto::Rng;

    let iv = Rng::rand_vec(12).expect("rng iv");
    let total = aead_envelope::seal(AeadAlg::AesGcm256, param_key, &iv, aad, plaintext, None)
        .expect("aead size");
    let mut out = vec![0u8; total];
    let n = aead_envelope::seal(
        AeadAlg::AesGcm256,
        param_key,
        &iv,
        aad,
        plaintext,
        Some(&mut out),
    )
    .expect("aead seal");
    out.truncate(n);
    out
}

/// Open a CO session under the supplied PSK (bypassing the partition
/// default).
pub(super) fn open_co_with(ctx: &TestCtx, psk: &[u8; PSK_LEN]) -> SessionHandshake {
    let opts = OpenSessionInitOptions::new(CO, SessionType::Authenticated).with_psk(psk);
    let pending = ctx
        .open_session_init_with_options(opts)
        .expect("open_session_init under PSK");
    ctx.open_session_finish(pending)
        .expect("open_session_finish under PSK")
}

/// Bootstrap: open CO under the default PSK, rotate to `target_psk`,
/// drop the bootstrap session, and return a fresh CO session opened
/// under the rotated PSK — ready for the in-session command under
/// test.
pub(crate) fn bootstrap_rotated_co(ctx: &TestCtx, target_psk: &[u8; PSK_LEN]) -> SessionHandshake {
    let bootstrap = ctx.open_session(CO, SessionType::Authenticated);
    ctx.change_psk(bootstrap.handshake(), target_psk)
        .expect("rotate CO PSK");
    bootstrap.close().expect("close bootstrap CO session");
    open_co_with(ctx, target_psk)
}
