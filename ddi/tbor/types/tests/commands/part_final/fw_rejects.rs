// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `PartFinal` handler gates that reject **before** the PTA cert-chain
//! walk.
//!
//! These tests supply an empty `certs` slice, so nothing is carried out
//! of band and no SGL Data Block is referenced. That makes them the only
//! part of the `PartFinal` surface that runs on real hardware today: the
//! host-side OOB path is implemented for the emulator only (`ddi/emu`),
//! while `ddi/nix` still rejects non-empty `oob_items`. Everything that
//! needs a real chain lives in [`super::chain_path`] and stays emu-gated.
//!
//! The reachable gates, in the order the firmware applies them
//! (`fw/core/lib/src/ddi/tbor/part_final.rs`):
//!
//! 1. `parse_request` — CO-only role gate, then the
//!    `prev_local_mk_backup` length check.
//! 2. `handle` — the `Initializing` lifecycle gate, then
//!    `SHA-384(part_policy) == policy_hash`.
//!
//! Only after those does `validate_pta_chain` touch the OOB page, so
//! everything above is testable on silicon.

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
use azihsm_ddi_tbor_types::PSK_LEN;

use super::*;
use crate::commands::part_init::CU;
use crate::commands::part_init::ROTATED_CU_PSK;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::session_guard::SessionGuard;
use crate::harness::SessionOpenInitOptions;

/// Rotates the PSK for `role`, closes the bootstrap session, and opens a
/// new guarded session under the rotated credential.
///
/// `PartFinal` sits behind the dispatcher's default-PSK gate, so a
/// session opened on the factory PSK would be rejected there rather than
/// by the handler gate under test. Rotating first makes the request reach
/// the handler. Mirrors the helper in `part_init::fw_rejects`.
fn rotate_psk_and_open_role<'a>(
    ctx: &'a TestCtx,
    role: u8,
    sty: SessionType,
    rotated_psk: &[u8; PSK_LEN],
) -> SessionGuard<'a> {
    let bootstrap = ctx.open_session(role, sty).expect("open bootstrap session");

    ctx.psk_change(bootstrap.handshake(), rotated_psk)
        .expect("rotate role PSK");

    bootstrap
        .close()
        .expect("close bootstrap session after PSK rotation");

    let opts = SessionOpenInitOptions::new(role, sty).with_psk(rotated_psk);
    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("session_open_init under rotated PSK");
    let handshake = ctx
        .session_open_finish(pending)
        .expect("session_open_finish under rotated PSK");
    SessionGuard::new(ctx, handshake)
}

/// `PartFinal` is CO-only: a CU session must be rejected by the handler's
/// role gate with [`TborStatus::InvalidPermissions`].
///
/// The CU PSK is rotated first so the request clears the default-PSK
/// dispatcher gate and actually reaches the role check.  This is the
/// first gate in `parse_request`, so it fires before the cert-chain walk
/// and needs no out-of-band data.
#[test]
fn part_final_reject_cu_session() {
    let ctx = TestCtx::new();

    let session = rotate_psk_and_open_role(&ctx, CU, SessionType::PlainText, &ROTATED_CU_PSK);
    let policy = known_good_part_policy();

    let err = ctx
        .part_final(session.handshake(), &policy, &[], &[])
        .expect_err("PartFinal on a CU session must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidPermissions);
}

/// A present-but-wrong-length `prev_local_mk_backup` must be rejected.
///
/// The field is variable (empty = absent); when present it must be
/// exactly [`LOCAL_MK_BACKUP_LEN`].  `PartInit` runs first so the
/// partition is `Initializing` — that way the rejection comes from the
/// length check in `parse_request` rather than the lifecycle gate, which
/// also surfaces `InvalidArg`.
#[test]
fn part_final_reject_bad_prev_backup_len() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();

    ctx.part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit roundtrip");

    // Non-empty (so "absent" does not apply) but not the envelope length.
    let short_backup = [0u8; LOCAL_MK_BACKUP_LEN - 1];

    let err = ctx
        .part_final(&session, &policy, &short_backup, &[])
        .expect_err("PartFinal with a wrong-length prev backup must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// `PartFinal` before `PartInit` must be rejected: the partition is not
/// in the `Initializing` lifecycle state.  This gate fires before the
/// cert-chain walk, so no chain is supplied.
#[test]
fn part_final_reject_wrong_state() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();

    ctx.part_final(&session, &policy, &[], &[])
        .expect_err("PartFinal without PartInit must be rejected by the state gate");
}

/// `PartFinal` re-supplying a policy that does not match the one bound at
/// `PartInit` must be rejected (`SHA-384(part_policy) != policy_hash`).
/// This gate fires before the cert-chain walk, so no chain is supplied.
#[test]
fn part_final_reject_policy_mismatch() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();

    ctx.part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit roundtrip");

    // Flip a byte in the `info` tail (still a structurally valid policy,
    // but a different SHA-384 digest).
    let mut wrong = policy;
    let last = wrong.len() - 2;
    wrong[last] ^= 0x01;

    ctx.part_final(&session, &wrong, &[], &[])
        .expect_err("PartFinal with a mismatched policy must be rejected");
}
