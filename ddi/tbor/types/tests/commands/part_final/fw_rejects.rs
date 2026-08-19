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

use super::*;

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
