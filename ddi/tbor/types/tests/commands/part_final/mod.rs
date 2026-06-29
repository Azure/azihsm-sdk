// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end `PartFinal` tests against the std-PAL emulator.
//!
//! `PartFinal` runs after `PartInit` and finalizes the partition: it
//! derives the partition-local masking keys and returns the current
//! `local_mk` backup.  These tests drive the full
//! `OpenSession → PskChange → PartInit → PartFinal` flow.

#![cfg(feature = "emu")]

use crate::commands::part_init::bootstrap_rotated_co;
use crate::commands::part_init::known_good_part_policy;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;
use crate::commands::part_init::ROTATED_CO_PSK;
use crate::harness::TestCtx;

/// Exact on-the-wire `local_mk_backup` length (164 B); the firmware
/// schema (`azihsm_fw_ddi_tbor_types::part_final::LOCAL_MK_BACKUP_LEN`)
/// is the authority.
const LOCAL_MK_BACKUP_LEN: usize = 164;

/// Happy path: `PartInit` then a first-instantiation `PartFinal`
/// (no prior backup) returns a `local_mk_backup` of the pinned length.
#[test]
fn part_final_smoke_roundtrip_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    // PartInit binds the policy hash + UMS and leaves `Initializing`.
    ctx.part_init(&session, &seed, &policy, &thumb)
        .expect("PartInit roundtrip");

    // PartFinal (fresh): no prior backup → mint a PartLocalMK and
    // return its backup.
    let resp = ctx
        .part_final(&session, &policy, &[])
        .expect("PartFinal roundtrip");

    assert_eq!(
        resp.local_mk_backup.len(),
        LOCAL_MK_BACKUP_LEN,
        "local_mk_backup must be the masked-envelope length",
    );
}

/// Restore path: a `local_mk_backup` minted on one (fresh) device is
/// accepted on a second device that re-initializes with the same machine
/// seed/owner; the handler re-derives `PartLocalBMK`, unmasks the prior
/// `PartLocalMK`, and returns a fresh backup of the pinned length.
#[test]
fn part_final_restore_prev_backup_emu() {
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    // First device: mint a backup, then release the device (drops the
    // process-global test lock so a second device can be opened).
    let backup = {
        let ctx1 = TestCtx::new();
        let session1 = bootstrap_rotated_co(&ctx1, &ROTATED_CO_PSK);
        ctx1.part_init(&session1, &seed, &policy, &thumb)
            .expect("PartInit roundtrip");
        ctx1.part_final(&session1, &policy, &[])
            .expect("PartFinal roundtrip")
            .local_mk_backup
    };
    assert_eq!(backup.len(), LOCAL_MK_BACKUP_LEN);

    // Second device, same seed/owner: restore from the prior backup.
    let ctx2 = TestCtx::new();
    let session2 = bootstrap_rotated_co(&ctx2, &ROTATED_CO_PSK);
    ctx2.part_init(&session2, &seed, &policy, &thumb)
        .expect("PartInit roundtrip");
    let resp = ctx2
        .part_final(&session2, &policy, &backup)
        .expect("PartFinal must restore PartLocalMK from a valid prior backup");
    assert_eq!(
        resp.local_mk_backup.len(),
        LOCAL_MK_BACKUP_LEN,
        "restored backup must be re-masked to the envelope length",
    );
}

/// A tampered `prev_local_mk_backup` must be rejected: flipping a byte in
/// the tag-bound metadata makes the re-derived `PartLocalBMK` unmask fail
/// the AEAD tag check, so restore must error rather than mint blindly.
#[test]
fn part_final_reject_tampered_backup_emu() {
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    // First device: mint a backup, then release the test lock.
    let mut backup = {
        let ctx1 = TestCtx::new();
        let session1 = bootstrap_rotated_co(&ctx1, &ROTATED_CO_PSK);
        ctx1.part_init(&session1, &seed, &policy, &thumb)
            .expect("PartInit roundtrip");
        ctx1.part_final(&session1, &policy, &[])
            .expect("PartFinal roundtrip")
            .local_mk_backup
    };

    // Corrupt the ciphertext/tag region; AEAD verification must fail.
    let last = backup.len() - 1;
    backup[last] ^= 0x01;

    let ctx2 = TestCtx::new();
    let session2 = bootstrap_rotated_co(&ctx2, &ROTATED_CO_PSK);
    ctx2.part_init(&session2, &seed, &policy, &thumb)
        .expect("PartInit roundtrip");
    ctx2.part_final(&session2, &policy, &backup)
        .expect_err("PartFinal with a tampered backup must fail the AEAD tag check");
}

/// `PartFinal` before `PartInit` must be rejected: the partition is not
/// in the `Initializing` lifecycle state.
#[test]
fn part_final_reject_wrong_state_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();

    ctx.part_final(&session, &policy, &[])
        .expect_err("PartFinal without PartInit must be rejected by the state gate");
}

/// `PartFinal` re-supplying a policy that does not match the one bound at
/// `PartInit` must be rejected (`SHA-384(part_policy) != policy_hash`).
#[test]
fn part_final_reject_policy_mismatch_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    ctx.part_init(&session, &seed, &policy, &thumb)
        .expect("PartInit roundtrip");

    // Flip a byte in the `info` tail (still a structurally valid policy,
    // but a different SHA-384 digest).
    let mut wrong = policy;
    let last = wrong.len() - 2;
    wrong[last] ^= 0x01;

    ctx.part_final(&session, &wrong, &[])
        .expect_err("PartFinal with a mismatched policy must be rejected");
}

/// Regression: after `PartFinal` the partition is `Initialized`, and an
/// `Initialized` partition must continue to serve host IO (the dispatch
/// enable gate includes `Initialized`).  Before that fix any
/// post-finalize command — here `PartInfo` — was silently dropped as a
/// "disabled partition".
#[test]
fn part_final_partition_serves_io_when_initialized_emu() {
    use azihsm_ddi_tbor_types::TborPartInfoReq;

    /// `PartState::Initialized` wire discriminant.
    const PART_STATE_INITIALIZED: u8 = 5;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();

    ctx.part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit");
    ctx.part_final(&session, &policy, &[]).expect("PartFinal");

    // The partition is now Initialized; a follow-up command must still be
    // served rather than dropped as a disabled partition.
    let info = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo after PartFinal must be served");
    assert_eq!(
        info.part_state, PART_STATE_INITIALIZED,
        "PartInfo must report Initialized after PartFinal",
    );
}
