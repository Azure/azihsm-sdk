// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `PartFinal` handler gates that reject **before** the PTA cert-chain
//! walk.
//!
//! These tests supply an empty `certs` slice. That does not mean no
//! descriptor is sent — the harness still emits a single placeholder
//! [`CertDescriptor`], because the request schema requires one — it
//! means no OOB payload accompanies it. What isolates these tests from
//! the OOB transport is the *order* of the firmware's checks: every gate
//! below rejects before `validate_pta_chain` dereferences the OOB page,
//! so the placeholder is never followed. The tests that supply a real
//! chain live in [`super::chain_path`] and now run on hardware too, via
//! the driver's data-transfer ioctl.
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

use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;

use super::*;
use crate::harness::assertions::assert_fw_rejects;

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
