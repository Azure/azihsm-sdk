// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for the TBOR security-domain (`emu`-backed)
//! integration tests.
//!
//! These exercise the public `azihsm_api` surface end to end against the
//! FW emulator. `open_session_ex` / `part_*` run against the partition's
//! *default* PSK and identity key, so they need only a freshly reset
//! partition — no MBOR credential establishment (`init`).

use azihsm_api::*;
use parking_lot::Mutex;

/// PSK id selecting the Crypto Officer role.
pub(crate) const CO: u8 = 0;
/// PSK id selecting the Crypto User role.
pub(crate) const CU: u8 = 1;

/// Serialises tests against the process-global FW emulator singleton.
/// `cargo-nextest` runs each test in its own process, but this keeps a
/// plain `cargo test` (single process, multi-threaded) correct too.
pub(crate) static EMU_LOCK: Mutex<()> = Mutex::new(());

/// Open the emu-backed partition at its maximum supported revision and
/// factory-reset it, so each test starts from byte-identical state (no
/// inherited session slots or PSK rotations). Returns the partition and
/// the negotiated api revision.
pub(crate) fn fresh_emu_partition() -> (HsmPartition, HsmApiRev) {
    let info = HsmPartitionManager::partition_info_list()
        .into_iter()
        .next()
        .expect("emu backend should advertise a partition");
    let rev = info
        .api_rev_range
        .expect("emu partition should report an api-rev range")
        .max();
    let part = HsmPartitionManager::open_partition(&info.path, rev).expect("open emu partition");
    part.reset().expect("factory-reset emu partition");
    (part, rev)
}

/// Open a fresh partition and bring up a Crypto-Officer V2 session,
/// ready for the in-session provisioning commands (`part_init_ex` /
/// `part_final_ex`).
pub(crate) fn fresh_co_session() -> HsmSession {
    let (part, rev) = fresh_emu_partition();
    part.open_session_ex(rev, CO, HsmSessionExType::Authenticated)
        .expect("open CO session")
}
