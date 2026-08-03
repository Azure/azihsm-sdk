// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for the TBOR security-domain (`session_ex`) integration
//! tests, which run against a real backend (the FW emulator or hardware).
//!
//! These exercise the public `azihsm_api` surface end to end.
//! `open_session_ex` / `part_*` run against the partition's *default* PSK
//! and identity key, so they need only a freshly reset partition — no MBOR
//! credential establishment (`init`).

use azihsm_api::*;
use parking_lot::Mutex;

/// Serialises tests against the single shared partition the backend (emu or
/// hardware) exposes. `cargo-nextest` runs each test in its own process, but
/// this keeps a plain `cargo test` (single process, multi-threaded) correct
/// too.
pub(crate) static PARTITION_LOCK: Mutex<()> = Mutex::new(());

/// Open the backend's partition at its maximum supported revision and
/// factory-reset it, so each test starts from byte-identical state (no
/// inherited session slots or PSK rotations). Returns the partition and
/// the negotiated api revision.
pub(crate) fn new_partition() -> (HsmPartition, HsmApiRev) {
    let info = HsmPartitionManager::partition_info_list()
        .into_iter()
        .next()
        .expect("backend should advertise a partition");
    let rev = info
        .api_rev_range
        .expect("partition should report an api-rev range")
        .max();
    let part = HsmPartitionManager::open_partition(&info.path, rev).expect("open partition");
    part.reset().expect("factory-reset partition");
    (part, rev)
}

/// Open a fresh partition and bring up a Crypto-Officer V2 session,
/// ready for the in-session provisioning commands (`part_init_ex` /
/// `part_final_ex`).
pub(crate) fn new_co_session() -> HsmSession {
    let (part, rev) = new_partition();
    part.open_session_ex(
        rev,
        HsmSessionPsk::new(HsmPskId::CO),
        HsmSessionExType::Authenticated,
    )
    .expect("open CO session")
}
