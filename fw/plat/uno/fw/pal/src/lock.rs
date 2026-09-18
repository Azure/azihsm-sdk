// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmPartitionLock`] implementation for the Uno PAL.
//!
//! Per-partition [`embassy_sync::mutex::Mutex`] serializing state-mutating
//! DDI handlers. Mirrors `fw/plat/std/pal/src/part_lock.rs`.

#![allow(unsafe_code)]

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPartitionLock;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_uno_drivers_part_store::NUM_PARTITIONS;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_sync::mutex::MutexGuard;

use crate::UnoHsmPal;

/// Per-partition async mutex table, one slot per partition id.
struct PartLocks([Mutex<NoopRawMutex, ()>; NUM_PARTITIONS]);

// SAFETY: single-core Cortex-M7 with Embassy cooperative scheduling; no
// ISR accesses these mutexes.
unsafe impl Sync for PartLocks {}

static PART_LOCKS: PartLocks = PartLocks([const { Mutex::new(()) }; NUM_PARTITIONS]);

impl HsmPartitionLock for UnoHsmPal {
    type PartitionGuard<'a> = MutexGuard<'a, NoopRawMutex, ()>;

    async fn partition_lock(&self, io: &impl HsmIo) -> HsmResult<Self::PartitionGuard<'_>> {
        let idx = usize::from(u8::from(io.pid()));
        let slot = PART_LOCKS.0.get(idx).ok_or(HsmError::InvalidArg)?;
        Ok(slot.lock().await)
    }
}
