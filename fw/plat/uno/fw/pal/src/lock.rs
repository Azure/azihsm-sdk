// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmPartitionLock`] implementation for the Uno PAL.
//!
//! Per-partition async mutex, one [`embassy_sync`] [`Mutex`] per slot. The
//! uno firmware runs on a single-core cooperative Embassy executor, so
//! contention only ever arises between co-operatively scheduled tasks.
//!
//! A [`CriticalSectionRawMutex`] (rather than the `NoopRawMutex` the std PAL
//! uses for its owned, non-`static` lock array) lets the lock table live in a
//! `static`: it is `Sync`, and it integrates with the `cortex-m`
//! single-core `critical-section` implementation the app links. The critical
//! section is only entered briefly while manipulating the mutex's own state on
//! lock/unlock — it is *not* held across the guard's lifetime, so a handler may
//! `.await` while holding the guard (the point of an async mutex).
//!
//! Handlers that perform a multi-step read-modify-write of partition state
//! across an `.await` take this lock so the sequence is serialised per
//! partition. `GetUnwrappingKey`'s first-use key import is the motivating
//! case: it must `.await` the GDMA vault import between reading
//! `unwrapping_key_id` and committing it, so without the lock two concurrent
//! first-use requests for the same partition could both import the key. This
//! mirrors the std reference PAL, whose shared handlers already take this lock.

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPartitionLock;
use azihsm_fw_hsm_pal_traits::HsmResult;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_sync::mutex::MutexGuard;

use crate::UnoHsmPal;
use crate::part::NUM_PARTITIONS;

/// Per-partition locks. Runtime-only — independent of the persistent slot
/// layout in the partition store.
static PART_LOCKS: [Mutex<CriticalSectionRawMutex, ()>; NUM_PARTITIONS] =
    [const { Mutex::new(()) }; NUM_PARTITIONS];

impl HsmPartitionLock for UnoHsmPal {
    type PartitionGuard<'a> = MutexGuard<'a, CriticalSectionRawMutex, ()>;

    async fn partition_lock(&self, io: &impl HsmIo) -> HsmResult<Self::PartitionGuard<'_>> {
        let idx = usize::from(u8::from(io.pid()));
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        Ok(PART_LOCKS[idx].lock().await)
    }
}
