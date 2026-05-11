// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmPartitionLock`] implementation for the standard PAL.
//!
//! Uses per-partition [`embassy_sync::mutex::Mutex`] with
//! [`NoopRawMutex`] — correct for Embassy's single-threaded executor
//! where the only contention is between co-operatively scheduled
//! async tasks.

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::MutexGuard;

use super::*;
use crate::part::NUM_PARTITIONS;

impl HsmPartitionLock for StdHsmPal {
    type PartitionGuard<'a> = MutexGuard<'a, NoopRawMutex, ()>;

    async fn partition_lock(&self, io: &impl HsmIo) -> HsmResult<Self::PartitionGuard<'_>> {
        let idx = u8::from(io.pid()) as usize;
        if idx >= NUM_PARTITIONS {
            return Err(HsmError::InvalidArg);
        }
        Ok(self.part_locks[idx].lock().await)
    }
}
