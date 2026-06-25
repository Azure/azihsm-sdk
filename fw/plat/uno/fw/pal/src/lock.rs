// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmPartitionLock`] no-op implementation for the Uno PAL.
//!
//! The Uno firmware is single-threaded with cooperative async
//! scheduling, so partition-level mutual exclusion is not required.
//! [`partition_lock`](HsmPartitionLock::partition_lock) returns a
//! unit-typed guard that performs no action on drop.

#![allow(clippy::unused_async)]

use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPartitionLock;
use azihsm_fw_hsm_pal_traits::HsmResult;

use crate::UnoHsmPal;

impl HsmPartitionLock for UnoHsmPal {
    /// No-op guard. The unit type carries no state and its `Drop` impl
    /// is also a no-op.
    type PartitionGuard<'a>
        = ()
    where
        Self: 'a;

    /// Acquire the (logical) lock for the given partition.
    ///
    /// # Parameters
    /// * `_io` — IO context associated with the request (ignored).
    ///
    /// # Returns
    /// * `Ok(())` — the unit guard, which holds no resources.
    async fn partition_lock(&self, _io: &impl HsmIo) -> HsmResult<Self::PartitionGuard<'_>> {
        Ok(())
    }
}
