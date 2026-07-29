// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmPartitionLock`] implementation for the Uno PAL.
//!
//! The Uno PAL is **lock-free**: per-partition serialization is unnecessary.
//! Admin teardown cannot race in-flight host IOs (a partition can't be
//! disabled/freed while host IOs are outstanding), and host↔host overlap is
//! resolved by the handlers' guards-first sync commit.  Legacy MBOR handlers
//! still call [`partition_lock`](HsmPartitionLock::partition_lock), so the
//! trait is implemented as a no-op guard.

use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPartitionLock;
use azihsm_fw_hsm_pal_traits::HsmResult;

use crate::UnoHsmPal;

impl HsmPartitionLock for UnoHsmPal {
    type PartitionGuard<'a> = ();

    /// No-op: the Uno PAL needs no partition lock (see module docs).
    async fn partition_lock(&self, _io: &impl HsmIo) -> HsmResult<Self::PartitionGuard<'_>> {
        Ok(())
    }
}
