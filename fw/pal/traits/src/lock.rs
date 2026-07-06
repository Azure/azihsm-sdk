// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-partition async lock trait.
//!
//! Defines [`HsmPartitionLock`] which provides per-partition mutual
//! exclusion for DDI handlers that modify partition state (session
//! open/close, key create/delete, credential establishment).
//!
//! ## Purpose
//!
//! On Embassy's single-threaded co-operative executor, tasks interleave
//! at `.await` points.  A multi-step DDI handler (e.g., OpenSession:
//! derive key → create vault entry → allocate session slot) must not
//! be interleaved with another handler on the **same partition**.
//! The partition lock serializes these operations.
//!
//! Read-only queries (key lookup, state check) typically do not need
//! the lock since they complete synchronously (no `.await` points).
//!
//! ## Implementation
//!
//! The trait uses a GAT (`PartitionGuard<'a>`) so that each PAL can
//! return its own guard type.  The standard PAL uses
//! `embassy_sync::mutex::MutexGuard<'_, NoopRawMutex, ()>`.

use super::*;

/// Per-partition async lock for serializing state-modifying operations.
///
/// Each partition has an independent lock.  Acquiring the lock for
/// partition *A* does not block operations on partition *B*.
///
/// # Usage
///
/// ```text
/// async fn handle_ddi<P: HsmPal>(pal: &P, io: &impl HsmIo) {
///     let _lock = pal.partition_lock(io).await;
///     // Exclusive access to this partition until _lock drops.
///     let _sess_id = pal.session_create(io, api_rev, mk, None)?;
/// }
/// ```
pub trait HsmPartitionLock {
    /// RAII guard returned by [`partition_lock`](Self::partition_lock).
    ///
    /// Holds the per-partition lock until dropped.  The guard does not
    /// dereference to any data — it exists solely for lifetime-based
    /// lock management.
    type PartitionGuard<'a>
    where
        Self: 'a;

    /// Acquire exclusive access to the given partition.
    ///
    /// If another task already holds the lock for this partition, the
    /// caller yields (`.await`) until the lock is released.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidArg`] if `io.pid()` is out of range.
    async fn partition_lock(&self, io: &impl HsmIo) -> HsmResult<Self::PartitionGuard<'_>>;
}
