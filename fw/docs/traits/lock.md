# HsmPartitionLock — Per-Partition Async Mutex

**Crate:** `azihsm_fw_hsm_pal_traits`
**File:** `fw/pal/traits/src/lock.rs`

## Overview

The partition lock trait provides a per-partition async mutex to serialize DDI command execution within a single partition. Multiple partitions can process commands concurrently, but commands within the same partition are serialized.

## Trait Definition

```rust
pub trait HsmPartitionLock {
    type PartitionGuard<'a>: 'a where Self: 'a;

    async fn partition_lock(&self, pid: HsmPartId) -> HsmResult<Self::PartitionGuard<'_>>;
}
```

| Method | Description |
|--------|-------------|
| `partition_lock(pid)` | Acquires the async mutex for partition `pid`. Returns a guard that releases the lock on drop. Suspends if the lock is already held. |

## Usage

DDI handlers that mutate partition state (e.g., OpenSession, EstablishCredential) acquire the partition lock before proceeding. This ensures that concurrent IOs targeting the same partition are serialized without blocking IOs to other partitions.

```rust
async fn handle_ddi<P: HsmPal>(pal: &P, pid: HsmPartId) {
    let _guard = pal.partition_lock(pid).await?;
    // ... DDI handler runs with exclusive access to partition pid ...
    // guard dropped → lock released
}
```
