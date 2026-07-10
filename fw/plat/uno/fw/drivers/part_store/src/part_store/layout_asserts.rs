// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Compile-time layout assertions for the partition-store [`Storage`] slot.
//!
//! These are `const` assertions evaluated in *every* build (including the
//! firmware target), locking the on-storage layout to the reference format.
//! They are not `#[cfg(test)]` unit tests — keeping them in a plain child
//! module preserves that always-on compile-time coverage while keeping the
//! layout checks out of the main source file.

use super::*;

// Lock the layout to the reference 3072-byte slot. The whole partition-store
// GSRAM region (`PART_STORE_T_BASE`..key vault) is sized for exactly
// `NUM_PARTITIONS` of these.
const _: () = assert!(core::mem::size_of::<Storage>() == STORE_SIZE);
const _: () = assert!(STRIDE == STORE_SIZE);
// The ECC keygen engine writes the public keys directly into these fields
// via DMA, which requires 4-byte alignment (see `Storage` field ordering).
const _: () = assert!(core::mem::offset_of!(Storage, ec_pub_key) % 4 == 0);
const _: () = assert!(core::mem::offset_of!(Storage, se_pub_key) % 4 == 0);
