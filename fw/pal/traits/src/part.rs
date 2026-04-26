// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition management types and traits.
//!
//! Defines the [`PartitionManager`] trait for querying and managing HSM
//! partitions. Each partition represents a distinct host controller interface
//! identified by a `u8` index (`pid`).

use super::*;

/// Opaque identity blob for a partition.
pub type PartId<'a> = &'a [u8];

/// Public key portion of a partition's identity key pair.
pub type PartIdPubKey<'a> = &'a [u8];

/// Private key portion of a partition's identity key pair.
pub type PartIdPrivKey<'a> = &'a [u8];

/// A (public, private) key pair for a partition's identity credential.
pub type PartIdKey<'a> = (PartIdPubKey<'a>, PartIdPrivKey<'a>);

/// Represents the current state of a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartState {
    /// The partition has not yet been initialized.
    Uninitialized,

    /// The partition has been initialized and is ready for use.
    Initialized,

    /// The partition has been disabled and cannot be used.
    Disabled,
}

/// Partition manager interface.
///
/// Provides methods for querying partition status, resource allocation, and
/// identity credentials. Each partition is addressed by a `u8` index.
pub trait HsmPartitionManager {
    /// Returns whether the partition identified by `pid` is enabled.
    ///
    /// # Parameters
    /// - `pid` — Partition index.
    ///
    /// # Returns
    /// The current [`PartState`] of the partition identified by `pid`.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the partition index is invalid.
    fn part_state(&self, pid: u8) -> HsmResult<PartState>;

    /// Returns the resource count allocated to the given partition.
    ///
    /// # Parameters
    /// - `pid` — Partition index.
    ///
    /// # Returns
    /// The number of resources allocated to the partition.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the partition index is invalid.
    fn part_res_count(&self, pid: u8) -> HsmResult<u8>;

    /// Returns the opaque identity blob for the given partition.
    ///
    /// # Parameters
    /// - `pid` — Partition index.
    ///
    /// # Returns
    /// A borrowed byte slice ([`PartId`]) containing the partition's identity.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the partition index is invalid.
    fn part_id(&self, pid: u8) -> HsmResult<PartId<'_>>;

    /// Returns the identity key pair (public, private) for the given partition.
    ///
    /// # Parameters
    /// - `pid` — Partition index.
    ///
    /// # Returns
    /// A [`PartIdKey`] tuple of borrowed byte slices for the public and
    /// private keys.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the partition index is invalid.
    fn part_id_key(&self, pid: u8) -> HsmResult<PartIdKey<'_>>;
}
