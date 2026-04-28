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

/// Represents the current state of a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartState {
    /// Partition slot is not allocated. No resources assigned.
    Unallocated,

    /// Partition is allocated with resources and identity key pair, but
    /// internal crypto keys (establish-cred, session-enc) and nonce
    /// have not been created yet.
    Allocated,

    /// Partition is fully operational. Internal keys and nonce are
    /// present. DDI operations can proceed.
    Enabled,

    /// Partition has been disabled. Internal keys, nonce, vault keys,
    /// and sessions are cleared, but resources and identity remain.
    /// Can be re-enabled via `part_enable`.
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

    /// Returns the vault key ID for the partition's identity ECC-384 key.
    ///
    /// The private key is stored in the vault as `Ecc384Private` with
    /// `sign + local + internal` attributes.
    fn part_id_key_id(&self, pid: u8) -> HsmResult<HsmKeyId>;

    /// Returns the DER-encoded public key for the partition's identity key.
    ///
    /// Pass `None` to query the size; pass `Some(buf)` to copy into `buf`.
    fn part_id_pub_key(&self, pid: u8, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Returns the establish-credential encryption key ID.
    ///
    /// Returns `None` if the key has been cleared (one-time use pattern)
    /// or if the partition is not in [`Enabled`](PartState::Enabled) state.
    fn part_establish_cred_key_id(&self, pid: u8) -> HsmResult<Option<HsmKeyId>>;

    /// Returns the DER-encoded public key for establish-credential encryption.
    ///
    /// Pass `None` to query the size; pass `Some(buf)` to copy into `buf`.
    /// Returns 0 if the key has been cleared.
    fn part_establish_cred_pub_key(&self, pid: u8, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Clear the establish-credential encryption key from the vault.
    ///
    /// After clearing, [`part_establish_cred_key_id`](Self::part_establish_cred_key_id)
    /// returns `None`.  This implements the one-time-use pattern: the
    /// core calls this after credential establishment completes.
    ///
    /// Idempotent — calling on an already-cleared key succeeds silently.
    fn part_clear_establish_cred_key(&self, pid: u8) -> HsmResult<()>;

    /// Returns the session encryption key ID.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the partition is not [`Enabled`](PartState::Enabled).
    fn part_session_enc_key_id(&self, pid: u8) -> HsmResult<HsmKeyId>;

    /// Returns the DER-encoded public key for session encryption.
    ///
    /// Pass `None` to query the size; pass `Some(buf)` to copy into `buf`.
    fn part_session_enc_pub_key(&self, pid: u8, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Returns the 32-byte random nonce for the partition.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the partition is not [`Enabled`](PartState::Enabled).
    fn part_nonce(&self, pid: u8) -> HsmResult<&[u8]>;

    /// Refresh (regenerate) the partition nonce from the RNG.
    ///
    /// Called after credential establishment or session open to ensure
    /// nonce freshness.
    fn part_nonce_refresh(&self, pid: u8) -> HsmResult<()>;
}
