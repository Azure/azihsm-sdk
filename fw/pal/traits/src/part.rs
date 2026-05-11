// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition management types and traits.
//!
//! Defines the [`HsmPartitionManager`] trait used by core to query
//! and mutate per-partition state.  Each partition is a host-facing
//! controller interface identified by [`HsmPartId`]; the firmware
//! supports up to `HSM_NUM_PARTITIONS` of them, addressed implicitly
//! through the [`HsmIo`] handle (`io.pid()`).
//!
//! ## Per-partition state
//!
//! Each partition slot owns:
//!
//! - A [`PartState`] lifecycle field.
//! - A resource count (number of host-allocated SQ/CQ pairs).
//! - An opaque identity blob ([`PartId`]) and an ECC-P384 identity
//!   key pair.
//! - A pair of crypto material slots used during credential
//!   establishment and session setup:
//!   - **establish-cred** — one-time RSA-OAEP keypair used to receive
//!     the host's bootstrap credential. Cleared after use.
//!   - **session-enc** — long-lived ECDH key used to derive
//!     per-session encryption keys.
//! - A 32-byte randomness nonce, refreshed per credential / session
//!   event.
//! - An optional sealed BK3 blob (set once, ≤ 1024 bytes).
//!
//! ## Lifecycle
//!
//! ```text
//! Unallocated ── allocate resources + identity ──▶ Allocated
//!                                                      │
//!                          generate internal keys + nonce
//!                                                      ▼
//!                                                  Enabled ──▶ Disabled
//!                                                                │
//!                                              re-enable internal keys
//!                                                                │
//!                                                                ▼
//!                                                            Enabled
//! ```
//!
//! ## Implicit partition addressing
//!
//! All trait methods take an [`HsmIo`] handle rather than an explicit
//! [`HsmPartId`].  The partition is resolved via [`HsmIo::pid`].  This
//! prevents accidental cross-partition queries and keeps the trait
//! shape uniform with the rest of the PAL.

use super::*;

/// Opaque identity blob for a partition.
///
/// Returned by [`HsmPartitionManager::part_id`].  The slice borrows
/// directly from partition state and is valid for the duration of the
/// `&self` borrow on the [`HsmPartitionManager`] implementation.  The
/// content is treated as opaque by core; only the host knows how to
/// interpret it.
pub type PartId<'a> = &'a [u8];

/// Lifecycle state of a partition slot.
///
/// State transitions are driven by host management commands; this
/// enum is the canonical observation point for downstream code (DDI
/// dispatch, IO gating, vault/session scoping).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartState {
    /// The partition slot is free.  No resources, no identity, no
    /// keys.  IO arriving for this partition is dropped.
    Unallocated,

    /// Resources and the ECC-P384 identity key pair are present, but
    /// the establish-cred and session-enc keys plus the nonce have
    /// not been generated yet.  The host must complete provisioning
    /// before DDI traffic is accepted.
    Allocated,

    /// The partition is fully provisioned and ready for DDI
    /// operations.  All internal crypto material (identity,
    /// establish-cred, session-enc, nonce) is present.
    Enabled,

    /// The partition was previously [`Enabled`](Self::Enabled) and has
    /// been disabled by the host.  Internal crypto material, vault
    /// keys, and sessions are cleared, but the resource allocation
    /// and identity key pair are retained so the partition can be
    /// re-enabled without a full re-provision.
    Disabled,
}

/// Partition manager interface.
///
/// All methods take an [`HsmIo`] handle and operate on the partition
/// resolved from `io.pid()`.  The trait is `&self`; PAL
/// implementations are expected to use interior mutability.
///
/// Methods returning `usize` follow a uniform query/copy pattern: pass
/// `out = None` to obtain the required buffer size, then call again
/// with `out = Some(&mut buf[..size])` to perform the copy.  Both
/// calls return the same canonical size.
pub trait HsmPartitionManager {
    /// Returns the lifecycle state of the calling partition.
    ///
    /// Cheap probe used by IO dispatch to drop traffic for
    /// non-[`Enabled`](PartState::Enabled) partitions.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition selected via
    ///   [`HsmIo::pid`]).
    ///
    /// # Returns
    ///
    /// - `Ok(state)` — the current [`PartState`].
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range
    ///   for this build.
    fn part_state(&self, io: &impl HsmIo) -> HsmResult<PartState>;

    /// Returns the number of host-allocated resources (SQ/CQ pairs)
    /// bound to this partition.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    ///
    /// # Returns
    ///
    /// - `Ok(count)` — number of resources, in the range `0..=u8::MAX`.
    ///   `0` is valid for [`PartState::Unallocated`].
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range.
    fn part_res_count(&self, io: &impl HsmIo) -> HsmResult<u8>;

    /// Borrows the opaque identity blob for the calling partition.
    ///
    /// The returned slice points into partition storage and is valid
    /// for the duration of the `&self` borrow.  Content is opaque to
    /// core.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    ///
    /// # Returns
    ///
    /// - `Ok(id)` — borrowed [`PartId`] slice.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range.
    /// - `Err(HsmError::PartitionNotProvisioned)` — partition is
    ///   [`Unallocated`](PartState::Unallocated).
    fn part_id(&self, io: &impl HsmIo) -> HsmResult<PartId<'_>>;

    /// Returns the vault key ID for the partition's ECC-P384
    /// identity key pair.
    ///
    /// The private key is stored in the vault as
    /// [`HsmVaultKeyKind::Ecc384Private`] with `sign + local +
    /// internal` attributes set.  The corresponding public key is
    /// served by [`part_id_pub_key`](Self::part_id_pub_key).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    ///
    /// # Returns
    ///
    /// - `Ok(key_id)` — vault [`HsmKeyId`] for the identity private
    ///   key.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range.
    /// - `Err(HsmError::PartitionNotProvisioned)` — partition is
    ///   [`Unallocated`](PartState::Unallocated) (no identity key yet).
    fn part_id_key_id(&self, io: &impl HsmIo) -> HsmResult<HsmKeyId>;

    /// Returns the DER-encoded SubjectPublicKeyInfo for the
    /// partition's identity key, optionally copying it into a
    /// caller-supplied buffer.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `out` —
    ///   - `None` — query mode; no copy is performed, just return the
    ///     required size.
    ///   - `Some(buf)` — copy mode; the encoded key is written to
    ///     `buf[..size]`.  `buf.len()` must be ≥ size.
    ///
    /// # Returns
    ///
    /// - `Ok(size)` — number of bytes that were (or would be) written.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range, or
    ///   `out` is `Some(buf)` and `buf.len() < size`.
    /// - `Err(HsmError::PartitionNotProvisioned)` — no identity key.
    fn part_id_pub_key(&self, io: &impl HsmIo, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Returns the vault key ID of the establish-credential
    /// encryption key, if present.
    ///
    /// The establish-cred key is a one-time-use RSA-OAEP keypair
    /// generated when the partition transitions to
    /// [`Enabled`](PartState::Enabled).  Core calls
    /// [`part_clear_establish_cred_key`](Self::part_clear_establish_cred_key)
    /// once the bootstrap credential has been received, after which
    /// this method returns `Ok(None)`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(key_id))` — key is present in the vault.
    /// - `Ok(None)` — key has been cleared (one-time-use complete).
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_establish_cred_key_id(&self, io: &impl HsmIo) -> HsmResult<Option<HsmKeyId>>;

    /// Returns the DER-encoded SubjectPublicKeyInfo for the
    /// establish-credential encryption key, optionally copying it.
    ///
    /// Follows the same query/copy pattern as
    /// [`part_id_pub_key`](Self::part_id_pub_key).  After the key has
    /// been cleared, returns `Ok(0)` (no data, no error) so callers
    /// can treat absence as a `len == 0` reply.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `out` — `None` for size query, `Some(buf)` to copy.
    ///
    /// # Returns
    ///
    /// - `Ok(size)` — bytes that were (or would be) written; `0` if
    ///   the key has been cleared.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range, or
    ///   `out = Some(buf)` and `buf.len() < size`.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_establish_cred_pub_key(
        &self,
        io: &impl HsmIo,
        out: Option<&mut [u8]>,
    ) -> HsmResult<usize>;

    /// Removes the establish-credential encryption key from the
    /// vault.
    ///
    /// Implements the one-time-use pattern: core calls this after
    /// the bootstrap credential has been received.  Idempotent —
    /// calling on an already-cleared key returns `Ok(())`.  After
    /// this call,
    /// [`part_establish_cred_key_id`](Self::part_establish_cred_key_id)
    /// returns `Ok(None)` and
    /// [`part_establish_cred_pub_key`](Self::part_establish_cred_pub_key)
    /// returns `Ok(0)`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success or if already cleared.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_clear_establish_cred_key(&self, io: &impl HsmIo) -> HsmResult<()>;

    /// Returns the vault key ID of the session encryption key.
    ///
    /// Unlike the establish-cred key, this key is long-lived and is
    /// reused for every session opened against this partition.  It
    /// is regenerated only on disable→enable transitions.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    ///
    /// # Returns
    ///
    /// - `Ok(key_id)` — vault [`HsmKeyId`] for the session-enc
    ///   private key.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_session_enc_key_id(&self, io: &impl HsmIo) -> HsmResult<HsmKeyId>;

    /// Returns the DER-encoded SubjectPublicKeyInfo for the session
    /// encryption key, optionally copying it.
    ///
    /// Follows the same query/copy pattern as
    /// [`part_id_pub_key`](Self::part_id_pub_key).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `out` — `None` for size query, `Some(buf)` to copy.
    ///
    /// # Returns
    ///
    /// - `Ok(size)` — bytes that were (or would be) written.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range, or
    ///   `out = Some(buf)` and `buf.len() < size`.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_session_enc_pub_key(&self, io: &impl HsmIo, out: Option<&mut [u8]>)
    -> HsmResult<usize>;

    /// Returns the partition's 32-byte random nonce, optionally
    /// copying it.
    ///
    /// The nonce is freshened by
    /// [`part_nonce_refresh`](Self::part_nonce_refresh) on credential
    /// and session events; the size is therefore always 32.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `out` — `None` for size query, `Some(buf)` to copy.
    ///
    /// # Returns
    ///
    /// - `Ok(32)` always (on success), with `buf[..32]` populated when
    ///   `out = Some(buf)`.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range, or
    ///   `out = Some(buf)` and `buf.len() < 32`.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_nonce(&self, io: &impl HsmIo, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Regenerates the partition nonce from the hardware RNG.
    ///
    /// Called by core after credential establishment and session open
    /// to ensure the nonce read by the host has not been observed in
    /// a previous transaction.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    /// - `Err(HsmError)` — propagated from the RNG driver.
    fn part_nonce_refresh(&self, io: &impl HsmIo) -> HsmResult<()>;

    /// Returns the sealed BK3 blob for the partition, optionally
    /// copying it.
    ///
    /// The sealed BK3 is set once via
    /// [`part_set_sealed_bk3`](Self::part_set_sealed_bk3); subsequent
    /// reads return the same blob.  Before any write, returns
    /// `Ok(0)`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `out` — `None` for size query, `Some(buf)` to copy.
    ///
    /// # Returns
    ///
    /// - `Ok(size)` — bytes that were (or would be) written; `0` if
    ///   no sealed BK3 has been stored.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range, or
    ///   `out = Some(buf)` and `buf.len() < size`.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_sealed_bk3(&self, io: &impl HsmIo, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Stores the sealed BK3 blob for the partition.
    ///
    /// Write-once: a second call returns
    /// [`HsmError::SealedBk3AlreadySet`].
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `data` — sealed BK3 bytes; must be ≤ 1024 bytes.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    /// - `Err(HsmError::SealedBk3AlreadySet)` — a sealed BK3 has
    ///   already been stored.
    /// - `Err(HsmError::SealedBk3TooLarge)` — `data.len() > 1024`.
    fn part_set_sealed_bk3(&self, io: &impl HsmIo, data: &[u8]) -> HsmResult<()>;
}
