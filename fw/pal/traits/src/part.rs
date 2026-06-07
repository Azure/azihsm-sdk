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

/// Canonical byte length of a TBOR PartPolicy blob.
pub const PART_POLICY_LEN: usize = 167;

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

    /// The TBOR `PartInit` handler has bound the Partition Trust
    /// Anchor (PTA) key, the partition policy, and the POTA
    /// thumbprint to this incarnation, but partition finalization
    /// has not yet run.  No further `PartInit` is permitted until
    /// the next alloc/free cycle (one-shot enforcement).
    Initializing,
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

    /// Returns the partition's 16-byte VM launch GUID.
    ///
    /// The VM launch GUID identifies the host VM that owns the
    /// partition.  It is established during partition enable and is
    /// always exactly 16 bytes.  Follows the same query/copy pattern
    /// as [`part_id_pub_key`](Self::part_id_pub_key): pass
    /// `out = None` to learn the canonical size, then `Some(buf)` to
    /// copy.
    ///
    /// On the standard PAL this returns a hardcoded value; on real
    /// hardware it returns the platform-supplied GUID.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `out` — `None` for size query, `Some(buf)` to copy.
    ///
    /// # Returns
    ///
    /// - `Ok(16)` on success.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range, or
    ///   `out = Some(buf)` and `buf.len() < 16`.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_vm_launch_guid(&self, io: &impl HsmIo, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Returns the partition's current Security Version Number (SVN).
    ///
    /// Used as masked-key metadata by BK3 masking and other
    /// platform-bound operations.  Application-layer code reads the
    /// SVN through this method rather than touching the underlying
    /// BKS tables, which remain hidden inside the PAL.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    ///
    /// # Returns
    ///
    /// - `Ok(svn)` — current SVN.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_svn(&self, io: &impl HsmIo) -> HsmResult<u64>;

    /// Returns the partition's BKS2 ID.
    ///
    /// BKS2 is always available in firmware (every partition has an
    /// assigned BKS2 seed slot), so this is non-optional.  The
    /// returned identifier is recorded in masked-key metadata so the
    /// blob can later be unmasked against the same BKS2 lineage.
    /// `BKS1` / `BKS2` themselves are never exposed to
    /// application-layer code.
    ///
    /// Note: the wire-format metadata field
    /// [`bks2_index`](azihsm_fw_ddi_mbor_types::masked_key::DdiMaskedKeyMetadata::bks2_index)
    /// is `Option<u16>` only for backward compatibility with legacy
    /// blobs from the prior reference firmware that were masked with
    /// `None`; firmware code that produces new masked keys must
    /// always populate the value returned by this method.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    ///
    /// # Returns
    ///
    /// - `Ok(id)` — BKS2 identifier for the current partition.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_bks2_id(&self, io: &impl HsmIo) -> HsmResult<u16>;

    /// Returns the partition's `BK_BOOT` boot-key material.
    ///
    /// `BK_BOOT` is a per-partition secret created during partition
    /// enable (on real hardware derived from `BKS1`/`BKS2` via the
    /// platform key engine; on the std PAL emulator it is opaque
    /// random material).  It is the input to BK3 masking performed by
    /// the `DdiInitBk3` handler.  `BK_BOOT` is treated as a secret;
    /// the partition lifecycle clears it on every disable/free, and
    /// the platform must not log it.
    ///
    /// Follows the same query/copy pattern as
    /// [`part_id_pub_key`](Self::part_id_pub_key): pass `out = None`
    /// to learn the canonical length, then `Some(buf)` to copy.
    /// `buf.len()` must be `>=` the returned length or the call
    /// returns [`HsmError::InvalidArg`].
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `out` — `None` for size query, `Some(buf)` to copy.
    ///
    /// # Returns
    ///
    /// - `Ok([`BK_BOOT_LEN`])` on success.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range, or
    ///   `out = Some(buf)` and `buf.len() < BK_BOOT_LEN`.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_bk_boot(&self, io: &impl HsmIo, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Returns whether BK3 has been initialized for the current
    /// partition incarnation.
    ///
    /// Used by the `DdiInitBk3` handler as a fail-fast check before
    /// performing masking work.  The authoritative one-shot commit is
    /// [`part_mark_bk3_initialized`](Self::part_mark_bk3_initialized);
    /// this read-only getter is intentionally lock-free.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — `InitBk3` has succeeded for the current
    ///   partition incarnation.
    /// - `Ok(false)` — `InitBk3` has not yet been issued for the
    ///   current partition incarnation.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_is_bk3_initialized(&self, io: &impl HsmIo) -> HsmResult<bool>;

    /// Atomically commits the BK3 init state to initialized.
    ///
    /// This is the authoritative one-shot gate for `DdiInitBk3`.
    /// Concurrent or repeated callers race here: the first call
    /// succeeds and subsequent calls return
    /// [`HsmError::Bk3AlreadyInitialized`].  Handler-level partition
    /// write-lock serialization is an optimization, not the
    /// correctness barrier.
    ///
    /// Callers must perform any masking-or-encoding work that should
    /// be visible to the host *before* calling this method, because
    /// once the state has transitioned no further `InitBk3` will
    /// succeed for the current partition incarnation.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — state transitioned from not-initialized to
    ///   initialized.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    /// - `Err(HsmError::Bk3AlreadyInitialized)` — BK3 has already
    ///   been initialized for the current partition incarnation.
    fn part_mark_bk3_initialized(&self, io: &impl HsmIo) -> HsmResult<()>;

    /// Returns the partition's `Masked_BK_BOOT` envelope.
    ///
    /// `Masked_BK_BOOT` is the AES-CBC-256 + HMAC-SHA-384 envelope
    /// of raw `BK_BOOT` under `BKx`, persisted by the `DdiInitBk3`
    /// handler via
    /// [`part_set_masked_bk_boot`](Self::part_set_masked_bk_boot).
    /// Subsequent handlers (e.g. `DdiEstablishCredential`) read this
    /// blob and recover raw `BK_BOOT` via
    /// `key_masking::cbc::unmask` so plaintext `BK_BOOT` never needs to
    /// be persisted across calls.
    ///
    /// Follows the same query/copy pattern as
    /// [`part_sealed_bk3`](Self::part_sealed_bk3): pass `out = None`
    /// to learn the encoded length, then `Some(buf)` to copy.  The
    /// length is variable (≤ [`MASKED_BK_BOOT_LEN`]) because the
    /// envelope's metadata size depends on the encoded labels and
    /// fields.  Before any successful [`part_set_masked_bk_boot`]
    /// call, returns `Ok(0)` — callers that require an initialised
    /// blob (e.g. unmask paths) must treat a returned length of `0`
    /// as "not yet initialised" and surface an appropriate error to
    /// the host.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `out` — `None` for size query, `Some(buf)` to copy.
    ///
    /// # Returns
    ///
    /// - `Ok(size)` — bytes that were (or would be) written; `0` if
    ///   no `Masked_BK_BOOT` has been stored yet.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range, or
    ///   `out = Some(buf)` and `buf.len() < size`.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_masked_bk_boot(&self, io: &impl HsmIo, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Persists `Masked_BK_BOOT` for the partition.
    ///
    /// Called by the `DdiInitBk3` handler after producing the
    /// AES-CBC-256 + HMAC-SHA-384 envelope of raw `BK_BOOT` under
    /// `BKx` (derived per-call via
    /// [`derive_masking_key`](Self::derive_masking_key)).  The blob
    /// is stored alongside other partition state and cleared on
    /// every disable/free.
    ///
    /// Overwrite-allowed: a retry of `DdiInitBk3` after a partial
    /// failure will re-envelope the same `BK_BOOT` (with a fresh IV)
    /// and write the new blob.  The handler-level one-shot gate
    /// ([`part_mark_bk3_initialized`](Self::part_mark_bk3_initialized))
    /// is the authoritative idempotency barrier.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `data` — masked envelope bytes; must be
    ///   `<= MASKED_BK_BOOT_LEN`.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range, or
    ///   `data.len() > MASKED_BK_BOOT_LEN`.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_set_masked_bk_boot(&self, io: &impl HsmIo, data: &[u8]) -> HsmResult<()>;

    /// Returns a borrow of the PAL-internal firmware boot seed
    /// (`FBS` / `fw_seed`).
    ///
    /// The returned slice points into PAL-owned storage; the caller
    /// must not retain it past the current request scope.  Typical
    /// use is passing it straight to
    /// [`derive_masking_key`](Self::derive_masking_key) as the KDK
    /// for `BKx`-style derivations:
    ///
    /// ```ignore
    /// pal.derive_masking_key(io, pal.fw_seed(), label, extra, svn, bks2, out).await?;
    /// ```
    ///
    /// The returned slice is secret material; it must never be
    /// logged, copied into non-secret state, or returned over the
    /// wire.  The PAL is responsible for ensuring the underlying
    /// storage is DMA-stageable (the implementation of
    /// [`derive_masking_key`](Self::derive_masking_key) typically
    /// copies it into a DMA scratch buffer before invoking the
    /// SP 800-108 driver).
    fn fw_seed(&self) -> &[u8];

    /// Derives an 80-byte masking key for [`BK_BOOT_LEN`]-sized
    /// `MaskedKey` envelopes using SP 800-108 Counter Mode KBKDF
    /// with HMAC-SHA-384.
    ///
    /// The effective KDF context is
    /// `BKS1[svn] || BKS2[bks2_index] || extra_context`, where
    /// `BKS1`/`BKS2` are partition-binding seed tables held in the
    /// PAL.  The `svn` and `bks2_index` arguments select rows from
    /// those tables; they are *not* mixed into the context as raw
    /// integers.  Only the BKS tables are PAL-internal; the KDK is
    /// caller-supplied so the same primitive can derive multiple
    /// flavours of masking key:
    ///
    /// | Derivation | KDK | `label` | `extra_context` |
    /// |---|---|---|---|
    /// | `BKx` for `Masked_BK_BOOT` | [`fw_seed`](Self::fw_seed) | `b"BK_BOOT_MK_DEFAULT"` | `&[]` |
    /// | Partition `BK` | partition `BK3` | `b"PARTITION_BK"` ‖ `pota_pub_key` | `&[]` |
    /// | Session `BK` | session `BK3` | `b"SESSION_BK"` | `session_seed` |
    ///
    /// ## Caller responsibilities
    ///
    /// - `InitBk3` (forward direction) passes the *current* partition
    ///   values from [`part_svn`](Self::part_svn) and
    ///   [`part_bks2_id`](Self::part_bks2_id), so the produced key
    ///   binds the new `Masked_BK_BOOT` to today's firmware and
    ///   partition.
    /// - Recovery paths (e.g. `EstablishCredential` unwrapping a
    ///   stored `Masked_BK_BOOT`) must pass the `svn` and
    ///   `bks2_index` decoded from the masked-key metadata, not the
    ///   "current" PAL values — otherwise post-rotation recovery will
    ///   fail.
    /// - The caller is responsible for selecting the appropriate KDK
    ///   for the derivation flavour (typically a borrow of
    ///   [`fw_seed`](Self::fw_seed) or an unmasked `BK3` already in
    ///   DMA scratch).
    ///
    /// ## Memory contract
    ///
    /// `kdk`, `label`, and `extra_context` are plain byte slices; the
    /// PAL implementation is responsible for staging them (along
    /// with `BKS1` and `BKS2`) into DMA-capable memory before
    /// invoking the underlying SP 800-108 driver.  `output` must
    /// already be DMA-accessible (typically allocated via
    /// [`HsmAlloc::dma_alloc`]); the implementation writes the
    /// derived key directly into it without an intermediate copy.
    ///
    /// `output.len()` selects the output length; for `BK_BOOT`
    /// masking this is always [`BK_BOOT_LEN`].  The derived key is
    /// secret material and must never be logged or copied into
    /// non-secret state.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `kdk` — KBKDF key-derivation key (e.g.
    ///   [`fw_seed`](Self::fw_seed) for `BKx`, or unmasked `BK3` for
    ///   partition/session `BK` derivations).
    /// - `label` — KBKDF purpose label; e.g. `b"BK_BOOT_MK_DEFAULT"`.
    ///   `&[]` is permitted (no label).
    /// - `extra_context` — caller-supplied context suffix appended
    ///   after `BKS1 || BKS2`.  `&[]` is permitted (no suffix).
    /// - `svn` — selects which row of the PAL-internal `BKS1` table
    ///   to use.  Values out of range for this PAL must error with
    ///   [`HsmError::InvalidArg`].
    /// - `bks2_index` — selects which row of the PAL-internal `BKS2`
    ///   table to use.  Values out of range must error with
    ///   [`HsmError::InvalidArg`].
    /// - `output` — DMA-accessible destination for the derived key.
    ///   `output.len()` bytes are written.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `output` filled with the derived masking key.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range,
    ///   `svn` or `bks2_index` is out of range, or `output.len()`
    ///   exceeds the KBKDF block-counter cap.
    /// - `Err(HsmError::NotEnoughSpace)` — DMA arena cannot satisfy
    ///   the internal staging allocations.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    /// - `Err(HsmError)` — propagated from the underlying KBKDF
    ///   driver.
    #[allow(clippy::too_many_arguments)]
    async fn derive_masking_key(
        &self,
        io: &impl HsmIo,
        kdk: &[u8],
        label: &[u8],
        extra_context: &[u8],
        svn: u64,
        bks2_index: u16,
        output: &mut DmaBuf,
    ) -> HsmResult<()>;

    // ------------------------------------------------------------------
    // Establish-credential and provisioning state
    // ------------------------------------------------------------------

    /// Verifies that the provided nonce matches the partition's current
    /// nonce.
    ///
    /// Returns `Ok(())` if the nonces match, or
    /// `Err(HsmError::NonceMismatch)` if they differ.  The check is
    /// constant-time where supported by the platform.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `nonce` — 32-byte nonce to compare against the partition's
    ///   stored nonce.
    fn part_verify_nonce(&self, io: &impl HsmIo, nonce: &[u8]) -> HsmResult<()>;

    /// Stores the user credential (ID and PIN) for the partition.
    ///
    /// Write-once per credential lifecycle: if credentials are already
    /// set, returns [`HsmError::VaultAppLimitReached`] (matching the
    /// `verify_cred_is_not_set` behavior in real firmware).  The PAL is
    /// responsible for storing the credential securely and clearing it
    /// on partition disable/deprovision.
    ///
    /// Both `id` and `pin` are exactly 16 bytes (AES block size).  An
    /// all-zero `id` or `pin` is rejected with
    /// [`HsmError::InvalidAppCredentials`], matching the reference
    /// firmware's `cred_mgr::change_user_cred` invariant.  The all-zero
    /// value is also the sentinel that `part_is_credential_set` uses
    /// for "unset", so accepting it would corrupt the lifecycle.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `id` — 16-byte user credential identifier (non-zero).
    /// - `pin` — 16-byte user credential PIN (non-zero).
    fn part_set_credential(&self, io: &impl HsmIo, id: &[u8], pin: &[u8]) -> HsmResult<()>;

    /// Returns whether the partition's user credential is already set.
    fn part_is_credential_set(&self, io: &impl HsmIo) -> HsmResult<bool>;

    /// Constant-time compares `id` and `pin` against the partition's
    /// stored user credential.
    ///
    /// Used by `OpenSession` to authenticate the credential the host
    /// just decrypted from the wrapped session-credential payload.
    /// Both fields are compared even when the first mismatches so a
    /// timing side-channel cannot distinguish "wrong id" from "wrong
    /// pin" — both yield [`HsmError::InvalidAppCredentials`].
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `id` — 16-byte user credential identifier to compare.
    /// - `pin` — 16-byte user credential PIN to compare.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — both `id` and `pin` match the stored credential.
    /// - `Err(HsmError::InvalidAppCredentials)` — credential is not
    ///   yet set, or either field does not match.
    /// - `Err(HsmError::InvalidArg)` — `id` or `pin` length differs
    ///   from 16 bytes.
    fn part_verify_credential(&self, io: &impl HsmIo, id: &[u8], pin: &[u8]) -> HsmResult<()>;

    /// Returns whether the partition has been fully provisioned.
    ///
    /// A partition is provisioned when it has a masking key (MK)
    /// imported into its vault.  This flag is the gate that
    /// `EstablishCredential` uses to prevent double-provisioning.
    fn part_is_provisioned(&self, io: &impl HsmIo) -> HsmResult<bool>;

    /// Stores the BK3 session key (48 bytes) for the partition.
    ///
    /// The BK3 session key is derived from BK3 via SP 800-108 KDF
    /// during `EstablishCredential` and used for subsequent session
    /// operations.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `data` — 48-byte BK3 session key.
    fn part_set_bk3_session(&self, io: &impl HsmIo, data: &[u8]) -> HsmResult<()>;

    /// Returns the vault key ID of the partition's masking key (MK),
    /// or `None` if no MK has been imported.
    fn part_mk_key_id(&self, io: &impl HsmIo) -> HsmResult<Option<HsmKeyId>>;

    /// Stores the vault key ID of the partition's masking key (MK).
    ///
    /// Set once during `EstablishCredential` provisioning.  After this
    /// call, [`part_is_provisioned`](Self::part_is_provisioned) returns
    /// `true` and [`part_mk_key_id`](Self::part_mk_key_id) returns the
    /// stored ID.
    fn part_set_mk_key_id(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()>;

    /// Returns the vault key ID of the partition's unwrapping key, or
    /// `None` if no unwrapping key has been imported.
    fn part_unwrapping_key_id(&self, io: &impl HsmIo) -> HsmResult<Option<HsmKeyId>>;

    /// Stores the vault key ID of the partition's unwrapping key.
    fn part_set_unwrapping_key_id(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()>;

    /// Returns the partition's pre-shared key (PSK) for the requested
    /// role identifier.
    ///
    /// PSKs identify the caller role in the session-establishment
    /// handshake: `psk_id = 0` is the Crypto Officer (CO) PSK,
    /// `psk_id = 1` is the Crypto User (CU) PSK.  Any other identifier
    /// returns [`HsmError::InvalidPskId`].
    ///
    /// If [`part_psk_set`](Self::part_psk_set) has not been called for
    /// this `psk_id`, the well-known compiled-in default
    /// ([`DEFAULT_PSK_CO`](crate::DEFAULT_PSK_CO) or
    /// [`DEFAULT_PSK_CU`](crate::DEFAULT_PSK_CU)) is returned.  The
    /// well-known defaults are public; production deployments MUST
    /// rotate them via [`part_psk_set`](Self::part_psk_set) before
    /// exposing the partition to untrusted traffic.
    ///
    /// Follows the standard query/copy pattern: pass `out = None` to
    /// learn the size, then `Some(buf)` to copy.  All PSKs are
    /// [`PSK_LEN`](crate::PSK_LEN) bytes.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `psk_id` — `0` for CO PSK, `1` for CU PSK.
    /// - `out` — `None` for size query, `Some(buf)` to copy.
    ///
    /// # Returns
    ///
    /// - `Ok(PSK_LEN)` on success.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range, or
    ///   `out = Some(buf)` and `buf.len() < PSK_LEN`.
    /// - `Err(HsmError::InvalidPskId)` — `psk_id` is not `0` or `1`.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_psk(&self, io: &impl HsmIo, psk_id: u8, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Rotates the partition's pre-shared key (PSK) for the requested
    /// role identifier, replacing the well-known default (or a prior
    /// rotated value).
    ///
    /// Once called, [`part_psk`](Self::part_psk) returns `psk` for the
    /// matching `psk_id` until the next rotation or partition
    /// disable.  No wire command currently exposes this PAL method;
    /// callers must drive it via privileged provisioning paths only.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `psk_id` — `0` for CO PSK, `1` for CU PSK.
    /// - `psk` — replacement PSK; must be exactly
    ///   [`PSK_LEN`](crate::PSK_LEN) bytes.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` is out of range, or
    ///   `psk.len() != PSK_LEN`.
    /// - `Err(HsmError::InvalidPskId)` — `psk_id` is not `0` or `1`.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_psk_set(&self, io: &impl HsmIo, psk_id: u8, psk: &[u8]) -> HsmResult<()>;

    /// Reports whether the role's effective PSK still equals the
    /// public, compiled-in default
    /// ([`DEFAULT_PSK_CO`](crate::DEFAULT_PSK_CO) /
    /// [`DEFAULT_PSK_CU`](crate::DEFAULT_PSK_CU)).
    ///
    /// **Authoritative byte-compare**, not a rotation-history flag:
    /// even if [`part_psk_set`](Self::part_psk_set) was called with
    /// the default bytes (e.g. via a malformed/malicious `ChangePsk`),
    /// this method still reports `true` because the effective PSK is
    /// still the public default.  This keeps the TBOR dispatcher's
    /// default-PSK gate strictly tied to the bytes actually in use.
    ///
    /// The well-known defaults are public by design so partitions are
    /// usable at bring-up, but they offer no authentication and MUST
    /// be rotated before any sensitive operation is permitted.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `psk_id` — role identifier; `0` = Crypto Officer, `1` =
    ///   Crypto User.  Any other value returns
    ///   [`HsmError::InvalidPskId`].
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — the partition's effective PSK for this `psk_id`
    ///   is byte-identical to the compiled-in default.
    /// - `Ok(false)` — the effective PSK differs from the default.
    /// - `Err(HsmError::InvalidPskId)` — `psk_id > 1`.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled).
    fn part_psk_is_default(&self, io: &impl HsmIo, psk_id: u8) -> HsmResult<bool>;

    // ── PartInit surface ──────────────────────────────────────────

    /// Returns the per-machine Unique Device Secret (UDS).
    ///
    /// On real hardware this is a fused per-device secret; on the std
    /// PAL it is a fixed per-partition pseudo-random blob established
    /// at allocation time.  Follows the standard query/copy pattern.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `out` — `None` for size query, `Some(buf)` to copy.
    ///
    /// # Returns
    ///
    /// - `Ok(size)` — UDS byte length (`32` for the std PAL).
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled) (and not
    ///   [`Initializing`](PartState::Initializing)).
    /// - `Err(HsmError::InvalidArg)` — `out` buffer too small.
    fn part_uds(&self, io: &impl HsmIo, out: Option<&mut [u8]>) -> HsmResult<usize>;

    /// Binds the partition's PTA (Partition Trust Anchor) ECC-P384
    /// key to this incarnation.
    ///
    /// One-shot: subsequent calls return
    /// [`HsmError::PtaKeyAlreadySet`].  The PAL stores both the
    /// vault key id of the private half and the raw 97-byte SEC1
    /// uncompressed public key bytes for later attestation use.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `key_id` — vault id of the PTA private key (kind
    ///   [`HsmVaultKeyKind::PartitionTrustAnchor`](crate::HsmVaultKeyKind::PartitionTrustAnchor)).
    /// - `pub_sec1` — 97-byte SEC1 uncompressed encoding
    ///   (`0x04 ‖ X_be ‖ Y_be`) of the PTA public key.
    fn part_set_pta_key(&self, io: &impl HsmIo, key_id: HsmKeyId, pub_sec1: &[u8])
    -> HsmResult<()>;

    /// Stores the validated `PartPolicy` blob for this incarnation.
    ///
    /// The bytes are stored verbatim (the caller is responsible for
    /// pre-validation via `policy::from_bytes`).
    ///
    /// One-shot: subsequent calls return [`HsmError::InvalidArg`].
    /// The slot is cleared on `part_disable`.
    fn part_set_policy(&self, io: &impl HsmIo, policy: &[u8]) -> HsmResult<()>;

    /// Stores the 48-byte POTA (Partition Owner Trust Anchor)
    /// SHA-384 thumbprint for this incarnation.
    ///
    /// One-shot: subsequent calls return [`HsmError::InvalidArg`].
    /// The slot is cleared on `part_disable`.
    fn part_set_pota_thumbprint(&self, io: &impl HsmIo, thumb: &[u8]) -> HsmResult<()>;

    /// Binds the partition's Unique Machine Secret (UMS) vault key id
    /// to this incarnation.
    ///
    /// The UMS is a 48-byte HMAC-SHA-384-sized secret derived by
    /// `PartInit` from `UDS` plus the request-side
    /// (`MachineSeed`, `PartPolicy`, `POTAThumbprint`) inputs.  The
    /// raw bytes live inside the partition key vault under `key_id`
    /// (kind
    /// [`HsmVaultKeyKind::PartitionUniqueMachineSecret`](crate::HsmVaultKeyKind::PartitionUniqueMachineSecret));
    /// the PAL only stores the id so later phases can reach the
    /// material through the normal vault read path.
    ///
    /// One-shot: subsequent calls return
    /// [`HsmError::UmsKeyAlreadySet`].  The slot is cleared (and the
    /// underlying vault entry deleted) on `part_disable`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `key_id` — vault id of the UMS secret (kind
    ///   [`HsmVaultKeyKind::PartitionUniqueMachineSecret`](crate::HsmVaultKeyKind::PartitionUniqueMachineSecret)).
    fn part_set_ums_key(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()>;

    /// Returns the vault key id of the partition's Unique Machine
    /// Secret (UMS), set by a prior successful
    /// [`part_set_ums_key`](Self::part_set_ums_key).
    ///
    /// # Errors
    ///
    /// - `Err(HsmError::UmsKeyNotSet)` — `PartInit` has not yet
    ///   successfully bound a UMS for this partition incarnation.
    /// - `Err(HsmError::PartitionNotEnabled)` — partition is not
    ///   currently [`Enabled`](PartState::Enabled) (or
    ///   [`Initializing`](PartState::Initializing)).
    fn part_ums_key_id(&self, io: &impl HsmIo) -> HsmResult<HsmKeyId>;

    /// Transitions the partition from [`Enabled`](PartState::Enabled)
    /// to [`Initializing`](PartState::Initializing).
    ///
    /// All four of [`part_set_pta_key`](Self::part_set_pta_key),
    /// [`part_set_ums_key`](Self::part_set_ums_key),
    /// [`part_set_policy`](Self::part_set_policy), and
    /// [`part_set_pota_thumbprint`](Self::part_set_pota_thumbprint)
    /// must have succeeded for this call to succeed; otherwise the
    /// PAL returns [`HsmError::InvalidArg`].
    fn part_mark_initializing(&self, io: &impl HsmIo) -> HsmResult<()>;
}

/// Length of the per-partition `BK_BOOT` boot-key material in bytes.
///
/// Sized to mirror the prior reference firmware's AES-CBC-256 +
/// HMAC-SHA-384 boot key layout (32-byte AES key + 48-byte HMAC
/// key).  All PAL implementations must produce a `BK_BOOT` of
/// exactly this length so that the platform-agnostic BK3 masking in
/// `DdiInitBk3` works uniformly across the std emulator and real
/// hardware.
pub const BK_BOOT_LEN: usize = 80;

/// Maximum size of the `Masked_BK_BOOT` envelope in bytes.
///
/// `Masked_BK_BOOT` is the AES-CBC-256 + HMAC-SHA-384 envelope of
/// raw `BK_BOOT` produced by the `DdiInitBk3` handler.  The exact
/// encoded length depends on the embedded metadata, but the upper
/// bound is fixed to mirror the prior reference firmware's
/// `MASKED_BK_BOOT_SIZE` (300 bytes) so blobs stay bit-compatible
/// with host-side tooling and persistent stores sized by that
/// firmware.  All PAL implementations size [`PartitionEntry`]-equivalent
/// storage to at least this many bytes.
pub const MASKED_BK_BOOT_LEN: usize = 300;
