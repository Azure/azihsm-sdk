// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition management trait and property surface.
//!
//! This module defines:
//!
//! - [`HsmPartitionManager`] — the PAL trait core uses to read and
//!   mutate per-partition state.
//! - The **property surface** ([`PartPropId`], [`PartPropMeta`],
//!   [`PartPropKind`], [`PartPropAccess`], [`PartPropDefault`]) —
//!   a generic, kind-typed key-value view of that state, addressed
//!   by `(PartPropId, idx: u16)` pairs whose wire shape is pinned
//!   at compile time.
//! - The [`PartState`] lifecycle enum and a small set of canonical
//!   length constants ([`PART_POLICY_LEN`], [`BK_BOOT_LEN`],
//!   [`SEALED_BK3_MAX_LEN`], [`MASKED_BK_BOOT_LEN`]) that pin the
//!   byte sizes shared between core, the PAL, and host-side tools.
//!
//! Each partition is a host-facing controller interface identified
//! by [`HsmPartId`]; the firmware supports up to `HSM_NUM_PARTITIONS`
//! of them.  Every trait method takes an [`HsmIo`] handle and
//! operates on the partition resolved from `io.pid()` — partitions
//! are never named explicitly at the trait boundary, which prevents
//! accidental cross-partition queries.
//!
//! # Property surface at a glance
//!
//! All partition state is reached through one of seven methods on
//! [`HsmPartitionManager`]:
//!
//! - One getter and one setter per scalar kind
//!   (`U8` / `U16` / `U32` / `U64` / `Bool`).
//! - [`part_prop_get_bytes`](HsmPartitionManager::part_prop_get_bytes) /
//!   [`part_prop_set_bytes`](HsmPartitionManager::part_prop_set_bytes)
//!   for `FixedBytes` / `VarBytes` slots, exchanging `&DmaBuf` so
//!   the bytes flow into further PAL crypto without a copy.
//! - [`part_prop_clear`](HsmPartitionManager::part_prop_clear) to
//!   reset an absent-capable slot.
//!
//! The full set of slots backed by the PAL is enumerated by the
//! `pub const` catalogue on [`PartPropId`]; each entry's
//! [`PartPropMeta`] (returned by [`PartPropId::meta`]) pins its
//! kind, cardinality, access mode ([`PartPropAccess::Rw`] /
//! [`PartPropAccess::Ro`]), presence semantics
//! ([`PartPropDefault::RequiredPresent`] /
//! [`PartPropDefault::AbsentUntilSet`]), and whether the bytes are
//! sensitive.
//!
//! # Lifecycle
//!
//! ```text
//!   Unallocated ── allocate resources + identity ──▶ Allocated
//!                                                        │
//!                       generate internal keys + nonce + provisioning
//!                                                        │
//!                                                        ▼
//!                                                     Enabled ──▶ Disabled
//!                                                        │           │
//!                                                        │   re-enable internal keys
//!                                                        │           │
//!                                                        │           ▼
//!                                                        │       Enabled
//!                                                        ▼
//!     PartInit binds PTA / policy / POTA thumbprint  Initializing
//! ```
//!
//! [`PartState::Initializing`] is a one-shot transient: once
//! `PartInit` has bound the Partition Trust Anchor (PTA) key, the
//! partition policy, and the POTA thumbprint, no further `PartInit`
//! is permitted until the next alloc/free cycle.
//!
//! # Cardinality and indexing
//!
//! Every getter/setter takes a `u16` `idx`.  Single-valued props
//! (the common case) have `cardinality = 1` and accept only
//! `idx = 0`; out-of-range indices yield [`HsmError::InvalidArg`].
//! Indexed properties (`cardinality > 1`) address a flat array of
//! homogeneous slots — both the storage backend and the undo log
//! treat `(id, idx)` as an atomic addressing pair.  See
//! [`PartPropMeta::fixed_indexed`].
//!
//! # Presence semantics
//!
//! Each slot is either *present* (has a value) or *absent*.  Getters
//! return [`HsmError::PartPropNotFound`] for absent slots; whether
//! absence is reachable is pinned by [`PartPropDefault`]:
//!
//! - **`RequiredPresent`** — populated by the PAL before the
//!   partition is exposed to callers; `PartPropNotFound` is
//!   unreachable, [`part_prop_clear`](HsmPartitionManager::part_prop_clear)
//!   returns [`HsmError::InvalidArg`].
//! - **`AbsentUntilSet`** — starts absent; first successful setter
//!   makes it present; `part_prop_clear` resets it to absent (and
//!   is idempotent on an already-absent slot).
//!
//! # Sensitivity
//!
//! Slots whose meta marks them `sensitive = true` (PSKs, credentials,
//! nonce, sealed / masked / unmasked BK_BOOT, UDS, firmware seed,
//! root-of-trust seeds, BK3 session) MUST be zeroised by the PAL
//! on clear and on overwrite so plaintext secrets do not linger in
//! shared storage (DMA pool, flat persistent region).
//!
//! # Pure-state surface
//!
//! The property API is **pure state**.  Cryptographic derivations
//! (e.g. masking-key derivation), credential verification, nonce
//! refresh, and similar behaviours live on dedicated PAL traits and
//! consume the partition via this property surface where they need
//! to read partition-owned bytes.

use super::*;

/// Opaque identity blob for a partition.
///
/// Borrowed view of the bytes stored at [`PartPropId::ID`].  The
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
#[repr(u8)]
pub enum PartState {
    /// The partition slot is free.  No resources, no identity, no
    /// keys.  IO arriving for this partition is dropped.
    Unallocated = 0,

    /// Resources and the ECC-P384 identity key pair are present, but
    /// the establish-cred and session-enc keys plus the nonce have
    /// not been generated yet.  The host must complete provisioning
    /// before DDI traffic is accepted.
    Allocated = 1,

    /// The partition is fully provisioned and ready for DDI
    /// operations.  All internal crypto material (identity,
    /// establish-cred, session-enc, nonce) is present.
    Enabled = 2,

    /// The partition was previously [`Enabled`](Self::Enabled) and has
    /// been disabled by the host.  Internal crypto material, vault
    /// keys, and sessions are cleared, but the resource allocation
    /// and identity key pair are retained so the partition can be
    /// re-enabled without a full re-provision.
    Disabled = 3,

    /// The TBOR `PartInit` handler has bound the Partition Trust
    /// Anchor (PTA) key, the partition policy, and the POTA
    /// thumbprint to this incarnation, but partition finalization
    /// has not yet run.  No further `PartInit` is permitted until
    /// the next alloc/free cycle (one-shot enforcement).
    Initializing = 4,
}

impl PartState {
    /// Decode a serialized `u8` discriminant back into a `PartState`.
    ///
    /// # Parameters
    ///
    /// - `raw` — the `#[repr(u8)]` discriminant byte, typically
    ///   produced by an earlier read of [`PartPropId::STATE`] or by
    ///   on-disk decoders.
    ///
    /// # Returns
    ///
    /// [`Option<Self>`] — `Some(state)` for a recognised byte, or
    /// `None` for any byte that does not name a known lifecycle
    /// state.  Callers that read state from persistent storage or
    /// the property API treat `None` as storage corruption /
    /// unsupported lifecycle byte and fail closed.
    #[inline]
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Unallocated),
            1 => Some(Self::Allocated),
            2 => Some(Self::Enabled),
            3 => Some(Self::Disabled),
            4 => Some(Self::Initializing),
            _ => None,
        }
    }
}

/// Partition manager interface.
///
/// PAL impls back per-partition state and expose it to core through
/// the **property surface** documented in the module-level overview
/// above.  Every method takes an [`HsmIo`] handle and operates on the
/// partition resolved from `io.pid()`; the trait is `&self`, so PAL
/// implementations are expected to use interior mutability.
///
/// # Error contract
///
/// Common to every `part_prop_*` method:
///
/// - [`HsmError::InvalidArg`] — unknown `id`,
///   `idx >= cardinality`, kind/accessor mismatch (e.g. `get_u8`
///   on a `U32` slot, or `set_bytes` on a `Bool` slot), bytes
///   length violates the `FixedBytes` / `VarBytes` bound, or a
///   write/clear targets an [`Access::Ro`](PartPropAccess::Ro) or
///   [`RequiredPresent`](PartPropDefault::RequiredPresent) slot.
/// - [`HsmError::PartPropNotFound`] — getter on an absent slot.
///   Unreachable for `RequiredPresent` slots; reachable for
///   `AbsentUntilSet` slots until the first successful setter or
///   after the most recent [`Self::part_prop_clear`].
/// - Other [`HsmError`] variants — PAL-level failures (for example
///   [`HsmError::InternalError`] on backing-store corruption,
///   [`HsmError::Bk3AlreadyInitialized`] on the one-shot
///   [`PartPropId::BK3_INITIALIZED`] guard).
///
/// Partition scoping is implicit via `io.pid()`, as elsewhere on
/// this trait.
pub trait HsmPartitionManager {
    /// Read a [`PartPropKind::U8`] slot.
    ///
    /// # Parameters
    ///
    /// - `io` — IO handle; the target partition is resolved from
    ///   [`io.pid()`](HsmIo::pid).
    /// - `id` — property identifier; its [`meta`](PartPropId::meta)
    ///   `kind` must be [`PartPropKind::U8`].
    /// - `idx` — row index within `0..id.meta().cardinality`.
    ///
    /// # Returns
    ///
    /// [`HsmResult<u8>`] — the stored byte on success.  See the
    /// [`HsmPartitionManager`] doc-comment for the shared error
    /// contract.
    fn part_prop_get_u8(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<u8>;

    /// Write a [`PartPropKind::U8`] slot.
    ///
    /// # Parameters
    ///
    /// - `io` — IO handle; the target partition is resolved from
    ///   [`io.pid()`](HsmIo::pid).
    /// - `id` — property identifier; its [`meta`](PartPropId::meta)
    ///   `kind` must be [`PartPropKind::U8`] and `access` must be
    ///   [`PartPropAccess::Rw`].
    /// - `idx` — row index within `0..id.meta().cardinality`.
    /// - `value` — byte to store; replaces any previous value and
    ///   transitions [`AbsentUntilSet`](PartPropDefault::AbsentUntilSet)
    ///   slots to present.
    ///
    /// # Returns
    ///
    /// [`HsmResult<()>`] — `Ok(())` on success.  See the
    /// [`HsmPartitionManager`] doc-comment for the shared error
    /// contract.
    fn part_prop_set_u8(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        value: u8,
    ) -> HsmResult<()>;

    /// Read a [`PartPropKind::U16`] slot.
    ///
    /// # Parameters
    ///
    /// - `io` — IO handle; the target partition is resolved from
    ///   [`io.pid()`](HsmIo::pid).
    /// - `id` — property identifier; its [`meta`](PartPropId::meta)
    ///   `kind` must be [`PartPropKind::U16`].
    /// - `idx` — row index within `0..id.meta().cardinality`.
    ///
    /// # Returns
    ///
    /// [`HsmResult<u16>`] — the stored value on success.
    fn part_prop_get_u16(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<u16>;

    /// Write a [`PartPropKind::U16`] slot.
    ///
    /// # Parameters
    ///
    /// - `io` — IO handle; the target partition is resolved from
    ///   [`io.pid()`](HsmIo::pid).
    /// - `id` — property identifier; its [`meta`](PartPropId::meta)
    ///   `kind` must be [`PartPropKind::U16`] and `access` must be
    ///   [`PartPropAccess::Rw`].
    /// - `idx` — row index within `0..id.meta().cardinality`.
    /// - `value` — value to store; replaces any previous value and
    ///   transitions [`AbsentUntilSet`](PartPropDefault::AbsentUntilSet)
    ///   slots to present.
    ///
    /// # Returns
    ///
    /// [`HsmResult<()>`] — `Ok(())` on success.
    fn part_prop_set_u16(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        value: u16,
    ) -> HsmResult<()>;

    /// Read a [`PartPropKind::U32`] slot.
    ///
    /// # Parameters
    ///
    /// - `io` — IO handle; the target partition is resolved from
    ///   [`io.pid()`](HsmIo::pid).
    /// - `id` — property identifier; its [`meta`](PartPropId::meta)
    ///   `kind` must be [`PartPropKind::U32`].
    /// - `idx` — row index within `0..id.meta().cardinality`.
    ///
    /// # Returns
    ///
    /// [`HsmResult<u32>`] — the stored value on success.
    fn part_prop_get_u32(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<u32>;

    /// Write a [`PartPropKind::U32`] slot.
    ///
    /// # Parameters
    ///
    /// - `io` — IO handle; the target partition is resolved from
    ///   [`io.pid()`](HsmIo::pid).
    /// - `id` — property identifier; its [`meta`](PartPropId::meta)
    ///   `kind` must be [`PartPropKind::U32`] and `access` must be
    ///   [`PartPropAccess::Rw`].
    /// - `idx` — row index within `0..id.meta().cardinality`.
    /// - `value` — value to store.
    ///
    /// # Returns
    ///
    /// [`HsmResult<()>`] — `Ok(())` on success.
    fn part_prop_set_u32(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        value: u32,
    ) -> HsmResult<()>;

    /// Read a [`PartPropKind::U64`] slot.
    ///
    /// # Parameters
    ///
    /// - `io` — IO handle; the target partition is resolved from
    ///   [`io.pid()`](HsmIo::pid).
    /// - `id` — property identifier; its [`meta`](PartPropId::meta)
    ///   `kind` must be [`PartPropKind::U64`].
    /// - `idx` — row index within `0..id.meta().cardinality`.
    ///
    /// # Returns
    ///
    /// [`HsmResult<u64>`] — the stored value on success.
    fn part_prop_get_u64(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<u64>;

    /// Write a [`PartPropKind::U64`] slot.
    ///
    /// # Parameters
    ///
    /// - `io` — IO handle; the target partition is resolved from
    ///   [`io.pid()`](HsmIo::pid).
    /// - `id` — property identifier; its [`meta`](PartPropId::meta)
    ///   `kind` must be [`PartPropKind::U64`] and `access` must be
    ///   [`PartPropAccess::Rw`].
    /// - `idx` — row index within `0..id.meta().cardinality`.
    /// - `value` — value to store.
    ///
    /// # Returns
    ///
    /// [`HsmResult<()>`] — `Ok(())` on success.
    fn part_prop_set_u64(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        value: u64,
    ) -> HsmResult<()>;

    /// Read a [`PartPropKind::Bool`] slot.
    ///
    /// # Parameters
    ///
    /// - `io` — IO handle; the target partition is resolved from
    ///   [`io.pid()`](HsmIo::pid).
    /// - `id` — property identifier; its [`meta`](PartPropId::meta)
    ///   `kind` must be [`PartPropKind::Bool`].
    /// - `idx` — row index within `0..id.meta().cardinality`.
    ///
    /// # Returns
    ///
    /// [`HsmResult<bool>`] — the stored flag on success.
    fn part_prop_get_bool(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<bool>;

    /// Write a [`PartPropKind::Bool`] slot.
    ///
    /// # Parameters
    ///
    /// - `io` — IO handle; the target partition is resolved from
    ///   [`io.pid()`](HsmIo::pid).
    /// - `id` — property identifier; its [`meta`](PartPropId::meta)
    ///   `kind` must be [`PartPropKind::Bool`] and `access` must be
    ///   [`PartPropAccess::Rw`].  Per-slot semantics may further
    ///   constrain the legal transitions (for example
    ///   [`PartPropId::BK3_INITIALIZED`] permits only `false → true`).
    /// - `idx` — row index within `0..id.meta().cardinality`.
    /// - `value` — flag to store.
    ///
    /// # Returns
    ///
    /// [`HsmResult<()>`] — `Ok(())` on success.
    fn part_prop_set_bool(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        value: bool,
    ) -> HsmResult<()>;

    /// Read a [`PartPropKind::FixedBytes`] or [`PartPropKind::VarBytes`]
    /// slot.
    ///
    /// # Parameters
    ///
    /// - `io` — IO handle; the target partition is resolved from
    ///   [`io.pid()`](HsmIo::pid).
    /// - `id` — property identifier; its [`meta`](PartPropId::meta)
    ///   `kind` must be [`PartPropKind::FixedBytes`] or
    ///   [`PartPropKind::VarBytes`].
    /// - `idx` — row index within `0..id.meta().cardinality`.
    ///
    /// # Returns
    ///
    /// [`HsmResult<&DmaBuf>`] — on success, a borrowed sub-view of
    /// the PAL's backing storage so the bytes can flow into further
    /// PAL crypto primitives without a copy.  For `FixedBytes` the
    /// length equals the slot's declared `len`; for `VarBytes` it is
    /// the recorded value length (which may be `0` and is at most
    /// `max`).
    ///
    /// The returned view is valid for the duration of the `&self`
    /// borrow on the [`HsmPartitionManager`] implementation; PAL
    /// impls must not invalidate it before the borrow ends.
    fn part_prop_get_bytes<'a>(
        &'a self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
    ) -> HsmResult<&'a DmaBuf>;

    /// Write a [`PartPropKind::FixedBytes`] or
    /// [`PartPropKind::VarBytes`] slot.
    ///
    /// # Parameters
    ///
    /// - `io` — IO handle; the target partition is resolved from
    ///   [`io.pid()`](HsmIo::pid).
    /// - `id` — property identifier; its [`meta`](PartPropId::meta)
    ///   `kind` must be [`PartPropKind::FixedBytes`] or
    ///   [`PartPropKind::VarBytes`], and `access` must be
    ///   [`PartPropAccess::Rw`].
    /// - `idx` — row index within `0..id.meta().cardinality`.
    /// - `data` — bytes to store.  For `FixedBytes`, `data.len()`
    ///   must equal the declared `len`; for `VarBytes`, `data.len()`
    ///   must be `≤` the declared `max`.  Any other length returns
    ///   [`HsmError::InvalidArg`].  Writing replaces any previous
    ///   value and transitions [`AbsentUntilSet`](PartPropDefault::AbsentUntilSet)
    ///   slots to present; PAL impls zeroise the previous bytes of a
    ///   `sensitive` slot before the overwrite.
    ///
    /// # Returns
    ///
    /// [`HsmResult<()>`] — `Ok(())` on success.
    fn part_prop_set_bytes(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        idx: u16,
        data: &DmaBuf,
    ) -> HsmResult<()>;

    /// Reset a property slot to its absent state.
    ///
    /// # Parameters
    ///
    /// - `io` — IO handle; the target partition is resolved from
    ///   [`io.pid()`](HsmIo::pid).
    /// - `id` — property identifier.  Its [`meta`](PartPropId::meta)
    ///   `default` must be [`PartPropDefault::AbsentUntilSet`] and
    ///   `access` must be [`PartPropAccess::Rw`];
    ///   [`RequiredPresent`](PartPropDefault::RequiredPresent) slots
    ///   have no "absent" state to reset to and return
    ///   [`HsmError::InvalidArg`].
    /// - `idx` — row index within `0..id.meta().cardinality`.
    ///
    /// PAL impls that back the store with reusable memory must
    /// zeroise the underlying bytes of a `sensitive = true` slot on
    /// clear so plaintext secrets do not linger in shared storage.
    ///
    /// # Returns
    ///
    /// [`HsmResult<()>`] — `Ok(())` on success.  Idempotent on an
    /// already-absent slot (also returns `Ok(())`).
    fn part_prop_clear(&self, io: &impl HsmIo, id: PartPropId, idx: u16) -> HsmResult<()>;
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

/// Maximum size of the `Sealed_BK3` blob in bytes.
///
/// `Sealed_BK3` is the host-supplied sealed envelope holding the
/// per-power-cycle BK3 secret consumed by the `DdiInitBk3` handler.
/// The upper bound mirrors the prior reference firmware's
/// `SEALED_BK3_SIZE` so blobs stay bit-compatible with host-side
/// tooling.  PAL implementations size their backing storage to at
/// least this many bytes.
pub const SEALED_BK3_MAX_LEN: u16 = 512;

/// Maximum size of the `Masked_BK_BOOT` envelope in bytes.
///
/// `Masked_BK_BOOT` is the AES-CBC-256 + HMAC-SHA-384 envelope of
/// raw `BK_BOOT` produced by the `DdiInitBk3` handler.  The exact
/// encoded length depends on the embedded metadata, but the upper
/// bound is fixed to mirror the prior reference firmware's
/// `MASKED_BK_BOOT_SIZE` (300 bytes) so blobs stay bit-compatible
/// with host-side tooling and persistent stores sized by that
/// firmware.  All PAL implementations size their backing storage
/// for the [`PartPropId::MASKED_BK_BOOT`] slot to at least this
/// many bytes.
pub const MASKED_BK_BOOT_LEN: usize = 300;

// ============================================================================
// Property surface — types and the PartPropId catalogue.
//
// Crate-level concepts (presence, cardinality, sensitivity, pure-state)
// are documented at the module level (see the //! block above);
// the items below carry only item-specific documentation.
// ============================================================================

// ─── Access mode ──────────────────────────────────────────────────────────

/// Access mode for a property.
///
/// Pinned per [`PartPropId`] by its meta; the PAL impl enforces it
/// in the typed setters (`set_*`) and in [`HsmPartitionManager::part_prop_clear`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartPropAccess {
    /// Caller may read and write the property.  All typed setters
    /// and [`HsmPartitionManager::part_prop_clear`] are permitted (subject to
    /// [`PartPropDefault`] for `clear`).
    Rw,

    /// Caller may only read the property.  All typed setters and
    /// [`HsmPartitionManager::part_prop_clear`] return [`HsmError::InvalidArg`].
    /// Used for state owned by the PAL itself (e.g. firmware-supplied
    /// seeds, resource counters) where the caller has no business
    /// mutating the value.
    Ro,
}

// ─── Default presence ─────────────────────────────────────────────────────

/// Initial presence semantics for a property slot.
///
/// Pinned per [`PartPropId`] by its meta; the PAL impl uses it both
/// at partition-allocation time (to populate `RequiredPresent` slots)
/// and at [`HsmPartitionManager::part_prop_clear`] time (to reject clears on
/// always-present slots).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartPropDefault {
    /// The slot is initialised by the PAL when the partition is
    /// allocated (or earlier) and is never observed absent from the
    /// caller's perspective.  Getters do not return
    /// [`HsmError::PartPropNotFound`] for this slot; the PAL impl
    /// must guarantee a value is materialised before the partition
    /// is exposed to callers.  [`HsmPartitionManager::part_prop_clear`] on such a
    /// slot returns [`HsmError::InvalidArg`].
    RequiredPresent,

    /// The slot starts absent and only becomes present after a
    /// successful setter call.  Getters return
    /// [`HsmError::PartPropNotFound`] until then.
    /// [`HsmPartitionManager::part_prop_clear`] resets the slot back to absent and is
    /// idempotent on an already-absent slot (returns `Ok(())`).
    AbsentUntilSet,
}

// ─── Wire-shape ───────────────────────────────────────────────────────────

/// Wire-shape ("kind") of a property's stored value.
///
/// Pins both the typed accessor that may be used and the storage
/// footprint per slot.  Mismatched access (e.g. calling
/// [`HsmPartitionManager::part_prop_get_u8`] on a `U32` slot) returns
/// [`HsmError::InvalidArg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartPropKind {
    /// Single unsigned byte.  Access: [`HsmPartitionManager::part_prop_get_u8`] /
    /// [`HsmPartitionManager::part_prop_set_u8`].
    U8,

    /// 16-bit unsigned integer.  Access: [`HsmPartitionManager::part_prop_get_u16`] /
    /// [`HsmPartitionManager::part_prop_set_u16`].
    U16,

    /// 32-bit unsigned integer.  Access: [`HsmPartitionManager::part_prop_get_u32`] /
    /// [`HsmPartitionManager::part_prop_set_u32`].
    U32,

    /// 64-bit unsigned integer.  Access: [`HsmPartitionManager::part_prop_get_u64`] /
    /// [`HsmPartitionManager::part_prop_set_u64`].
    U64,

    /// Boolean flag.  Access: [`HsmPartitionManager::part_prop_get_bool`] /
    /// [`HsmPartitionManager::part_prop_set_bool`].
    Bool,

    /// Fixed-length byte buffer.  Every present slot holds exactly
    /// `len` bytes.  Access: [`HsmPartitionManager::part_prop_get_bytes`] /
    /// [`HsmPartitionManager::part_prop_set_bytes`]; setter writes that pass a
    /// different length return [`HsmError::InvalidArg`].
    FixedBytes {
        /// Mandatory exact length, in bytes, of every present slot.
        len: u16,
    },

    /// Variable-length byte buffer with an upper bound.  Present
    /// slots hold between 0 and `max` bytes (inclusive); the actual
    /// length is recorded with the value.  Access:
    /// [`HsmPartitionManager::part_prop_get_bytes`] / [`HsmPartitionManager::part_prop_set_bytes`];
    /// setter writes that exceed `max` return [`HsmError::InvalidArg`].
    VarBytes {
        /// Inclusive upper bound, in bytes, on any present slot.
        max: u16,
    },
}

// ─── Metadata ─────────────────────────────────────────────────────────────

/// Compile-time metadata for a [`PartPropId`].
///
/// Returned by [`PartPropId::meta`].  Drives both:
///
/// - **Static layout** — PAL impls that use a flat storage backing
///   (presence bitmap + value region) compute slot offsets from
///   `(kind, cardinality)` at compile time.
/// - **Runtime enforcement** — the PAL impl checks `kind` against the
///   typed accessor, `cardinality` against the `idx` argument,
///   `access` against any mutation, and `default` against `clear`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartPropMeta {
    /// Wire-shape of the slot's value.
    pub kind: PartPropKind,

    /// Number of slots addressable by `idx`.  Single-valued props
    /// have `cardinality = 1` (only `idx = 0` is legal).
    /// Indexed props have `cardinality > 1`; `idx` ranges over
    /// `0..cardinality`.  Values exceeding this bound return
    /// [`HsmError::InvalidArg`].
    pub cardinality: u16,

    /// Whether the caller may mutate the property; see
    /// [`PartPropAccess`].
    pub access: PartPropAccess,

    /// Whether the slot starts present or absent; see
    /// [`PartPropDefault`].
    pub default: PartPropDefault,

    /// Whether the slot's value is secret.  PAL impls that back the
    /// store with reusable memory (DMA pool, flat persistent
    /// storage) should zeroise the underlying bytes whenever a
    /// `sensitive = true` slot is cleared or overwritten so plaintext
    /// secrets do not linger in shared storage after they are no
    /// longer needed.
    pub sensitive: bool,
}

impl PartPropMeta {
    /// Single-slot fixed-length byte buffer
    /// ([`PartPropKind::FixedBytes`], `cardinality = 1`).
    ///
    /// Use for slots whose every present value is exactly `len`
    /// bytes (identity blobs, raw public-key coordinates, fixed-size
    /// keys).  Setter writes that pass a different length return
    /// [`HsmError::InvalidArg`].
    ///
    /// # Parameters
    ///
    /// - `len` — exact byte length of every present value.
    /// - `access` — caller mutability ([`Rw`](PartPropAccess::Rw) /
    ///   [`Ro`](PartPropAccess::Ro)).
    /// - `default` — initial presence semantics.
    /// - `sensitive` — `true` if the slot's bytes are secret and
    ///   must be zeroised on clear/overwrite by the PAL.
    ///
    /// # Returns
    ///
    /// [`Self`] — the assembled metadata.
    pub const fn fixed(
        len: u16,
        access: PartPropAccess,
        default: PartPropDefault,
        sensitive: bool,
    ) -> Self {
        Self {
            kind: PartPropKind::FixedBytes { len },
            cardinality: 1,
            access,
            default,
            sensitive,
        }
    }

    /// Indexed fixed-length byte buffer (`cardinality` slots, each
    /// `len` bytes).
    ///
    /// `idx` addresses the row in `0..cardinality`; rows out of range
    /// return [`HsmError::InvalidArg`].  Use for homogeneous arrays
    /// (e.g. per-SVN root-of-trust seed rows).  Per-row presence is
    /// independent — unprovisioned rows return
    /// [`HsmError::PartPropNotFound`] when `default` is
    /// [`PartPropDefault::AbsentUntilSet`].
    ///
    /// # Parameters
    ///
    /// - `len` — exact byte length of every present row.
    /// - `cardinality` — number of rows; getter/setter `idx`
    ///   ranges over `0..cardinality`.
    /// - `access`, `default`, `sensitive` — see [`Self::fixed`].
    ///
    /// # Returns
    ///
    /// [`Self`] — the assembled metadata.
    pub const fn fixed_indexed(
        len: u16,
        cardinality: u16,
        access: PartPropAccess,
        default: PartPropDefault,
        sensitive: bool,
    ) -> Self {
        Self {
            kind: PartPropKind::FixedBytes { len },
            cardinality,
            access,
            default,
            sensitive,
        }
    }

    /// Single-slot variable-length byte buffer with an inclusive
    /// upper bound ([`PartPropKind::VarBytes`], `cardinality = 1`).
    ///
    /// Use for slots whose value length is data-dependent but
    /// bounded (sealed envelopes, masked boot-key blobs).  The PAL
    /// records the actual length alongside the bytes; setter writes
    /// exceeding `max` return [`HsmError::InvalidArg`].
    ///
    /// # Parameters
    ///
    /// - `max` — inclusive upper bound on a present value's
    ///   length, in bytes.  Present values may be any size in
    ///   `0..=max`.
    /// - `access`, `default`, `sensitive` — see [`Self::fixed`].
    ///
    /// # Returns
    ///
    /// [`Self`] — the assembled metadata.
    pub const fn var(
        max: u16,
        access: PartPropAccess,
        default: PartPropDefault,
        sensitive: bool,
    ) -> Self {
        Self {
            kind: PartPropKind::VarBytes { max },
            cardinality: 1,
            access,
            default,
            sensitive,
        }
    }

    /// Single-slot scalar (`U8` / `U16` / `U32` / `U64` / `Bool`).
    ///
    /// Use for any non-byte-buffer kind.  The caller picks the
    /// [`PartPropKind`] variant; calling a typed accessor of a
    /// different kind (e.g. `get_u8` on a slot built with `U32`)
    /// returns [`HsmError::InvalidArg`].
    ///
    /// # Parameters
    ///
    /// - `kind` — the scalar variant; must not be
    ///   [`PartPropKind::FixedBytes`] or [`PartPropKind::VarBytes`]
    ///   (use [`Self::fixed`] / [`Self::var`] for those).
    /// - `access`, `default`, `sensitive` — see [`Self::fixed`].
    ///
    /// # Returns
    ///
    /// [`Self`] — the assembled metadata.
    pub const fn scalar(
        kind: PartPropKind,
        access: PartPropAccess,
        default: PartPropDefault,
        sensitive: bool,
    ) -> Self {
        Self {
            kind,
            cardinality: 1,
            access,
            default,
            sensitive,
        }
    }
}

// ─── PartPropId ───────────────────────────────────────────────────────────

/// Stable wire identifier for a partition property.
///
/// `PartPropId` is a `#[repr(transparent)]` `u16` newtype: the raw
/// value is part of the on-disk and undo-log encoding and MUST NOT
/// be reassigned once shipped.  Adding new properties is allowed (
/// pick the next free id in the appropriate range and add a match arm
/// to [`PartPropId::meta`]); reassigning, repurposing, or shifting
/// existing ids is a wire-breaking change.
///
/// # Id ranges
///
/// Ids are grouped into ranges by category to keep the on-disk and
/// undo-log dumps readable, but the ranges are purely organisational
/// — the PAL impl does not gate behaviour on the id range.
///
/// | Range            | Category                                |
/// |------------------|-----------------------------------------|
/// | `0x0001..0x000F` | Identity, lifecycle, and platform state |
/// | `0x0010..0x0016` | Vault references (`HsmKeyId` scalars)   |
/// | `0x0017..0x001F` | Raw public-key views (P-384 coordinates / SEC1) |
/// | `0x0020..0x002F` | Caller-presented secrets                |
/// | `0x0030..0x003F` | Boot / launch-time bound material       |
///
/// # Adding a property
///
/// 1. Pick the next free `u16` in the appropriate range and add a
///    `pub const` here, with a doc comment that records the wire
///    shape, who sets the slot, and who reads it.
/// 2. Add a match arm to [`PartPropId::meta`] returning the
///    [`PartPropMeta`] for the new id — prefer the
///    [`PartPropMeta::fixed`] / [`PartPropMeta::var`] /
///    [`PartPropMeta::scalar`] / [`PartPropMeta::fixed_indexed`]
///    constructors over building the struct literal by hand.
/// 3. Update the PAL implementation(s) to back the new slot in their
///    storage layout (presence bit + value region, undo-log entry
///    if applicable).
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartPropId(u16);

impl PartPropId {
    // ── Identity, lifecycle, and platform state (0x0001..) ────────

    /// Opaque partition identity blob (16 B).  Read-only from caller
    /// perspective; populated by the PAL during partition setup.
    pub const ID: PartPropId = PartPropId(0x0001);

    /// Unique Device Secret (32 B).  Sensitive; used as the root
    /// secret for partition-bound derivations.  Read-only from
    /// caller perspective; provisioned by the PAL.
    pub const UDS: PartPropId = PartPropId(0x0002);

    /// Lifecycle state.  Encoded as `u8` matching
    /// [`PartState`](crate::PartState) discriminants.
    pub const STATE: PartPropId = PartPropId(0x0003);

    /// Monotonic partition generation counter, incremented on every
    /// allocate/free cycle.  Used by lifetime guards to detect
    /// partition reuse.  Read-only from caller perspective; managed
    /// by the PAL.
    pub const GEN: PartPropId = PartPropId(0x0004);

    /// Security version number of the firmware bound into the
    /// partition's derivation lineage.  Read-only from caller
    /// perspective.
    pub const SVN: PartPropId = PartPropId(0x0005);

    /// Number of host-allocated SQ/CQ resource pairs.  Read-only
    /// from caller perspective.
    pub const RES_COUNT: PartPropId = PartPropId(0x0006);

    /// Firmware-supplied per-partition seed (48 B).  Read-only;
    /// PAL-owned input to partition-bound derivations.
    pub const FW_SEED: PartPropId = PartPropId(0x0007);

    /// One-shot BK3 initialization flag.  Bool, `RequiredPresent`,
    /// `Rw` but **the only legal transition is `false → true`**;
    /// the PAL setter rejects redundant `true` writes with
    /// [`HsmError::Bk3AlreadyInitialized`] and rejects `* → false`
    /// with [`HsmError::InvalidArg`].  Reset back to `false` happens
    /// PAL-internally on partition free / NSSR.
    pub const BK3_INITIALIZED: PartPropId = PartPropId(0x0008);

    /// BKS2 lineage identifier (`u16`).  Read-only; selects which
    /// `BKS2` seed row binds the partition's boot-key derivations.
    pub const BKS2_ID: PartPropId = PartPropId(0x0009);

    /// Manufacturer-provisioned 32-byte seed row, indexed by SVN
    /// (`0..64`).  PAL-private root-of-trust material used as the
    /// first half of the KBKDF context for masking-key derivations.
    /// Sensitive, read-only.  Indexed properties — only rows that
    /// have been provisioned for the current PAL are present;
    /// unprovisioned rows return [`HsmError::PartPropNotFound`].
    pub const MFGR_SEED: PartPropId = PartPropId(0x000A);

    /// Device-owner-provisioned 32-byte seed row, indexed by
    /// `bks2_index` (`0..64`).  PAL-private root-of-trust material
    /// used as the second half of the KBKDF context for masking-key
    /// derivations.  Sensitive, read-only.  Indexed properties —
    /// only rows provisioned for the current PAL are present.
    pub const DEV_OWNER_SEED: PartPropId = PartPropId(0x000B);

    // ── Vault references (0x0010..) ───────────────────────────────

    /// Vault [`HsmKeyId`](crate::HsmKeyId) for the partition identity
    /// key (ECC-P384).  Read-only from caller perspective; assigned
    /// by the PAL when the identity key is materialised.
    pub const ID_KEY_ID: PartPropId = PartPropId(0x0010);

    /// Vault [`HsmKeyId`](crate::HsmKeyId) for the partition masking
    /// key.
    pub const MK_KEY_ID: PartPropId = PartPropId(0x0011);

    /// Vault [`HsmKeyId`](crate::HsmKeyId) for the partition Unique
    /// Partition Secret derived key.
    pub const UPS_KEY_ID: PartPropId = PartPropId(0x0012);

    /// Vault [`HsmKeyId`](crate::HsmKeyId) for the Partition Trust
    /// Anchor (PTA) key.
    pub const PTA_KEY_ID: PartPropId = PartPropId(0x0013);

    /// Vault [`HsmKeyId`](crate::HsmKeyId) for the partition's
    /// unwrapping key.  Read-only from caller perspective; assigned
    /// by the PAL when the key is materialised.
    pub const RSA_UNWRAPPING_KEY_ID: PartPropId = PartPropId(0x0014);

    /// Vault [`HsmKeyId`](crate::HsmKeyId) for the partition's
    /// session encryption key (long-lived ECDH).
    pub const SESSION_ENC_KEY_ID: PartPropId = PartPropId(0x0015);

    /// Vault [`HsmKeyId`](crate::HsmKeyId) for the partition's
    /// one-shot establish-credential RSA-OAEP key.
    pub const ESTABLISH_CRED_KEY_ID: PartPropId = PartPropId(0x0016);

    /// Raw ECC-P384 public-key coordinates (x ∥ y, 96 B) of the
    /// partition identity key.  Read-only from caller perspective;
    /// materialised by the PAL alongside [`ID_KEY_ID`](Self::ID_KEY_ID).
    pub const ID_PUB_KEY: PartPropId = PartPropId(0x0017);

    /// Raw ECC-P384 public-key coordinates (x ∥ y, 96 B) for the
    /// session encryption key.  Read-only from caller perspective.
    pub const SESSION_ENC_PUB_KEY: PartPropId = PartPropId(0x0018);

    /// Raw ECC-P384 public-key coordinates (x ∥ y, 96 B) for the
    /// one-shot establish-credential key.  Read-only from caller
    /// perspective.
    pub const ESTABLISH_CRED_PUB_KEY: PartPropId = PartPropId(0x0019);

    /// SEC1-uncompressed ECC-P384 public key (97 B) for the
    /// Partition Trust Anchor.  Set together with
    /// [`PTA_KEY_ID`](Self::PTA_KEY_ID) by `PartInit`.
    pub const PTA_PUB_SEC1: PartPropId = PartPropId(0x001A);

    // ── Caller-presented secrets (0x0020..) ───────────────────────

    /// Crypto Officer pre-shared key (32 B).  Sensitive.
    /// Default-baked at allocation time
    /// (see [`DEFAULT_PSK_CO`](crate::DEFAULT_PSK_CO)) so callers
    /// can establish a CO session immediately; rotation through the
    /// setter is required before exposing the partition to
    /// untrusted traffic.
    pub const PSK_CO: PartPropId = PartPropId(0x0020);

    /// Crypto User pre-shared key (32 B).  Sensitive.  Default-baked
    /// at allocation; see [`PSK_CO`](Self::PSK_CO).
    pub const PSK_CU: PartPropId = PartPropId(0x0021);

    /// Caller-presented credential blob (32 B).  Sensitive.
    /// Absent-until-set; verified by the upper layer via
    /// constant-time compare against the value returned by
    /// [`HsmPartitionManager::part_prop_get_bytes`].
    pub const CREDENTIAL: PartPropId = PartPropId(0x0022);

    /// 32-byte partition nonce, refreshed per credential / session
    /// event.  Sensitive.  Caller refreshes by writing a fresh
    /// PAL-RNG buffer via [`HsmPartitionManager::part_prop_set_bytes`].
    pub const NONCE: PartPropId = PartPropId(0x0023);

    // ── Boot / launch-time bound material (0x0030..) ──────────────

    /// Sealed BK3 blob (≤ [`SEALED_BK3_MAX_LEN`](crate::SEALED_BK3_MAX_LEN) B).
    /// Sensitive.  Absent-until-set; set once per power cycle.
    pub const SEALED_BK3: PartPropId = PartPropId(0x0030);

    /// Masked BK_BOOT blob (variable, ≤ [`MASKED_BK_BOOT_LEN`](crate::MASKED_BK_BOOT_LEN)).
    /// Sensitive.
    pub const MASKED_BK_BOOT: PartPropId = PartPropId(0x0031);

    /// Unmasked BK_BOOT (exactly [`BK_BOOT_LEN`](crate::BK_BOOT_LEN)).
    /// Sensitive.  Read-only from caller perspective; derived by the
    /// PAL from the masked form.
    pub const BK_BOOT: PartPropId = PartPropId(0x0032);

    /// VM-launch GUID (16 B), bound at session-establishment time.
    /// Read-only from caller perspective; populated by the PAL.
    pub const VM_LAUNCH_GUID: PartPropId = PartPropId(0x0033);

    /// Partition policy blob (exactly [`PART_POLICY_LEN`](crate::PART_POLICY_LEN)).
    /// Set by `PartInit`.
    pub const POLICY: PartPropId = PartPropId(0x0034);

    /// POTA thumbprint (48 B).  Set by `PartInit`.
    pub const POTA_THUMBPRINT: PartPropId = PartPropId(0x0035);

    /// BK3 session key (48 B).  Sensitive.  Set by EstablishCredential
    /// once per session.
    pub const BK3_SESSION: PartPropId = PartPropId(0x0036);

    /// Wrap a raw `u16` as a [`PartPropId`].
    ///
    /// Used by undo-log replay and on-disk decoders that read raw
    /// ids off the wire.  Callers obtain ids from the named
    /// constants in normal code; this constructor exists for
    /// generic dispatch.
    ///
    /// # Parameters
    ///
    /// - `v` — the raw 16-bit wire identifier.
    ///
    /// # Returns
    ///
    /// [`Self`] — the wrapped id.  Unknown ids are accepted here
    /// and rejected later by the PAL impl (via [`Self::meta`]
    /// returning `None`).
    #[inline]
    pub const fn from_raw(v: u16) -> Self {
        Self(v)
    }

    /// Unwrap to the raw `u16` value.
    ///
    /// # Returns
    ///
    /// [`u16`] — the wire-stable identifier that may be journaled
    /// to the undo log or written to persistent storage.
    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Compile-time metadata for this id.
    ///
    /// # Returns
    ///
    /// [`Option<PartPropMeta>`] — `Some(meta)` describing the
    /// slot's wire shape, cardinality, access mode, presence
    /// semantics, and sensitivity for any id known to this build of
    /// the PAL traits crate; `None` for any id not added to the
    /// match below at compile time.  PAL impls surface unknown ids
    /// as [`HsmError::InvalidArg`] in their getters and setters.
    pub const fn meta(self) -> Option<PartPropMeta> {
        use PartPropAccess::Ro;
        use PartPropAccess::Rw;
        use PartPropDefault::AbsentUntilSet as Abs;
        use PartPropDefault::RequiredPresent as Req;
        use PartPropKind::Bool;
        use PartPropKind::U8;
        use PartPropKind::U16;
        use PartPropKind::U32;
        use PartPropKind::U64;

        // Writable vault-ref props share the same shape (u16 HsmKeyId, RW, absent).
        const VAULT_REF_RW: PartPropMeta = PartPropMeta::scalar(U16, Rw, Abs, false);
        // Read-only vault-ref props share the same shape (u16 HsmKeyId, RO, absent).
        const VAULT_REF_RO: PartPropMeta = PartPropMeta::scalar(U16, Ro, Abs, false);

        let meta = match self {
            // ── Identity, lifecycle, platform ──
            Self::ID => PartPropMeta::fixed(16, Ro, Abs, false),
            Self::UDS => PartPropMeta::fixed(32, Ro, Abs, true),
            Self::STATE => PartPropMeta::scalar(U8, Rw, Req, false),
            Self::GEN => PartPropMeta::scalar(U32, Ro, Req, false),
            Self::SVN => PartPropMeta::scalar(U64, Ro, Req, false),
            Self::RES_COUNT => PartPropMeta::scalar(U8, Ro, Req, false),
            Self::FW_SEED => PartPropMeta::fixed(48, Ro, Req, true),
            Self::BK3_INITIALIZED => PartPropMeta::scalar(Bool, Rw, Req, false),
            Self::BKS2_ID => PartPropMeta::scalar(U16, Ro, Req, false),
            Self::MFGR_SEED | Self::DEV_OWNER_SEED => {
                PartPropMeta::fixed_indexed(32, 64, Ro, Abs, true)
            }

            // ── Vault refs (HsmKeyId as u16) ──
            Self::ID_KEY_ID | Self::RSA_UNWRAPPING_KEY_ID => VAULT_REF_RO,
            Self::MK_KEY_ID
            | Self::UPS_KEY_ID
            | Self::PTA_KEY_ID
            | Self::SESSION_ENC_KEY_ID
            | Self::ESTABLISH_CRED_KEY_ID => VAULT_REF_RW,

            // ── Public-key views (fixed P-384 sizes) ──
            Self::ID_PUB_KEY | Self::SESSION_ENC_PUB_KEY | Self::ESTABLISH_CRED_PUB_KEY => {
                PartPropMeta::fixed(96, Ro, Abs, false)
            }
            Self::PTA_PUB_SEC1 => PartPropMeta::fixed(97, Rw, Abs, false),

            // ── Caller-presented secrets ──
            Self::PSK_CO | Self::PSK_CU => PartPropMeta::fixed(PSK_LEN as u16, Rw, Req, true),
            Self::CREDENTIAL => PartPropMeta::fixed(32, Rw, Abs, true),
            Self::NONCE => PartPropMeta::fixed(32, Rw, Req, true),

            // ── Boot / launch-time bound material ──
            Self::SEALED_BK3 => PartPropMeta::var(SEALED_BK3_MAX_LEN, Rw, Abs, true),
            Self::MASKED_BK_BOOT => PartPropMeta::var(MASKED_BK_BOOT_LEN as u16, Rw, Abs, true),
            Self::BK_BOOT => PartPropMeta::fixed(BK_BOOT_LEN as u16, Ro, Abs, true),
            Self::VM_LAUNCH_GUID => PartPropMeta::fixed(16, Ro, Abs, false),
            Self::POLICY => PartPropMeta::fixed(PART_POLICY_LEN as u16, Rw, Abs, false),
            Self::POTA_THUMBPRINT => PartPropMeta::fixed(48, Rw, Abs, false),
            Self::BK3_SESSION => PartPropMeta::fixed(48, Rw, Abs, true),

            _ => return None,
        };
        Some(meta)
    }
}

impl From<u16> for PartPropId {
    #[inline]
    fn from(v: u16) -> Self {
        Self(v)
    }
}

impl From<PartPropId> for u16 {
    #[inline]
    fn from(id: PartPropId) -> Self {
        id.0
    }
}
