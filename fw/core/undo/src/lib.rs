// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Unified undo log — the dual-semantics rollback engine.
//!
//! A command (host-IO or Admin-IPC) drives state changes *optimistically*
//! through plain PAL verbs and records, next to each mutation, an
//! [`UndoLog`] entry describing how to **reverse** it on failure and how
//! to **finalise** it on success.  The dispatcher walks the log once at
//! command completion:
//!
//! - success → [`UndoLog::apply_commit`] (FIFO): finalise (e.g. zeroise a
//!   soft-deleted key);
//! - failure → [`UndoLog::apply_undo`] (LIFO): reverse every mutation.
//!
//! The PAL stays **undo-unaware**: the walk drives the same id-keyed verbs
//! handlers use, via the narrow [`UndoVerbs`] adapter (blanket-implemented
//! for any [`HsmVault`] + [`HsmPartitionManager`]).  The log lives in a
//! leaf crate so both core (host) and a platform PAL (admin) can own one.
//!
//! # Backing buffer
//!
//! Entry slots (a fixed [`ENTRY_SIZE`] bytes each: `tag`/`aux`/`id`/`data`)
//! and variable byte pre-images share **one** buffer, packed from opposite
//! ends — slots up from the front, pre-images down from the back.  An
//! entry's `data` holds an inline scalar or a packed `{offset, len}` handle
//! into the back arena.
//!
//! # Failure policy
//!
//! See [`FailurePolicy`].  Reversing a *logical* change (re-enable a key,
//! restore a property) must succeed → a failure **poisons** the partition;
//! finalising *physical cleanup* (zeroise) that fails leaves only a benign
//! orphan → **best-effort** + reclaim by the recovery sweep.

#![no_std]
// The narrow `UndoVerbs` adapter mirrors the PAL's own `async fn` vault
// methods; an explicit future type buys nothing here.
#![allow(async_fn_in_trait)]

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmPartitionManager;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmSessionManager;
use azihsm_fw_hsm_pal_traits::HsmVault;
use azihsm_fw_hsm_pal_traits::PartPropId;
use azihsm_fw_hsm_pal_traits::PartPropKind;

/// Serialized size of one undo entry slot in the backing buffer (bytes).
pub const ENTRY_SIZE: usize = 8;

/// Recommended per-command entry budget.
///
/// The busiest command (`PartInit`) needs ~10 entries, so 16 leaves
/// headroom.  Entry slots and the byte arena share one buffer
/// (double-ended), so this is a sizing guide, not a hard cap.
pub const MAX_UNDO_ACTIONS: usize = 16;

/// Recommended byte-arena allowance (bytes) for property pre-images.
///
/// Most undos carry no payload (id-only or inline scalar); only an
/// overwrite of an already-set byte property (e.g. a 32-byte PSK) spends
/// arena, so 128 bytes comfortably covers the partition/vault commands.
pub const UNDO_ARENA: usize = 128;

/// Recommended single-buffer size (bytes) for [`UndoLog::new`].
///
/// The dispatcher allocates this much from the per-io heap (or a per-opcode
/// amount) and hands the slice to [`UndoLog::new`], which packs
/// [`ENTRY_SIZE`]-byte entry slots up from the front and byte pre-images
/// down from the back: `16 × 8 + 128 = 256`.
pub const UNDO_LOG_SIZE: usize = MAX_UNDO_ACTIONS * ENTRY_SIZE + UNDO_ARENA;

// ── `tag` byte encoding ──────────────────────────────────────────────
//
//   bits[2:0] kind   bits[4:3] mode (PropRestore only)   bits[7:5] spare
const KIND_MASK: u8 = 0b0000_0111;
const KIND_VAULT_CREATE: u8 = 0;
const KIND_VAULT_DISABLE: u8 = 1;
const KIND_PROP_RESTORE: u8 = 2;
const KIND_SESSION_DESTROY: u8 = 3;

const MODE_SHIFT: u8 = 3;
const MODE_MASK: u8 = 0b0000_0011;
const MODE_ABSENT: u8 = 0;
const MODE_SCALAR: u8 = 1;
const MODE_BYTES: u8 = 2;

/// One undo record, serialized to [`ENTRY_SIZE`] little-endian bytes.
///
/// | field  | bytes | meaning                                            |
/// |--------|-------|----------------------------------------------------|
/// | `tag`  | 1     | action kind + (for `PropRestore`) the `data` mode  |
/// | `aux`  | 1     | reserved (0 today)                                 |
/// | `id`   | 2     | [`HsmKeyId`] or [`PartPropId`] raw value           |
/// | `data` | 4     | inline scalar, or packed `{offset:u16, len:u16}`   |
#[derive(Clone, Copy)]
struct UndoEntry {
    tag: u8,
    /// Reserved (used by the session actions added in P3, e.g. a
    /// `SessionPropId`); written as 0 today.
    aux: u8,
    id: u16,
    data: u32,
}

impl UndoEntry {
    #[inline]
    fn kind(&self) -> u8 {
        self.tag & KIND_MASK
    }

    #[inline]
    fn mode(&self) -> u8 {
        (self.tag >> MODE_SHIFT) & MODE_MASK
    }

    #[inline]
    fn vault_create(id: HsmKeyId) -> Self {
        Self {
            tag: KIND_VAULT_CREATE,
            aux: 0,
            id: u16::from(id),
            data: 0,
        }
    }

    #[inline]
    fn vault_disable(id: HsmKeyId) -> Self {
        Self {
            tag: KIND_VAULT_DISABLE,
            aux: 0,
            id: u16::from(id),
            data: 0,
        }
    }

    #[inline]
    fn session_destroy(id: HsmSessId) -> Self {
        Self {
            tag: KIND_SESSION_DESTROY,
            aux: 0,
            id: u16::from(id),
            data: 0,
        }
    }

    #[inline]
    fn prop_restore_absent(id: PartPropId) -> Self {
        Self {
            tag: KIND_PROP_RESTORE | (MODE_ABSENT << MODE_SHIFT),
            aux: 0,
            id: id.raw(),
            data: 0,
        }
    }

    #[inline]
    fn prop_restore_scalar(id: PartPropId, prior: u32) -> Self {
        Self {
            tag: KIND_PROP_RESTORE | (MODE_SCALAR << MODE_SHIFT),
            aux: 0,
            id: id.raw(),
            data: prior,
        }
    }

    #[inline]
    fn prop_restore_bytes(id: PartPropId, handle: u32) -> Self {
        Self {
            tag: KIND_PROP_RESTORE | (MODE_BYTES << MODE_SHIFT),
            aux: 0,
            id: id.raw(),
            data: handle,
        }
    }

    /// Serialize into an [`ENTRY_SIZE`]-byte slot (little-endian).
    #[inline]
    fn write(&self, slot: &mut [u8]) {
        slot[0] = self.tag;
        slot[1] = self.aux;
        slot[2..4].copy_from_slice(&self.id.to_le_bytes());
        slot[4..8].copy_from_slice(&self.data.to_le_bytes());
    }

    /// Deserialize from an [`ENTRY_SIZE`]-byte slot (little-endian).
    #[inline]
    fn read(slot: &[u8]) -> Self {
        Self {
            tag: slot[0],
            aux: slot[1],
            id: u16::from_le_bytes([slot[2], slot[3]]),
            data: u32::from_le_bytes([slot[4], slot[5], slot[6], slot[7]]),
        }
    }
}

#[inline]
fn pack_bytes_handle(offset: usize, len: usize) -> HsmResult<u32> {
    if offset > usize::from(u16::MAX) || len > usize::from(u16::MAX) {
        return Err(HsmError::UndoLogFull);
    }
    Ok(((offset as u32) << 16) | (len as u32))
}

#[inline]
fn unpack_bytes_handle(handle: u32) -> (usize, usize) {
    ((handle >> 16) as usize, (handle & 0xFFFF) as usize)
}

/// What to do when an [`UndoLog`] walk step's verb fails mid-walk.
///
/// One rule decides it: failures of operations that *restore logical
/// consistency* (re-enable, prop restore) poison; failures of *physical
/// cleanup* (zeroise/delete of already-removed material) are best-effort.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FailurePolicy {
    /// Benign orphan → log and continue; reclaimed by the recovery sweep.
    BestEffort,
    /// In-memory state is now incoherent → fail closed (poison).
    Poison,
}

/// Result of an [`UndoLog`] walk.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[must_use]
pub enum WalkOutcome {
    /// Every step succeeded (or failed best-effort).
    Ok,
    /// A `Poison`-class step failed; the dispatcher must quarantine the
    /// partition (set `Faulted`) and reject further commands until reset.
    Poisoned,
}

/// Per-command undo log — the inverse actions to roll a command back.
///
/// Borrows a **single** backing buffer from the per-command io heap
/// (`io.alloc`) and packs it **double-ended**: fixed [`ENTRY_SIZE`]-byte
/// entry slots grow up from the front, variable byte pre-images grow down
/// from the back, meeting in the middle.  The log therefore costs **no
/// fixed memory** and is sized per-opcode ([`UNDO_LOG_SIZE`] by default, 0
/// for read-only commands).  Lifetime `'a` ties the buffer to the command
/// scope.
///
/// The command runs **lock-free** (see the crate's concurrency model):
/// rollback safety comes from structural invariants, not a lock or a
/// generation counter.  Admin teardown cannot race an in-flight host IO
/// (a partition can't be disabled/freed while host IOs are outstanding,
/// and the undo walk runs before the io is dropped), and host↔host
/// overlap is resolved by the handlers' guards-first sync commit — so the
/// log carries no partition lock guard.
pub struct UndoLog<'a> {
    /// Double-ended backing: entry slots front, byte arena back.
    buf: &'a mut DmaBuf,
    /// Entry slots used (each [`ENTRY_SIZE`] bytes, from the front).
    nentries: usize,
    /// Bytes used by the pre-image arena (from the back).
    arena_used: usize,
}

impl<'a> UndoLog<'a> {
    /// Create an empty log over a single caller-provided [`DmaBuf`].
    ///
    /// `buf.len()` bounds the combined cost of entry slots ([`ENTRY_SIZE`]
    /// bytes each, from the front) and byte pre-images (from the back).
    /// The dispatcher carves `buf` from the per-io DMA heap (sized from
    /// [`UNDO_LOG_SIZE`] / a per-opcode table); tests pass a fixed array
    /// branded as a `DmaBuf`. A `DmaBuf` is required (not a plain slice)
    /// so the log's internal `zeroize` on walk completion can securely
    /// scrub captured secret pre-images with volatile writes.
    pub fn new(buf: &'a mut DmaBuf) -> Self {
        Self {
            buf,
            nentries: 0,
            arena_used: 0,
        }
    }

    /// `true` if no entries have been pushed.
    pub fn is_empty(&self) -> bool {
        self.nentries == 0
    }

    /// Number of entries pushed.
    pub fn len(&self) -> usize {
        self.nentries
    }

    /// Reset the log (success path discards it after the commit walk; the
    /// dispatcher calls this once per command regardless of outcome).
    pub fn discard(&mut self) {
        self.nentries = 0;
        self.arena_used = 0;
    }

    /// Deserialize the `i`th entry slot from the front of the buffer.
    fn entry_at(&self, i: usize) -> UndoEntry {
        let o = i * ENTRY_SIZE;
        UndoEntry::read(&self.buf[o..o + ENTRY_SIZE])
    }

    /// Append an entry slot, given `extra` further arena bytes must also
    /// fit (the byte-payload pushes reserve their bytes here).  Fails with
    /// [`HsmError::UndoLogFull`] if the slots (front) would overrun the
    /// arena (back).
    fn push_entry_reserving(&mut self, entry: UndoEntry, extra: usize) -> HsmResult<()> {
        let slots_end = self
            .nentries
            .checked_add(1)
            .and_then(|n| n.checked_mul(ENTRY_SIZE))
            .ok_or(HsmError::UndoLogFull)?;
        let back = self
            .arena_used
            .checked_add(extra)
            .ok_or(HsmError::UndoLogFull)?;
        if slots_end.checked_add(back).ok_or(HsmError::UndoLogFull)? > self.buf.len() {
            return Err(HsmError::UndoLogFull);
        }
        let o = self.nentries * ENTRY_SIZE;
        entry.write(&mut self.buf[o..o + ENTRY_SIZE]);
        self.nentries += 1;
        Ok(())
    }

    fn push_entry(&mut self, entry: UndoEntry) -> HsmResult<()> {
        self.push_entry_reserving(entry, 0)
    }

    /// Record that a vault key was **created**.
    ///
    /// undo → delete (zeroise) the new key; commit → keep.
    pub fn push_vault_create(&mut self, id: HsmKeyId) -> HsmResult<()> {
        self.push_entry(UndoEntry::vault_create(id))
    }

    /// Record that a vault key was **disabled** (soft-deleted).
    ///
    /// undo → re-enable; commit → delete (zeroise).
    pub fn push_vault_disable(&mut self, id: HsmKeyId) -> HsmResult<()> {
        self.push_entry(UndoEntry::vault_disable(id))
    }

    /// Record that a session was **created** (or promoted from Pending).
    ///
    /// undo → destroy the session (its slot + backing vault keys); commit →
    /// keep.  The inverse is the coarse [`HsmSessionManager::session_destroy`]
    /// (the PAL session ops manage slot + vault together), which is exactly
    /// what the handlers' bespoke rollback used before conversion.
    pub fn push_session_destroy(&mut self, id: HsmSessId) -> HsmResult<()> {
        self.push_entry(UndoEntry::session_destroy(id))
    }

    /// Record that a property was set while previously **absent**.
    ///
    /// undo → clear the slot; commit → keep.
    pub fn push_prop_restore_absent(&mut self, id: PartPropId) -> HsmResult<()> {
        self.push_entry(UndoEntry::prop_restore_absent(id))
    }

    /// Record a scalar property's **prior value** (`U8`/`U16`/`U32`/`Bool`,
    /// widened to `u32`).
    ///
    /// undo → write `prior` back (raw, overwriting); commit → keep.
    pub fn push_prop_restore_scalar(&mut self, id: PartPropId, prior: u32) -> HsmResult<()> {
        self.push_entry(UndoEntry::prop_restore_scalar(id, prior))
    }

    /// Record a byte property's **prior bytes** (copied into the arena).
    ///
    /// undo → write the bytes back; commit → keep.  Fails with
    /// [`HsmError::UndoLogFull`] if the buffer cannot hold the slot plus
    /// `prior`.
    pub fn push_prop_restore_bytes(&mut self, id: PartPropId, prior: &[u8]) -> HsmResult<()> {
        let len = prior.len();
        // Pre-images sit at the back; this one's offset is from the start.
        let new_arena_used = self
            .arena_used
            .checked_add(len)
            .ok_or(HsmError::UndoLogFull)?;
        let off = self
            .buf
            .len()
            .checked_sub(new_arena_used)
            .ok_or(HsmError::UndoLogFull)?;
        let handle = pack_bytes_handle(off, len)?;
        // Reserve the slot AND the arena bytes in one overflow check; only
        // then copy the payload, so a full log never leaks arena.
        self.push_entry_reserving(UndoEntry::prop_restore_bytes(id, handle), len)?;
        self.buf[off..off + len].copy_from_slice(prior);
        self.arena_used = new_arena_used;
        Ok(())
    }

    fn bytes_from_handle(&self, handle: u32) -> HsmResult<&DmaBuf> {
        let (off, len) = unpack_bytes_handle(handle);
        let end = off.checked_add(len).ok_or(HsmError::InvalidArg)?;
        if end > self.buf.len() {
            return Err(HsmError::InvalidArg);
        }
        // `self.buf` is a `&mut DmaBuf`; indexing a `DmaBuf` by range yields
        // a `DmaBuf` sub-view, so this stays DMA-typed with no re-branding.
        Ok(&self.buf[off..end])
    }

    /// Reverse every recorded mutation, **LIFO** (failure path).
    ///
    /// Consumes the log.  Returns [`WalkOutcome::Poisoned`] if any
    /// `Poison`-class step failed; the walk always runs to completion
    /// (best-effort for the rest).  Zeroizes the backing buffer last, so
    /// any captured secret pre-image (e.g. a prior PSK) does not linger.
    pub async fn apply_undo<V: UndoVerbs>(mut self, verbs: &V, io: &impl HsmIo) -> WalkOutcome {
        let mut outcome = WalkOutcome::Ok;
        let mut i = self.nentries;
        while i > 0 {
            i -= 1;
            let entry = self.entry_at(i);
            if self.undo_one(&entry, verbs, io).await.is_err()
                && undo_policy(entry.kind()) == FailurePolicy::Poison
            {
                outcome = WalkOutcome::Poisoned;
            }
        }
        self.zeroize();
        outcome
    }

    /// Finalise every recorded mutation, **FIFO** (success path).
    ///
    /// Consumes the log.  All commit-side failures are best-effort
    /// (benign orphans), so this always returns [`WalkOutcome::Ok`]; the
    /// return type mirrors [`apply_undo`](Self::apply_undo) for a uniform
    /// dispatcher.  Zeroizes the backing buffer last, so any captured
    /// secret pre-image (e.g. a prior PSK) does not linger.
    pub async fn apply_commit<V: UndoVerbs>(mut self, verbs: &V, io: &impl HsmIo) -> WalkOutcome {
        for i in 0..self.nentries {
            let entry = self.entry_at(i);
            // Best-effort: a failed zeroise leaves a benign orphan.
            let _ = self.commit_one(&entry, verbs, io).await;
        }
        self.zeroize();
        WalkOutcome::Ok
    }

    /// Scrub the backing buffer (entries + arena) before the borrow ends,
    /// so captured secret pre-images do not linger in the per-IO DMA heap
    /// (which is only watermark-reset, not cleared, on the next IO).
    fn zeroize(&mut self) {
        // Delegate to `DmaBuf::zeroize`, which uses per-byte volatile
        // writes + a compiler fence so the wipe cannot be elided even
        // though these bytes are never read again through this reference.
        self.buf.zeroize();
        self.nentries = 0;
        self.arena_used = 0;
    }

    async fn undo_one<V: UndoVerbs>(
        &self,
        entry: &UndoEntry,
        verbs: &V,
        io: &impl HsmIo,
    ) -> HsmResult<()> {
        match entry.kind() {
            KIND_VAULT_CREATE => verbs.vault_delete(io, HsmKeyId::from(entry.id)).await,
            KIND_VAULT_DISABLE => verbs.vault_enable(io, HsmKeyId::from(entry.id)),
            KIND_PROP_RESTORE => {
                let id = PartPropId::from_raw(entry.id);
                match entry.mode() {
                    MODE_ABSENT => verbs.prop_clear(io, id),
                    MODE_SCALAR => {
                        let meta = id.meta().ok_or(HsmError::InvalidArg)?;
                        match meta.kind {
                            PartPropKind::U8 => verbs.prop_set_u8(io, id, entry.data as u8),
                            PartPropKind::U16 => verbs.prop_set_u16(io, id, entry.data as u16),
                            PartPropKind::U32 => verbs.prop_set_u32(io, id, entry.data),
                            PartPropKind::Bool => verbs.prop_set_bool(io, id, entry.data != 0),
                            _ => Err(HsmError::InvalidArg),
                        }
                    }
                    MODE_BYTES => {
                        let bytes = self.bytes_from_handle(entry.data)?;
                        verbs.prop_set_bytes(io, id, bytes)
                    }
                    _ => Err(HsmError::InvalidArg),
                }
            }
            KIND_SESSION_DESTROY => verbs.session_destroy(io, HsmSessId::from(entry.id)).await,
            _ => Err(HsmError::InvalidArg),
        }
    }

    async fn commit_one<V: UndoVerbs>(
        &self,
        entry: &UndoEntry,
        verbs: &V,
        io: &impl HsmIo,
    ) -> HsmResult<()> {
        match entry.kind() {
            // Finalise a soft-delete: zeroise the retired key.
            KIND_VAULT_DISABLE => verbs.vault_delete(io, HsmKeyId::from(entry.id)).await,
            // VaultCreate / PropRestore: the live writes already stand.
            _ => Ok(()),
        }
    }
}

/// Failure policy for the **undo** (failure-path) side of an action.
///
/// Commit-side failures are uniformly [`FailurePolicy::BestEffort`].
fn undo_policy(kind: u8) -> FailurePolicy {
    match kind {
        // undo = delete the freshly-created key; a failure orphans a key
        // that was never observable → benign.
        KIND_VAULT_CREATE => FailurePolicy::BestEffort,
        // undo = destroy the freshly-created session; a failure leaks a
        // never-established session slot → benign (reclaimed on teardown).
        KIND_SESSION_DESTROY => FailurePolicy::BestEffort,
        // undo = re-enable / restore: must succeed for consistency.
        _ => FailurePolicy::Poison,
    }
}

/// The narrow set of PAL verbs the undo walk drives.
///
/// Blanket-implemented for any [`HsmVault`] + [`HsmPartitionManager`], so
/// the engine never names the full `HsmPal` super-trait and tests can
/// supply a tiny mock.  The PAL stays undo-unaware — these map onto the
/// same id-keyed verbs handlers already use.
pub trait UndoVerbs {
    /// Delete (zeroise) a vault key.
    async fn vault_delete(&self, io: &impl HsmIo, id: HsmKeyId) -> HsmResult<()>;
    /// Re-enable a soft-deleted (disabled) vault key.
    fn vault_enable(&self, io: &impl HsmIo, id: HsmKeyId) -> HsmResult<()>;
    /// Clear a property slot (restore-to-absent).
    fn prop_clear(&self, io: &impl HsmIo, id: PartPropId) -> HsmResult<()>;
    /// Restore a `U8` property.
    fn prop_set_u8(&self, io: &impl HsmIo, id: PartPropId, value: u8) -> HsmResult<()>;
    /// Restore a `U16` property.
    fn prop_set_u16(&self, io: &impl HsmIo, id: PartPropId, value: u16) -> HsmResult<()>;
    /// Restore a `U32` property.
    fn prop_set_u32(&self, io: &impl HsmIo, id: PartPropId, value: u32) -> HsmResult<()>;
    /// Restore a `Bool` property.
    fn prop_set_bool(&self, io: &impl HsmIo, id: PartPropId, value: bool) -> HsmResult<()>;
    /// Restore a byte property from arena bytes.
    fn prop_set_bytes(&self, io: &impl HsmIo, id: PartPropId, data: &DmaBuf) -> HsmResult<()>;
    /// Destroy a session (its slot + backing vault keys) — the coarse
    /// inverse of session create/promote.
    async fn session_destroy(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<()>;
}

impl<P> UndoVerbs for P
where
    P: HsmVault + HsmPartitionManager + HsmSessionManager,
{
    async fn vault_delete(&self, io: &impl HsmIo, id: HsmKeyId) -> HsmResult<()> {
        HsmVault::vault_key_delete(self, io, id).await
    }

    fn vault_enable(&self, io: &impl HsmIo, id: HsmKeyId) -> HsmResult<()> {
        HsmVault::vault_key_enable(self, io, id)
    }

    fn prop_clear(&self, io: &impl HsmIo, id: PartPropId) -> HsmResult<()> {
        HsmPartitionManager::part_prop_clear(self, io, id)
    }

    fn prop_set_u8(&self, io: &impl HsmIo, id: PartPropId, value: u8) -> HsmResult<()> {
        HsmPartitionManager::part_prop_set_u8(self, io, id, value)
    }

    fn prop_set_u16(&self, io: &impl HsmIo, id: PartPropId, value: u16) -> HsmResult<()> {
        HsmPartitionManager::part_prop_set_u16(self, io, id, value)
    }

    fn prop_set_u32(&self, io: &impl HsmIo, id: PartPropId, value: u32) -> HsmResult<()> {
        HsmPartitionManager::part_prop_set_u32(self, io, id, value)
    }

    fn prop_set_bool(&self, io: &impl HsmIo, id: PartPropId, value: bool) -> HsmResult<()> {
        HsmPartitionManager::part_prop_set_bool(self, io, id, value)
    }

    fn prop_set_bytes(&self, io: &impl HsmIo, id: PartPropId, data: &DmaBuf) -> HsmResult<()> {
        // `data` is already a `&DmaBuf` sub-view of the per-IO undo arena
        // (itself carved from the DMA heap), so no re-branding is needed.
        HsmPartitionManager::part_prop_set_bytes(self, io, id, data)
    }

    async fn session_destroy(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<()> {
        HsmSessionManager::session_destroy(self, io, id).await
    }
}

#[cfg(test)]
mod tests {
    // `.unwrap()` is the idiomatic assertion in unit tests (repo-wide
    // convention; `unwrap_used` is denied only in production code).
    #![allow(clippy::unwrap_used)]

    use core::cell::Cell;
    use core::cell::RefCell;
    use core::future::Future;
    use core::pin::pin;
    use core::task::Context;
    use core::task::Poll;
    use core::task::RawWaker;
    use core::task::RawWakerVTable;
    use core::task::Waker;

    use azihsm_fw_hsm_pal_traits::HsmCqe;
    use azihsm_fw_hsm_pal_traits::HsmPartId;
    use azihsm_fw_hsm_pal_traits::HsmSqe;
    use azihsm_fw_hsm_pal_traits::PartState;

    use super::*;

    // ── Poll-once executor (mock verbs complete immediately) ──────────
    #[allow(unsafe_code)]
    fn block_on<F: Future>(fut: F) -> F::Output {
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        // SAFETY: all vtable ops are no-ops over a null data pointer.
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = pin!(fut);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    #[derive(Default)]
    struct FakeIo {
        sqe: HsmSqe,
        cqe: HsmCqe,
    }

    impl HsmIo for FakeIo {
        fn index(&self) -> u16 {
            0
        }
        fn pid(&self) -> HsmPartId {
            HsmPartId::from(0u8)
        }
        fn queue_id(&self) -> u16 {
            0
        }
        fn queue_idx(&self) -> u16 {
            0
        }
        fn sqe(&self) -> &HsmSqe {
            &self.sqe
        }
        fn cqe(&mut self) -> &mut HsmCqe {
            &mut self.cqe
        }
    }

    // Op codes recorded by the mock, in call order.
    const OP_DELETE: u8 = 1;
    const OP_ENABLE: u8 = 2;
    const OP_CLEAR: u8 = 3;
    const OP_SET_U8: u8 = 4;
    const OP_SET_U16: u8 = 5;
    const OP_SET_U32: u8 = 6;
    const OP_SET_BOOL: u8 = 7;
    const OP_SET_BYTES: u8 = 8;
    const OP_SESSION_DESTROY: u8 = 9;

    #[derive(Clone, Copy, Default)]
    struct Rec {
        op: u8,
        id: u16,
        val: u32,
    }

    struct MockVerbs {
        recs: RefCell<[Rec; 32]>,
        n: Cell<usize>,
        fail_enable: Cell<bool>,
        fail_delete: Cell<bool>,
        fail_session_destroy: Cell<bool>,
        last_bytes: RefCell<[u8; 64]>,
        last_bytes_len: Cell<usize>,
    }

    impl MockVerbs {
        fn new() -> Self {
            Self {
                recs: RefCell::new([Rec::default(); 32]),
                n: Cell::new(0),
                fail_enable: Cell::new(false),
                fail_delete: Cell::new(false),
                fail_session_destroy: Cell::new(false),
                last_bytes: RefCell::new([0u8; 64]),
                last_bytes_len: Cell::new(0),
            }
        }
        fn record(&self, op: u8, id: u16, val: u32) {
            let i = self.n.get();
            self.recs.borrow_mut()[i] = Rec { op, id, val };
            self.n.set(i + 1);
        }
        fn rec(&self, i: usize) -> Rec {
            self.recs.borrow()[i]
        }
        fn count(&self) -> usize {
            self.n.get()
        }

        fn assert_rec(&self, index: usize, op: u8, id: u16, val: u32) {
            let rec = self.rec(index);
            assert_eq!(rec.op, op);
            assert_eq!(rec.id, id);
            assert_eq!(rec.val, val);
        }

        fn assert_last_bytes(&self, expected: &[u8]) {
            assert_eq!(self.last_bytes_len.get(), expected.len());
            assert_eq!(&self.last_bytes.borrow()[..expected.len()], expected);
        }
    }

    fn run_undo(log: UndoLog<'_>, verbs: &MockVerbs, io: &FakeIo) -> WalkOutcome {
        block_on(log.apply_undo(verbs, io))
    }

    fn run_commit(log: UndoLog<'_>, verbs: &MockVerbs, io: &FakeIo) -> WalkOutcome {
        block_on(log.apply_commit(verbs, io))
    }

    impl UndoVerbs for MockVerbs {
        async fn vault_delete(&self, _io: &impl HsmIo, id: HsmKeyId) -> HsmResult<()> {
            self.record(OP_DELETE, u16::from(id), 0);
            if self.fail_delete.get() {
                Err(HsmError::KeyNotFound)
            } else {
                Ok(())
            }
        }
        fn vault_enable(&self, _io: &impl HsmIo, id: HsmKeyId) -> HsmResult<()> {
            self.record(OP_ENABLE, u16::from(id), 0);
            if self.fail_enable.get() {
                Err(HsmError::KeyNotFound)
            } else {
                Ok(())
            }
        }
        fn prop_clear(&self, _io: &impl HsmIo, id: PartPropId) -> HsmResult<()> {
            self.record(OP_CLEAR, id.raw(), 0);
            Ok(())
        }
        fn prop_set_u8(&self, _io: &impl HsmIo, id: PartPropId, value: u8) -> HsmResult<()> {
            self.record(OP_SET_U8, id.raw(), u32::from(value));
            Ok(())
        }
        fn prop_set_u16(&self, _io: &impl HsmIo, id: PartPropId, value: u16) -> HsmResult<()> {
            self.record(OP_SET_U16, id.raw(), u32::from(value));
            Ok(())
        }
        fn prop_set_u32(&self, _io: &impl HsmIo, id: PartPropId, value: u32) -> HsmResult<()> {
            self.record(OP_SET_U32, id.raw(), value);
            Ok(())
        }
        fn prop_set_bool(&self, _io: &impl HsmIo, id: PartPropId, value: bool) -> HsmResult<()> {
            self.record(OP_SET_BOOL, id.raw(), u32::from(value));
            Ok(())
        }
        fn prop_set_bytes(&self, _io: &impl HsmIo, id: PartPropId, data: &DmaBuf) -> HsmResult<()> {
            self.record(OP_SET_BYTES, id.raw(), data.len() as u32);
            self.last_bytes.borrow_mut()[..data.len()].copy_from_slice(data);
            self.last_bytes_len.set(data.len());
            Ok(())
        }
        async fn session_destroy(&self, _io: &impl HsmIo, id: HsmSessId) -> HsmResult<()> {
            self.record(OP_SESSION_DESTROY, u16::from(id), 0);
            if self.fail_session_destroy.get() {
                Err(HsmError::InvalidArg)
            } else {
                Ok(())
            }
        }
    }

    // Declares a stack-local backing buffer and a log borrowing it —
    // mirrors what the dispatcher's `bind_undo` does from the per-io heap.
    macro_rules! log {
        ($name:ident) => {
            let mut buf = [0u8; UNDO_LOG_SIZE];
            // SAFETY: in-process test heap buffer; branding as a DmaBuf is sound.
            #[allow(unsafe_code)]
            let dma = unsafe { DmaBuf::from_raw_mut(&mut buf) };
            let mut $name: UndoLog<'_> = UndoLog::new(dma);
        };
    }

    fn key(v: u16) -> HsmKeyId {
        HsmKeyId::from(v)
    }

    #[test]
    fn undo_walk_is_lifo_and_dispatches() {
        log!(log);
        log.push_vault_create(key(11)).unwrap();
        log.push_prop_restore_scalar(PartPropId::UPS_KEY_ID, 0x42)
            .unwrap();
        log.push_vault_disable(key(22)).unwrap();

        let m = MockVerbs::new();
        let io = FakeIo::default();
        assert_eq!(run_undo(log, &m, &io), WalkOutcome::Ok);

        // LIFO: disable→enable(22), then prop→set_u16(UPS, 0x42), then create→delete(11).
        assert_eq!(m.count(), 3);
        m.assert_rec(0, OP_ENABLE, 22, 0);
        m.assert_rec(1, OP_SET_U16, PartPropId::UPS_KEY_ID.raw(), 0x42);
        m.assert_rec(2, OP_DELETE, 11, 0);
    }

    #[test]
    fn commit_walk_finalizes_disable_only() {
        log!(log);
        log.push_vault_create(key(11)).unwrap();
        log.push_vault_disable(key(22)).unwrap();
        log.push_prop_restore_scalar(PartPropId::UPS_KEY_ID, 7)
            .unwrap();

        let m = MockVerbs::new();
        let io = FakeIo::default();
        assert_eq!(run_commit(log, &m, &io), WalkOutcome::Ok);

        // Only the disable finalises (zeroise the retired key); the rest noop.
        assert_eq!(m.count(), 1);
        m.assert_rec(0, OP_DELETE, 22, 0);
    }

    #[test]
    fn prop_restore_absent_clears_on_undo() {
        log!(log);
        log.push_prop_restore_absent(PartPropId::UPS_KEY_ID)
            .unwrap();
        let m = MockVerbs::new();
        let io = FakeIo::default();
        assert_eq!(run_undo(log, &m, &io), WalkOutcome::Ok);
        assert_eq!(m.count(), 1);
        m.assert_rec(0, OP_CLEAR, PartPropId::UPS_KEY_ID.raw(), 0);
    }

    #[test]
    fn scalar_restore_picks_kind_width() {
        log!(log);
        // STATE is U8, UPS_KEY_ID is U16.
        log.push_prop_restore_scalar(PartPropId::STATE, PartState::Enabled as u32)
            .unwrap();
        log.push_prop_restore_scalar(PartPropId::UPS_KEY_ID, 0x1234)
            .unwrap();
        let m = MockVerbs::new();
        let io = FakeIo::default();
        assert_eq!(run_undo(log, &m, &io), WalkOutcome::Ok);
        // LIFO: UPS first (U16), then STATE (U8).
        m.assert_rec(0, OP_SET_U16, PartPropId::UPS_KEY_ID.raw(), 0x1234);
        m.assert_rec(
            1,
            OP_SET_U8,
            PartPropId::STATE.raw(),
            PartState::Enabled as u32,
        );
    }

    #[test]
    fn bytes_restore_round_trips_through_arena() {
        log!(log);
        let prior = [0xABu8; 32];
        log.push_prop_restore_bytes(PartPropId::PSK_CU, &prior)
            .unwrap();
        let m = MockVerbs::new();
        let io = FakeIo::default();
        assert_eq!(run_undo(log, &m, &io), WalkOutcome::Ok);
        m.assert_rec(0, OP_SET_BYTES, PartPropId::PSK_CU.raw(), 32);
        m.assert_last_bytes(&prior);
    }

    #[test]
    fn poison_when_restore_verb_fails() {
        log!(log);
        log.push_vault_disable(key(5)).unwrap(); // undo = enable (Poison-class)
        let m = MockVerbs::new();
        m.fail_enable.set(true);
        let io = FakeIo::default();
        assert_eq!(run_undo(log, &m, &io), WalkOutcome::Poisoned);
    }

    #[test]
    fn best_effort_when_create_undo_fails() {
        log!(log);
        log.push_vault_create(key(5)).unwrap(); // undo = delete (BestEffort)
        let m = MockVerbs::new();
        m.fail_delete.set(true);
        let io = FakeIo::default();
        // Delete fails, but a never-observable new key is a benign orphan.
        assert_eq!(run_undo(log, &m, &io), WalkOutcome::Ok);
    }

    #[test]
    fn session_destroy_undoes_and_commit_noops() {
        let m = MockVerbs::new();
        let io = FakeIo::default();

        // commit → keep the session (no verb calls).
        log!(commit_log);
        commit_log.push_session_destroy(HsmSessId::from(7)).unwrap();
        assert_eq!(run_commit(commit_log, &m, &io), WalkOutcome::Ok);
        assert_eq!(m.count(), 0, "commit must not tear down a live session");

        // undo → session_destroy(id).
        log!(undo_log);
        undo_log.push_session_destroy(HsmSessId::from(7)).unwrap();
        assert_eq!(run_undo(undo_log, &m, &io), WalkOutcome::Ok);
        m.assert_rec(0, OP_SESSION_DESTROY, 7, 0);
    }

    #[test]
    fn session_destroy_undo_is_best_effort() {
        // A failed teardown leaks a never-established session → benign.
        log!(log);
        log.push_session_destroy(HsmSessId::from(3)).unwrap();
        let m = MockVerbs::new();
        m.fail_session_destroy.set(true);
        let io = FakeIo::default();
        assert_eq!(run_undo(log, &m, &io), WalkOutcome::Ok);
    }

    #[test]
    fn push_overflows_when_buffer_full() {
        log!(log);
        // With no arena bytes spent, the whole buffer holds entry slots.
        let cap = UNDO_LOG_SIZE / ENTRY_SIZE;
        for _ in 0..cap {
            log.push_vault_create(key(1)).unwrap();
        }
        assert_eq!(log.len(), cap);
        assert_eq!(log.push_vault_create(key(1)), Err(HsmError::UndoLogFull));
    }

    #[test]
    fn discard_resets_buffer() {
        log!(log);
        // Two arena-sized payloads cannot coexist (their slots + bytes
        // exceed the buffer), but one fits; discard resets the back
        // pointer so the second still fits afterwards.
        log.push_prop_restore_bytes(PartPropId::PSK_CU, &[1u8; UNDO_ARENA])
            .unwrap();
        assert!(!log.is_empty());
        log.discard();
        assert!(log.is_empty());
        log.push_prop_restore_bytes(PartPropId::PSK_CU, &[2u8; UNDO_ARENA])
            .unwrap();
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn bytes_push_overflows_when_buffer_full() {
        log!(log);
        // One payload that, with its slot, exactly fills the buffer.
        log.push_prop_restore_bytes(PartPropId::PSK_CU, &[1u8; UNDO_LOG_SIZE - ENTRY_SIZE])
            .unwrap();
        // Even a single further byte now overflows.
        assert_eq!(
            log.push_prop_restore_bytes(PartPropId::PSK_CU, &[2u8; 1]),
            Err(HsmError::UndoLogFull)
        );
    }
}
