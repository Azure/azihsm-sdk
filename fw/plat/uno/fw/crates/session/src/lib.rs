// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Platform-agnostic per-partition session-table logic for Uno firmware.

#![no_std]

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmSessionState;
use azihsm_fw_hsm_pal_traits::SessionRole;
use azihsm_fw_hsm_pal_traits::SESSION_PENDING_BLOB_MAX;

/// Maximum concurrent sessions per partition.
pub const MAX_SESSIONS: usize = 8;

/// Opaque per-slot handshake state for Pending sessions.
#[repr(C)]
#[derive(Clone)]
pub struct PendingBlob {
    data: [u8; SESSION_PENDING_BLOB_MAX],
    len: u32,
}

impl PendingBlob {
    pub fn clear(&mut self) {
        self.data.fill(0);
        self.len = 0;
    }

    pub fn store(&mut self, src: &[u8]) -> HsmResult<()> {
        if src.len() > SESSION_PENDING_BLOB_MAX {
            return Err(HsmError::InvalidArg);
        }
        self.data[..src.len()].copy_from_slice(src);
        self.data[src.len()..].fill(0);
        self.len = src.len() as u32;
        Ok(())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

/// Per-partition session slot allocator.
///
/// Resident in GSRAM (see [`SessionStore`]); all-zero is the valid empty
/// state.  Logic ported verbatim from the std PAL `SessionTable`.
#[repr(C)]
pub struct SessionTable {
    /// Bit N set when slot N is allocated (any state).
    alloc_mask: u8,
    /// Bit N set when slot N needs renegotiation.
    renego_mask: u8,
    /// Bit N set when slot N is in the Pending state.
    pending_mask: u8,
    /// Bit N set after a successful one-shot PSK change on slot N.
    psk_change_mask: u8,
    /// Logical -> physical vault key id, valid when allocated and not pending.
    phys_ids: [u16; MAX_SESSIONS],
    /// Per-slot handshake state, valid when the pending bit is set.
    pending_blobs: [PendingBlob; MAX_SESSIONS],
    /// Per-slot init-sequence stamp, for oldest-Pending eviction.
    pending_seqs: [u64; MAX_SESSIONS],
    /// Monotonic counter stamped into `pending_seqs` on each Pending alloc.
    next_init_seq: u64,
}

impl SessionTable {
    /// Validate that a logical session id refers to an allocated slot.
    pub fn active_slot(&self, id: HsmSessId) -> HsmResult<usize> {
        let slot = u16::from(id) as usize;
        if slot >= MAX_SESSIONS || (self.alloc_mask & (1 << slot)) == 0 {
            return Err(HsmError::SessionNotFound);
        }
        Ok(slot)
    }

    /// Allocate a new Active session in the lowest free slot.
    pub fn create(&mut self, physical_id: HsmKeyId) -> HsmResult<HsmSessId> {
        let slot = self.alloc_mask.trailing_ones() as usize;
        if slot >= MAX_SESSIONS {
            return Err(HsmError::VaultSessionLimitReached);
        }
        self.alloc_mask |= 1 << slot;
        self.phys_ids[slot] = u16::from(physical_id);
        Ok(HsmSessId::from(slot as u16))
    }

    /// Delete (close) a session, freeing its slot and zeroizing pending state.
    pub fn delete(&mut self, id: HsmSessId) -> HsmResult<HsmKeyId> {
        let slot = self.active_slot(id)?;
        let mask = !(1u8 << slot);
        let was_pending = (self.pending_mask & (1 << slot)) != 0;
        let phys = if was_pending {
            HsmKeyId::from(0)
        } else {
            HsmKeyId::from(self.phys_ids[slot])
        };
        self.alloc_mask &= mask;
        self.renego_mask &= mask;
        self.pending_mask &= mask;
        self.psk_change_mask &= mask;
        self.phys_ids[slot] = 0;
        self.pending_blobs[slot].clear();
        self.pending_seqs[slot] = 0;
        Ok(phys)
    }

    /// Look up the physical vault key id for an Active/NeedsRenegotiation slot.
    pub fn physical_id(&self, id: HsmSessId) -> HsmResult<HsmKeyId> {
        let slot = self.active_slot(id)?;
        if (self.pending_mask & (1 << slot)) != 0 {
            return Err(HsmError::SessionNotFound);
        }
        Ok(HsmKeyId::from(self.phys_ids[slot]))
    }

    /// Re-key a session that is in the NeedsRenegotiation state.
    pub fn recreate(
        &mut self,
        id: HsmSessId,
        new_physical: HsmKeyId,
    ) -> HsmResult<HsmSessId> {
        let slot = self.active_slot(id)?;
        if (self.renego_mask & (1 << slot)) == 0 {
            return Err(HsmError::InvalidArg);
        }
        self.renego_mask &= !(1u8 << slot);
        // Fresh key material -> fresh one-shot PSK-change budget.
        self.psk_change_mask &= !(1u8 << slot);
        self.phys_ids[slot] = u16::from(new_physical);
        Ok(id)
    }

    /// Query the lifecycle state of a session slot.
    pub fn state(&self, id: HsmSessId) -> HsmSessionState {
        let Ok(slot) = self.active_slot(id) else {
            return HsmSessionState::Invalid;
        };
        if (self.pending_mask & (1 << slot)) != 0 {
            return HsmSessionState::Pending;
        }
        if (self.renego_mask & (1 << slot)) != 0 {
            return HsmSessionState::NeedsRenegotiation;
        }
        HsmSessionState::Active
    }

    /// Whether all session slots are occupied.
    pub fn limit_reached(&self) -> bool {
        self.alloc_mask.count_ones() >= MAX_SESSIONS as u32
    }

    /// Mark a session as needing renegotiation (CP1-internal; P0).
    pub fn set_needs_renego(&mut self, id: HsmSessId) {
        let slot = u16::from(id) as usize;
        if slot < MAX_SESSIONS && (self.alloc_mask & (1 << slot)) != 0 {
            self.renego_mask |= 1 << slot;
        }
    }

    /// Reserve a Pending slot for an in-flight handshake, with role-ranged
    /// placement and oldest-Pending eviction.
    pub fn create_pending(
        &mut self,
        role: SessionRole,
        handshake_state: &[u8],
    ) -> HsmResult<HsmSessId> {
        if handshake_state.len() > SESSION_PENDING_BLOB_MAX {
            return Err(HsmError::InvalidArg);
        }
        let (range_start, range_end) = role_slot_range(role);

        // 1. Find an Empty slot in range.
        for slot in range_start..=range_end {
            if (self.alloc_mask & (1 << slot)) == 0 {
                self.install_pending(slot, handshake_state)?;
                return Ok(HsmSessId::from(slot as u16));
            }
        }

        // 2. Evict the oldest Pending slot in range.
        let mut victim: Option<usize> = None;
        let mut victim_seq = u64::MAX;
        for slot in range_start..=range_end {
            if (self.pending_mask & (1 << slot)) != 0 && self.pending_seqs[slot] < victim_seq {
                victim_seq = self.pending_seqs[slot];
                victim = Some(slot);
            }
        }
        if let Some(slot) = victim {
            let _ = self.delete(HsmSessId::from(slot as u16))?;
            self.install_pending(slot, handshake_state)?;
            return Ok(HsmSessId::from(slot as u16));
        }

        // 3. All slots in range are Active or NeedsRenegotiation.
        Err(HsmError::VaultSessionLimitReached)
    }

    pub fn install_pending(&mut self, slot: usize, handshake_state: &[u8]) -> HsmResult<()> {
        self.pending_blobs[slot].store(handshake_state)?;
        self.alloc_mask |= 1 << slot;
        self.pending_mask |= 1 << slot;
        self.next_init_seq = self.next_init_seq.wrapping_add(1);
        self.pending_seqs[slot] = self.next_init_seq;
        self.phys_ids[slot] = 0;
        Ok(())
    }

    /// Borrow the Pending handshake blob for a slot.
    pub fn pending_state(&self, id: HsmSessId) -> HsmResult<&[u8]> {
        let slot = self.active_slot(id)?;
        if (self.pending_mask & (1 << slot)) == 0 {
            return Err(HsmError::SessionNotPending);
        }
        Ok(self.pending_blobs[slot].as_slice())
    }

    /// Promote a Pending slot to Active, binding it to a vault key.
    pub fn promote(&mut self, id: HsmSessId, physical_id: HsmKeyId) -> HsmResult<()> {
        let slot = self.active_slot(id)?;
        if (self.pending_mask & (1 << slot)) == 0 {
            return Err(HsmError::SessionNotPending);
        }
        self.pending_mask &= !(1u8 << slot);
        self.psk_change_mask &= !(1u8 << slot);
        self.pending_blobs[slot].clear();
        self.pending_seqs[slot] = 0;
        self.phys_ids[slot] = u16::from(physical_id);
        Ok(())
    }

    /// Atomically reserve the slot's one-shot PSK-change budget.
    pub fn try_consume_psk_change(&mut self, id: HsmSessId) -> HsmResult<()> {
        let slot = self.active_slot(id)?;
        if (self.pending_mask & (1 << slot)) != 0 {
            return Err(HsmError::SessionNotFound);
        }
        let bit = 1u8 << slot;
        if (self.psk_change_mask & bit) != 0 {
            return Err(HsmError::InvalidPermissions);
        }
        self.psk_change_mask |= bit;
        Ok(())
    }
}

/// Inclusive `(start, end)` slot range eligible for a session role.
pub fn role_slot_range(role: SessionRole) -> (usize, usize) {
    match role {
        SessionRole::CryptoOfficer => (0, 0),
        SessionRole::CryptoUser => (1, MAX_SESSIONS - 1),
    }
}

