// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmVault`] implementation for the Uno PAL.
//!
//! Key material lives in the GSRAM key-vault region. The platform-agnostic
//! allocator and key logic live in the [`KeyVault`] crate; the GSRAM table
//! layout and access live in the
//! [`VaultStorage`](azihsm_fw_uno_drivers_vault::VaultStorage) driver. This
//! module just wires the async [`HsmVault`] trait methods to a per-call
//! [`KeyVault`] over that storage, using the PAL's own GDMA controller for
//! large-key copy/zeroize.
//!
//! All state is in GSRAM, so a [`KeyVault`] is constructed per call over a
//! lightweight [`VaultStorage`](azihsm_fw_uno_drivers_vault::VaultStorage)
//! handle that carries only the calling partition's resource mask — there
//! is no PAL-resident vault state.
//!
//! Following the reference firmware, the SDK `meta` (key label) is not
//! stored (see the [`KeyVault`] crate docs).

#![allow(unsafe_code)]

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVault;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_uno_drivers_part_store::PartStore;
use azihsm_fw_uno_drivers_vault::VaultStorage;
use azihsm_fw_uno_key_vault::KeyVault;
use zeroize::Zeroize;

use crate::UnoHsmPal;

#[inline]
pub(crate) fn vault(io: &impl HsmIo) -> KeyVault<VaultStorage> {
    // Out-of-range partitions own no tables (empty mask → no storage).
    let res_mask = PartStore::partition(io.pid()).map_or(0, |p| p.res_mask());
    KeyVault::new(VaultStorage::new(res_mask))
}

impl HsmVault for UnoHsmPal {
    async fn vault_key_create(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        kind: HsmVaultKeyKind,
        session_id: Option<HsmSessId>,
        attrs: HsmVaultKeyAttrs,
    ) -> HsmResult<HsmKeyId> {
        // Bulk keys (AES-GCM / XTS) are consumed by the fast-path engine,
        // not stored as material in the vault: register the key with the
        // engine and keep only the 2-byte handle here.  Ordinary keys are
        // stored directly.
        if is_bulk_kind(kind) {
            return fp_bulk_create(self, io, key, kind, session_id, attrs).await;
        }
        let app_id = u8::from(io.pid());
        let session = session_id.map(u16::from);
        let mut v = vault(io);
        v.create(self, io, app_id, key, kind, session, attrs).await
    }

    fn bulk_key_id(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<Option<u16>> {
        if !is_bulk_kind(self.vault_key_kind(io, key_id)?) {
            return Ok(None);
        }
        let blob = self.vault_key(io, key_id)?;
        let bytes: &[u8] = blob;
        if bytes.len() != core::mem::size_of::<u16>() {
            return Err(HsmError::InternalError);
        }
        Ok(Some(u16::from_le_bytes([bytes[0], bytes[1]])))
    }

    async fn vault_key_delete(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        // Non-bulk keys live entirely in the vault; delete directly.
        if !is_bulk_kind(self.vault_key_kind(io, key_id)?) {
            return vault(io).delete(self, io, key_id).await;
        }

        // Bulk keys are mirrored in the fast-path engine and keep only their
        // 2-byte handle in the vault.  Read the handle + creating session
        // while the entry is live, disable it (synchronous: hides the key and
        // pins its slot across the engine round-trip), delete the engine key,
        // then drop the vault entry.  Re-enable on engine-delete failure.
        let session = vault(io).key_session(key_id)?;
        let bulk_id = {
            let blob = self.vault_key(io, key_id)?;
            let bytes: &[u8] = blob;
            // A bulk entry holds exactly the 2-byte handle; any other length
            // is a corrupt entry.
            if bytes.len() != core::mem::size_of::<u16>() {
                return Err(HsmError::InternalError);
            }
            u16::from_le_bytes([bytes[0], bytes[1]])
        };

        vault(io).disable(key_id)?;

        if let Err(e) =
            fp_bulk_delete(self, io, bulk_id, session.unwrap_or(0), session.is_some()).await
        {
            let _ = vault(io).enable(key_id);
            return Err(e);
        }

        vault(io).delete(self, io, key_id).await
    }

    fn vault_key_disable(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let mut v = vault(io);
        v.disable(key_id)
    }

    fn vault_key_enable(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let mut v = vault(io);
        v.enable(key_id)
    }

    async fn vault_key_delete_by_session(
        &self,
        io: &impl HsmIo,
        session_id: HsmSessId,
    ) -> HsmResult<()> {
        // Session teardown: a single DeleteEphemeral clears the session's
        // bulk keys on the fast-path engine (matched by session id + app id;
        // a no-op when the session owns none), then reclaim their HSM-side
        // slot bitmap, then drop the vault entries.
        let sess = u16::from(session_id);
        fp_delete_ephemeral(self, io, sess).await?;
        vault(io).for_each_session_key(sess, |_key_id, kind, blob| {
            if is_bulk_kind(kind) {
                let bytes: &[u8] = blob;
                if bytes.len() == core::mem::size_of::<u16>() {
                    let id = AesBulk256KeyId::from_bits(u16::from_le_bytes([bytes[0], bytes[1]]));
                    fp_slot_free(id.vault_id(), id.key_index());
                }
            }
        })?;
        vault(io).delete_by_session(self, io, sess).await
    }

    async fn vault_clear(&self, io: &impl HsmIo) -> HsmResult<()> {
        // Partition reset: the fast-path engine drops this partition's bulk
        // keys as part of the accompanying function reset (its resource
        // groups lose their owner), matching the reference firmware, which
        // sends no per-key delete here.  Free the HSM-side slot bitmap for
        // the partition's owned tables so they can be reused, then drop the
        // vault entries.
        let res_mask = PartStore::partition(io.pid()).map_or(0, |p| p.res_mask());
        fp_slots_free_mask(res_mask);
        let mut v = vault(io);
        v.clear(self, io).await
    }

    fn vault_key(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<&DmaBuf> {
        let (table, off, len) = vault(io).key_location(key_id)?;
        let addr = VaultStorage::blob_addr(table) + off;
        // SAFETY: `key_location` validated the key is live; `addr..addr+len`
        // lies within that table's 'static GSRAM blob region.
        Ok(unsafe { DmaBuf::from_raw(core::slice::from_raw_parts(addr as *const u8, len)) })
    }

    fn vault_key_len(&self, _io: &impl HsmIo, kind: HsmVaultKeyKind) -> HsmResult<u16> {
        KeyVault::<VaultStorage>::key_len(kind)
    }

    fn vault_key_kind(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyKind> {
        vault(io).key_kind(key_id)
    }

    fn vault_key_attrs(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyAttrs> {
        vault(io).key_attrs(key_id)
    }
}

// ---------------------------------------------------------------------------
// Fast-path (FP) bulk-key IPC helpers
// ---------------------------------------------------------------------------

use azihsm_fw_single_cell::SingleCell;

use crate::ipc::AesBulk256KeyId;
use crate::ipc::AesBulkKeyType;
use crate::ipc::AesKeyFlag;
use crate::ipc::IPC_MESSAGE_LENGTH;
use crate::ipc::IPC_MESSAGE_PAYLOAD_LEN;
use crate::ipc::IpcMessage;
use crate::ipc::IpcMessageDecoder;
use crate::ipc::IpcMessageEncoderTrait;
use crate::ipc::IpcMessageHeader;
use crate::ipc::IpcMessageKeyUpdate;
use crate::ipc::IpcMessageStatusCode;
use crate::ipc::IpcMessageType;
use crate::ipc::KeyUpdateAction;
use crate::ipc::KeyUpdateInfo;
use crate::pal::IpcChannel;

/// AES-256 bulk key length in bytes.
const FP_BULK_KEY_LEN: usize = 32;

/// FP application id reported to the fast-path engine.  The firmware
/// reports `short_app_id = 0` to the host, so the engine `app_id` is 0.
const FP_APP_ID: u8 = 0;

/// True for the AES bulk vault kinds mirrored in the fast-path engine
/// rather than stored as material in the vault.
fn is_bulk_kind(kind: HsmVaultKeyKind) -> bool {
    matches!(
        kind,
        HsmVaultKeyKind::AesGcmBulk256
            | HsmVaultKeyKind::AesGcmBulk256Unapproved
            | HsmVaultKeyKind::AesXtsBulk256
    )
}

/// Maximum FP bulk-key slots per resource-group table (FP addresses a key
/// within a table by a 0..=6 sub-index).
const FP_MAX_SLOTS_PER_PART: u8 = 7;

/// Number of global FP key-vault tables (resource groups), ids `0..=64`.
const NUM_FP_TABLES: usize = 65;

/// Per-table FP bulk-key slot occupancy bitmap (bit `i` set = slot `i` in
/// use).  Tables are global and each is owned by at most one partition;
/// a partition may own several (its `res_mask`), so a bulk key is placed
/// in a free slot of one of the calling partition's owned tables — the
/// same table-based scheme the HSM key vault uses, giving `7 × owned`
/// capacity rather than a single table's 7 slots.  The FP engine
/// addresses bulk keys by `(vault_id = table, key_index = slot)`.
static FP_SLOTS: SingleCell<[u8; NUM_FP_TABLES]> = SingleCell::new([0u8; NUM_FP_TABLES]);

/// Translate a raw partition id ([`HsmIo::pid`], a SoC MemoryLocation id)
/// into the PCIe function number the fast-path engine matches against.
///
/// The FP engine scopes a bulk key by PCIe function; the host's GCM SQE
/// carries that same PCIe function.  The PF's MemoryLocation id `0x10`
/// maps to PCIe function `64`; VF MemoryLocation ids `0x20..=0x5F` map to
/// VF functions `0..=63`.
fn part_id_to_pcie_fn(part_id: u8) -> HsmResult<u8> {
    const MEM_LOC_PF: u8 = 0x10;
    const MEM_LOC_VF_START: u8 = 0x20;
    const MEM_LOC_VF_END: u8 = 0x5F;
    const PCIE_FN_PF: u8 = 64;
    match part_id {
        MEM_LOC_PF => Ok(PCIE_FN_PF),
        MEM_LOC_VF_START..=MEM_LOC_VF_END => Ok(part_id - MEM_LOC_VF_START),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Allocate a free FP bulk-key slot from one of the partition's owned
/// resource-group tables (`res_mask` bit `t` set = table `t` is owned).
///
/// Returns `(vault_id, key_index)` — the owning table id and the assigned
/// 0..=6 slot — mirroring the HSM key vault's table-based allocation so
/// bulk-key capacity scales with the partition's owned tables.
fn fp_slot_alloc(res_mask: u128) -> HsmResult<(u8, u8)> {
    FP_SLOTS.with(|slots| {
        for (table, used) in slots.iter_mut().enumerate().take(NUM_FP_TABLES) {
            if res_mask & (1u128 << table) == 0 {
                continue; // table not owned by this partition
            }
            for bit in 0..FP_MAX_SLOTS_PER_PART {
                if *used & (1 << bit) == 0 {
                    *used |= 1 << bit;
                    return Ok((table as u8, bit));
                }
            }
        }
        Err(HsmError::NotEnoughSpace)
    })
}

/// Release a previously allocated FP bulk-key slot in table `vault_id`.
fn fp_slot_free(vault_id: u8, key_index: u8) {
    FP_SLOTS.with(|slots| {
        let idx = usize::from(vault_id);
        if idx < slots.len() && key_index < FP_MAX_SLOTS_PER_PART {
            slots[idx] &= !(1 << key_index);
        }
    });
}

/// Free every FP bulk-key slot in the tables owned by `res_mask`.
fn fp_slots_free_mask(res_mask: u128) {
    FP_SLOTS.with(|slots| {
        for (table, used) in slots.iter_mut().enumerate().take(NUM_FP_TABLES) {
            if res_mask & (1u128 << table) != 0 {
                *used = 0;
            }
        }
    });
}

/// Register a bulk key with the fast-path engine and record its 2-byte
/// handle in the vault.
///
/// The engine consumes AES-GCM / XTS bulk keys; the vault keeps only the
/// handle.  `session_id` is the vault binding — `Some` for a session-scoped
/// key (its id is the engine's create/delete match value), `None` for a
/// partition (app) key (which uses `0`).  If the vault write fails after the
/// engine create, the engine key is released so no slot leaks.
async fn fp_bulk_create(
    pal: &UnoHsmPal,
    io: &impl HsmIo,
    key: &DmaBuf,
    kind: HsmVaultKeyKind,
    session_id: Option<HsmSessId>,
    attrs: HsmVaultKeyAttrs,
) -> HsmResult<HsmKeyId> {
    let key_bytes: &[u8] = key;
    if key_bytes.len() != FP_BULK_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }
    let key_type = match kind {
        HsmVaultKeyKind::AesGcmBulk256 => AesBulkKeyType::Gcm,
        HsmVaultKeyKind::AesGcmBulk256Unapproved => AesBulkKeyType::GcmUnapproved,
        HsmVaultKeyKind::AesXtsBulk256 => AesBulkKeyType::Xts,
        _ => return Err(HsmError::InvalidKeyType),
    };

    // The engine scopes a bulk key by PCIe function; `io.pid()` is the raw
    // SoC MemoryLocation id used elsewhere in the HSM, so translate first.
    let pcie_fn = part_id_to_pcie_fn(u8::from(io.pid()))?;
    // Place the key in a free slot of one of the partition's owned tables;
    // `(vault_id, key_index)` addresses it in the engine.
    let res_mask = PartStore::partition(io.pid()).map_or(0, |p| p.res_mask());
    let (vault_id, key_index) = fp_slot_alloc(res_mask)?;

    // The session id the key is scoped to is also the engine's create/delete
    // match value; app keys are unscoped and use 0.
    let session_only = session_id.is_some();
    let fp_session_id = session_id.map(u16::from).unwrap_or(0);

    let mut info = KeyUpdateInfo {
        key_index,
        resource_id: vault_id,
        pfn: pcie_fn,
        action: KeyUpdateAction::Create.0,
        session_id: fp_session_id,
        app_id: FP_APP_ID,
        flag: AesKeyFlag::new()
            .with_session_only(session_only)
            .with_key_type(key_type)
            .into_bits(),
        key_data: [0u8; FP_BULK_KEY_LEN],
    };
    info.key_data.copy_from_slice(key_bytes);
    if let Err(e) = fp_send_key_update(pal, info).await {
        fp_slot_free(vault_id, key_index);
        return Err(e);
    }
    let bulk_id = AesBulk256KeyId::new()
        .with_key_index(key_index)
        .with_vault_id(vault_id)
        .into_bits();

    // Record the 2-byte handle in the vault; on failure, release the engine
    // key so its slot does not leak with no vault entry pointing at it.
    let id_bytes = pal.dma_alloc(io, core::mem::size_of::<u16>())?;
    id_bytes.copy_from_slice(&bulk_id.to_le_bytes());
    let app_id = u8::from(io.pid());
    let mut v = vault(io);
    match v
        .create(
            pal,
            io,
            app_id,
            id_bytes,
            kind,
            session_id.map(u16::from),
            attrs,
        )
        .await
    {
        Ok(handle) => Ok(handle),
        Err(e) => {
            let _ = fp_bulk_delete(pal, io, bulk_id, fp_session_id, session_only).await;
            Err(e)
        }
    }
}

/// Delete a single bulk key from the fast-path engine and free its
/// HSM-side slot.
///
/// `fp_session_id` / `session_only` must match the values the key was
/// created with (the engine matches create against delete); callers read
/// them back from the vault entry.
async fn fp_bulk_delete(
    pal: &UnoHsmPal,
    io: &impl HsmIo,
    bulk_id: u16,
    fp_session_id: u16,
    session_only: bool,
) -> HsmResult<()> {
    let id = AesBulk256KeyId::from_bits(bulk_id);
    let pcie_fn = part_id_to_pcie_fn(u8::from(io.pid()))?;
    let info = KeyUpdateInfo {
        key_index: id.key_index(),
        resource_id: id.vault_id(),
        pfn: pcie_fn,
        action: KeyUpdateAction::Delete.0,
        session_id: fp_session_id,
        app_id: FP_APP_ID,
        flag: AesKeyFlag::new()
            .with_session_only(session_only)
            .into_bits(),
        key_data: [0u8; FP_BULK_KEY_LEN],
    };
    fp_send_key_update(pal, info).await?;
    fp_slot_free(id.vault_id(), id.key_index());
    Ok(())
}

/// Clear all of session `session_id`'s ephemeral bulk keys from the
/// fast-path engine in a single message — the engine iterates its table and
/// matches by session id + app id, mirroring the reference firmware's
/// close-session path.
async fn fp_delete_ephemeral(pal: &UnoHsmPal, io: &impl HsmIo, session_id: u16) -> HsmResult<()> {
    let pcie_fn = part_id_to_pcie_fn(u8::from(io.pid()))?;
    let info = KeyUpdateInfo {
        key_index: 0,
        resource_id: 0,
        pfn: pcie_fn,
        action: KeyUpdateAction::DeleteEphemeral.0,
        session_id,
        app_id: FP_APP_ID,
        flag: AesKeyFlag::new().with_session_only(true).into_bits(),
        key_data: [0u8; FP_BULK_KEY_LEN],
    };
    fp_send_key_update(pal, info).await
}

/// Send an `AesKeyUpdate` message to the bulk-crypto backend over the
/// HSM↔backend IPC channel and await the response, mapping a
/// non-`Success` status to an error.
///
/// The message body carries raw 32-byte AES key material.  The backend
/// zeroizes `key_data` in the shared IPC payload after consuming it, so
/// the HSM does not scrub the ring slot itself; only the local stack copy
/// of the request is zeroized here once the send completes.
async fn fp_send_key_update(pal: &UnoHsmPal, info: KeyUpdateInfo) -> HsmResult<()> {
    let mut request = IpcMessageKeyUpdate {
        header: IpcMessageHeader::new()
            .with_msg_op(IpcMessageKeyUpdate::OP as u32)
            .with_length(IpcMessageKeyUpdate::LEN as u32),
        info,
        _rsvd: [0u8; IPC_MESSAGE_PAYLOAD_LEN - IpcMessageKeyUpdate::LEN],
    }
    .encode();

    let mut resp = [0u32; IPC_MESSAGE_LENGTH];
    pal.ipc
        .send(IpcChannel::FpMessage as u8, &request.data, &mut resp)
        .await;
    // Scrub our local copy of the key material; the backend owns and
    // clears the shared ring slot.
    request.data.zeroize();

    let header = IpcMessageDecoder::decode_header(&IpcMessage { data: resp })
        .map_err(|_| HsmError::InternalError)?;
    // A genuine FP reply sets the response bit; a spurious wake that left
    // the RX ring empty would leave `resp` zeroed (response=false), which
    // must not be mistaken for a `Success` (0) status.
    if !header.response() {
        return Err(HsmError::InternalError);
    }
    // Reject a reply whose opcode is not the AesKeyUpdate we sent: FP echoes
    // the request opcode on its response, so a mismatch means stale or
    // unexpected data in the RX ring, not our key-update ack.
    if header.msg_op() != IpcMessageKeyUpdate::OP as u32 {
        return Err(HsmError::InternalError);
    }
    if header.status() != IpcMessageStatusCode::Success as u32 {
        return Err(HsmError::InternalError);
    }
    Ok(())
}
