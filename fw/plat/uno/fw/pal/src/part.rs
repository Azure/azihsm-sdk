// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmPartitionManager`] for the Uno PAL.
//!
//! Partition state lives in the GSRAM-resident partition table
//! (`PART_STORE`, mirroring the reference firmware's
//! `hsm_partition_table`).  One entry per partition records the
//! lifecycle [`PartState`], a monotonic generation counter, and a
//! 128-bit resource mask selecting which of the 65 global key-vault
//! tables the partition owns.
//!
//! The mask defaults to **zero** — a partition has no key storage until
//! Admin assigns tables via the `SetResource` IPC.  Lifecycle state, by
//! contrast, defaults to [`PartState::Enabled`] at boot so the emulated
//! device accepts host DDI traffic (e.g. `GetApiRev`) without an
//! explicit enable step; assigning a zero mask via `SetResource` frees
//! the partition back to [`PartState::Unallocated`].
//!
//! Partition management uses the property-based API: [`PartPropId::STATE`]
//! and [`PartPropId::RES_COUNT`] are backed by the table; the remaining
//! property ids return [`HsmError::UnsupportedCmd`] until the uno
//! partition-crypto handlers are implemented.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmEcc;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmEccPct;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_hsm_pal_traits::HsmPartitionManager;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::PartPropId;
use azihsm_fw_hsm_pal_traits::PartState;
use azihsm_fw_uno_trace::tracing::info;

use crate::UnoHsmPal;
use crate::alloc::UnoScopedAlloc;
use crate::io::UnoHsmIo;
use crate::ipc::PfnEnableDisableAction;
use azihsm_fw_uno_drivers_part_store::PartTable;
use azihsm_fw_uno_drivers_part_store::ID_LEN;
use azihsm_fw_uno_drivers_part_store::ID_PUB_KEY_LEN;
pub(crate) use azihsm_fw_uno_drivers_part_store::NUM_PARTITIONS;
use azihsm_fw_uno_drivers_session_store::SessionStore;
use azihsm_fw_uno_drivers_session_store::SessionTable;

/// Length of an ECC P-384 private scalar (HSM wire format), in bytes.
const P384_PRIV_LEN: usize = 48;

/// Stored length of the enable-time keys (establish-credential and
/// session-encryption): ECC P-384 `pub(96) ‖ priv(48)`, mirroring the
/// reference firmware's 144-byte blob.
const ENABLE_KEY_LEN: usize = ID_PUB_KEY_LEN + P384_PRIV_LEN;

impl UnoHsmPal {
    /// Applies a `SetResource` assignment from Admin, driving the partition
    /// lifecycle's allocation transitions (mirroring the reference
    /// firmware's `part_alloc` / `part_free`; identity only — no certs).
    ///
    /// A non-zero `mask` (re)allocates the partition: any prior allocation
    /// is freed, the listed key-vault tables are assigned, the random ID
    /// and ECC P-384 identity key are generated, and the partition moves to
    /// [`PartState::Allocated`]. A separate `PfnEnable` IPC is required to
    /// reach [`PartState::Enabled`] before host IO is accepted.
    ///
    /// A zero `mask` deallocates the partition via [`part_free`].
    ///
    /// Returns the resulting owned-table count (`mask.count_ones()`).
    ///
    /// [`part_free`]: Self::part_free
    pub(crate) async fn set_resource(&self, pid: HsmPartId, mask: u128) -> HsmResult<u32> {
        if mask == 0 {
            self.part_free(pid).await?;
            Ok(0)
        } else {
            self.part_alloc(pid, mask).await
        }
    }

    /// Allocates partition `pid` with resource `mask`, transitioning to
    /// [`PartState::Allocated`] (mirrors `part_alloc`).
    ///
    /// Any existing allocation is freed first so `SetResource` is a
    /// declarative "set the resources to this mask" operation.
    async fn part_alloc(&self, pid: HsmPartId, mask: u128) -> HsmResult<u32> {
        let idx = PartTable::index(pid)?;

        // Free any prior allocation so keygen starts from a clean slate.
        self.part_free(pid).await?;

        // Reject masks overlapping tables already owned by another partition --
        // each key-vault table has exactly one owner.
        if mask & PartTable::others_res_mask(idx) != 0 {
            return Err(HsmError::InvalidArg);
        }
        PartTable::set_res_mask(idx, mask);

        info!("part_alloc", "Provision identity for pid={:?}", pid);
        match self.provision_identity(pid).await {
            Ok(()) => {
                info!("part_alloc", "Provisioned identity for pid={:?}", pid);
                // Generate the enable-time keys at allocation, matching the
                // reference firmware's part_init provisioning. Enable is then
                // just an unconditional flag (see set_pfn_action).
                if let Err(e) = self.provision_enabled_keys(pid).await {
                    PartTable::clear_identity(idx);
                    PartTable::set_res_mask(idx, 0);
                    PartTable::set_state(idx, PartState::Unallocated);
                    return Err(e);
                }
                PartTable::set_state(idx, PartState::Allocated);
                Ok(mask.count_ones())
            }
            Err(e) => {
                info!("part_alloc", "Failed to provision identity for pid={:?}: {:?}", pid, e);
                // Roll back: release resources, wipe any partial identity.
                PartTable::clear_identity(idx);
                PartTable::set_res_mask(idx, 0);
                PartTable::set_state(idx, PartState::Unallocated);
                Err(e)
            }
        }
    }

    /// Frees partition `pid` (mirrors `part_free`):
    /// `Allocated | Enabled | Disabled → Unallocated`.
    ///
    /// If the partition is `Enabled`, its enable-time state is cleared first
    /// (an implicit disable). The identity key is deleted, all identity and
    /// enable-time material is zeroized, the resource mask is released, and
    /// the generation counter is bumped so previously issued key handles are
    /// rejected. Freeing an already-`Unallocated` partition is a no-op.
    async fn part_free(&self, pid: HsmPartId) -> HsmResult<()> {
        let idx = PartTable::index(pid)?;
        if PartTable::state(idx)? == PartState::Unallocated {
            return Ok(());
        }

        // Disable: clear enable-time keys/state (no-op if not enabled).
        self.clear_enabled_state(pid).await;

        // Dealloc: delete the identity key and zeroize identity material.
        if let Some(key_id) = PartTable::id_key(idx) {
            self.delete_key(pid, key_id).await;
        }
        PartTable::clear_identity(idx);

        // Drop all sessions for this incarnation, then release resources and
        // reset lifecycle state. (Disable preserves sessions; free does not.)
        SessionStore::clear(idx);
        PartTable::set_enabled(idx, false);
        PartTable::set_res_mask(idx, 0);
        PartTable::bump_gen(idx);
        PartTable::set_state(idx, PartState::Unallocated);
        Ok(())
    }

    /// Generates an internal ECC P-384 key pair, stores the private key in
    /// partition `pid`'s vault, and returns `(key_handle, public_key)`.
    ///
    /// Mirrors the reference firmware's `create_internal_ecc384_key`. The
    /// `pct` argument is accepted for parity with the trait; the uno PKA
    /// path performs no pairwise-consistency self-test.
    async fn create_internal_ecc384(
        &self,
        pid: HsmPartId,
        kind: HsmVaultKeyKind,
        attrs: HsmVaultKeyAttrs,
        pct: HsmEccPct,
        pub_key_pid: usize,
        pub_key_store: fn(usize, &[u8]),
    ) -> HsmResult<HsmKeyId> {
        let admin_io = UnoHsmIo::admin(pid);
        let alloc = UnoScopedAlloc::for_admin(self);

        // P-384 wire-format lengths: 48-byte scalar, 96-byte X ‖ Y point.
        let priv_buf = alloc.dma_alloc(P384_PRIV_LEN)?;
        let pub_buf = alloc.dma_alloc(ID_PUB_KEY_LEN)?;
        let (_priv_len, pub_len) = self
            .ecc_gen_keypair(
                &admin_io,
                &alloc,
                HsmEccCurve::P384,
                Some((priv_buf, pub_buf)),
                pct,
            )
            .await?;
        if pub_len != ID_PUB_KEY_LEN {
            return Err(HsmError::InternalError);
        }

        // Cache the public key into the partition entry's GSRAM field,
        // copied straight from the DMA buffer (no stack / task-storage
        // intermediate array).
        pub_key_store(pub_key_pid, &pub_buf[..ID_PUB_KEY_LEN]);

        // Assemble the stored blob to the format the vault expects for
        // `kind`: the identity key stores the bare 48-byte private scalar,
        // while the establish-credential and session-encryption keys store
        // the 144-byte `pub(96) ‖ priv(48)` blob (matching the reference
        // firmware's on-storage layout). All buffers come from the DMA
        // allocator — nothing on the stack.
        let key_buf: &DmaBuf = match kind {
            HsmVaultKeyKind::Ecc384Private => priv_buf,
            HsmVaultKeyKind::EstablishCred | HsmVaultKeyKind::SessionEncryption => {
                let buf = alloc.dma_alloc(ENABLE_KEY_LEN)?;
                buf[..ID_PUB_KEY_LEN].copy_from_slice(&pub_buf[..ID_PUB_KEY_LEN]);
                buf[ID_PUB_KEY_LEN..ENABLE_KEY_LEN].copy_from_slice(&priv_buf[..P384_PRIV_LEN]);
                buf
            }
            _ => return Err(HsmError::InternalError),
        };

        crate::vault::vault(&admin_io)
            .create(self, &admin_io, u8::from(pid), key_buf, kind, None, attrs)
            .await
    }

    /// Generates the partition's random ID and ECC P-384 identity key,
    /// storing the private key in the partition's vault and caching the
    /// ID, key handle, and public key in the partition table.
    async fn provision_identity(&self, pid: HsmPartId) -> HsmResult<()> {
        let idx = PartTable::index(pid)?;

        let attrs = HsmVaultKeyAttrs::new()
            .with_internal(true)
            .with_local(true)
            .with_sign(true);
        info!("part_alloc", "create ecc 384 private");
        let key_id = self
            .create_internal_ecc384(
                pid,
                HsmVaultKeyKind::Ecc384Private,
                attrs,
                HsmEccPct::SignVerify,
                idx,
                PartTable::set_id_pub_key,
            )
            .await?;
        info!("part_alloc", "created ecc 384 private");
        PartTable::set_id_key(idx, key_id);

        // Generate the random partition identity straight into its GSRAM
        // field from the DMA buffer (no stack array).
        let alloc = UnoScopedAlloc::for_admin(self);
        let id_buf = alloc.dma_alloc(ID_LEN)?;
        self.rng.fill_bytes(id_buf)?;
        PartTable::set_id(idx, &id_buf[..ID_LEN]);
        Ok(())
    }

    /// Generates the enable-time ECC P-384 key pairs — the
    /// establish-credential and session-encryption keys — mirroring the
    /// reference firmware's `part_enable`. On failure, any partial key is
    /// rolled back. Certificates, nonce, and BK_BOOT are out of scope.
    async fn provision_enabled_keys(&self, pid: HsmPartId) -> HsmResult<()> {
        let idx = PartTable::index(pid)?;
        let attrs = HsmVaultKeyAttrs::new()
            .with_internal(true)
            .with_local(true)
            .with_derive(true);

        info!("part_alloc", "Generating enable-time keys for pid={:?}", pid);

        let ec_id = self
            .create_internal_ecc384(
                pid,
                HsmVaultKeyKind::EstablishCred,
                attrs,
                HsmEccPct::KeyAgreement,
                idx,
                PartTable::set_ec_pub_key,
            )
            .await?;
        PartTable::set_ec_key(idx, ec_id);

        info!("part_alloc", "Generating session-encryption key for pid={:?}", pid);
        match self
            .create_internal_ecc384(
                pid,
                HsmVaultKeyKind::SessionEncryption,
                attrs,
                HsmEccPct::KeyAgreement,
                idx,
                PartTable::set_se_pub_key,
            )
            .await
        {
            Ok(se_id) => {
                PartTable::set_se_key(idx, se_id);
                Ok(())
            }
            Err(e) => {
                // Roll back the establish-credential key.
                info!("part_alloc", "Failed to generate session-encryption key for pid={:?}, rolling back establish-credential key", pid);
                self.delete_key(pid, ec_id).await;
                PartTable::clear_enabled_keys(idx);
                Err(e)
            }
        }
    }

    /// Best-effort deletion of one vault key for partition `pid`.
    async fn delete_key(&self, pid: HsmPartId, key_id: HsmKeyId) {
        let admin_io = UnoHsmIo::admin(pid);
        let _ = crate::vault::vault(&admin_io)
            .delete(self, &admin_io, key_id)
            .await;
    }

    /// Clears partition `pid`'s enable-time state — deletes its
    /// establish-credential and session-encryption keys and zeroes their
    /// handles and public keys (mirrors `clear_enabled_state`).
    ///
    /// Best-effort and idempotent: keys are deleted only if present, so it
    /// is safe to call regardless of the current lifecycle state.
    async fn clear_enabled_state(&self, pid: HsmPartId) {
        let Ok(idx) = PartTable::index(pid) else {
            return;
        };
        if let Some(key_id) = PartTable::ec_key(idx) {
            self.delete_key(pid, key_id).await;
        }
        if let Some(key_id) = PartTable::se_key(idx) {
            self.delete_key(pid, key_id).await;
        }
        PartTable::clear_enabled_keys(idx);
    }

    /// Applies a `PfnEnableDisable` action from Admin, driving the
    /// partition lifecycle:
    ///
    /// * `Enable` — `Allocated` | `Disabled` → `Enabled`: generates the
    ///   establish-credential and session-encryption ECC P-384 key pairs,
    ///   then accepts host IO.
    /// * `Disable` — `Enabled` → `Disabled`: deletes the enable-time keys.
    /// * `Migrate` — not yet supported.
    ///
    /// Returns [`HsmError::InvalidArg`] for an illegal transition and
    /// [`HsmError::UnsupportedCmd`] for unsupported actions.
    pub(crate) async fn set_pfn_action(
        &self,
        pid: HsmPartId,
        action: PfnEnableDisableAction,
    ) -> HsmResult<()> {
        let idx = PartTable::index(pid)?;
        match action {
            // Enable is an unconditional flag set (mirrors the reference
            // firmware's `enable()`); enable-time keys are generated at
            // allocation (SetResource), not here, so the Admin may enable a
            // partition before -- or after -- assigning its resources.
            PfnEnableDisableAction::Enable => {
                PartTable::set_enabled(idx, true);
                Ok(())
            }
            // Disable clears the operational (enable-time) crypto state and
            // unsets the flag (mirrors the reference `disable()`).
            PfnEnableDisableAction::Disable => {
                self.clear_enabled_state(pid).await;
                PartTable::set_enabled(idx, false);
                Ok(())
            }
            _ => {
                Err(HsmError::UnsupportedCmd)
            }
        }
    }
}

/// A validated handle to one partition's GSRAM entry -- the Uno analog of the
/// std PAL's `&PartitionEntry`. Carries only the table index; all state lives
/// in GSRAM and is reached through [`PartTable`]. The session-table view will
/// hang off this handle in a later phase, giving the session PAL impl the same
/// `active_part(io.pid()).session_table()` ergonomics as the std PAL.
#[allow(dead_code)] // consumed by the session/vault phases (P3/P4)
pub(crate) struct PartEntryRef {
    idx: usize,
}

#[allow(dead_code)] // accessors consumed by the session/vault phases (P3/P4)
impl PartEntryRef {
    /// Table index this handle resolves to.
    #[inline]
    pub(crate) fn index(&self) -> usize {
        self.idx
    }

    /// Current lifecycle state.
    #[inline]
    pub(crate) fn state(&self) -> HsmResult<PartState> {
        PartTable::state(self.idx)
    }

    /// Monotonic generation counter (for stale-handle rejection).
    #[inline]
    pub(crate) fn generation(&self) -> u32 {
        PartTable::generation(self.idx)
    }

    /// 128-bit resource (table-ownership) mask.
    #[inline]
    pub(crate) fn res_mask(&self) -> u128 {
        PartTable::res_mask(self.idx)
    }

    /// Exclusive handle to this partition's GSRAM-backed session table.
    /// The Uno analog of std's `entry.session_table`, giving the session PAL
    /// impl `active_part(io.pid()).session_table()` ergonomics.
    #[inline]
    pub(crate) fn session_table(&self) -> &'static mut SessionTable {
        SessionStore::table_mut(self.idx)
    }
}

impl UnoHsmPal {
    /// Resolves `pid` to a partition handle, bounds-checked against
    /// [`NUM_PARTITIONS`]. The Uno analog of the std PAL's `active_part`; does
    /// not gate on lifecycle state -- callers check [`PartEntryRef::state`] as
    /// needed. Session and vault access will hang off the returned handle.
    #[allow(dead_code)] // consumed by the session/vault phases (P3/P4)
    #[inline]
    pub(crate) fn active_part(&self, pid: HsmPartId) -> HsmResult<PartEntryRef> {
        Ok(PartEntryRef {
            idx: PartTable::index(pid)?,
        })
    }
}

impl HsmPartitionManager for UnoHsmPal {
    fn part_prop_get_u8(&self, io: &impl HsmIo, id: PartPropId, _idx: u16) -> HsmResult<u8> {
        let pid = PartTable::index(io.pid())?;
        match id {
            PartPropId::STATE => {
                // The core gates DDI on STATE == Enabled. Report Enabled only
                // when the partition is both allocated (provisioned) AND
                // flagged enabled by PfnEnable.
                let st = PartTable::state(pid)?;
                let en = PartTable::enabled(pid);
                info!(
                    "part",
                    "STATE get: pid={:?} idx={} state={:?} enabled={}",
                    io.pid(),
                    pid,
                    st,
                    en
                );
                if st == PartState::Allocated && en {
                    Ok(PartState::Enabled as u8)
                } else {
                    Ok(st as u8)
                }
            }
            PartPropId::RES_COUNT => Ok(PartTable::res_mask(pid).count_ones() as u8),
            _ => Err(HsmError::UnsupportedCmd),
        }
    }

    fn part_prop_set_u8(
        &self,
        io: &impl HsmIo,
        id: PartPropId,
        _idx: u16,
        value: u8,
    ) -> HsmResult<()> {
        let pid = PartTable::index(io.pid())?;
        match id {
            PartPropId::STATE => {
                let state = PartState::from_u8(value).ok_or(HsmError::InvalidArg)?;
                PartTable::set_state(pid, state);
                Ok(())
            }
            // RES_COUNT is read-only; it is derived from the resource mask.
            _ => Err(HsmError::UnsupportedCmd),
        }
    }

    fn part_prop_get_u16(&self, io: &impl HsmIo, id: PartPropId, _idx: u16) -> HsmResult<u16> {
        let pid = PartTable::index(io.pid())?;
        let key = match id {
            PartPropId::ID_KEY_ID => PartTable::id_key(pid),
            PartPropId::ESTABLISH_CRED_KEY_ID => PartTable::ec_key(pid),
            PartPropId::SESSION_ENC_KEY_ID => PartTable::se_key(pid),
            _ => return Err(HsmError::UnsupportedCmd),
        };
        key.map(u16::from).ok_or(HsmError::KeyNotFound)
    }

    fn part_prop_set_u16(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _value: u16,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_get_u32(&self, _io: &impl HsmIo, _id: PartPropId, _idx: u16) -> HsmResult<u32> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_set_u32(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _value: u32,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_get_u64(&self, _io: &impl HsmIo, _id: PartPropId, _idx: u16) -> HsmResult<u64> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_set_u64(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _value: u64,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_get_bool(&self, _io: &impl HsmIo, _id: PartPropId, _idx: u16) -> HsmResult<bool> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_set_bool(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _value: bool,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_get_bytes<'a>(
        &'a self,
        io: &impl HsmIo,
        id: PartPropId,
        _idx: u16,
    ) -> HsmResult<&'a DmaBuf> {
        let pid = PartTable::index(io.pid())?;
        // Each public-key field is only valid once its backing key has
        // been provisioned (identity at SetResource, the others at enable).
        let (bytes, present) = match id {
            PartPropId::ID => (PartTable::id(pid), PartTable::id_key(pid).is_some()),
            PartPropId::ID_PUB_KEY => (PartTable::id_pub_key(pid), PartTable::id_key(pid).is_some()),
            PartPropId::ESTABLISH_CRED_PUB_KEY => {
                (PartTable::ec_pub_key(pid), PartTable::ec_key(pid).is_some())
            }
            PartPropId::SESSION_ENC_PUB_KEY => {
                (PartTable::se_pub_key(pid), PartTable::se_key(pid).is_some())
            }
            _ => return Err(HsmError::UnsupportedCmd),
        };
        if !present {
            return Err(HsmError::KeyNotFound);
        }
        // SAFETY: the driver returned a partition field in 'static GSRAM;
        // the single-threaded executor guarantees no aliasing mutation for
        // the borrow's duration.
        Ok(unsafe { DmaBuf::from_raw(bytes) })
    }

    fn part_prop_set_bytes(
        &self,
        _io: &impl HsmIo,
        _id: PartPropId,
        _idx: u16,
        _data: &DmaBuf,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_clear(&self, _io: &impl HsmIo, _id: PartPropId, _idx: u16) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }
}
