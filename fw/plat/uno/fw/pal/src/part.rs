// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmPartitionManager`] for the Uno PAL.
//!
//! Per-partition state lives in the GSRAM-resident partition persistent
//! store, owned by the
//! [`PartStore`](azihsm_fw_uno_drivers_part_store::PartStore) driver. This
//! module maps the property-based partition API onto that driver via
//! [`PartStore::partition`] handles — it no longer touches GSRAM directly.
//!
//! The resource mask defaults to **zero** — a partition has no key storage
//! until Admin assigns tables via the `SetResource` IPC, at which point the
//! identity is generated. Lifecycle state defaults to
//! [`PartState::Unallocated`]; a non-zero `SetResource` allocates the
//! partition and a `PfnEnable` IPC enables it.

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
use azihsm_fw_uno_drivers_part_store::PartStore;
use azihsm_fw_uno_drivers_session_store::SessionStore;

use crate::UnoHsmPal;
use crate::alloc::UnoScopedAlloc;
use crate::io::UnoHsmIo;

/// Number of partition slots (one per global key-vault table index).
pub const NUM_PARTITIONS: usize = 65;

/// Length of the identity ECC P-384 public key (X ‖ Y), in bytes.
pub const ID_PUB_KEY_LEN: usize = 96;

/// Length of an ECC P-384 private scalar (HSM wire format), in bytes.
const P384_PRIV_LEN: usize = 48;

/// Stored length of the enable-time keys (establish-credential and
/// session-encryption): ECC P-384 `pub(96) ‖ priv(48)`, mirroring the
/// reference firmware's 144-byte blob.
const ENABLE_KEY_LEN: usize = ID_PUB_KEY_LEN + P384_PRIV_LEN;

impl UnoHsmPal {
    /// Allocates partition `pid` with resource `mask`: assigns the key-vault
    /// tables, generates the random ID and ECC P-384 identity key, and
    /// provisions the masked boot key (mirrors the reference firmware's
    /// `part_alloc`; identity only — no certs).
    ///
    /// The final state depends on the admin's PF/VF ordering:
    /// - **VF** (`is_pf == false`): `SetResource` precedes `PfnEnable`, so the
    ///   partition is left [`PartState::Allocated`]; a later [`part_enable`]
    ///   provisions the enable-time keys and reaches [`PartState::Enabled`].
    /// - **PF** (`is_pf == true`): `PfnEnable` already ran (the partition is
    ///   [`PartState::Enabled`] with `res_mask == 0` and deferred keys), so
    ///   this provisions the deferred enable-time keys too and leaves the
    ///   partition [`PartState::Enabled`], ready for host IO.
    ///
    /// Any existing allocation is freed first — except the PF pre-enable case,
    /// which must preserve the enable — so `SetResource` is a declarative
    /// "set the resources to this mask" operation.
    ///
    /// [`part_enable`]: Self::part_enable
    pub(crate) async fn part_alloc(
        &self,
        pid: HsmPartId,
        mask: u128,
        is_pf: bool,
    ) -> HsmResult<()> {
        let part = PartStore::partition(pid)?;

        // A PF enabled before its resources were assigned is `Enabled` with no
        // resource mask yet (its identity/enabled keys are deferred); freeing
        // it would tear the enable down, so skip the free only in that exact
        // PF pre-enable case. Every other prior state — a VF, or a
        // fully-provisioned `Enabled` partition being reallocated — is freed so
        // keygen starts from a clean slate (no leaked vault keys, no stale
        // resource mask).
        let pre_enabled = is_pf && part.state()? == PartState::Enabled && part.res_mask() == 0;
        if !pre_enabled {
            self.part_free(pid).await?;
        }
        part.set_res_mask(mask);

        // Provision the identity then the masked boot key; on any failure
        // roll the whole allocation back so the slot is left fully
        // `Unallocated` — no leaked vault key, no stale resource mask. A
        // bare `?` here would skip cleanup and strand resources.
        if let Err(e) = self.provision_allocation(pid).await {
            self.rollback_alloc(pid).await;
            return Err(e);
        }

        if pre_enabled {
            // PF pre-enable: PfnEnable preceded SetResource, so the enabled keys were
            // deferred from `part_enable`; provision them now that `res_mask`
            // exists and leave the partition `Enabled`.
            if let Err(e) = self.provision_enabled_keys(pid).await {
                self.rollback_alloc(pid).await;
                return Err(e);
            }
            part.set_state(PartState::Enabled);
        } else {
            // VF (or PF SetResource-before-enable): PfnEnable follows and provisions the enabled keys.
            part.set_state(PartState::Allocated);
        }
        Ok(())
    }

    /// Provisions the per-allocation key material: the random ID and ECC
    /// P-384 identity key, then the partition's `Masked_BK_BOOT`.
    async fn provision_allocation(&self, pid: HsmPartId) -> HsmResult<()> {
        self.provision_identity(pid).await?;
        self.provision_masked_bk_boot(pid).await
    }

    /// Reverts a failed [`part_alloc`]: deletes the identity vault key (if
    /// one was created), zeroizes all identity and boot-key material, and
    /// releases the resource mask, returning the slot to `Unallocated`.
    ///
    /// Best-effort and used only on the allocation error path — it mirrors
    /// [`part_free`]'s teardown but skips the generation bump (no handles
    /// were ever handed out for this aborted allocation).
    ///
    /// [`part_free`]: Self::part_free
    async fn rollback_alloc(&self, pid: HsmPartId) {
        let Ok(part) = PartStore::partition(pid) else {
            return;
        };
        if let Some(key_id) = part.id_key_id() {
            self.delete_key(pid, key_id).await;
        }
        part.clear_identity();
        part.clear_masked_bk_boot();
        part.set_res_mask(0);
        part.set_state(PartState::Unallocated);
    }

    /// Creates the partition's `Masked_BK_BOOT` once at allocation.
    ///
    /// Generates a fresh random `BK_BOOT`, envelopes it under the
    /// partition's `BKx`, and persists only the masked form.  The raw
    /// boot key is never stored; it is recovered on demand by unmasking
    /// this blob.  Stable for the partition's whole allocation lifetime
    /// (survives enable/disable; cleared on free).
    async fn provision_masked_bk_boot(&self, pid: HsmPartId) -> HsmResult<()> {
        let part = PartStore::partition(pid)?;
        let admin_io = UnoHsmIo::admin(pid);
        // Rewind the admin slot's bump heap before the masking sequence.
        let _alloc = UnoScopedAlloc::for_admin(self);
        let masked = azihsm_fw_core_crypto_key_derive::mask_bk_boot(self, &admin_io).await?;
        part.set_masked_bk_boot(masked)
    }

    /// Frees partition `pid` (mirrors `part_free`):
    /// `Allocated | Enabled | Disabled → Unallocated`.
    ///
    /// If the partition is `Enabled`, its enable-time state is cleared first
    /// (an implicit disable). The identity key is deleted, all identity and
    /// enable-time material is zeroized, the resource mask is released, and
    /// the generation counter is bumped so previously issued key handles are
    /// rejected. Freeing an already-`Unallocated` partition is a no-op.
    pub(crate) async fn part_free(&self, pid: HsmPartId) -> HsmResult<()> {
        let part = PartStore::partition(pid)?;
        if part.state()? == PartState::Unallocated {
            return Ok(());
        }

        // Disable: clear enable-time keys/state (no-op if not enabled).
        self.clear_enabled_state(pid).await;

        // Dealloc: delete the identity key and zeroize identity material.
        if let Some(key_id) = part.id_key_id() {
            self.delete_key(pid, key_id).await;
        }
        part.clear_identity();
        // The masked boot key persists across enable/disable; it is wiped
        // only here, on free.
        part.clear_masked_bk_boot();

        // Release resources and reset lifecycle state.
        part.set_res_mask(0);
        part.bump_generation();
        part.set_state(PartState::Unallocated);
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
    ) -> HsmResult<HsmKeyId> {
        let part = PartStore::partition(pid)?;
        let admin_io = UnoHsmIo::admin(pid);
        let alloc = UnoScopedAlloc::for_admin(self);

        // Generate the key pair into transient admin-slot DMA scratch
        // buffers. The public key is *not* written straight into its
        // part_store field: doing so would hold a `&mut` borrow into the
        // GSRAM-backed PartStore across the keygen `.await`, which the
        // PartStore driver forbids (no yielding while a slot is mutably
        // borrowed). The store is updated synchronously after the await.
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

        // Persist the freshly generated public key into its part_store
        // field (selected by `kind`). This borrow of the PartStore slot is
        // strictly synchronous — no `.await` is reached while it is held.
        match kind {
            HsmVaultKeyKind::Ecc384Private => part.set_id_pub_key(pub_buf)?,
            HsmVaultKeyKind::EstablishCred => part.set_ec_pub_key(pub_buf)?,
            HsmVaultKeyKind::SessionEncryption => part.set_se_pub_key(pub_buf)?,
            _ => return Err(HsmError::InternalError),
        }

        // Assemble the stored blob to the format the vault expects for
        // `kind`: the identity key stores the bare 48-byte private scalar,
        // while the establish-credential and session-encryption keys store
        // the 144-byte `pub(96) ‖ priv(48)` blob (matching the reference
        // firmware's on-storage layout), using the scratch public key.
        let key_buf: &DmaBuf = match kind {
            HsmVaultKeyKind::Ecc384Private => priv_buf,
            HsmVaultKeyKind::EstablishCred | HsmVaultKeyKind::SessionEncryption => {
                self.build_enable_key_blob(&alloc, pub_buf, priv_buf)?
            }
            _ => return Err(HsmError::InternalError),
        };

        crate::vault::vault(&admin_io)
            .create(self, &admin_io, u8::from(pid), key_buf, kind, None, attrs)
            .await
    }

    /// Builds the enable-key blob (`pub(96) ‖ priv(48)`, the
    /// establish-credential / session-encryption on-storage layout) in a
    /// freshly allocated DMA buffer.
    fn build_enable_key_blob<'a>(
        &self,
        alloc: &'a UnoScopedAlloc<'_>,
        pub_key: &[u8],
        priv_buf: &DmaBuf,
    ) -> HsmResult<&'a mut DmaBuf> {
        let buf = alloc.dma_alloc(ENABLE_KEY_LEN)?;
        buf[..ID_PUB_KEY_LEN].copy_from_slice(pub_key);
        buf[ID_PUB_KEY_LEN..ENABLE_KEY_LEN].copy_from_slice(&priv_buf[..P384_PRIV_LEN]);
        Ok(buf)
    }

    /// Generates the partition's random ID and ECC P-384 identity key,
    /// storing the private key in the partition's vault and caching the
    /// ID, key handle, and public key in the partition table.
    async fn provision_identity(&self, pid: HsmPartId) -> HsmResult<()> {
        let mut part = PartStore::partition(pid)?;

        let attrs = HsmVaultKeyAttrs::new()
            .with_internal(true)
            .with_local(true)
            .with_sign(true);

        let key_id = self
            .create_internal_ecc384(
                pid,
                HsmVaultKeyKind::Ecc384Private,
                attrs,
                HsmEccPct::SignVerify,
            )
            .await?;
        part.set_id_key_id(Some(key_id));

        // Generate the random partition identity straight into its
        // part_store field (RNG fill is a plain CPU copy, no DMA buffer
        // needed).
        self.rng.fill_bytes(part.id_mut())?;
        Ok(())
    }

    /// Generates the enable-time ECC P-384 key pairs — the
    /// establish-credential and session-encryption keys — mirroring the
    /// reference firmware's `part_enable`. On failure, any partial key is
    /// rolled back. Certificates, nonce, and BK_BOOT are out of scope.
    async fn provision_enabled_keys(&self, pid: HsmPartId) -> HsmResult<()> {
        let part = PartStore::partition(pid)?;
        let attrs = HsmVaultKeyAttrs::new()
            .with_internal(true)
            .with_local(true)
            .with_derive(true);

        let ec_id = self
            .create_internal_ecc384(
                pid,
                HsmVaultKeyKind::EstablishCred,
                attrs,
                HsmEccPct::KeyAgreement,
            )
            .await?;
        part.set_ec_key_id(Some(ec_id));

        match self
            .create_internal_ecc384(
                pid,
                HsmVaultKeyKind::SessionEncryption,
                attrs,
                HsmEccPct::KeyAgreement,
            )
            .await
        {
            Ok(se_id) => {
                part.set_se_key_id(Some(se_id));
                Ok(())
            }
            Err(e) => {
                // Roll back the establish-credential key.
                self.delete_key(pid, ec_id).await;
                part.clear_enabled_keys();
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

    /// Clears partition `pid`'s per-tenant state — deletes every
    /// enable-time and provisioning vault key plus every session-blob
    /// vault key, then zeroizes all cached public keys, caller-presented
    /// secrets, write-once provisioning fields, the nonce, VM launch GUID,
    /// BK3 incarnation flag, and the session table (see [`PartStore`]'s
    /// `clear_enabled_state`).
    ///
    /// The partition identity and `Masked_BK_BOOT` are preserved — they
    /// are torn down only on free. Best-effort and idempotent: keys are
    /// deleted only if present, so it is safe to call regardless of the
    /// current lifecycle state.
    async fn clear_enabled_state(&self, pid: HsmPartId) {
        let Ok(part) = PartStore::partition(pid) else {
            return;
        };
        // Delete every enable-time and provisioning vault key before the
        // backing handles are zeroized below.
        for key_id in [
            part.ec_key_id(),
            part.se_key_id(),
            part.mk_key_id(),
            part.ups_key_id(),
            part.pta_key_id(),
            part.unwrapping_key_id(),
        ]
        .into_iter()
        .flatten()
        {
            self.delete_key(pid, key_id).await;
        }
        // Delete every session-blob vault key (Active, NeedsRenegotiation,
        // or Pending) mapped by the session table, so none are orphaned in
        // the vault when the table is zeroized below.
        if let Ok(sessions) = SessionStore::partition(pid) {
            for key_id in sessions.occupied_physical_ids().into_iter().flatten() {
                self.delete_key(pid, key_id).await;
            }
        }
        part.clear_enabled_state();
    }

    /// Enables partition `pid` (mirrors the reference firmware's
    /// `part_enable`). The accepted transitions depend on the PF/VF ordering:
    ///
    /// - **VF / re-enable** (`Allocated | Disabled → Enabled`): the
    ///   establish-credential and session-encryption ECC P-384 key pairs are
    ///   generated here, then host IO is accepted.
    /// - **PF enable-before-SetResource** (`Unallocated → Enabled`, only when
    ///   `is_pf`): `res_mask` is not yet assigned, so the enable-time keys
    ///   cannot be provisioned (the vault has no table). The enable is
    ///   recorded and key provisioning is *deferred* to [`part_alloc`], which
    ///   runs when `SetResource` arrives.
    ///
    /// Re-enabling an already-`Enabled` partition is idempotent. Certificates,
    /// nonce, and BK_BOOT are out of scope.
    ///
    /// Returns [`HsmError::InvalidArg`] for an illegal transition.
    ///
    /// [`part_alloc`]: Self::part_alloc
    pub(crate) async fn part_enable(&self, pid: HsmPartId, is_pf: bool) -> HsmResult<()> {
        let part = PartStore::partition(pid)?;
        match part.state()? {
            PartState::Allocated | PartState::Disabled => {
                self.provision_enabled_keys(pid).await?;
                part.set_state(PartState::Enabled);
                Ok(())
            }
            // PF (PcieFunction::Pf) is enabled before SetResource assigns its
            // `res_mask`, so the enabled keys cannot be provisioned here (the
            // vault has no table yet). Record the enable; `part_alloc`
            // provisions the keys once the resources arrive.
            PartState::Unallocated if is_pf => {
                part.set_state(PartState::Enabled);
                Ok(())
            }
            // Idempotent re-enable (e.g. an Admin/driver retry).
            PartState::Enabled => Ok(()),
            _ => Err(HsmError::InvalidArg),
        }
    }

    /// Disables partition `pid`: `Enabled` → `Disabled`.
    ///
    /// Deletes the enable-time keys and clears their handles and public
    /// keys.
    ///
    /// Returns [`HsmError::InvalidArg`] for an illegal transition.
    pub(crate) async fn part_disable(&self, pid: HsmPartId) -> HsmResult<()> {
        let part = PartStore::partition(pid)?;
        match part.state()? {
            PartState::Enabled => {
                self.clear_enabled_state(pid).await;
                part.set_state(PartState::Disabled);
                Ok(())
            }
            _ => Err(HsmError::InvalidArg),
        }
    }
}

impl HsmPartitionManager for UnoHsmPal {
    fn part_prop_get_u8(&self, io: &impl HsmIo, id: PartPropId) -> HsmResult<u8> {
        let part = PartStore::partition(io.pid())?;
        match id {
            PartPropId::STATE => Ok(part.state()? as u8),
            PartPropId::RES_COUNT => Ok(part.res_mask().count_ones() as u8),
            _ => Err(HsmError::UnsupportedCmd),
        }
    }

    fn part_prop_set_u8(&self, io: &impl HsmIo, id: PartPropId, value: u8) -> HsmResult<()> {
        let part = PartStore::partition(io.pid())?;
        match id {
            PartPropId::STATE => {
                let target = PartState::from_u8(value).ok_or(HsmError::InvalidArg)?;
                let current = part.state()?;
                match (current, target) {
                    // The single caller-facing transition: `Enabled →
                    // Initializing`, which additionally requires the four
                    // write-once provisioning fields (PTA key, UPS key,
                    // policy hash, POTA thumbprint) to be present. Mirrors
                    // the std PAL property-API contract.
                    (PartState::Enabled, PartState::Initializing) => {
                        if part.pta_key_id().is_none()
                            || part.ups_key_id().is_none()
                            || !part.policy_hash_valid()
                            || !part.pota_thumbprint_valid()
                        {
                            return Err(HsmError::InvalidArg);
                        }
                        part.set_state(PartState::Initializing);
                        Ok(())
                    }
                    // No-op writes (same state) are accepted as a convenience.
                    (cur, tgt) if cur == tgt => Ok(()),
                    // All other transitions are PAL-internal (driven by the
                    // device-command lifecycle) — reject from the prop API.
                    _ => Err(HsmError::InvalidArg),
                }
            }
            // RES_COUNT is read-only; it is derived from the resource mask.
            _ => Err(HsmError::UnsupportedCmd),
        }
    }

    fn part_prop_get_u16(&self, io: &impl HsmIo, id: PartPropId) -> HsmResult<u16> {
        let part = PartStore::partition(io.pid())?;
        let key = match id {
            PartPropId::ID_KEY_ID => part.id_key_id(),
            PartPropId::MK_KEY_ID => part.mk_key_id(),
            PartPropId::UPS_KEY_ID => part.ups_key_id(),
            PartPropId::PTA_KEY_ID => part.pta_key_id(),
            PartPropId::RSA_UNWRAPPING_KEY_ID => part.unwrapping_key_id(),
            PartPropId::ESTABLISH_CRED_KEY_ID => part.ec_key_id(),
            PartPropId::SESSION_ENC_KEY_ID => part.se_key_id(),
            _ => return Err(HsmError::UnsupportedCmd),
        };
        key.map(u16::from).ok_or(HsmError::PartPropNotFound)
    }

    fn part_prop_set_u16(&self, io: &impl HsmIo, id: PartPropId, value: u16) -> HsmResult<()> {
        let part = PartStore::partition(io.pid())?;
        let key = HsmKeyId::from(value);
        match id {
            PartPropId::MK_KEY_ID => part.set_mk_key_id(Some(key)),
            PartPropId::SESSION_ENC_KEY_ID => part.set_se_key_id(Some(key)),
            PartPropId::ESTABLISH_CRED_KEY_ID => part.set_ec_key_id(Some(key)),
            // UPS / PTA key ids are write-once provisioning fields.
            PartPropId::UPS_KEY_ID => {
                if part.ups_key_id().is_some() {
                    return Err(HsmError::UpsKeyAlreadySet);
                }
                part.set_ups_key_id(Some(key));
            }
            PartPropId::PTA_KEY_ID => {
                if part.pta_key_id().is_some() {
                    return Err(HsmError::PtaKeyAlreadySet);
                }
                part.set_pta_key_id(Some(key));
            }
            // ID_KEY_ID / RSA_UNWRAPPING_KEY_ID are read-only.
            _ => return Err(HsmError::UnsupportedCmd),
        }
        Ok(())
    }

    fn part_prop_get_u32(&self, io: &impl HsmIo, id: PartPropId) -> HsmResult<u32> {
        let part = PartStore::partition(io.pid())?;
        match id {
            PartPropId::GEN => Ok(part.generation()),
            _ => Err(HsmError::UnsupportedCmd),
        }
    }

    fn part_prop_set_u32(&self, _io: &impl HsmIo, _id: PartPropId, _value: u32) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn part_prop_get_bool(&self, io: &impl HsmIo, id: PartPropId) -> HsmResult<bool> {
        let part = PartStore::partition(io.pid())?;
        match id {
            PartPropId::BK3_INITIALIZED => Ok(part.bk3_initialized()),
            _ => Err(HsmError::UnsupportedCmd),
        }
    }

    fn part_prop_set_bool(&self, io: &impl HsmIo, id: PartPropId, value: bool) -> HsmResult<()> {
        let part = PartStore::partition(io.pid())?;
        match id {
            // One-shot gate: false→true is the only legal transition.
            // Re-asserting true returns Bk3AlreadyInitialized; clearing
            // back to false is rejected (reset happens PAL-internally on
            // partition free / NSSR).
            PartPropId::BK3_INITIALIZED => {
                if !value {
                    return Err(HsmError::InvalidArg);
                }
                if part.bk3_initialized() {
                    return Err(HsmError::Bk3AlreadyInitialized);
                }
                part.set_bk3_initialized(true);
                Ok(())
            }
            _ => Err(HsmError::UnsupportedCmd),
        }
    }

    fn part_prop_get_bytes<'a>(&'a self, io: &impl HsmIo, id: PartPropId) -> HsmResult<&'a DmaBuf> {
        let p = PartStore::partition(io.pid())?;
        match id {
            // Identity / public keys — present once the backing key has
            // been provisioned (identity at SetResource, the others at
            // enable).
            PartPropId::ID if p.id_key_id().is_some() => Ok(p.id()),
            PartPropId::ID_PUB_KEY if p.id_key_id().is_some() => Ok(p.id_pub_key()),
            PartPropId::ESTABLISH_CRED_PUB_KEY if p.ec_key_id().is_some() => Ok(p.ec_pub_key()),
            PartPropId::SESSION_ENC_PUB_KEY if p.se_key_id().is_some() => Ok(p.se_pub_key()),
            PartPropId::ID
            | PartPropId::ID_PUB_KEY
            | PartPropId::ESTABLISH_CRED_PUB_KEY
            | PartPropId::SESSION_ENC_PUB_KEY => Err(HsmError::PartPropNotFound),

            // Always-present fields.
            PartPropId::NONCE => Ok(p.nonce()),
            PartPropId::VM_LAUNCH_GUID => Ok(p.vm_launch_guid()),
            PartPropId::PSK_CO => Ok(p.psk_co()),
            PartPropId::PSK_CU => Ok(p.psk_cu()),

            // AbsentUntilSet fields — `PartPropNotFound` until provisioned.
            PartPropId::CREDENTIAL if p.credential_valid() => Ok(p.credential()),
            PartPropId::POTA_THUMBPRINT if p.pota_thumbprint_valid() => Ok(p.pota_thumbprint()),
            PartPropId::SATA_THUMBPRINT if p.sata_thumbprint_valid() => Ok(p.sata_thumbprint()),
            PartPropId::SAPOTA_THUMBPRINT if p.sapota_thumbprint_valid() => {
                Ok(p.sapota_thumbprint())
            }
            PartPropId::BK3_SESSION if p.bk3_session_valid() => Ok(p.bk3_session()),
            PartPropId::PTA_PUB_KEY if p.pta_pub_key_valid() => Ok(p.pta_pub_key()),
            PartPropId::POLICY_HASH if p.policy_hash_valid() => Ok(p.policy_hash()),
            PartPropId::CREDENTIAL
            | PartPropId::POTA_THUMBPRINT
            | PartPropId::SATA_THUMBPRINT
            | PartPropId::SAPOTA_THUMBPRINT
            | PartPropId::BK3_SESSION
            | PartPropId::PTA_PUB_KEY
            | PartPropId::POLICY_HASH => Err(HsmError::PartPropNotFound),
            // Variable-length blobs are absent when their stored length is 0.
            PartPropId::SEALED_BK3 => {
                let b = p.sealed_bk3();
                if b.is_empty() {
                    Err(HsmError::PartPropNotFound)
                } else {
                    Ok(b)
                }
            }
            PartPropId::MASKED_BK_BOOT => {
                let b = p.masked_bk_boot();
                if b.is_empty() {
                    Err(HsmError::PartPropNotFound)
                } else {
                    Ok(b)
                }
            }
            _ => Err(HsmError::UnsupportedCmd),
        }
    }

    fn part_prop_set_bytes(&self, io: &impl HsmIo, id: PartPropId, data: &DmaBuf) -> HsmResult<()> {
        let p = PartStore::partition(io.pid())?;
        match id {
            PartPropId::NONCE => p.set_nonce(data),
            PartPropId::PSK_CO => p.set_psk_co(data),
            PartPropId::PSK_CU => p.set_psk_cu(data),
            PartPropId::CREDENTIAL => p.set_credential(data),
            PartPropId::SEALED_BK3 => p.set_sealed_bk3(data),
            PartPropId::MASKED_BK_BOOT => p.set_masked_bk_boot(data),
            PartPropId::BK3_SESSION => p.set_bk3_session(data),
            PartPropId::POTA_THUMBPRINT => p.set_pota_thumbprint(data),
            PartPropId::SATA_THUMBPRINT => p.set_sata_thumbprint(data),
            PartPropId::SAPOTA_THUMBPRINT => p.set_sapota_thumbprint(data),
            PartPropId::PTA_PUB_KEY => p.set_pta_pub_key(data),
            PartPropId::POLICY_HASH => p.set_policy_hash(data),
            _ => Err(HsmError::UnsupportedCmd),
        }
    }

    fn part_prop_clear(&self, io: &impl HsmIo, id: PartPropId) -> HsmResult<()> {
        let p = PartStore::partition(io.pid())?;
        match id {
            // Read-write vault-ref key ids reset to absent.
            PartPropId::MK_KEY_ID => p.set_mk_key_id(None),
            PartPropId::UPS_KEY_ID => p.set_ups_key_id(None),
            PartPropId::PTA_KEY_ID => p.set_pta_key_id(None),
            PartPropId::SESSION_ENC_KEY_ID => p.set_se_key_id(None),
            PartPropId::ESTABLISH_CRED_KEY_ID => p.set_ec_key_id(None),
            // AbsentUntilSet byte fields zeroize and reset to absent.
            PartPropId::CREDENTIAL => p.clear_credential(),
            PartPropId::POTA_THUMBPRINT => p.clear_pota_thumbprint(),
            PartPropId::SATA_THUMBPRINT => p.clear_sata_thumbprint(),
            PartPropId::SAPOTA_THUMBPRINT => p.clear_sapota_thumbprint(),
            PartPropId::BK3_SESSION => p.clear_bk3_session(),
            PartPropId::SEALED_BK3 => p.clear_sealed_bk3(),
            PartPropId::MASKED_BK_BOOT => p.clear_masked_bk_boot(),
            PartPropId::PTA_PUB_KEY => p.clear_pta_pub_key(),
            PartPropId::POLICY_HASH => p.clear_policy_hash(),
            _ => return Err(HsmError::UnsupportedCmd),
        }
        Ok(())
    }
}
