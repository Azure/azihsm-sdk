// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pairwise consistency tests (PCTs) for the partition's RSA unwrapping key.
//!
//! The unwrapping key reaches the vault two ways, and FIPS 140-3 requires a
//! PCT on both before the key is used:
//!
//! - **Published by the SP:** The SP generates the key, writes it into
//!   the partition's GSRAM slot, and marks the slot `PendingPct`.
//!   [`UnoHsmPal::certify_pending_unwrapping_key`] runs the PCT on a copy of
//!   the slot bytes, then marks the slot `PctPassed` only if it still holds
//!   those bytes. The existing first-use import
//!   (`ensure_unwrapping_key_imported`) imports only a `PctPassed` slot, so
//!   the key never enters the vault untested.
//! - **Restored from its masked backup:** `EstablishCredential` restores
//!   the key after a live migration. `vault_key_create` runs the PCT before
//!   it stores the key.
//!
//! The PCT is the encrypt/decrypt form, because the key only unwraps
//! ([`UnoHsmPal::unwrapping_key_pct`]). Both paths run it through the PAL's
//! RSA PCT runner (see [`crate::pct`]). A key that fails it sends the module
//! to the FIPS error state. A failed SP-published key is first discarded from
//! its slot, if the slot still holds it.

use core::cell::Cell;
use core::future::Future;

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmRsaKey;
use azihsm_fw_hsm_pal_traits::HsmRsaPct;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::PartState;
use azihsm_fw_uno_drivers_part_store::PartStore;
use azihsm_fw_uno_drivers_part_store::UnwrappingKeySlot;
use azihsm_fw_uno_pct::ct_eq;

use crate::UnoHsmPal;

/// Returns `true` for the partition's RSA unwrapping key.
///
/// It's the only `Rsa2kPrivate` key with both `internal` and `unwrap` set.
/// Only the device sets `internal`, so no host-imported key matches.
pub(crate) fn is_unwrapping_key(kind: HsmVaultKeyKind, attrs: HsmVaultKeyAttrs) -> bool {
    kind == HsmVaultKeyKind::Rsa2kPrivate && attrs.internal() && attrs.unwrap()
}

/// A partition's claim on its unwrapping-key PCT, so only one IO tests the
/// slot at a time. Dropping it releases the claim, on every exit path.
struct PctReservation<'a> {
    busy: &'a Cell<bool>,
}

impl<'a> PctReservation<'a> {
    /// Claims the PCT for `pid`, or returns `None` if another IO holds it.
    fn acquire(pal: &'a UnoHsmPal, pid: HsmPartId) -> Option<Self> {
        let busy = pal.unwrap_pct_busy.get(usize::from(u8::from(pid)))?;
        if busy.replace(true) {
            return None;
        }
        Some(Self { busy })
    }
}

impl Drop for PctReservation<'_> {
    fn drop(&mut self) {
        self.busy.set(false);
    }
}

impl UnoHsmPal {
    /// Runs the unwrapping key's PCT on `key`: the encrypt/decrypt form for an
    /// RSA-2048 key in the PKA's layout, `d ‖ n ‖ e`.
    ///
    /// Returns the future of [`rsa_key_pct`](Self::rsa_key_pct) directly. An
    /// `async fn` that awaited it would wrap it in another state machine, which
    /// makes the release image larger.
    pub(crate) fn unwrapping_key_pct<'a>(
        &'a self,
        io: &'a impl HsmIo,
        key: &'a DmaBuf,
    ) -> impl Future<Output = HsmResult<bool>> + 'a {
        self.rsa_key_pct(io, key, HsmRsaKey::Rsa2048Priv, HsmRsaPct::EncryptDecrypt)
    }

    /// Certifies the SP-published unwrapping key of `io`'s partition.
    ///
    /// The Uno app calls this for each host IO before the HSM core handles
    /// it. When the slot holds a `PendingPct` key that isn't imported yet,
    /// this copies the key into the IO's scratch and runs the PCT on the
    /// copy. The result applies only if the slot still holds the tested
    /// bytes: a pass marks the slot `PctPassed`, so a command in this or a
    /// later IO can import the key, and a failure discards the key. A failed
    /// PCT always enters the FIPS error state.
    ///
    /// It leaves the slot unchanged when the partition isn't serving host
    /// traffic, when another IO is testing the slot, when an operation such
    /// as an allocation fails, or when the test passes but the slot changed
    /// during it. Until a later IO certifies the key, `GetUnwrappingKey`
    /// reports it as still pending (`PendingKeyGeneration`), and the host
    /// retries.
    pub async fn certify_pending_unwrapping_key(&self, io: &impl HsmIo) {
        let pid = io.pid();
        let Ok(part) = PartStore::partition(pid) else {
            return;
        };
        // The same admission rule that the core applies to host traffic.
        if !matches!(
            part.state(),
            Ok(PartState::Enabled | PartState::Initializing | PartState::Initialized)
        ) {
            return;
        }
        if part.unwrapping_key_slot() != Some(UnwrappingKeySlot::PendingPct)
            || part.unwrapping_key_id().is_some()
        {
            return;
        }
        let Some(_reservation) = PctReservation::acquire(self, pid) else {
            return;
        };

        // Test a copy. The slot can change while the test waits on the PKA,
        // for example when a teardown wipes it and the SP publishes a new key.
        self.alloc_scoped_async(io, async |alloc| {
            let Ok(key) = alloc.dma_alloc(part.unwrapping_key_bk().len()) else {
                return;
            };
            key.copy_from_slice(part.unwrapping_key_bk());
            let result = self.unwrapping_key_pct(io, key).await;

            // Nothing below awaits, so no teardown can run before the slot is
            // marked or discarded, and the SP doesn't write an occupied slot.
            let same = part.unwrapping_key_slot() == Some(UnwrappingKeySlot::PendingPct)
                && ct_eq(part.unwrapping_key_bk(), key);
            key.zeroize();
            match result {
                Ok(true) if same => part.mark_unwrapping_key_pct_passed(),
                Ok(false) => {
                    // Discard the failed key before entering the error
                    // state. A slot that now holds a different key is left
                    // alone.
                    if same {
                        part.discard_unwrapping_key();
                    }
                    azihsm_fw_uno_fault::enter_error_state(
                        HsmError::PctValidationUnwrappingKeyFailed,
                    );
                }
                // The test didn't finish, or it passed bytes that the slot no
                // longer holds. Leave the slot for a later IO to test.
                _ => {}
            }
        })
        .await;
    }
}
