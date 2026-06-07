// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Session-scoped helpers shared across DDI handlers.
//!
//! Currently this exposes [`session_app_id`], which projects the
//! public [`APP_ID_LEN`]-byte AppId out of the partition PSK bound
//! to a given session.  See [`azihsm_fw_hsm_pal_traits::PSK_LEN`]
//! for the `app_id ‖ app_pin` PSK layout.

use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::APP_ID_LEN;
use azihsm_fw_hsm_pal_traits::PSK_LEN;

/// Returns the public AppId bound to `sess_id`'s partition PSK slot.
///
/// The PSK is structured as `app_id (16) ‖ app_pin (16)` (see
/// [`PSK_LEN`]); this helper loads the PSK by the slot implied by
/// the session role (CO → slot 0, CU → slot 1) and copies its first
/// [`APP_ID_LEN`] bytes into the returned array.  The PIN portion
/// is zeroized from the temporary buffer before return; the AppId
/// itself is public by design (it is surfaced in attestation
/// reports such as PTAReport).
///
/// Combined with the dispatcher's post-`ChangePsk` "drained
/// session" gate, the returned value is stable for the lifetime of
/// the session: once a session has rotated its PSK the only
/// admissible follow-up is `CloseSession`, so no handler can ever
/// observe a post-rotation AppId.
///
/// # Parameters
///
/// - `pal` — PAL implementation.
/// - `io` — caller's I/O context (partition scope).
/// - `sess_id` — Active session slot.
///
/// # Returns
///
/// - `Ok(app_id)` on success.
/// - Any error propagated from
///   [`HsmPartitionManager::part_psk`](azihsm_fw_hsm_pal_traits::HsmPartitionManager::part_psk),
///   notably `PartitionNotEnabled` / `InvalidArg` if the partition
///   is no longer active.
pub fn session_app_id<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    sess_id: HsmSessId,
) -> HsmResult<[u8; APP_ID_LEN]> {
    let psk_id = u8::from(sess_id.role() == azihsm_fw_hsm_pal_traits::SessionRole::CryptoUser);

    let mut psk = [0u8; PSK_LEN];
    let res = pal.part_psk(io, psk_id, Some(&mut psk[..]));

    let mut app_id = [0u8; APP_ID_LEN];
    if res.is_ok() {
        app_id.copy_from_slice(&psk[..APP_ID_LEN]);
    }
    psk.fill(0);
    res.map(|_| app_id)
}
