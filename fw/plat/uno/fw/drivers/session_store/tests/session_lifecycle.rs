// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host regression tests for the persistent session lifecycle.

// Compile the real storage drivers together so both use part_store's existing
// cfg(test) heap-backed GSRAM. A normal dependency would use hardware addresses.
extern crate self as azihsm_fw_uno_drivers_part_store;

#[allow(dead_code)]
#[path = "../../part_store/src/part_store.rs"]
mod part_store;
#[allow(dead_code)]
#[path = "../src/session_store.rs"]
mod session_store;

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmSessionState;
use azihsm_fw_hsm_pal_traits::SessionRole;
use part_store::PartResetKind;
pub use part_store::PartStore;
pub use part_store::Partition;
use session_store::SessionStore;

#[test]
fn migrate_retains_established_ids_and_releases_pending_handshakes() {
    let pid = HsmPartId::from(50u8);
    let part = PartStore::partition(pid).unwrap();
    part.reset();
    let mut table = SessionStore::partition(pid).unwrap();
    let active = table.create(HsmKeyId::from(0u16)).unwrap();
    let (pending, _) = table
        .create_pending(SessionRole::CryptoUser, HsmKeyId::from(1u16))
        .unwrap();
    table.try_consume_psk_change(active).unwrap();

    table.mark_all_needs_renego();
    part.clear_state(PartResetKind::Migrate);

    assert!(matches!(
        table.state(active),
        HsmSessionState::NeedsRenegotiation
    ));
    assert!(matches!(table.state(pending), HsmSessionState::Invalid));
    let retained = 1u8 << u16::from(active);
    assert_eq!(&part.session_table()[..2], &[retained, retained]);
    assert_eq!(&part.session_table()[2..], &[0u8; 16]);
    assert_eq!(part.session_meta(), &[0u8; 2]);
    assert!(table.occupied_physical_ids().iter().all(Option::is_none));

    // A repeated reset must not release the established reservation.
    table.mark_all_needs_renego();
    part.clear_state(PartResetKind::Migrate);
    assert!(matches!(
        table.state(active),
        HsmSessionState::NeedsRenegotiation
    ));

    let new_key = HsmKeyId::from(2u16);
    assert_eq!(table.recreate(active, new_key).unwrap(), active);
    assert!(matches!(table.state(active), HsmSessionState::Active));
    assert_eq!(table.physical_id(active).unwrap(), new_key);
    table.try_consume_psk_change(active).unwrap();
    assert_eq!(table.create(HsmKeyId::from(3u16)).unwrap(), pending);
}

#[test]
fn recreate_rejects_non_renegotiating_slots_without_changing_the_table() {
    let pid = HsmPartId::from(51u8);
    let part = PartStore::partition(pid).unwrap();
    part.reset();
    let mut table = SessionStore::partition(pid).unwrap();
    let active = table.create(HsmKeyId::from(0u16)).unwrap();
    let (pending, _) = table
        .create_pending(SessionRole::CryptoUser, HsmKeyId::from(1u16))
        .unwrap();
    let before = *part.session_table();
    let meta_before = *part.session_meta();
    let replacement = HsmKeyId::from(2u16);

    assert_eq!(
        table.recreate(active, replacement),
        Err(HsmError::InvalidArg)
    );
    assert_eq!(
        table.recreate(pending, replacement),
        Err(HsmError::InvalidArg)
    );
    assert_eq!(
        table.recreate(HsmSessId::from(7u16), replacement),
        Err(HsmError::SessionNotFound)
    );
    assert_eq!(part.session_table(), &before);
    assert_eq!(part.session_meta(), &meta_before);
}

#[test]
fn reopen_rollback_preserves_the_reserved_id_for_retry() {
    let pid = HsmPartId::from(52u8);
    PartStore::partition(pid).unwrap().reset();
    let mut table = SessionStore::partition(pid).unwrap();
    let id = table.create(HsmKeyId::from(0u16)).unwrap();
    table.mark_all_needs_renego();
    let migrated = *PartStore::partition(pid).unwrap().session_table();

    table.recreate(id, HsmKeyId::from(1u16)).unwrap();
    table.rollback_recreation(id).unwrap();
    assert!(matches!(
        table.state(id),
        HsmSessionState::NeedsRenegotiation
    ));
    assert_eq!(
        PartStore::partition(pid).unwrap().session_table(),
        &migrated
    );
    assert!(table.occupied_physical_ids().iter().all(Option::is_none));
    assert_eq!(table.recreate(id, HsmKeyId::from(2u16)).unwrap(), id);
}

#[test]
fn disable_retains_ids_but_free_releases_them() {
    let pid = HsmPartId::from(53u8);
    let part = PartStore::partition(pid).unwrap();
    part.reset();
    let mut table = SessionStore::partition(pid).unwrap();
    let id = table.create(HsmKeyId::from(0u16)).unwrap();
    let (pending, _) = table
        .create_pending(SessionRole::CryptoUser, HsmKeyId::from(1u16))
        .unwrap();

    table.mark_all_needs_renego();
    part.clear_state(PartResetKind::Disable);
    assert!(matches!(
        table.state(id),
        HsmSessionState::NeedsRenegotiation
    ));
    assert!(matches!(table.state(pending), HsmSessionState::Invalid));
    let retained = 1u8 << u16::from(id);
    assert_eq!(&part.session_table()[..2], &[retained, retained]);
    assert!(table.occupied_physical_ids().iter().all(Option::is_none));

    table.clear_all();
    assert!(matches!(table.state(id), HsmSessionState::Invalid));
    assert_eq!(part.session_table(), &[0u8; 18]);
    assert_eq!(table.create(HsmKeyId::from(2u16)).unwrap(), id);
}

#[test]
fn clear_all_releases_active_pending_and_renegotiating_slots() {
    let pid = HsmPartId::from(54u8);
    let part = PartStore::partition(pid).unwrap();
    part.reset();
    let mut table = SessionStore::partition(pid).unwrap();
    let renegotiating = table.create(HsmKeyId::from(0u16)).unwrap();
    table.mark_all_needs_renego();
    let active = table.create(HsmKeyId::from(1u16)).unwrap();
    let (pending, _) = table
        .create_pending(SessionRole::CryptoUser, HsmKeyId::from(2u16))
        .unwrap();
    table.try_consume_psk_change(active).unwrap();

    // Full teardown must clear both masks, even if some slots already
    // needed renegotiation before resources were removed.
    table.clear_all();

    assert_eq!(part.session_table(), &[0u8; 18]);
    assert_eq!(part.session_meta(), &[0u8; 2]);
    for id in [renegotiating, active, pending] {
        assert!(matches!(table.state(id), HsmSessionState::Invalid));
        assert_eq!(
            table.recreate(id, HsmKeyId::from(3u16)),
            Err(HsmError::SessionNotFound)
        );
    }
    assert!(table.occupied_physical_ids().iter().all(Option::is_none));
    assert_eq!(table.create(HsmKeyId::from(4u16)).unwrap(), renegotiating);
}
