// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Suite-private helpers for the `RawKeyImport` integration tests.

use azihsm_crypto::Rng;
use azihsm_ddi::Ddi;
use azihsm_ddi::DdiError;
use azihsm_ddi_mbor_test_hooks::helper_get_priv_key;
use azihsm_ddi_mbor_test_hooks::helper_raw_key_import;
use azihsm_ddi_mbor_types::DdiDeviceKind;
use azihsm_ddi_mbor_types::DdiKeyAvailability;
use azihsm_ddi_mbor_types::DdiKeyType;
use azihsm_ddi_mbor_types::DdiKeyUsage;
use azihsm_ddi_mbor_types::DdiStatus;

use crate::common::*;

/// Skip the test when the device is not physical (the hooks are hardware-only).
pub(super) fn require_physical_device(dev: &mut <DdiTest as Ddi>::Dev) -> bool {
    if get_device_kind(dev) != DdiDeviceKind::Physical {
        println!("Physical device NOT found. Test only supported on physical device.");
        return false;
    }
    true
}

pub(super) fn import_and_verify(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    raw_key: &[u8],
    key_type: DdiKeyType,
    usage: DdiKeyUsage,
    key_tag: Option<u16>,
) -> bool {
    let properties = helper_key_properties(usage, DdiKeyAvailability::App);
    let resp = helper_raw_key_import(
        dev,
        Some(session_id),
        raw_key,
        key_type,
        key_tag,
        properties,
    );
    if let Err(err) = &resp {
        if is_unsupported_cmd(err) {
            return false;
        }
    }

    let resp = resp.unwrap().data;
    assert_ne!(resp.key_id, 0);
    assert!(!resp.masked_key.is_empty());
    let stored = helper_get_priv_key(dev, Some(session_id), resp.key_id)
        .unwrap()
        .data;
    assert_eq!(stored.key_kind, key_type);
    assert_eq!(stored.key_data.as_slice(), raw_key);
    true
}

pub(super) fn rsa2k_private_key() -> [u8; 516] {
    let mut key = [0x5au8; 516];
    key[512..].copy_from_slice(&65_537u32.to_le_bytes());
    key
}

pub(super) fn require_raw_key_import(dev: &mut <DdiTest as Ddi>::Dev, session_id: u16) -> bool {
    let mut probe = [0u8; 32];
    Rng::rand_bytes(&mut probe).unwrap();
    import_and_verify(
        dev,
        session_id,
        &probe,
        DdiKeyType::Secret256,
        DdiKeyUsage::Derive,
        None,
    )
}

pub(super) fn expect_import_error(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    key_type: DdiKeyType,
    usage: DdiKeyUsage,
    availability: DdiKeyAvailability,
    expected: DdiStatus,
) {
    if !require_raw_key_import(dev, session_id) {
        return;
    }
    let key = [0x5au8; 32];
    let properties = helper_key_properties(usage, availability);
    let resp = helper_raw_key_import(dev, Some(session_id), &key, key_type, None, properties);
    assert!(matches!(resp, Err(DdiError::DdiStatus(status)) if status == expected));
}

pub(super) fn expect_rsa2k_import_error(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    usage: DdiKeyUsage,
    expected: DdiStatus,
) {
    if !require_raw_key_import(dev, session_id) {
        return;
    }
    let key = rsa2k_private_key();
    let properties = helper_key_properties(usage, DdiKeyAvailability::App);
    let resp = helper_raw_key_import(
        dev,
        Some(session_id),
        &key,
        DdiKeyType::Rsa2kPrivate,
        None,
        properties,
    );
    assert!(matches!(resp, Err(DdiError::DdiStatus(status)) if status == expected));
}
