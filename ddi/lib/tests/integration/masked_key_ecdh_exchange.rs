// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_masked_key_ecdh_256_key_exchange() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_ecdh_key_exchange(dev, session_id, DdiKeyType::Secret256);
        },
    );
}

#[test]
fn test_masked_key_ecdh_384_key_exchange() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_ecdh_key_exchange(dev, session_id, DdiKeyType::Secret384);
        },
    );
}

#[test]
fn test_masked_key_ecdh_521_key_exchange() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_ecdh_key_exchange(dev, session_id, DdiKeyType::Secret521);
        },
    );
}

fn test_ecdh_key_exchange(dev: &mut <DdiTest as Ddi>::Dev, session_id: u16, key_type: DdiKeyType) {
    let curve = match key_type {
        DdiKeyType::Secret256 => DdiEccCurve::P256,
        DdiKeyType::Secret384 => DdiEccCurve::P384,
        DdiKeyType::Secret521 => DdiEccCurve::P521,
        _ => unreachable!(),
    };

    let (priv_key_id1, _pub_key1, _pub_key1_len, _priv_key_id2, pub_key2, pub_key2_len) =
        helper_create_ecc_key_pairs(
            dev,
            Some(session_id),
            Some(DdiApiRev { major: 1, minor: 0 }),
            curve,
            None,
        );

    let key_tag = 1;
    let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
    let resp = helper_ecdh_key_exchange(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        priv_key_id1,
        MborByteArray::new(pub_key2, pub_key2_len).expect("failed to create byte array"),
        Some(key_tag),
        key_type,
        key_props,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();
    let key_id = resp.data.key_id;
    let masked_key = resp.data.masked_key;

    let resp = helper_get_new_key_id_from_unmask(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        true,
        masked_key,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let (new_key_id, _, _) = resp.unwrap();

    // Confirm we can find the secret by tag
    let resp = helper_open_key(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_tag,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    assert_eq!(resp.data.key_id, new_key_id);
    assert_eq!(resp.data.key_kind, key_type);
}
