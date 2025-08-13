// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) fn helper_hkdf_derive(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_id: u16,
    hash_algorithm: DdiHashAlgorithm,
    key_type: DdiKeyType,
    key_usage: DdiKeyUsage,
) -> DdiResult<u16> {
    let salt = Some(MborByteArray::new([100u8; 256], 64).expect("failed to create byte array"));
    let info = Some(MborByteArray::new([100u8; 256], 64).expect("failed to create byte array"));

    let req = DdiHkdfDeriveCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::HkdfDerive,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiHkdfDeriveReq {
            key_id,
            hash_algorithm,
            salt,
            info,
            key_type,
            key_tag: None,
            key_properties: helper_key_properties(key_usage, DdiKeyAvailability::App),
        },
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie)?;
    Ok(resp.data.key_id)
}

pub(crate) fn helper_hkdf_and_delete(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_id: u16,
    hash_algorithm: DdiHashAlgorithm,
    key_type: DdiKeyType,
    key_usage: DdiKeyUsage,
) -> DdiResult<()> {
    let key_id = helper_hkdf_derive(
        dev,
        app_sess_id,
        key_id,
        hash_algorithm,
        key_type,
        key_usage,
    )?;

    helper_delete_key(dev, app_sess_id, key_id)
}

pub(crate) fn helper_kbkdf_derive(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_id: u16,
    hash_algorithm: DdiHashAlgorithm,
    key_type: DdiKeyType,
    key_usage: DdiKeyUsage,
) -> DdiResult<u16> {
    let label = Some(MborByteArray::new([100u8; 256], 64).expect("failed to create byte array"));
    let context = Some(MborByteArray::new([100u8; 256], 64).expect("failed to create byte array"));

    let req = DdiKbkdfCounterHmacDeriveCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::KbkdfCounterHmacDerive,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiKbkdfCounterHmacDeriveReq {
            key_id,
            hash_algorithm,
            label,
            context,
            key_type,
            key_tag: None,
            key_properties: helper_key_properties(key_usage, DdiKeyAvailability::App),
        },
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie)?;
    Ok(resp.data.key_id)
}

pub(crate) fn helper_kbkdf_and_delete(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_id: u16,
    hash_algorithm: DdiHashAlgorithm,
    key_type: DdiKeyType,
    key_usage: DdiKeyUsage,
) -> DdiResult<()> {
    let key_id = helper_kbkdf_derive(
        dev,
        app_sess_id,
        key_id,
        hash_algorithm,
        key_type,
        key_usage,
    )?;

    helper_delete_key(dev, app_sess_id, key_id)
}
