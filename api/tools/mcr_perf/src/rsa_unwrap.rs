// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) fn helper_get_unwrapping_key(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
) -> DdiResult<(u16, Vec<u8>)> {
    let req = DdiGetUnwrappingKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetUnwrappingKey,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetUnwrappingKeyReq {},
        ext: None,
    };
    let mut cookie = None;

    // If key is not found, re-check for key once every 5 seconds for up to 30 minutes.
    let mut timeout_s = 30 * 60;
    let interval_s = 5;
    loop {
        assert!(timeout_s > 0, "Unwrapping key generation took too long");

        let resp = dev.exec_op(&req, &mut cookie);

        if let Err(err) = resp {
            assert!(matches!(
                err,
                DdiError::DdiStatus(DdiStatus::PendingKeyGeneration)
            ));

            thread::sleep(std::time::Duration::from_secs(interval_s));
            timeout_s -= interval_s;
            println!(
                "Awaiting unwrapping key generation, will retry after {} seconds",
                interval_s
            );
            continue;
        }
        assert!(resp.is_ok(), "resp {:?}", resp);
        let resp = resp.unwrap();

        return Ok((
            resp.data.key_id,
            resp.data.pub_key.der.data()[..resp.data.pub_key.der.len()].to_vec(),
        ));
    }
}

pub(crate) fn helper_rsa_unwrap(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_id: u16,
    wrapped_blob: &[u8; 3072],
    len: usize,
    key_class: DdiKeyClass,
    target_key_tag: Option<u16>,
    target_key_properties: DdiKeyProperties,
) -> DdiResult<u16> {
    let req = DdiRsaUnwrapCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::RsaUnwrap,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiRsaUnwrapReq {
            key_id,
            wrapped_blob: MborByteArray::new(*wrapped_blob, len)
                .expect("failed to create byte array"),
            wrapped_blob_key_class: key_class,
            wrapped_blob_padding: DdiRsaCryptoPadding::Oaep,
            wrapped_blob_hash_algorithm: DdiHashAlgorithm::Sha256,
            key_tag: target_key_tag,
            key_properties: target_key_properties,
        },
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie);

    resp.map(|resp| resp.data.key_id)
}

pub(crate) fn helper_rsa_unwrap_delete(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_id: u16,
    wrapped_blob: &[u8; 3072],
    len: usize,
    key_class: DdiKeyClass,
    target_key_tag: Option<u16>,
    target_key_properties: DdiKeyProperties,
) -> DdiResult<()> {
    let unwrap_key_id = helper_rsa_unwrap(
        dev,
        app_sess_id,
        key_id,
        wrapped_blob,
        len,
        key_class,
        target_key_tag,
        target_key_properties,
    )?;

    // Delete the key we produced
    helper_delete_key(dev, app_sess_id, unwrap_key_id)
}
