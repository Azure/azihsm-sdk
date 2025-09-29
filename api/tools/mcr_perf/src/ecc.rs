// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) fn helper_ecc_sign(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_id: u16,
    digest: [u8; 96],
    digest_len: usize,
) -> DdiResult<()> {
    let digest_algo = match digest_len {
        20 => DdiHashAlgorithm::Sha1,
        32 => DdiHashAlgorithm::Sha256,
        48 => DdiHashAlgorithm::Sha384,
        64 => DdiHashAlgorithm::Sha512,
        _ => panic!("Unsupported digest length: {}", digest_len),
    };

    let req = DdiEccSignCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EccSign,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiEccSignReq {
            key_id,
            digest: MborByteArray::new(digest, digest_len).expect("failed to create byte array"),
            digest_algo,
        },
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie);
    resp.map(|_| ())
}

pub(crate) fn helper_create_ecc_key(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    curve: DdiEccCurve,
    key_tag: Option<u16>,
    key_usage: DdiKeyUsage,
) -> DdiResult<u16> {
    let req = DdiEccGenerateKeyPairCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EccGenerateKeyPair,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiEccGenerateKeyPairReq {
            curve,
            key_tag,
            key_properties: helper_key_properties(key_usage, DdiKeyAvailability::App)
                .try_into()
                .unwrap(),
        },
        ext: None,
    };

    let mut cookie = None;
    let resp = dev.exec_op(&req, &mut cookie);
    assert!(resp.is_ok(), "resp {:?}", resp);
    resp.map(|resp| resp.data.private_key_id)
}

pub(crate) fn helper_create_ecdh_key(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_id: u16,
    key_tag: Option<u16>,
    key_der: [u8; 192],
    key_der_len: usize,
    key_type: DdiKeyType,
) -> DdiResult<u16> {
    let req = DdiEcdhKeyExchangeCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EcdhKeyExchange,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiEcdhKeyExchangeReq {
            priv_key_id: key_id,
            pub_key_der: MborByteArray::new(key_der, key_der_len)
                .expect("failed to create byte array"),
            key_type,
            key_tag,
            key_properties: helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App)
                .try_into()
                .unwrap(),
        },
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie);

    resp.map(|resp| resp.data.key_id)
}

pub(crate) fn helper_ecdh_and_delete(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_id: u16,
    key_tag: Option<u16>,
    key_der: [u8; 192],
    key_der_len: usize,
    key_type: DdiKeyType,
) -> DdiResult<()> {
    let key_id = helper_create_ecdh_key(
        dev,
        app_sess_id,
        key_id,
        key_tag,
        key_der,
        key_der_len,
        key_type,
    )?;

    // Delete the key we produced
    helper_delete_key(dev, app_sess_id, key_id)
}

pub(crate) fn helper_create_ecc_key_and_delete(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    curve: DdiEccCurve,
    key_tag: Option<u16>,
    key_usage: DdiKeyUsage,
) -> DdiResult<()> {
    let key_id = helper_create_ecc_key(dev, app_sess_id, curve, key_tag, key_usage)?;

    // Delete the key we produced
    helper_delete_key(dev, app_sess_id, key_id)
}
