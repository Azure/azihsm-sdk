// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) fn helper_rsa_mod_exp(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_id: u16,
    data: [u8; 512],
    data_len: usize,
    op_type: DdiRsaOpType,
) -> DdiResult<()> {
    let req = DdiRsaModExpCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::RsaModExp,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiRsaModExpReq {
            key_id,
            y: MborByteArray::new(data, data_len).expect("failed to create byte array"),
            op_type,
        },
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie);
    resp.map(|_| ())
}

pub(crate) fn helper_rsa_secure_import_key(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key: &[u8],
    key_tag: Option<u16>,
    key_usage: DdiKeyUsage,
    key_class: DdiKeyClass,
) -> DdiResult<u16> {
    let (unwrap_key_id, unwrap_pub_key_der) = helper_get_unwrapping_key(dev, app_sess_id).unwrap();

    let wrapped_key = local_wrap_data(unwrap_pub_key_der, key);

    let mut der = [0u8; 3072];
    der[..wrapped_key.len()].copy_from_slice(&wrapped_key);
    let der_len = wrapped_key.len();

    let req = DdiRsaUnwrapCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::RsaUnwrap,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiRsaUnwrapReq {
            key_id: unwrap_key_id,
            wrapped_blob: MborByteArray::new(der, der_len).expect("failed to create byte array"),
            wrapped_blob_key_class: key_class,
            wrapped_blob_padding: DdiRsaCryptoPadding::Oaep,
            wrapped_blob_hash_algorithm: DdiHashAlgorithm::Sha256,
            key_tag,
            key_properties: helper_key_properties(key_usage, DdiKeyAvailability::App)
                .try_into()
                .unwrap(),
        },
        ext: None,
    };
    let mut cookie = None;
    let resp = dev.exec_op(&req, &mut cookie);

    resp.map(|resp| resp.data.key_id)
}

pub(crate) fn helper_create_rsa_key(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    rsa_size: u16,
    key_tag: Option<u16>,
    key_usage: DdiKeyUsage,
) -> DdiResult<u16> {
    let rsa_priv_key = if rsa_size == 2048 {
        TEST_RSA_2K_PRIVATE_KEY.as_slice()
    } else if rsa_size == 3072 {
        TEST_RSA_3K_PRIVATE_KEY.as_slice()
    } else if rsa_size == 4096 {
        TEST_RSA_4K_PRIVATE_KEY.as_slice()
    } else {
        panic!("Invalid RSA key size");
    };

    helper_rsa_secure_import_key(
        dev,
        app_sess_id,
        rsa_priv_key,
        key_tag,
        key_usage,
        DdiKeyClass::Rsa,
    )
}

pub(crate) fn helper_create_rsa_crt_key(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    rsa_size: u16,
    key_tag: Option<u16>,
    key_usage: DdiKeyUsage,
) -> DdiResult<u16> {
    let rsa_priv_key = if rsa_size == 2048 {
        TEST_RSA_2K_PRIVATE_KEY.as_slice()
    } else if rsa_size == 3072 {
        TEST_RSA_3K_PRIVATE_KEY.as_slice()
    } else if rsa_size == 4096 {
        TEST_RSA_4K_PRIVATE_KEY.as_slice()
    } else {
        panic!("Invalid RSA key size");
    };

    helper_rsa_secure_import_key(
        dev,
        app_sess_id,
        rsa_priv_key,
        key_tag,
        key_usage,
        DdiKeyClass::RsaCrt,
    )
}
