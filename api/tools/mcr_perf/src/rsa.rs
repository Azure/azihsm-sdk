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

pub(crate) fn helper_create_rsa_key(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    rsa_size: u16,
    key_tag: Option<u16>,
    key_usage: DdiKeyUsage,
) -> DdiResult<u16> {
    let mut der = [0u8; 3072];
    let der_len: usize;

    if rsa_size == 2048 {
        der[..TEST_RSA_2K_PRIVATE_KEY.len()].copy_from_slice(&TEST_RSA_2K_PRIVATE_KEY);
        der_len = TEST_RSA_2K_PRIVATE_KEY.len();
    } else if rsa_size == 3072 {
        der[..TEST_RSA_3K_PRIVATE_KEY.len()].copy_from_slice(&TEST_RSA_3K_PRIVATE_KEY);
        der_len = TEST_RSA_3K_PRIVATE_KEY.len();
    } else if rsa_size == 4096 {
        der[..TEST_RSA_4K_PRIVATE_KEY.len()].copy_from_slice(&TEST_RSA_4K_PRIVATE_KEY);
        der_len = TEST_RSA_4K_PRIVATE_KEY.len();
    } else {
        panic!("Invalid RSA key size");
    }

    let req = DdiDerKeyImportCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::DerKeyImport,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiDerKeyImportReq {
            der: MborByteArray::new(der, der_len).expect("failed to create byte array"),
            key_class: DdiKeyClass::Rsa,
            key_tag,
            key_properties: helper_key_properties(key_usage, DdiKeyAvailability::App),
        },
        ext: None,
    };
    let mut cookie = None;
    let resp = dev.exec_op(&req, &mut cookie);

    resp.map(|resp| resp.data.key_id)
}

pub(crate) fn helper_create_rsa_crt_key(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    rsa_size: u16,
    key_tag: Option<u16>,
    key_usage: DdiKeyUsage,
) -> DdiResult<u16> {
    let mut der = [0u8; 3072];
    let der_len: usize;

    if rsa_size == 2048 {
        der[..TEST_RSA_2K_PRIVATE_KEY.len()].copy_from_slice(&TEST_RSA_2K_PRIVATE_KEY);
        der_len = TEST_RSA_2K_PRIVATE_KEY.len();
    } else if rsa_size == 3072 {
        der[..TEST_RSA_3K_PRIVATE_KEY.len()].copy_from_slice(&TEST_RSA_3K_PRIVATE_KEY);
        der_len = TEST_RSA_3K_PRIVATE_KEY.len();
    } else if rsa_size == 4096 {
        der[..TEST_RSA_4K_PRIVATE_KEY.len()].copy_from_slice(&TEST_RSA_4K_PRIVATE_KEY);
        der_len = TEST_RSA_4K_PRIVATE_KEY.len();
    } else {
        panic!("Invalid RSA key size");
    }

    let req = DdiDerKeyImportCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::DerKeyImport,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiDerKeyImportReq {
            der: MborByteArray::new(der, der_len).expect("failed to create byte array"),
            key_class: DdiKeyClass::RsaCrt,
            key_tag,
            key_properties: helper_key_properties(key_usage, DdiKeyAvailability::App),
        },
        ext: None,
    };
    let mut cookie = None;
    let resp = dev.exec_op(&req, &mut cookie);

    resp.map(|resp| resp.data.key_id)
}
