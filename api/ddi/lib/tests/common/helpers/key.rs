// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
use crate::get_unwrapping_key;
use crate::wrap_data;

pub fn helper_delete_key(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
) -> Result<DdiDeleteKeyCmdResp, DdiError> {
    let req = DdiDeleteKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::DeleteKey,
            sess_id,
            rev,
        },
        data: DdiDeleteKeyReq { key_id },
        ext: None,
    };

    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_open_key(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_tag: u16,
) -> Result<DdiOpenKeyCmdResp, DdiError> {
    let req = DdiOpenKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::OpenKey,
            sess_id,
            rev,
        },
        data: DdiOpenKeyReq { key_tag },
        ext: None,
    };

    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_der_import_aes_bulk_key(
    dev: &mut <DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_tag: u16,
    key_class: DdiKeyClass,
    der: &[u8],
) -> Result<DdiDerKeyImportCmdResp, DdiError> {
    let req = DdiDerKeyImportCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::DerKeyImport,
            sess_id,
            rev,
        },
        data: DdiDerKeyImportReq {
            der: MborByteArray::from_slice(der).expect("failed to create byte array"),
            key_class,
            key_tag: Some(key_tag),
            key_properties: helper_key_properties(
                DdiKeyUsage::EncryptDecrypt,
                DdiKeyAvailability::App,
            )
            .try_into()
            .map_err(|_| DdiError::InvalidParameter)?,
        },
        ext: None,
    };
    let mut cookie = None;

    dev.exec_op(&req, &mut cookie)
}

#[allow(dead_code)]
pub fn helper_der_key_import(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    der: MborByteArray<3072>,
    key_class: DdiKeyClass,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
) -> Result<DdiDerKeyImportCmdResp, DdiError> {
    let req = DdiDerKeyImportCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::DerKeyImport,
            sess_id,
            rev,
        },
        data: DdiDerKeyImportReq {
            der,
            key_class,
            key_tag,
            key_properties: key_properties
                .try_into()
                .map_err(|_| DdiError::InvalidParameter)?,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn rsa_secure_import_key(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key: &[u8],
    key_class: DdiKeyClass,
    key_usage: DdiKeyUsage,
    key_tag: Option<u16>,
) -> Result<DdiRsaUnwrapCmdResp, DdiError> {
    let session_id = session_id.expect("session id required");

    let (unwrap_key_id, unwrap_pub_key_der, _) = get_unwrapping_key(dev, session_id);

    let wrapped_key = wrap_data(unwrap_pub_key_der, key);

    let mut der = [0u8; 3072];
    der[..wrapped_key.len()].copy_from_slice(&wrapped_key);
    let der_len = wrapped_key.len();

    let resp = helper_rsa_unwrap(
        dev,
        Some(session_id),
        rev,
        unwrap_key_id,
        MborByteArray::new(der, der_len).expect("failed to create byte array"),
        key_class,
        DdiRsaCryptoPadding::Oaep,
        DdiHashAlgorithm::Sha256,
        key_tag,
        helper_key_properties(key_usage, DdiKeyAvailability::App),
    )?;

    Ok(resp)
}

pub fn helper_get_establish_cred_encryption_key(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
) -> Result<DdiGetEstablishCredEncryptionKeyCmdResp, DdiError> {
    let req = DdiGetEstablishCredEncryptionKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetEstablishCredEncryptionKey,
            sess_id,
            rev,
        },
        data: DdiGetEstablishCredEncryptionKeyReq {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_get_session_encryption_key(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
) -> Result<DdiGetSessionEncryptionKeyCmdResp, DdiError> {
    let req = DdiGetSessionEncryptionKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetSessionEncryptionKey,
            sess_id,
            rev,
        },
        data: DdiGetSessionEncryptionKeyReq {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_get_unwrapping_key(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
) -> Result<DdiGetUnwrappingKeyCmdResp, DdiError> {
    let req = DdiGetUnwrappingKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetUnwrappingKey,
            sess_id,
            rev,
        },
        data: DdiGetUnwrappingKeyReq {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_get_priv_key(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
) -> Result<DdiGetPrivKeyCmdResp, DdiError> {
    let req = DdiGetPrivKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetPrivKey,
            sess_id,
            rev,
        },
        data: DdiGetPrivKeyReq { key_id },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
