// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_raw_key_import(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: Option<u16>,
    raw: [u8; 3072],
    key_length: usize,
    key_kind: DdiKeyType,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
) -> Result<DdiRawKeyImportCmdResp, DdiError> {
    let req = DdiRawKeyImportCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::RawKeyImport,
            sess_id: session_id,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiRawKeyImportReq {
            raw: MborByteArray::new(raw, key_length).expect("failed to create byte array"),
            key_kind,
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

pub fn retrieve_shared_raw_key<const N: usize>(
    dev: &mut <DdiTest as Ddi>::Dev,
    sess_id: u16,
    secret_key_id: u16,
) -> Result<[u8; N], DdiError> {
    // Changed return type to use DdiError
    let req = create_get_priv_key_request(Some(sess_id), secret_key_id);
    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie)?;

    // Extract the response and raw secret
    let raw_secret_len = resp.data.key_data.len();

    if raw_secret_len != N {
        return Err(DdiError::InvalidParameter);
    }

    // Convert slice to fixed-size array
    let mut result = [0u8; N];
    result.copy_from_slice(&resp.data.key_data.data()[..raw_secret_len]);

    Ok(result)
}

fn create_get_priv_key_request(session_id: Option<u16>, key_id: u16) -> DdiGetPrivKeyCmdReq {
    DdiGetPrivKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetPrivKey,
            sess_id: session_id,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetPrivKeyReq { key_id },
        ext: None,
    }
}
