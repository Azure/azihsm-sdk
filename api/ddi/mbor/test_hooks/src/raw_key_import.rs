// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host wire types and helpers for the `RawKeyImport` validation command.

use azihsm_ddi_mbor_codec::*;
use azihsm_ddi_mbor_derive::Ddi;
use azihsm_ddi_mbor_types::*;
use pastey::paste;

/// FIPS-validation import of raw key material.
pub const DDI_OP_RAW_KEY_IMPORT: DdiOp = DdiOp(2008);

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRawKeyImportReq {
    #[ddi(id = 1)]
    pub raw: MborByteArray<3072>,
    #[ddi(id = 2)]
    pub key_kind: DdiKeyType,
    #[ddi(id = 3)]
    pub key_tag: Option<u16>,
    #[ddi(id = 4)]
    pub key_properties: DdiTargetKeyProperties,
}

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRawKeyImportResp {
    #[ddi(id = 1)]
    pub key_id: u16,
    #[ddi(id = 2)]
    pub bulk_key_id: Option<u16>,
    #[ddi(id = 3)]
    pub masked_key: MborByteArray<3072>,
}

ddi_op_req_resp!(DdiRawKeyImport);

/// Import raw key material into validation firmware.
#[cfg(feature = "helpers")]
#[allow(clippy::too_many_arguments)]
pub fn helper_raw_key_import(
    dev: &mut <azihsm_ddi::AzihsmDdi as azihsm_ddi::Ddi>::Dev,
    session_id: Option<u16>,
    raw_key: &[u8],
    key_kind: DdiKeyType,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
) -> azihsm_ddi::DdiResult<DdiRawKeyImportCmdResp> {
    use azihsm_ddi::DdiDev;
    use azihsm_ddi::DdiError;

    let req = DdiRawKeyImportCmdReq {
        hdr: DdiReqHdr {
            op: DDI_OP_RAW_KEY_IMPORT,
            sess_id: session_id,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiRawKeyImportReq {
            raw: MborByteArray::from_slice(raw_key).map_err(|_| DdiError::InvalidParameter)?,
            key_kind,
            key_tag,
            key_properties: key_properties
                .try_into()
                .map_err(|_| DdiError::InvalidParameter)?,
        },
        ext: None,
    };
    dev.exec_op_mbor(&req, &mut None)
}

/// Read back a fixed-length raw secret and validate its length.
#[cfg(feature = "helpers")]
pub fn retrieve_shared_raw_key<const N: usize>(
    dev: &mut <azihsm_ddi::AzihsmDdi as azihsm_ddi::Ddi>::Dev,
    session_id: u16,
    secret_key_id: u16,
) -> azihsm_ddi::DdiResult<[u8; N]> {
    use azihsm_ddi::DdiError;

    let resp = crate::helper_get_priv_key(dev, Some(session_id), secret_key_id)?;
    let key_data = resp.data.key_data.as_slice();
    if key_data.len() != N {
        return Err(DdiError::InvalidParameter);
    }

    let mut result = [0u8; N];
    result.copy_from_slice(key_data);
    Ok(result)
}

/// Read back a variable-length raw secret and validate its length.
#[cfg(feature = "helpers")]
pub fn retrieve_shared_raw_key_var(
    dev: &mut <azihsm_ddi::AzihsmDdi as azihsm_ddi::Ddi>::Dev,
    session_id: u16,
    secret_key_id: u16,
    expected_len: usize,
) -> azihsm_ddi::DdiResult<std::vec::Vec<u8>> {
    use azihsm_ddi::DdiError;

    let resp = crate::helper_get_priv_key(dev, Some(session_id), secret_key_id)?;
    let key_data = resp.data.key_data.as_slice();
    if key_data.len() != expected_len {
        return Err(DdiError::InvalidParameter);
    }
    Ok(key_data.to_vec())
}
