// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Execution and key-readback helpers for the `RawKeyImport` validation command.

use azihsm_ddi_mbor_codec::*;
use azihsm_ddi_mbor_types::*;
use zeroize::Zeroize;

use crate::common::*;

/// Import raw key material into validation firmware.
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

    let key_properties = key_properties
        .try_into()
        .map_err(|_| DdiError::InvalidParameter)?;
    let mut action_req = DdiRawKeyImportReq {
        raw: MborByteArray::from_slice(raw_key).map_err(|_| DdiError::InvalidParameter)?,
        key_kind,
        key_tag,
        key_properties,
    };
    let data = DdiTestActionReq::encode(DdiTestAction::RawKeyImport, &action_req);
    action_req.raw.data_mut().zeroize();
    let data = data.map_err(|_| DdiError::InvalidParameter)?;

    let mut req = DdiRawKeyImportCmdReq {
        hdr: test_action_header(session_id),
        data,
        ext: None,
    };
    let result = dev.exec_op_mbor(&req, &mut None);
    req.data.payload.data_mut().zeroize();
    result
}

/// Read back a fixed-length raw secret and validate its length.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximum_request_fits_test_action_payload() {
        let req = DdiRawKeyImportReq {
            raw: MborByteArray::from_slice(&[0xa5; 3072])
                .expect("maximum raw key must fit its wire field"),
            key_kind: DdiKeyType::VarHmac512,
            key_tag: Some(u16::MAX),
            key_properties: DdiKeyProperties {
                key_usage: DdiKeyUsage::SignVerify,
                key_availability: DdiKeyAvailability::App,
                key_label: MborByteArray::from_slice(&[0x5a; DDI_MAX_KEY_LABEL_LENGTH])
                    .expect("maximum key label must fit its wire field"),
            }
            .try_into()
            .expect("valid key properties must convert"),
        };

        let payload = DdiTestActionReq::encode(DdiTestAction::RawKeyImport, &req)
            .expect("maximum request must fit the TestAction payload");
        assert!(
            payload.payload.len() <= TEST_ACTION_PAYLOAD_MAX,
            "encoded payload exceeds TestAction capacity"
        );
    }
}
