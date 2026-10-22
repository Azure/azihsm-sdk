// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Execution helper for the `AesGcm` known-answer command.

use azihsm_ddi_mbor_codec::*;

use crate::common::*;

/// Run one AES-GCM operation on the device's platform AES-GCM implementation.
///
/// `tag` is the tag to verify and is required for the decrypt operations;
/// pass `None` to encrypt. The response holds the output text, plus the tag
/// for the encrypt operations.
#[allow(clippy::too_many_arguments)]
pub fn helper_aes_gcm(
    dev: &<azihsm_ddi::AzihsmDdi as azihsm_ddi::Ddi>::Dev,
    session_id: u16,
    op: DdiAesGcmOp,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    text: &[u8],
    tag: Option<&[u8]>,
) -> azihsm_ddi::DdiResult<DdiAesGcmCmdResp> {
    use azihsm_ddi::DdiDev;
    use azihsm_ddi::DdiError;

    fn invalid<E>(_: E) -> DdiError {
        DdiError::InvalidParameter
    }
    let action_req = DdiAesGcmReq {
        op,
        key: MborByteArray::from_slice(key).map_err(invalid)?,
        iv: MborByteArray::from_slice(iv).map_err(invalid)?,
        aad: MborByteArray::from_slice(aad).map_err(invalid)?,
        text: MborByteArray::from_slice(text).map_err(invalid)?,
        tag: tag
            .map(MborByteArray::from_slice)
            .transpose()
            .map_err(invalid)?,
    };
    let data = DdiTestActionReq::encode(DdiTestAction::AesGcm, &action_req)
        .map_err(|_| DdiError::InvalidParameter)?;
    let req = DdiAesGcmCmdReq {
        hdr: test_action_header(Some(session_id)),
        data,
        ext: None,
    };
    dev.exec_op_mbor(&req, &mut None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximum_request_fits_test_action_payload() {
        let req = DdiAesGcmReq {
            op: DdiAesGcmOp::Decrypt,
            key: MborByteArray::from_slice(&[0xa5; 32]).expect("maximum key must fit"),
            iv: MborByteArray::from_slice(&[0x5a; 12]).expect("IV must fit"),
            aad: MborByteArray::from_slice(&[0x3c; 256]).expect("maximum AAD must fit"),
            text: MborByteArray::from_slice(&[0xc3; 512]).expect("maximum text must fit"),
            tag: Some(MborByteArray::from_slice(&[0x0f; 16]).expect("tag must fit")),
        };

        let payload = DdiTestActionReq::encode(DdiTestAction::AesGcm, &req)
            .expect("maximum request must fit the TestAction payload");
        assert!(
            payload.payload.len() <= TEST_ACTION_PAYLOAD_MAX,
            "encoded payload exceeds TestAction capacity"
        );
    }
}
