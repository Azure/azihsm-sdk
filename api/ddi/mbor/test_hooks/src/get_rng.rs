// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Execution helper for the `GetRng` validation command.

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi::Ddi;
use azihsm_ddi::DdiDev;
use azihsm_ddi::DdiError;
use azihsm_ddi::DdiResult;

use crate::common::*;

/// Request random bytes from validation firmware within a live session.
///
/// Firmware accepts lengths 0 through 64. Larger lengths are transmitted
/// unchanged so validation callers can check firmware rejection.
pub fn helper_get_rng(
    dev: &<AzihsmDdi as Ddi>::Dev,
    session_id: Option<u16>,
    rng_len: u8,
) -> DdiResult<DdiGetRngCmdResp> {
    let data = DdiTestActionReq::encode(DdiTestAction::GetRng, &DdiGetRngReq { rng_len })
        .map_err(|_| DdiError::InvalidParameter)?;
    let req = DdiGetRngCmdReq {
        hdr: test_action_header(session_id),
        data,
        ext: None,
    };
    dev.exec_op_mbor(&req, &mut None)
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_mbor_codec::*;
    use azihsm_ddi_mbor_types::DdiOpReq;

    use super::*;

    #[test]
    fn get_rng_uses_nested_test_action_payload() {
        for rng_len in [0, 1, 32, 64, 65, u8::MAX] {
            let request = DdiGetRngCmdReq {
                hdr: test_action_header(Some(7)),
                data: DdiTestActionReq::encode(DdiTestAction::GetRng, &DdiGetRngReq { rng_len })
                    .expect("RNG payload must encode"),
                ext: None,
            };
            assert_eq!(request.get_opcode(), DDI_OP_TEST_ACTION);
            assert_eq!(request.get_session_id(), Some(7));

            let mut buf = [0; 128];
            let mut encoder = MborEncoder::new(&mut buf, false);
            request
                .mbor_encode(&mut encoder)
                .expect("request must encode");
            let len = encoder.position();
            let mut decoder = MborDecoder::new(&buf[..len], false);
            let decoded = DdiGetRngCmdReq::mbor_decode(&mut decoder).expect("request must decode");
            assert_eq!(decoder.position(), len);
            assert_eq!(decoded.hdr.op, DDI_OP_TEST_ACTION);
            assert_eq!(decoded.hdr.sess_id, Some(7));
            assert_eq!(decoded.data.action, DdiTestAction::GetRng);

            let mut payload = MborDecoder::new(decoded.data.payload.as_slice(), false);
            let decoded_len = DdiGetRngReq::mbor_decode(&mut payload).expect("payload must decode");
            assert_eq!(decoded_len.rng_len, rng_len);
            assert_eq!(payload.position(), decoded.data.payload.len());
        }
    }

    #[test]
    fn get_rng_response_preserves_length_and_padding() {
        for len in 0..=64 {
            let bytes = [0x5a; 64];
            let response = DdiGetRngResp {
                rng_number: MborByteArray::from_slice(&bytes[..len]).expect("output must fit"),
            };
            let mut buf = [0; 128];
            let mut encoder = MborEncoder::new(&mut buf, false);
            response
                .mbor_encode(&mut encoder)
                .expect("response must encode");
            let encoded_len = encoder.position();
            let mut decoder = MborDecoder::new(&buf[..encoded_len], false);
            let decoded = DdiGetRngResp::mbor_decode(&mut decoder).expect("response must decode");
            assert_eq!(decoder.position(), encoded_len);
            assert_eq!(decoded.rng_number.as_slice(), &bytes[..len]);
        }
    }
}
