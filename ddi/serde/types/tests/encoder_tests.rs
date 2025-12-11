// Copyright (C) Microsoft Corporation. All rights reserved.

use mcr_ddi_types::*;

#[test]
fn test_encode() {
    {
        let mut buf = [0u8; 0];
        let hdr = DdiReqHdr {
            rev: Some(DdiApiRev { major: 1, minor: 1 }),
            op: DdiOp::GetApiRev,
            sess_id: None,
        };
        let data = DdiGetApiRevReq {};
        #[cfg(feature = "pre_encode")]
        let result = DdiEncoder::encode_parts(hdr, data, &mut buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let result = DdiEncoder::encode_parts(hdr, data, &mut buf);
        assert_eq!(result, Err(MborError::EncodeError));
    }
    {
        let mut buf = [0u8; 4];
        let hdr = DdiReqHdr {
            rev: Some(DdiApiRev { major: 1, minor: 1 }),
            op: DdiOp::GetApiRev,
            sess_id: None,
        };
        let data = DdiGetApiRevReq {};
        #[cfg(feature = "pre_encode")]
        let result = DdiEncoder::encode_parts(hdr, data, &mut buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let result = DdiEncoder::encode_parts(hdr, data, &mut buf);
        assert_eq!(result, Err(MborError::EncodeError));
    }
    {
        // Test encoding into buffer short by 1 byte
        let mut buf = [0u8; 30];
        let hdr = DdiReqHdr {
            rev: Some(DdiApiRev { major: 1, minor: 1 }),
            op: DdiOp::GetApiRev,
            sess_id: None,
        };
        let data = DdiGetApiRevReq {};
        #[cfg(feature = "pre_encode")]
        let result = DdiEncoder::encode_parts(hdr, data, &mut buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let result = DdiEncoder::encode_parts(hdr, data, &mut buf);
        assert_eq!(result, Err(MborError::EncodeError));
    }
    {
        // Test encoding into buffer of exact length
        let mut buf = [0u8; 31];
        let hdr = DdiReqHdr {
            rev: Some(DdiApiRev { major: 1, minor: 1 }),
            op: DdiOp::GetApiRev,
            sess_id: None,
        };
        let data = DdiGetApiRevReq {};
        #[cfg(feature = "pre_encode")]
        let len = DdiEncoder::encode_parts(hdr, data, &mut buf, true).unwrap();
        #[cfg(not(feature = "pre_encode"))]
        let len = DdiEncoder::encode_parts(hdr, data, &mut buf).unwrap();
        let expected_encoding = [
            162, 24, 0, 162, 24, 1, 162, 24, 1, 26, 0, 0, 0, 1, 24, 2, 26, 0, 0, 0, 1, 24, 2, 26,
            0, 0, 3, 234, 24, 1, 160,
        ];
        assert_eq!(&buf[..len], expected_encoding);
    }
    {
        let mut buf = [0u8; 1024];
        let hdr = DdiReqHdr {
            rev: Some(DdiApiRev { major: 1, minor: 1 }),
            op: DdiOp::GetApiRev,
            sess_id: None,
        };
        let data = DdiGetApiRevReq {};
        #[cfg(feature = "pre_encode")]
        let len = DdiEncoder::encode_parts(hdr, data, &mut buf, true).unwrap();
        #[cfg(not(feature = "pre_encode"))]
        let len = DdiEncoder::encode_parts(hdr, data, &mut buf).unwrap();
        let expected_encoding = [
            162, 24, 0, 162, 24, 1, 162, 24, 1, 26, 0, 0, 0, 1, 24, 2, 26, 0, 0, 0, 1, 24, 2, 26,
            0, 0, 3, 234, 24, 1, 160,
        ];
        assert_eq!(&buf[..len], expected_encoding);
    }
}
