// Copyright (c) Microsoft Corporation. All rights reserved.

use mcr_ddi_mbor::*;
use mcr_ddi_types::*;

#[test]
fn test_decode_hdr() {
    {
        let mut buf = [0u8; 1024];
        let hdr = DdiReqHdr {
            rev: None,
            op: DdiOp::GetApiRev,
            sess_id: None,
        };
        let data = DdiGetApiRevReq {};
        #[cfg(feature = "pre_encode")]
        let len = DdiEncoder::encode_parts(hdr, data, &mut buf, true).unwrap();
        #[cfg(not(feature = "pre_encode"))]
        let len = DdiEncoder::encode_parts(hdr, data, &mut buf).unwrap();
        let buf = &buf[..len];
        #[cfg(feature = "post_decode")]
        let mut decoder = DdiDecoder::new(buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = DdiDecoder::new(buf);
        let hdr = decoder.decode_hdr::<DdiReqHdr>().unwrap();
        assert!(hdr.rev.is_none());
        assert_eq!(hdr.op, DdiOp::GetApiRev);
        assert_eq!(hdr.sess_id, None);
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
        let buf = &buf[..len];
        #[cfg(feature = "post_decode")]
        let mut decoder = DdiDecoder::new(buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = DdiDecoder::new(buf);
        let hdr = decoder.decode_hdr::<DdiReqHdr>().unwrap();
        assert_eq!(hdr.rev.unwrap().major, 1);
        assert_eq!(hdr.rev.unwrap().minor, 1);
        assert_eq!(hdr.op, DdiOp::GetApiRev);
        assert_eq!(hdr.sess_id, None);
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
        buf[0] += 1;
        let buf = &buf[..len];
        #[cfg(feature = "post_decode")]
        let mut decoder = DdiDecoder::new(buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = DdiDecoder::new(buf);
        let result = decoder.decode_hdr::<DdiReqHdr>();
        assert!(result.is_err(), "result {:?}", result);
    }
}
#[test]
fn test_decode_data_extra_bytes() {
    {
        let mut buf = [0u8; 1024];
        #[cfg(feature = "pre_encode")]
        let mut encoder = MborEncoder::new(&mut buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let mut encoder = MborEncoder::new(&mut buf);
        0u8.mbor_encode(&mut encoder).unwrap();
        let len1 = encoder.position();
        let hdr = DdiReqHdr {
            rev: Some(DdiApiRev { major: 1, minor: 1 }),
            op: DdiOp::GetApiRev,
            sess_id: None,
        };
        let data = DdiGetApiRevReq {};
        #[cfg(feature = "pre_encode")]
        let len2 = DdiEncoder::encode_parts(hdr, data, &mut buf[len1..], true).unwrap();
        #[cfg(not(feature = "pre_encode"))]
        let len2 = DdiEncoder::encode_parts(hdr, data, &mut buf[len1..]).unwrap();
        let buf = &buf[..len1 + len2];

        #[cfg(feature = "post_decode")]
        let mut decoder = DdiDecoder::new(buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = DdiDecoder::new(buf);
        let result = decoder.decode_hdr::<DdiReqHdr>();
        assert!(result.is_err(), "result {:?}", result);
    }

    {
        let mut buf = [0u8; 1024];
        #[cfg(feature = "pre_encode")]
        let mut encoder = MborEncoder::new(&mut buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let mut encoder = MborEncoder::new(&mut buf);

        let hdr = DdiReqHdr {
            rev: Some(DdiApiRev { major: 1, minor: 1 }),
            op: DdiOp::GetApiRev,
            sess_id: None,
        };

        let map_len = 2;
        MborMap(map_len).mbor_encode(&mut encoder).unwrap();
        0u8.mbor_encode(&mut encoder).unwrap();
        hdr.mbor_encode(&mut encoder).unwrap();

        0u8.mbor_encode(&mut encoder).unwrap();

        let data = DdiGetApiRevReq {};

        1u8.mbor_encode(&mut encoder).unwrap();
        data.mbor_encode(&mut encoder).unwrap();

        let len = encoder.position();

        let buf = &buf[..len];

        #[cfg(feature = "post_decode")]
        let mut decoder = DdiDecoder::new(buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = DdiDecoder::new(buf);
        let result = decoder.decode_hdr::<DdiReqHdr>();
        assert!(result.is_ok());
        let result = decoder.decode_data::<DdiGetApiRevReq>();
        assert!(result.is_err(), "result {:?}", result);
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
        let buf = &buf[..len + 1];

        #[cfg(feature = "post_decode")]
        let mut decoder = DdiDecoder::new(buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = DdiDecoder::new(buf);
        let result = decoder.decode_hdr::<DdiReqHdr>();
        assert!(result.is_ok());
        let result = decoder.decode_data::<DdiGetApiRevReq>();
        assert!(result.is_err(), "result {:?}", result);
    }
}

#[test]
fn test_decode_data() {
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
    let buf = &buf[..len];
    #[cfg(feature = "post_decode")]
    let mut decoder = DdiDecoder::new(buf, true);
    #[cfg(not(feature = "post_decode"))]
    let mut decoder = DdiDecoder::new(buf);
    let hdr: DdiReqHdr = decoder.decode_hdr().unwrap();
    assert_eq!(hdr.rev.unwrap().major, 1);
    assert_eq!(hdr.rev.unwrap().minor, 1);
    assert_eq!(hdr.op, DdiOp::GetApiRev);
    assert_eq!(hdr.sess_id, None);
    let _data: DdiGetApiRevReq = decoder.decode_data().unwrap();
}
