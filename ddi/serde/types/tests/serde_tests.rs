// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_ddi_derive::*;
use azihsm_ddi_mbor::*;

#[test]
fn test_struct_opt_only_fields() {
    #[derive(Debug, Ddi)]
    #[ddi(map)]
    pub struct StructWithReqFields {
        #[ddi(id = 1)]
        pub field1: u16,

        #[ddi(id = 2)]
        pub field2: u16,
    }

    #[derive(Debug, Ddi)]
    #[ddi(map)]
    pub struct StructWithOptFields {
        #[ddi(id = 1)]
        pub field1: Option<u16>,

        #[ddi(id = 2)]
        pub field2: Option<u16>,
    }

    #[derive(Debug, Ddi)]
    #[ddi(map)]
    pub struct NestedStruct {
        #[ddi(id = 1)]
        pub field1: StructWithOptFields,

        #[ddi(id = 2)]
        pub field2: StructWithReqFields,
    }

    {
        let struct1 = StructWithReqFields {
            field1: 1,
            field2: 2,
        };

        let mut buf = [0; 100];
        let mut acc = MborLenAccumulator::default();
        struct1.mbor_len(&mut acc);
        let buf = &mut buf[..acc.len()];
        #[cfg(feature = "pre_encode")]
        let mut encoder = MborEncoder::new(buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let mut encoder = MborEncoder::new(buf);

        let encoded_data = struct1.mbor_encode(&mut encoder);
        assert!(encoded_data.is_ok());
        assert_eq!(encoder.position(), acc.len());

        #[cfg(feature = "post_decode")]
        let mut decoder = MborDecoder::new(buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = MborDecoder::new(buf);
        let decoded_data = StructWithReqFields::mbor_decode(&mut decoder);
        assert!(decoded_data.is_ok());
    }

    {
        let struct1 = StructWithOptFields {
            field1: Some(1),
            field2: None,
        };

        let mut buf = [0; 100];
        let mut acc = MborLenAccumulator::default();
        struct1.mbor_len(&mut acc);
        let buf = &mut buf[..acc.len()];
        #[cfg(feature = "pre_encode")]
        let mut encoder = MborEncoder::new(buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let mut encoder = MborEncoder::new(buf);

        let encoded_data = struct1.mbor_encode(&mut encoder);
        assert!(encoded_data.is_ok());
        assert_eq!(encoder.position(), acc.len());

        #[cfg(feature = "post_decode")]
        let mut decoder = MborDecoder::new(buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = MborDecoder::new(buf);
        let decoded_data = StructWithOptFields::mbor_decode(&mut decoder);
        assert!(decoded_data.is_ok());
    }

    {
        let struct1 = NestedStruct {
            field1: StructWithOptFields {
                field1: Some(1),
                field2: None,
            },
            field2: StructWithReqFields {
                field1: 1,
                field2: 1,
            },
        };

        let mut buf = [0; 100];
        let mut acc = MborLenAccumulator::default();
        struct1.mbor_len(&mut acc);
        let buf = &mut buf[..acc.len()];
        #[cfg(feature = "pre_encode")]
        let mut encoder = MborEncoder::new(buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let mut encoder = MborEncoder::new(buf);

        let encoded_data = struct1.mbor_encode(&mut encoder);
        assert!(encoded_data.is_ok());
        assert_eq!(encoder.position(), acc.len());

        #[cfg(feature = "post_decode")]
        let mut decoder = MborDecoder::new(buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = MborDecoder::new(buf);
        let decoded_data = NestedStruct::mbor_decode(&mut decoder);
        assert!(decoded_data.is_ok());
    }
}

#[test]
fn test_mbor_len_struct_with_array() {
    #[derive(Debug, Ddi)]
    #[ddi(map)]
    pub struct TestStructWithArray {
        #[ddi(id = 1)]
        pub field1: u16,

        #[ddi(id = 2)]
        pub field2: MborByteArray<16>,
    }

    let arr = [0xEE; 16];
    let data = TestStructWithArray {
        field1: 0xCCCC,
        #[cfg(not(feature = "array"))]
        field2: MborByteArray::new(arr.as_ptr()).expect("Failed to initialize MborByteArray"),
        #[cfg(feature = "array")]
        field2: MborByteArray::new(arr, arr.len()).expect("Failed to initialize MborByteArray"),
    };

    let mut acc = MborLenAccumulator::default();
    data.mbor_len(&mut acc);
    assert_eq!(28, acc.len());
}

#[test]
fn test_mbor_decode_with_more_fields() {
    #[derive(Debug, Ddi)]
    #[ddi(map)]
    pub struct StructWithLessFields {
        #[ddi(id = 1)]
        pub field1: u16,

        #[ddi(id = 2)]
        pub field2: u16,
    }

    #[derive(Debug, Ddi)]
    #[ddi(map)]
    pub struct StructWithMoreFields {
        #[ddi(id = 1)]
        pub field1: u16,

        #[ddi(id = 2)]
        pub field2: u16,

        #[ddi(id = 3)]
        pub field3: u16,
    }

    let struct1 = StructWithLessFields {
        field1: 1,
        field2: 2,
    };

    let mut buf = [0; 100];
    let mut acc = MborLenAccumulator::default();
    struct1.mbor_len(&mut acc);
    let buf = &mut buf[..acc.len()];
    #[cfg(feature = "pre_encode")]
    let mut encoder = MborEncoder::new(buf, true);
    #[cfg(not(feature = "pre_encode"))]
    let mut encoder = MborEncoder::new(buf);

    let encoded_data = struct1.mbor_encode(&mut encoder);
    assert!(encoded_data.is_ok());
    assert_eq!(encoder.position(), acc.len());

    #[cfg(feature = "post_decode")]
    let mut decoder = MborDecoder::new(buf, true);
    #[cfg(not(feature = "post_decode"))]
    let mut decoder = MborDecoder::new(buf);
    let decoded_data = StructWithMoreFields::mbor_decode(&mut decoder);
    assert!(decoded_data.is_err());
}

#[test]
fn test_mbor_decode_with_less_fields() {
    #[derive(Debug, Ddi)]
    #[ddi(map)]
    pub struct StructWithLessFields {
        #[ddi(id = 1)]
        pub field1: u16,

        #[ddi(id = 2)]
        pub field2: u16,
    }

    #[derive(Debug, Ddi)]
    #[ddi(map)]
    pub struct StructWithMoreFields {
        #[ddi(id = 1)]
        pub field1: u16,

        #[ddi(id = 2)]
        pub field2: u16,

        #[ddi(id = 3)]
        pub field3: u16,
    }

    let struct1 = StructWithMoreFields {
        field1: 1,
        field2: 2,
        field3: 3,
    };

    let mut buf = [0; 100];
    let mut acc = MborLenAccumulator::default();
    struct1.mbor_len(&mut acc);
    let buf = &mut buf[..acc.len()];
    #[cfg(feature = "pre_encode")]
    let mut encoder = MborEncoder::new(buf, true);
    #[cfg(not(feature = "pre_encode"))]
    let mut encoder = MborEncoder::new(buf);

    let encoded_data = struct1.mbor_encode(&mut encoder);
    assert!(encoded_data.is_ok());
    assert_eq!(encoder.position(), acc.len());

    #[cfg(feature = "post_decode")]
    let mut decoder = MborDecoder::new(buf, true);
    #[cfg(not(feature = "post_decode"))]
    let mut decoder = MborDecoder::new(buf);
    let decoded_data = StructWithLessFields::mbor_decode(&mut decoder);
    assert!(decoded_data.is_err());
}
