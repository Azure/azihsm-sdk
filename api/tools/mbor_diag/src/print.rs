// Copyright (C) Microsoft Corporation. All rights reserved.

use std::fmt::Write;

use mcr_ddi_mbor::*;

use crate::cli::*;
use crate::logger::*;

pub fn print_converted_data(logger: &mut dyn Logger, to: To, input: &[u8]) {
    if to == To::Debug {
        let mut decoder = MborDecoder::new(input, false);
        print_converted_data_debug_any(logger, 0, input.len(), &mut decoder, input);
        if decoder.position() != input.len() {
            panic!(
                "Error decoding input. {} bytes left to decode",
                input.len() - decoder.position()
            );
        }
    } else {
        panic!("Unsupported conversion type: {:?}", to);
    }
}

fn print_converted_data_debug_any(
    logger: &mut dyn Logger,
    indent: usize,
    max_pos: usize,
    decoder: &mut MborDecoder<'_>,
    input: &[u8],
) {
    if max_pos - decoder.position() < 1 {
        panic!(
            "Error decoding Map. Expecting at least 1 bytes from position {} to {}",
            decoder.position(),
            max_pos
        );
    }

    let byte = decoder.peek_byte();

    if byte.is_none() {
        panic!(
            "Error decoding byte # {:?} {:02X?}",
            decoder.position(),
            input[decoder.position()]
        );
    }

    let byte = byte.unwrap();

    if byte & MAP_MARKER == MAP_MARKER {
        print_converted_data_debug_map(logger, indent, max_pos, decoder, input);
    } else if byte & UINT_MARKER == UINT_MARKER {
        let uint_type = byte & !UINT_MARKER;

        match uint_type {
            U8_MASK => {
                print_converted_data_debug_u8(logger, indent, max_pos, decoder, input);
            }

            U16_MASK => {
                print_converted_data_debug_u16(logger, indent, max_pos, decoder, input);
            }

            U32_MASK => {
                print_converted_data_debug_u32(logger, indent, max_pos, decoder, input);
            }

            U64_MASK => {
                print_converted_data_debug_u64(logger, indent, max_pos, decoder, input);
            }

            _ => {
                panic!("Unknown uint type: {:02x}", uint_type);
            }
        }
    } else if byte & BOOL_MARKER == BOOL_MARKER {
        print_converted_data_debug_bool(logger, indent, max_pos, decoder, input);
    } else if byte & BYTES_MARKER == BYTES_MARKER {
        print_converted_data_debug_bytes(logger, indent, max_pos, decoder, input);
    } else {
        panic!("Unknown marker: {:02x}", byte);
    }
}

fn print_converted_data_debug_map(
    logger: &mut dyn Logger,
    indent: usize,
    max_pos: usize,
    decoder: &mut MborDecoder<'_>,
    input: &[u8],
) {
    if max_pos - decoder.position() < 1 {
        panic!(
            "Error decoding Map. Expecting at least 1 bytes from position {} to {}",
            decoder.position(),
            max_pos
        );
    }

    let old_pos = decoder.position();
    let mut field_count = MborMap::mbor_decode(decoder).unwrap().0;
    // let new_pos = decoder.position();

    // Print bytes in input from old_pos to new_pos
    let marker = &input[old_pos];
    logger.println(format_args!(
        "{:indent$}{:02X} # Map with {} fields",
        "",
        marker,
        field_count,
        indent = indent
    ));

    while decoder.position() < max_pos && field_count > 0 {
        field_count -= 1;

        // Each field in the map always starts with u8 field id followed by the field value

        // Print field id
        print_converted_data_debug_map_field_id(logger, indent + 4, max_pos, decoder, input);
        // Print field value
        print_converted_data_debug_any(logger, indent + 4, max_pos, decoder, input);
    }

    if field_count > 0 {
        panic!(
            "Error decoding map: {:?}. Expecting {} more map fields",
            decoder.position(),
            field_count
        );
    }
}

fn print_converted_data_debug_map_field_id(
    logger: &mut dyn Logger,
    indent: usize,
    max_pos: usize,
    decoder: &mut MborDecoder<'_>,
    input: &[u8],
) {
    if max_pos - decoder.position() < 2 {
        panic!(
            "Error decoding u8. Expecting at least 2 bytes from position {} to {}",
            decoder.position(),
            max_pos
        );
    }

    let old_pos = decoder.position();
    let value = u8::mbor_decode(decoder).unwrap();
    let new_pos = decoder.position();

    // Print bytes in input from old_pos to new_pos
    let marker = &input[old_pos];
    let bytes = &input[old_pos + 1..new_pos];
    let bytes_string = hex_encode(bytes);
    logger.println(format_args!(
        "{:indent$}{:02X} {} # Field ID {} (U8)",
        "",
        marker,
        bytes_string,
        value,
        indent = indent
    ));
}

fn print_converted_data_debug_u8(
    logger: &mut dyn Logger,
    indent: usize,
    max_pos: usize,
    decoder: &mut MborDecoder<'_>,
    input: &[u8],
) {
    if max_pos - decoder.position() < 2 {
        panic!(
            "Error decoding u8. Expecting at least 2 bytes from position {} to {}",
            decoder.position(),
            max_pos
        );
    }

    let old_pos = decoder.position();
    let value = u8::mbor_decode(decoder).unwrap();
    let new_pos = decoder.position();

    // Print bytes in input from old_pos to new_pos
    let marker = &input[old_pos];
    let bytes = &input[old_pos + 1..new_pos];
    let bytes_string = hex_encode(bytes);
    logger.println(format_args!(
        "{:indent$}{:02X} {} # U8 with value {}",
        "",
        marker,
        bytes_string,
        value,
        indent = indent
    ));
}

fn print_converted_data_debug_u16(
    logger: &mut dyn Logger,
    indent: usize,
    max_pos: usize,
    decoder: &mut MborDecoder<'_>,
    input: &[u8],
) {
    if max_pos - decoder.position() < 3 {
        panic!(
            "Error decoding u16. Expecting at least 3 bytes from position {} to {}",
            decoder.position(),
            max_pos
        );
    }

    let old_pos = decoder.position();
    let value = u16::mbor_decode(decoder).unwrap();
    let new_pos = decoder.position();

    // Print bytes in input from old_pos to new_pos
    let marker = &input[old_pos];
    let bytes = &input[old_pos + 1..new_pos];
    let bytes_string = hex_encode(bytes);
    logger.println(format_args!(
        "{:indent$}{:02X} {} # U16 with value {}",
        "",
        marker,
        bytes_string,
        value,
        indent = indent
    ));
}

fn print_converted_data_debug_u32(
    logger: &mut dyn Logger,
    indent: usize,
    max_pos: usize,
    decoder: &mut MborDecoder<'_>,
    input: &[u8],
) {
    if max_pos - decoder.position() < 5 {
        panic!(
            "Error decoding u32. Expecting at least 5 bytes from position {} to {}",
            decoder.position(),
            max_pos
        );
    }

    let old_pos = decoder.position();
    let value = u32::mbor_decode(decoder).unwrap();
    let new_pos = decoder.position();

    // Print bytes in input from old_pos to new_pos
    let marker = &input[old_pos];
    let bytes = &input[old_pos + 1..new_pos];
    let bytes_string = hex_encode(bytes);
    logger.println(format_args!(
        "{:indent$}{:02X} {} # U32 with value {}",
        "",
        marker,
        bytes_string,
        value,
        indent = indent
    ));
}

fn print_converted_data_debug_u64(
    logger: &mut dyn Logger,
    indent: usize,
    max_pos: usize,
    decoder: &mut MborDecoder<'_>,
    input: &[u8],
) {
    if max_pos - decoder.position() < 9 {
        panic!(
            "Error decoding u64. Expecting at least 9 bytes from position {} to {}",
            decoder.position(),
            max_pos
        );
    }

    let old_pos = decoder.position();
    let value = u64::mbor_decode(decoder).unwrap();
    let new_pos = decoder.position();

    // Print bytes in input from old_pos to new_pos
    let marker = &input[old_pos];
    let bytes = &input[old_pos + 1..new_pos];
    let bytes_string = hex_encode(bytes);
    logger.println(format_args!(
        "{:indent$}{:02X} {} # U64 with value {}",
        "",
        marker,
        bytes_string,
        value,
        indent = indent
    ));
}

fn print_converted_data_debug_bool(
    logger: &mut dyn Logger,
    indent: usize,
    max_pos: usize,
    decoder: &mut MborDecoder<'_>,
    input: &[u8],
) {
    if max_pos - decoder.position() < 1 {
        panic!(
            "Error decoding bool. Expecting at least 1 bytes from position {} to {}",
            decoder.position(),
            max_pos
        );
    }

    let old_pos = decoder.position();
    let value = bool::mbor_decode(decoder).unwrap();
    // let new_pos = decoder.position();

    // Print bytes in input from old_pos to new_pos
    let marker = &input[old_pos];
    logger.println(format_args!(
        "{:indent$}{:02X} # Bool with value {}",
        "",
        marker,
        value,
        indent = indent
    ));
}

fn print_converted_data_debug_bytes(
    logger: &mut dyn Logger,
    indent: usize,
    max_pos: usize,
    decoder: &mut MborDecoder<'_>,
    input: &[u8],
) {
    if max_pos - decoder.position() < 1 {
        panic!(
            "Error decoding bytes. Expecting at least 1 bytes from position {} to {}",
            decoder.position(),
            max_pos
        );
    }

    let old_pos = decoder.position();
    let value = MborByteArray::<8192>::mbor_decode(decoder).unwrap();
    let new_pos = decoder.position();

    // Print bytes in input from old_pos to new_pos
    let marker = &input[old_pos];
    let pad_len = marker & BYTES_PAD_MASK;
    let len = &input[old_pos + 1..old_pos + 3];
    let len_string = hex_encode(len);
    let pad = &input[old_pos + 3..old_pos + 3 + pad_len as usize];
    let pad_string = hex_encode(pad);

    let bytes = &input[old_pos + 3 + pad_len as usize..new_pos];
    let bytes_string = hex_encode(bytes);

    let len_u16 = u16::from_be_bytes([len[0], len[1]]);

    let value = &value.data()[..value.len()];

    logger.println(format_args!(
        "{:indent$}{:02X} {} {} # Bytes with len {} pad {}",
        "",
        marker,
        len_string,
        pad_string,
        len_u16,
        pad_len,
        indent = indent
    ));

    logger.println(format_args!(
        "{:indent$}{} # Bytes Value {:?}",
        "",
        bytes_string,
        value,
        indent = indent + 4
    ));
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02X}");
        output
    })
}

#[cfg(test)]
mod tests {
    use std::fmt::Arguments;

    use mcr_ddi_types::*;

    use super::*;

    #[derive(Default)]
    struct DummyLogger(Vec<String>);

    impl Logger for DummyLogger {
        fn println(&mut self, value: Arguments<'_>) {
            self.0.push(value.to_string());
            println!("{}", value);
        }
    }

    #[test]
    #[should_panic]
    fn test_print_converted_data_bad_data() {
        let mut logger = DummyLogger::default();
        let input = vec![0xA0, 0x01];
        print_converted_data(&mut logger, To::Debug, &input);
    }

    #[test]
    #[should_panic]
    fn test_print_converted_data_empty() {
        let mut logger = DummyLogger::default();
        let input = vec![];
        print_converted_data(&mut logger, To::Debug, &input);
    }

    #[test]
    #[should_panic]
    fn test_print_converted_data_bad_uint() {
        let mut logger = DummyLogger::default();
        let input = vec![UINT_MARKER | 4];
        print_converted_data(&mut logger, To::Debug, &input);
    }

    #[test]
    #[should_panic]
    fn test_print_converted_data_bad_type() {
        let mut logger = DummyLogger::default();
        let input = vec![0x00];
        print_converted_data(&mut logger, To::Debug, &input);
    }

    #[test]
    #[should_panic]
    fn test_print_converted_data_map_bad_field_count() {
        let mut logger = DummyLogger::default();
        let input = vec![0xA2, 0x18, 0x01, 0x1A, 0x00, 0x00, 0x00, 0x00];
        print_converted_data(&mut logger, To::Debug, &input);
    }

    #[test]
    #[should_panic]
    fn test_print_converted_data_map_bad_field_id() {
        let mut logger = DummyLogger::default();
        let input = vec![0xA2, 0x18];
        print_converted_data(&mut logger, To::Debug, &input);
    }

    #[test]
    #[should_panic]
    fn test_print_converted_data_u8_bad_data() {
        let mut logger = DummyLogger::default();
        let input = vec![0x18];
        print_converted_data(&mut logger, To::Debug, &input);
    }

    #[test]
    #[should_panic]
    fn test_print_converted_data_u16_bad_data() {
        let mut logger = DummyLogger::default();
        let input = vec![0x19];
        print_converted_data(&mut logger, To::Debug, &input);
    }

    #[test]
    #[should_panic]
    fn test_print_converted_data_u32_bad_data() {
        let mut logger = DummyLogger::default();
        let input = vec![0x1A];
        print_converted_data(&mut logger, To::Debug, &input);
    }

    #[test]
    fn test_print_converted_data_u8() {
        let data = 67u8;

        let mut logger = DummyLogger::default();
        let mut buf = [0u8; 512];
        let buf_len = buf.len();
        let mut encoder = MborEncoder::new(&mut buf, false);

        data.mbor_encode(&mut encoder).unwrap();
        let encoded_len = buf_len - encoder.remaining();

        let input = &buf[..encoded_len];
        print_converted_data(&mut logger, To::Debug, input);

        assert_eq!(logger.0.len(), 1);

        // Merge the output into a single string
        let merged_output = logger.0.join("\n");
        println!("Merged output: {}", merged_output);

        let expected_output = r#"18 43 # U8 with value 67"#;

        assert_eq!(merged_output, expected_output);
    }

    #[test]
    fn test_print_converted_data_u16() {
        let data = 679u16;

        let mut logger = DummyLogger::default();
        let mut buf = [0u8; 512];
        let buf_len = buf.len();
        let mut encoder = MborEncoder::new(&mut buf, false);

        data.mbor_encode(&mut encoder).unwrap();
        let encoded_len = buf_len - encoder.remaining();

        let input = &buf[..encoded_len];
        print_converted_data(&mut logger, To::Debug, input);

        assert_eq!(logger.0.len(), 1);

        // Merge the output into a single string
        let merged_output = logger.0.join("\n");
        println!("Merged output: {}", merged_output);

        let expected_output = r#"19 02A7 # U16 with value 679"#;

        assert_eq!(merged_output, expected_output);
    }

    #[test]
    fn test_print_converted_data_u32() {
        let data = 679012u32;

        let mut logger = DummyLogger::default();
        let mut buf = [0u8; 512];
        let buf_len = buf.len();
        let mut encoder = MborEncoder::new(&mut buf, false);

        data.mbor_encode(&mut encoder).unwrap();
        let encoded_len = buf_len - encoder.remaining();

        let input = &buf[..encoded_len];
        print_converted_data(&mut logger, To::Debug, input);

        assert_eq!(logger.0.len(), 1);

        // Merge the output into a single string
        let merged_output = logger.0.join("\n");
        println!("Merged output: {}", merged_output);

        let expected_output = r#"1A 000A5C64 # U32 with value 679012"#;

        assert_eq!(merged_output, expected_output);
    }

    #[test]
    fn test_print_converted_data_bool_true() {
        let data = true;

        let mut logger = DummyLogger::default();
        let mut buf = [0u8; 512];
        let buf_len = buf.len();
        let mut encoder = MborEncoder::new(&mut buf, false);

        data.mbor_encode(&mut encoder).unwrap();
        let encoded_len = buf_len - encoder.remaining();

        let input = &buf[..encoded_len];
        println!("Input: {:02X?}", input);

        print_converted_data(&mut logger, To::Debug, input);

        assert_eq!(logger.0.len(), 1);

        // Merge the output into a single string
        let merged_output = logger.0.join("\n");
        println!("Merged output: {}", merged_output);

        let expected_output = r#"15 # Bool with value true"#;

        assert_eq!(merged_output, expected_output);
    }

    #[test]
    fn test_print_converted_data_bool_false() {
        let data = false;

        let mut logger = DummyLogger::default();
        let mut buf = [0u8; 512];
        let buf_len = buf.len();
        let mut encoder = MborEncoder::new(&mut buf, false);

        data.mbor_encode(&mut encoder).unwrap();
        let encoded_len = buf_len - encoder.remaining();

        let input = &buf[..encoded_len];
        println!("Input: {:02X?}", input);

        print_converted_data(&mut logger, To::Debug, input);

        assert_eq!(logger.0.len(), 1);

        // Merge the output into a single string
        let merged_output = logger.0.join("\n");
        println!("Merged output: {}", merged_output);

        let expected_output = r#"14 # Bool with value false"#;

        assert_eq!(merged_output, expected_output);
    }

    #[test]
    fn test_print_converted_data_mba() {
        let mba = MborByteArray::<10>::new([2; 10], 4).unwrap();
        let data = MborPaddedByteArray::<10>(&mba, 1);

        let mut logger = DummyLogger::default();
        let mut buf = [0u8; 512];
        let buf_len = buf.len();
        let mut encoder = MborEncoder::new(&mut buf, false);

        data.mbor_encode(&mut encoder).unwrap();
        let encoded_len = buf_len - encoder.remaining();

        let input = &buf[..encoded_len];
        println!("Input: {:02X?}", input);

        print_converted_data(&mut logger, To::Debug, input);

        assert_eq!(logger.0.len(), 2);

        // Merge the output into a single string
        let merged_output = logger.0.join("\n");
        println!("Merged output: {}", merged_output);

        let expected_output = r#"81 0004 00 # Bytes with len 4 pad 1
    02020202 # Bytes Value [2, 2, 2, 2]"#;

        assert_eq!(merged_output, expected_output);
    }

    #[test]
    fn test_print_converted_data_get_api_rev_req() {
        let data = DdiGetApiRevReq {};

        let mut logger = DummyLogger::default();
        let mut buf = [0u8; 512];
        let buf_len = buf.len();
        let mut encoder = MborEncoder::new(&mut buf, false);

        data.mbor_encode(&mut encoder).unwrap();
        let encoded_len = buf_len - encoder.remaining();

        let input = &buf[..encoded_len];
        print_converted_data(&mut logger, To::Debug, input);

        assert_eq!(logger.0.len(), 1);

        // Merge the output into a single string
        let merged_output = logger.0.join("\n");
        println!("Merged output: {}", merged_output);

        let expected_output = r#"A0 # Map with 0 fields"#;

        assert_eq!(merged_output, expected_output);
    }

    #[test]
    fn test_print_converted_data_get_api_rev_resp() {
        let data = DdiGetApiRevResp {
            min: DdiApiRev {
                major: 123456789,
                minor: 87654321,
            },
            max: DdiApiRev {
                major: 0,
                minor: 0xFFFFFFFF,
            },
        };

        let mut logger = DummyLogger::default();
        let mut buf = [0u8; 512];
        let buf_len = buf.len();
        let mut encoder = MborEncoder::new(&mut buf, false);

        data.mbor_encode(&mut encoder).unwrap();
        let encoded_len = buf_len - encoder.remaining();

        let input = &buf[..encoded_len];
        println!("Input: {:02X?}", input);
        print_converted_data(&mut logger, To::Debug, input);

        assert_eq!(logger.0.len(), 13);

        // Merge the output into a single string
        let merged_output = logger.0.join("\n");
        println!("Merged output: {}", merged_output);

        let expected_output = r#"A2 # Map with 2 fields
    18 01 # Field ID 1 (U8)
    A2 # Map with 2 fields
        18 01 # Field ID 1 (U8)
        1A 075BCD15 # U32 with value 123456789
        18 02 # Field ID 2 (U8)
        1A 05397FB1 # U32 with value 87654321
    18 02 # Field ID 2 (U8)
    A2 # Map with 2 fields
        18 01 # Field ID 1 (U8)
        1A 00000000 # U32 with value 0
        18 02 # Field ID 2 (U8)
        1A FFFFFFFF # U32 with value 4294967295"#;

        assert_eq!(merged_output, expected_output);
    }

    #[test]
    fn test_print_converted_data_aes_generate_key_req() {
        let data = DdiAesGenerateKeyReq {
            key_size: DdiAesKeySize::Aes256,
            key_tag: None,
            key_properties: DdiKeyProperties {
                key_usage: DdiKeyUsage::EncryptDecrypt,
                key_availability: DdiKeyAvailability::App,
                key_label: MborByteArray::from_slice(&[]).unwrap(),
            },
        };

        let mut logger = DummyLogger::default();
        let mut buf = [0u8; 512];
        let buf_len = buf.len();
        let mut encoder = MborEncoder::new(&mut buf, false);

        data.mbor_encode(&mut encoder).unwrap();
        let encoded_len = buf_len - encoder.remaining();

        let input = &buf[..encoded_len];
        print_converted_data(&mut logger, To::Debug, input);

        assert_eq!(logger.0.len(), 12);

        // Merge the output into a single string
        let merged_output = logger.0.join("\n");
        println!("Merged output: {}", merged_output);

        let expected_output = r#"A2 # Map with 2 fields
    18 01 # Field ID 1 (U8)
    1A 00000003 # U32 with value 3
    18 03 # Field ID 3 (U8)
    A3 # Map with 3 fields
        18 01 # Field ID 1 (U8)
        1A 00000002 # U32 with value 2
        18 02 # Field ID 2 (U8)
        1A 00000001 # U32 with value 1
        18 03 # Field ID 3 (U8)
        82 0000 0000 # Bytes with len 0 pad 2
             # Bytes Value []"#;

        assert_eq!(merged_output, expected_output);
    }

    #[test]
    fn test_print_converted_data_aes_generate_key_resp() {
        let data = DdiAesGenerateKeyResp {
            key_id: 87,
            bulk_key_id: Some(123),
            masked_key: MborByteArray::from_slice(&[]).unwrap(),
        };

        let mut logger = DummyLogger::default();
        let mut buf = [0u8; 512];
        let buf_len = buf.len();
        let mut encoder = MborEncoder::new(&mut buf, false);

        data.mbor_encode(&mut encoder).unwrap();
        let encoded_len = buf_len - encoder.remaining();

        let input = &buf[..encoded_len];
        print_converted_data(&mut logger, To::Debug, input);

        assert_eq!(logger.0.len(), 8);

        // Merge the output into a single string
        let merged_output = logger.0.join("\n");
        println!("Merged output: {}", merged_output);

        let expected_output = r#"A3 # Map with 3 fields
    18 01 # Field ID 1 (U8)
    19 0057 # U16 with value 87
    18 02 # Field ID 2 (U8)
    19 007B # U16 with value 123
    18 03 # Field ID 3 (U8)
    80 0000  # Bytes with len 0 pad 0
         # Bytes Value []"#;

        assert_eq!(merged_output, expected_output);
    }

    #[test]
    fn test_print_converted_data_aes_encrypt_decrypt_req() {
        let data = DdiAesEncryptDecryptReq {
            key_id: 1234,
            op: DdiAesOp::Encrypt,
            msg: MborByteArray::new([2u8; 1024], 20).unwrap(),
            iv: MborByteArray::new([3u8; 16], 16).unwrap(),
        };

        let mut logger = DummyLogger::default();
        let mut buf = [0u8; 512];
        let buf_len = buf.len();
        let mut encoder = MborEncoder::new(&mut buf, false);

        data.mbor_encode(&mut encoder).unwrap();
        let encoded_len = buf_len - encoder.remaining();

        let input = &buf[..encoded_len];
        print_converted_data(&mut logger, To::Debug, input);

        assert_eq!(logger.0.len(), 11);

        // Merge the output into a single string
        let merged_output = logger.0.join("\n");
        println!("Merged output: {}", merged_output);

        let expected_output = r#"A4 # Map with 4 fields
    18 01 # Field ID 1 (U8)
    19 04D2 # U16 with value 1234
    18 02 # Field ID 2 (U8)
    1A 00000001 # U32 with value 1
    18 03 # Field ID 3 (U8)
    82 0014 0000 # Bytes with len 20 pad 2
        0202020202020202020202020202020202020202 # Bytes Value [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]
    18 04 # Field ID 4 (U8)
    83 0010 000000 # Bytes with len 16 pad 3
        03030303030303030303030303030303 # Bytes Value [3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3]"#;

        assert_eq!(merged_output, expected_output);
    }

    #[test]
    fn test_print_converted_data_aes_encrypt_decrypt_resp() {
        let data = DdiAesEncryptDecryptResp {
            msg: MborByteArray::new([12u8; 1024], 2).unwrap(),
            iv: MborByteArray::new([67u8; 16], 8).unwrap(),
        };

        let mut logger = DummyLogger::default();
        let mut buf = [0u8; 512];
        let buf_len = buf.len();
        let mut encoder = MborEncoder::new(&mut buf, false);

        data.mbor_encode(&mut encoder).unwrap();
        let encoded_len = buf_len - encoder.remaining();

        let input = &buf[..encoded_len];
        print_converted_data(&mut logger, To::Debug, input);

        assert_eq!(logger.0.len(), 7);

        // Merge the output into a single string
        let merged_output = logger.0.join("\n");
        println!("Merged output: {}", merged_output);

        let expected_output = r#"A2 # Map with 2 fields
    18 01 # Field ID 1 (U8)
    82 0002 0000 # Bytes with len 2 pad 2
        0C0C # Bytes Value [12, 12]
    18 02 # Field ID 2 (U8)
    81 0008 00 # Bytes with len 8 pad 1
        4343434343434343 # Bytes Value [67, 67, 67, 67, 67, 67, 67, 67]"#;

        assert_eq!(merged_output, expected_output);
    }
}
