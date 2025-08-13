// Copyright (c) Microsoft Corporation. All rights reserved.

use mcr_ddi_derive::Ddi;

use crate::*;

/// DDI RSA Operation Type.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiRsaOpType {
    /// Decrypt
    Decrypt = 1,

    /// Sign
    Sign = 2,
}

/// DDI RSA Modular Exponentiation Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone)]
#[ddi(map)]
pub struct DdiRsaModExpReq {
    /// Key ID
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Input data
    #[ddi(id = 2)]
    #[ddi(pre_encode_fn = "y_pre_encode")]
    pub y: MborByteArray<512>,

    /// RSA Operation Type
    #[ddi(id = 3)]
    pub op_type: DdiRsaOpType,
}

impl DdiRsaModExpReq {
    #[cfg(feature = "pre_encode")]
    pub fn y_pre_encode(
        &self,
        input_array: &MborByteArray<512>,
    ) -> Result<MborByteArray<512>, MborEncodeError> {
        // Change endianness
        let mut output_array = [0u8; 512];
        reverse_copy(
            &mut output_array[..input_array.len()],
            &input_array.data()[..input_array.len()],
        );

        Ok(MborByteArray::new(output_array, input_array.len())?)
    }
}

/// DDI RSA Modular Exponentiation Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone)]
#[ddi(map)]
pub struct DdiRsaModExpResp {
    /// Output data
    #[ddi(id = 1)]
    #[ddi(post_decode_fn = "x_post_decode")]
    pub x: MborByteArray<512>,
}

impl DdiRsaModExpResp {
    #[cfg(feature = "post_decode")]
    pub fn x_post_decode(
        &self,
        input_array: &MborByteArray<512>,
    ) -> Result<MborByteArray<512>, MborDecodeError> {
        // Change endianness
        let mut output_array = [0u8; 512];
        reverse_copy(
            &mut output_array[..input_array.len()],
            &input_array.data()[..input_array.len()],
        );

        Ok(MborByteArray::new(output_array, input_array.len())?)
    }
}

ddi_op_req_resp!(DdiRsaModExp);

/// DDI RSA Crypto Padding Enumeration
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiRsaCryptoPadding {
    /// OAEP Padding
    Oaep = 1,
}

/// DDI RSA Unwrap Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone)]
#[ddi(map)]
pub struct DdiRsaUnwrapReq {
    /// Unwrapping Key ID
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Wrapped blob
    #[ddi(id = 2)]
    #[ddi(pre_encode_fn = "wrapped_blob_pre_encode")]
    pub wrapped_blob: MborByteArray<3072>,

    /// Key class
    #[ddi(id = 3)]
    pub wrapped_blob_key_class: DdiKeyClass,

    /// Padding
    #[ddi(id = 4)]
    pub wrapped_blob_padding: DdiRsaCryptoPadding,

    /// Hash Algorithm
    #[ddi(id = 5)]
    pub wrapped_blob_hash_algorithm: DdiHashAlgorithm,

    /// Key tag (optional). May only be used with app keys.
    /// The key tag must be unique within the app.
    /// Key tag of 0x0000 is not allowed.
    #[ddi(id = 6)]
    pub key_tag: Option<u16>,

    /// Key Properties
    #[ddi(id = 7)]
    pub key_properties: DdiKeyProperties,
}

impl DdiRsaUnwrapReq {
    #[cfg(feature = "pre_encode")]
    pub fn wrapped_blob_pre_encode(
        &self,
        input_array: &MborByteArray<3072>,
    ) -> Result<MborByteArray<3072>, MborEncodeError> {
        let mut output_array = [0u8; 3072];

        let rsa_size = 256;
        let len = input_array.len();
        let data = input_array.data();

        if len > data.len() || len > output_array.len() || len < rsa_size {
            return Err(MborEncodeError::InvalidLen);
        }

        // Change endianness for just the rsa size chunk
        reverse_copy(&mut output_array[..rsa_size], &data[..rsa_size]);

        // Copy rest of data
        output_array[rsa_size..input_array.len()]
            .copy_from_slice(&data[rsa_size..input_array.len()]);

        Ok(MborByteArray::new(output_array, input_array.len())?)
    }
}

/// DDI RSA Unwrap Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone)]
#[ddi(map)]
pub struct DdiRsaUnwrapResp {
    /// Key ID
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Optional Public Key
    #[ddi(id = 2)]
    pub pub_key: Option<DdiDerPublicKey>,

    /// Optional Bulk Key ID
    #[ddi(id = 3)]
    pub bulk_key_id: Option<u16>,

    /// Key Type
    #[ddi(id = 4)]
    pub kind: DdiKeyType,

    /// Masked Key
    #[ddi(id = 5)]
    pub masked_key: MborByteArray<3072>,
}

ddi_op_req_resp!(DdiRsaUnwrap);
