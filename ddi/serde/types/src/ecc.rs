// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_ddi_derive::Ddi;

use crate::*;

/// DDI ECC Curve Enumeration
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiEccCurve {
    /// ECC 256-bit
    P256 = 1,

    /// ECC 384-bit
    P384 = 2,

    /// ECC 521-bit
    P521 = 3,
}

/// DDI ECC Generate Key Pair Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone, Copy)]
#[ddi(map)]
pub struct DdiEccGenerateKeyPairReq {
    /// ECC curve
    #[ddi(id = 1)]
    pub curve: DdiEccCurve,

    /// Key tag (optional). May only be used with persistent sessions.
    /// The key tag must be unique within the app.
    /// Key tag of 0x0000 is not allowed.
    #[ddi(id = 2)]
    pub key_tag: Option<u16>,

    /// Key properties
    #[ddi(id = 3)]
    pub key_properties: DdiTargetKeyProperties,
}

/// DDI ECC Generate Key Pair Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone)]
#[ddi(map)]
pub struct DdiEccGenerateKeyPairResp {
    /// Private key ID
    #[ddi(id = 1)]
    pub private_key_id: u16,

    /// Public Key
    #[ddi(id = 2)]
    pub pub_key: DdiDerPublicKey,

    /// Masked Key
    #[ddi(id = 3)]
    pub masked_key: MborByteArray<3072>,
}

ddi_op_req_resp!(DdiEccGenerateKeyPair);

/// DDI ECC Sign Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone)]
#[ddi(map)]
pub struct DdiEccSignReq {
    /// Key ID
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Digest data
    #[ddi(id = 2)]
    #[ddi(pre_encode_fn = "digest_pre_encode")]
    pub digest: MborByteArray<96>,

    // Digest type
    #[ddi(id = 3)]
    pub digest_algo: DdiHashAlgorithm,
}

impl DdiEccSignReq {
    #[cfg(feature = "pre_encode")]
    pub fn digest_pre_encode(
        &self,
        input_array: &MborByteArray<96>,
    ) -> Result<MborByteArray<96>, MborEncodeError> {
        let mut output_array = [0u8; 96];

        let len = input_array.len();
        let data = input_array.data();

        // Check for slice bound validity
        if len > data.len() || len > output_array.len() {
            return Err(MborEncodeError::InvalidLen);
        }

        // Convert from big Endian to little Endian
        reverse_copy(
            &mut output_array[..input_array.len()],
            &data[..input_array.len()],
        );

        // Ecc sign digest must be padded with zeros to max length (68)
        Ok(MborByteArray::new(output_array, 68)?)
    }
}

/// DDI ECC Sign Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone)]
#[ddi(map)]
pub struct DdiEccSignResp {
    /// Output data
    #[ddi(id = 1)]
    #[ddi(post_decode_fn = "signature_post_decode")]
    pub signature: MborByteArray<192>,
}

impl DdiEccSignResp {
    #[cfg(feature = "post_decode")]
    pub fn signature_post_decode(
        &self,
        input_array: &MborByteArray<192>,
    ) -> Result<MborByteArray<192>, MborDecodeError> {
        ecc_signature_post_decode(input_array)
    }
}

ddi_op_req_resp!(DdiEccSign);

/// DDI ECDH Key Exchange Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone)]
#[ddi(map)]
pub struct DdiEcdhKeyExchangeReq {
    /// Private ECC Key
    #[ddi(id = 1)]
    pub priv_key_id: u16,

    /// Public peer ECC Key DER
    /// Set to 192 to leave some buffer
    #[ddi(id = 2)]
    #[ddi(pre_encode_fn = "pub_key_der_pre_encode")]
    pub pub_key_der: MborByteArray<192>,

    /// Target key type
    #[ddi(id = 3)]
    pub key_type: DdiKeyType,

    /// Target key tag (optional). May only be used with app keys.
    /// The key tag must be unique within the app.
    /// Key tag of 0x0000 is not allowed.
    #[ddi(id = 4)]
    pub key_tag: Option<u16>,

    /// Target key properties
    #[ddi(id = 5)]
    pub key_properties: DdiTargetKeyProperties,
}

impl DdiEcdhKeyExchangeReq {
    #[cfg(feature = "pre_encode")]
    pub fn pub_key_der_pre_encode(
        &self,
        input_array: &MborByteArray<192>,
    ) -> Result<MborByteArray<192>, MborEncodeError> {
        let mut output_array = [0u8; 192];

        let key_data = ecc_pub_key_der_to_raw(&input_array.data()[..input_array.len()])?;

        let (pka_curve_len, der_curve_len) = match key_data.curve {
            DdiEccCurve::P256 => (32, 32),
            DdiEccCurve::P384 => (48, 48),
            DdiEccCurve::P521 => (68, 66),
            _ => {
                tracing::error!("Unexpected curve: {:?}", key_data.curve);
                Err(MborEncodeError::InvalidParameter)?
            }
        };

        // Convert x and y to little endian
        reverse_copy(
            &mut output_array[..der_curve_len],
            &key_data.x[..der_curve_len],
        );
        reverse_copy(
            &mut output_array[pka_curve_len..pka_curve_len + der_curve_len],
            &key_data.y[..der_curve_len],
        );

        Ok(MborByteArray::new(output_array, pka_curve_len * 2)?)
    }
}

/// DDI ECDH Key Exchange Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone, Copy)]
#[ddi(map)]
pub struct DdiEcdhKeyExchangeResp {
    /// Derived private ECDH secret
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Masked Key
    #[ddi(id = 2)]
    pub masked_key: MborByteArray<3072>,
}

ddi_op_req_resp!(DdiEcdhKeyExchange);

#[cfg(feature = "post_decode")]
pub(crate) fn ecc_signature_post_decode(
    input_array: &MborByteArray<192>,
) -> Result<MborByteArray<192>, MborDecodeError> {
    let mut output_array = [0u8; 192];

    // We need to split the array into two components,
    // then convert endianness for each component.

    // Get the length of each of the two components.
    let (firmware_component_len, output_component_len) = match input_array.len() {
        64 => (32, 32),
        96 => (48, 48),
        // Special case: firmware uses 68 size instead of usual 66 for curve 521
        136 => (68, 66),
        _ => Err(MborDecodeError::InvalidLen)?,
    };

    // Convert from little Endian to big Endian for first component.
    let data = input_array.data();
    reverse_copy(
        &mut output_array[..output_component_len],
        &data[..output_component_len],
    );

    // Convert from little Endian to big Endian for second component.
    reverse_copy(
        &mut output_array[output_component_len..output_component_len + output_component_len],
        &data[firmware_component_len..firmware_component_len + output_component_len],
    );

    Ok(MborByteArray::new(output_array, output_component_len * 2)?)
}
