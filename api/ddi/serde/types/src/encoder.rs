// Copyright (c) Microsoft Corporation. All rights reserved.

use mcr_ddi_mbor::MborEncode;
use mcr_ddi_mbor::MborEncoder;

use crate::*;

/// DDI Encoder
///
/// DDI MBOR encoder uses a non-allocating MBOR encoder. DDI
/// always encodes as 2 map elements. The first is always the map of the header.
/// The second is always the map of the opcode specific data. (In case on error
/// response, this will be an empty map).
pub struct DdiEncoder {}

impl DdiEncoder {
    /// Encode header and data
    ///
    /// Encode the header and the opcode specific data into a MBOR
    /// buffer. DDI always encodes as 2 map elements. The first is always the map of the
    /// header. The second is always the map of the opcode specific data. (In case on error
    /// response, this will be an empty map).
    ///
    /// # Arguments
    ///
    /// * `hdr`  - Header
    /// * `data` - Data
    /// * `out`  - Output buffer
    ///
    /// # Returns
    ///
    /// * Result of encoding the header and data
    pub fn encode_parts<H: MborEncode, D: MborEncode>(
        hdr: H,
        data: D,
        out: &mut [u8],
        #[cfg(feature = "pre_encode")] pre_encode: bool,
    ) -> Result<usize, MborError> {
        // Save total length of the buffer
        let out_len = out.len();

        // Initialize MBOR's encoder
        let mut encoder = MborEncoder::new(
            out,
            #[cfg(feature = "pre_encode")]
            pre_encode,
        );

        let map_len = 2;

        // Start with map containing map_len elements
        MborMap(map_len)
            .mbor_encode(&mut encoder)
            .map_err(|_| MborError::EncodeError)?;

        // Add hdr as the first array element
        0u8.mbor_encode(&mut encoder)
            .map_err(|_| MborError::EncodeError)?;
        hdr.mbor_encode(&mut encoder)
            .map_err(|_| MborError::EncodeError)?;

        // Add data as the second array element
        1u8.mbor_encode(&mut encoder)
            .map_err(|_| MborError::EncodeError)?;
        data.mbor_encode(&mut encoder)
            .map_err(|_| MborError::EncodeError)?;

        // Calculate the size of the encoded data
        let encoded_len = out_len - encoder.remaining();
        Ok(encoded_len)
    }
}
