// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_mbor::*;

use crate::*;

/// DDI Decoder
///
/// DDI MBOR decoder uses a non-allocating MBOR decoder.
/// The encoded data is expected to be 2 map elements. The first is
/// always the map of the header.The second is always the map of the opcode
/// specific data. (In case on error response, this will be an empty map).
/// One must call `DdiDecoder::decode_hdr` before calling `DdiDecoder::decode_data`.
/// Each must be called exactly once only.
pub struct DdiDecoder<'b> {
    /// The length of the input buffer
    in_len: usize,

    /// Mbor's decoder instance
    pub(crate) decoder: MborDecoder<'b>,
}

impl<'b> DdiDecoder<'b> {
    /// Create new instance of `DdiDecoder`
    ///
    /// # Arguments
    ///
    /// * `buf` - Input buffer
    ///
    /// # Returns
    ///
    ///
    pub fn new(buf: &'b [u8], #[cfg(feature = "post_decode")] post_decode: bool) -> Self {
        Self {
            // Save the length of the input buffer
            in_len: buf.len(),

            // Initialize Mbor's decoder
            decoder: MborDecoder::new(
                buf,
                #[cfg(feature = "post_decode")]
                post_decode,
            ),
        }
    }

    /// Decode Header
    ///
    /// The encoded data is expected to be 2 map elements. The first is always
    /// the map of the header. The second is always the map of the opcode specific
    /// data. (In case on error response, this will be an empty map).
    /// One must call `DdiDecoder::decode_hdr`
    /// before calling `DdiDecoder::decode_data`. Each must be called exactly once
    /// only.
    ///
    /// # Arguments
    ///
    /// * `T` - Type of the header
    ///
    /// # Returns
    ///
    /// * Result of decoding the header
    pub fn decode_hdr<T: MborDecode<'b>>(&mut self) -> Result<T, MborError> {
        // The encoded data must start with map
        if let Ok(count) = MborMap::mbor_decode(&mut self.decoder) {
            // The map size must be 2
            if count.0 == 2 {
                // Decode the map index entry
                let res = u8::mbor_decode(&mut self.decoder).map_err(|_| MborError::DecodeError)?;
                if res != 0 {
                    Err(MborError::DecodeError)?
                }

                // Decode the header map
                let res = T::mbor_decode(&mut self.decoder);

                if let Ok(hdr) = res {
                    return Ok(hdr);
                }
            }
        }

        Err(MborError::DecodeError)?
    }

    /// Decode Data
    ///
    /// The encoded data is expected to be 2-3 map elements. The first is always
    /// the map of the header. The second is always the map of the opcode specific
    /// data. (In case on error response, this will be an empty map).
    /// One must call `DdiDecoder::decode_hdr`
    /// before calling `DdiDecoder::decode_data`. Each must be called exactly once
    /// only.
    ///
    /// # Arguments
    ///
    /// * `T` - Type of the data
    ///
    /// # Returns
    ///
    /// * Result of decoding the data
    pub fn decode_data<T: MborDecode<'b>>(&mut self) -> Result<T, MborError> {
        // Decode the map index entry
        let res = u8::mbor_decode(&mut self.decoder).map_err(|_| MborError::DecodeError)?;
        if res != 1 {
            Err(MborError::DecodeError)?
        }

        // Decode the opcode specific data
        if let Ok(data) = T::mbor_decode(&mut self.decoder) {
            // Confirm we have reached end of the buffer and no bytes are left
            if self.in_len == self.decoder.position() {
                return Ok(data);
            }
        }

        Err(MborError::DecodeError)?
    }

    /// Get the number of map elements in the encoded data
    pub fn map_count(&self) -> u64 {
        2
    }
}
