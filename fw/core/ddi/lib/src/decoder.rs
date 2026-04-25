// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor::MborDecode;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor::MborMap;

use crate::MborError;

/// DDI-level decoder. Wraps an `MborDecoder` and validates the 2-element
/// map envelope `{0: header, 1: data}`.
pub struct DdiDecoder<'b> {
    in_len: usize,
    pub(crate) decoder: MborDecoder<'b>,
}

impl<'b> DdiDecoder<'b> {
    pub fn new(buf: &'b [u8]) -> Self {
        Self {
            in_len: buf.len(),
            decoder: MborDecoder::new(buf),
        }
    }

    /// Decode the header (map key 0).
    pub fn decode_hdr<T: MborDecode<'b>>(&mut self) -> Result<T, MborError> {
        let count = MborMap::mbor_decode(&mut self.decoder).map_err(|_| MborError::DecodeError)?;
        if count.0 != 2 {
            return Err(MborError::DecodeError);
        }

        let key = u8::mbor_decode(&mut self.decoder).map_err(|_| MborError::DecodeError)?;
        if key != 0 {
            return Err(MborError::DecodeError);
        }

        T::mbor_decode(&mut self.decoder).map_err(|_| MborError::DecodeError)
    }

    /// Decode the data body (map key 1). Must be called after `decode_hdr`.
    pub fn decode_data<T: MborDecode<'b>>(&mut self) -> Result<T, MborError> {
        let key = u8::mbor_decode(&mut self.decoder).map_err(|_| MborError::DecodeError)?;
        if key != 1 {
            return Err(MborError::DecodeError);
        }

        let data = T::mbor_decode(&mut self.decoder).map_err(|_| MborError::DecodeError)?;

        if self.in_len != self.decoder.position() {
            return Err(MborError::DecodeError);
        }

        Ok(data)
    }
}
