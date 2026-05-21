// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor::*;
use azihsm_fw_hsm_pal_traits::*;

/// DDI-level decoder. Wraps an `MborDecoder` and validates the 2-element
/// map envelope `{0: header, 1: data}`.
pub struct DdiDecoder<'b> {
    in_len: usize,
    pub(crate) decoder: MborDecoder<'b>,
}

impl<'b> DdiDecoder<'b> {
    pub fn new(buf: &'b DmaBuf) -> Self {
        Self {
            in_len: buf.len(),
            decoder: MborDecoder::new(buf),
        }
    }

    /// Decode the header (map key 0).
    pub fn decode_hdr<T: MborDecode<'b>>(&mut self) -> HsmResult<T> {
        let count = MborMap::mbor_decode(&mut self.decoder)?;
        if count.0 != 2 {
            return Err(HsmError::DdiDecodeFailed);
        }

        let key = u8::mbor_decode(&mut self.decoder)?;
        if key != 0 {
            return Err(HsmError::DdiDecodeFailed);
        }

        Ok(T::mbor_decode(&mut self.decoder)?)
    }

    /// Decode the data body (map key 1). Must be called after `decode_hdr`.
    pub fn decode_data<T: MborDecode<'b>>(&mut self) -> HsmResult<T> {
        let key = u8::mbor_decode(&mut self.decoder)?;
        if key != 1 {
            return Err(HsmError::DdiDecodeFailed);
        }

        let data = T::mbor_decode(&mut self.decoder)?;

        if self.in_len != self.decoder.position() {
            return Err(HsmError::DdiDecodeFailed);
        }

        Ok(data)
    }
}
