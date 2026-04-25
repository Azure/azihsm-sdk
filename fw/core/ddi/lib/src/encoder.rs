// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor::MborEncode;
use azihsm_fw_ddi_mbor::MborEncoder;
use azihsm_fw_ddi_mbor::MborMap;

use crate::MborError;

/// DDI-level encoder. Wraps a header + data pair into a 2-element MBOR map.
pub struct DdiEncoder;

impl DdiEncoder {
    /// Encode `hdr` (key 0) and `data` (key 1) into `out`.
    /// Returns the number of bytes written.
    pub fn encode_parts<H: MborEncode, D: MborEncode>(
        hdr: H,
        data: D,
        out: &mut [u8],
    ) -> Result<usize, MborError> {
        let out_len = out.len();
        let mut encoder = MborEncoder::new(out);

        MborMap(2)
            .mbor_encode(&mut encoder)
            .map_err(|_| MborError::EncodeError)?;
        0u8.mbor_encode(&mut encoder)
            .map_err(|_| MborError::EncodeError)?;
        hdr.mbor_encode(&mut encoder)
            .map_err(|_| MborError::EncodeError)?;
        1u8.mbor_encode(&mut encoder)
            .map_err(|_| MborError::EncodeError)?;
        data.mbor_encode(&mut encoder)
            .map_err(|_| MborError::EncodeError)?;

        Ok(out_len - encoder.remaining())
    }
}
