// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor::*;
use azihsm_fw_hsm_pal_traits::*;

/// DDI-level encoder. Wraps a header + data pair into a 2-element MBOR map.
pub struct DdiEncoder;

impl DdiEncoder {
    /// Encode `hdr` (key 0) and `data` (key 1) into `out`.
    /// Returns the number of bytes written.
    pub fn encode_parts<H: MborEncode, D: MborEncode>(
        hdr: H,
        data: D,
        out: &mut [u8],
    ) -> HsmResult<usize> {
        let mut encoder = MborEncoder::new(out);
        MborMap(2).mbor_encode(&mut encoder)?;
        0u8.mbor_encode(&mut encoder)?;
        hdr.mbor_encode(&mut encoder)?;
        1u8.mbor_encode(&mut encoder)?;
        data.mbor_encode(&mut encoder)?;
        Ok(encoder.position())
    }
}
