// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor::*;
use azihsm_fw_hsm_pal_traits::*;

/// DDI-level encoder. Wraps a header + data pair into a 2-element MBOR map.
pub struct DdiEncoder;

impl DdiEncoder {
    /// Encode `hdr` (key 0) and `data` (key 1) into `out`.
    /// Returns the number of bytes written.
    pub fn encode_parts<H: MborEncode + MborLen, D: MborEncode + MborLen>(
        hdr: H,
        data: D,
        out: &mut [u8],
    ) -> HsmResult<usize> {
        // Pre-compute total length
        let mut acc = MborLenAccumulator::default();
        MborMap(2).mbor_len(&mut acc);
        0u8.mbor_len(&mut acc);
        hdr.mbor_len(&mut acc);
        1u8.mbor_len(&mut acc);
        data.mbor_len(&mut acc);
        let total = acc.len();

        // Single bounds check
        if total > out.len() {
            return Err(HsmError::DdiEncodeFailed);
        }

        let mut encoder = MborEncoder::new_trusted(out);
        MborMap(2).mbor_encode(&mut encoder)?;
        0u8.mbor_encode(&mut encoder)?;
        hdr.mbor_encode(&mut encoder)?;
        1u8.mbor_encode(&mut encoder)?;
        data.mbor_encode(&mut encoder)?;

        Ok(total)
    }
}
