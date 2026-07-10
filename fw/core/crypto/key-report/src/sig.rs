// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signature wire-format helpers.

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;

use crate::consts::SIGNATURE_LEN;

/// Convert ECDSA `r || s` between little-endian and big-endian wire
/// forms by reversing each half independently.
///
/// Both buffers must be exactly [`SIGNATURE_LEN`] bytes.
pub(crate) fn reverse_signature_halves(dst: &mut [u8], src: &[u8]) -> HsmResult<()> {
    if dst.len() != SIGNATURE_LEN || src.len() != SIGNATURE_LEN {
        return Err(HsmError::InvalidArg);
    }

    let half = SIGNATURE_LEN / 2;
    for i in 0..half {
        dst[i] = src[half - 1 - i];
        dst[half + i] = src[SIGNATURE_LEN - 1 - i];
    }
    Ok(())
}
