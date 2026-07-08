// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-key decode path.
//!
//! Classifies a raw 16 / 24 / 32-byte AES key into its vault kind and
//! returns the [`DecodedKey`](super::DecodedKey) the caller persists.
//! Any other byte length is a host contract violation.  The raw key is
//! itself the vault material.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::DecodedKey;

/// Classify a raw AES key (16 / 24 / 32 B).
pub(super) fn decode(material: &DmaBuf) -> HsmResult<DecodedKey<'_>> {
    let kind = match material.len() {
        16 => HsmVaultKeyKind::Aes128,
        24 => HsmVaultKeyKind::Aes192,
        32 => HsmVaultKeyKind::Aes256,
        _ => return Err(HsmError::InvalidArg),
    };

    // Symmetric — no public key.
    Ok(DecodedKey {
        kind,
        material,
        pub_key: None,
    })
}
