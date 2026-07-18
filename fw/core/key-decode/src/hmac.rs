// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HMAC-key decode path.
//!
//! Classifies a raw 32 / 48 / 64-byte HMAC key into its fixed-length HMAC
//! vault kind (SHA-256 / 384 / 512) and returns the
//! [`DecodedKey`](super::DecodedKey) the caller persists / masks.  Any
//! other byte length is a host contract violation.  The raw key is itself
//! the vault material.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::DecodedKey;

/// Classify a raw HMAC key by length: 32 / 48 / 64 B → SHA-256 / 384 / 512.
pub(super) fn decode(material: &DmaBuf) -> HsmResult<DecodedKey<'_>> {
    let kind = match material.len() {
        32 => HsmVaultKeyKind::_HmacSha256,
        48 => HsmVaultKeyKind::_HmacSha384,
        64 => HsmVaultKeyKind::_HmacSha512,
        _ => return Err(HsmError::InvalidArg),
    };

    // Symmetric — no public key.
    Ok(DecodedKey {
        kind,
        material,
        pub_key: None,
    })
}
