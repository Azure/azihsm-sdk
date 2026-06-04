// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Masked-key metadata MBOR types.
//!
//! These types describe the cleartext metadata embedded inside a
//! masked-key blob (see
//! [`azihsm_fw_core_crypto_key_masking::MaskedKey`]).  The bytes
//! produced by MBOR-encoding [`DdiMaskedKeyMetadata`] are bound by
//! the integrity tag, so any change to the field values is detected
//! by the unmask path.
//!
//! Field IDs match the host-side serde representation
//! (`azihsm_ddi_types::DdiMaskedKeyMetadata`) so blobs produced by
//! the firmware are byte-compatible with host tooling.

use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;

use crate::DdiKeyType;

/// Opaque 32-byte key-attribute blob.
///
/// Carries the firmware-side [`HsmVaultKeyAttrs`] bitfield serialized
/// little-endian into the leading 8 bytes, with the remaining 24
/// bytes reserved for binary compatibility with the host-side serde
/// representation.
#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiMaskedKeyAttributes {
    /// Serialized 32-byte attribute blob: `flags` (little-endian
    /// `u64`) followed by 24 reserved zero bytes.  See
    /// [`From<HsmVaultKeyAttrs>`].
    #[ddi(id = 1)]
    pub blob: [u8; 32],
}

impl From<HsmVaultKeyAttrs> for DdiMaskedKeyAttributes {
    fn from(value: HsmVaultKeyAttrs) -> Self {
        let mut blob = [0u8; 32];
        blob[0..8].copy_from_slice(&value.into_bits().to_le_bytes());
        Self { blob }
    }
}

/// Cleartext metadata embedded inside a masked-key blob.
///
/// MBOR-encoded into the metadata slot of an
/// [`azihsm_fw_core_crypto_key_masking::MaskedKey`] blob and bound by
/// the trailing integrity tag.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiMaskedKeyMetadata<'a> {
    /// Security version number that masked this key.
    #[ddi(id = 1)]
    pub svn: u64,

    /// Key type tag identifying the masking algorithm.
    #[ddi(id = 2)]
    pub key_type: DdiKeyType,

    /// Reserved attribute bitflag blob.
    #[ddi(id = 3)]
    pub key_attributes: DdiMaskedKeyAttributes,

    /// Index of the BKS2 entry this key is anchored to.
    #[ddi(id = 4)]
    pub bks2_index: Option<u16>,

    /// Reserved for future use; not populated by the firmware.
    #[ddi(id = 5)]
    pub rsvd: Option<u16>,

    /// Caller-supplied label identifying the key role
    /// (e.g. `b"BK3"`).
    #[ddi(id = 6, max_len = 128)]
    pub key_label: &'a [u8],

    /// Length of the plaintext key in bytes before encryption.
    #[ddi(id = 7)]
    pub key_length: u16,
}

#[cfg(test)]
mod tests {
    use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;

    use super::*;

    #[test]
    fn from_attrs_internal_never_extractable() {
        let attrs: DdiMaskedKeyAttributes = HsmVaultKeyAttrs::new()
            .with_internal(true)
            .with_never_extractable(true)
            .into();
        // Bit 0 (internal) + bit 7 (never_extractable) = 0x81.
        assert_eq!(attrs.blob[0], 0x81);
        assert!(attrs.blob[1..32].iter().all(|&b| b == 0));
    }

    #[test]
    fn from_attrs_higher_bit_is_little_endian() {
        // Bit 10 = `encrypt`; little-endian u64 puts it in byte 1.
        let attrs: DdiMaskedKeyAttributes = HsmVaultKeyAttrs::new().with_encrypt(true).into();
        assert_eq!(attrs.blob[0], 0x00);
        assert_eq!(attrs.blob[1], 0x04);
        assert!(attrs.blob[2..32].iter().all(|&b| b == 0));
    }

    #[test]
    fn from_attrs_pads_reserved_bytes_with_zero() {
        let attrs: DdiMaskedKeyAttributes = HsmVaultKeyAttrs::new().into();
        assert!(attrs.blob.iter().all(|&b| b == 0));
    }
}
