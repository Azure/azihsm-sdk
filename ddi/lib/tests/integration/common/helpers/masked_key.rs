// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_mbor::MborDecode;
use azihsm_ddi_mbor::MborDecoder;

use super::*;

/// Size of the masked key attributes flags in bytes.
const MASKED_KEY_ATTRIBUTES_FLAGS_SIZE: usize = size_of::<u64>();

bitflags::bitflags! {
    /// Masked key attributes flags.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub (crate) struct MaskedKeyAttributes: u64 {
    /// Flag indicating if the key is a session key.
    const SESSION = 1 << 1;

    /// Flag indicating the key is locally generated or imported. The flag is set by the device
    /// and cannot be changed via the API.
    const LOCAL = 1 << 5;

    /// Flag indicating if the key can be used for encrypt operations. This flag can be
    /// specified only for Public Keys and Secret Keys.
    const ENCRYPT = 1 << 10;
    /// Flag indicating if the key can be used for decrypt operations. This flag can be
    /// specified only for Private and Secret Keys.
    const DECRYPT = 1 << 11;

    /// Flag indicating if the key can be used for sign operations. This flag can be
    /// specified only for Private Keys and Secret Keys.
    const SIGN = 1 << 12;
    /// Flag indicating if the key can be used for verify operations. This flag can be
    /// specified only for Public and Secret Keys.
    const VERIFY = 1 << 13;

    /// Flag indicating if the key can be used for wrap operations. This flag can be
    /// specified only for Public Keys and Secret Keys.
    const WRAP = 1 << 14;

    /// Flag indicating if the key can be used for unwrap operations. This flag can be
    /// specified only for Private and Secret Keys.
    const UNWRAP = 1 << 15;

    /// Flag indicating if the key can be used for derive operations. This flag can be
    /// specified only for Secret Keys.
    const DERIVE = 1 << 16;
    }
}

impl TryFrom<&DdiMaskedKeyAttributes> for MaskedKeyAttributes {
    type Error = DdiError;

    fn try_from(attrs: &DdiMaskedKeyAttributes) -> Result<Self, Self::Error> {
        let buf = &attrs.blob;
        if buf.len() < MASKED_KEY_ATTRIBUTES_FLAGS_SIZE {
            return Err(DdiError::InvalidParameter);
        }

        // Parse as 64-bit flags directly
        let flags = u64::from_le_bytes(
            buf[..MASKED_KEY_ATTRIBUTES_FLAGS_SIZE]
                .try_into()
                .map_err(|_| DdiError::InvalidParameter)?,
        );

        Ok(MaskedKeyAttributes::from_bits_truncate(flags))
    }
}

pub fn verify_iv_not_default_from_masked_key(masked_key: &[u8]) -> Option<bool> {
    const FORMAT_OFFSET: usize = 2;
    const ALGORITHM_OFFSET: usize = FORMAT_OFFSET + 2;
    const IV_LEN_OFFSET: usize = ALGORITHM_OFFSET + 2;
    const IV_PADDING_OFFSET: usize = IV_LEN_OFFSET + 2;
    const METADATA_LEN_OFFSET: usize = IV_PADDING_OFFSET + 2;
    const METADATA_PADDING_OFFSET: usize = METADATA_LEN_OFFSET + 2;
    const ENCRYPTED_KEY_LEN_OFFSET: usize = METADATA_PADDING_OFFSET + 2;
    const ENCRYPTED_KEY_PADDING_OFFSET: usize = ENCRYPTED_KEY_LEN_OFFSET + 2;
    const TAG_LEN_OFFSET: usize = ENCRYPTED_KEY_PADDING_OFFSET + 2;
    const RESERVED_OFFSET: usize = TAG_LEN_OFFSET + 34;

    if masked_key.len() < RESERVED_OFFSET {
        return None;
    }

    let iv_len: usize = u16::from_le_bytes(
        masked_key[ALGORITHM_OFFSET..IV_LEN_OFFSET]
            .try_into()
            .unwrap(),
    )
    .into();

    masked_key
        .get(RESERVED_OFFSET..RESERVED_OFFSET + iv_len)
        .map(|iv| iv.iter().any(|&x| x != 0))
}

pub fn extract_metadata_from_masked_key(masked_key: &[u8]) -> Option<DdiMaskedKeyMetadata> {
    const FORMAT_OFFSET: usize = 2;
    const ALGORITHM_OFFSET: usize = FORMAT_OFFSET + 2;
    const IV_LEN_OFFSET: usize = ALGORITHM_OFFSET + 2;
    const IV_PADDING_OFFSET: usize = IV_LEN_OFFSET + 2;
    const METADATA_LEN_OFFSET: usize = IV_PADDING_OFFSET + 2;
    const METADATA_PADDING_OFFSET: usize = METADATA_LEN_OFFSET + 2;
    const ENCRYPTED_KEY_LEN_OFFSET: usize = METADATA_PADDING_OFFSET + 2;
    const ENCRYPTED_KEY_PADDING_OFFSET: usize = ENCRYPTED_KEY_LEN_OFFSET + 2;
    const TAG_LEN_OFFSET: usize = ENCRYPTED_KEY_PADDING_OFFSET + 2;
    const RESERVED_OFFSET: usize = TAG_LEN_OFFSET + 34;

    if masked_key.len() < RESERVED_OFFSET {
        return None;
    }

    let iv_len: usize = u16::from_le_bytes(
        masked_key[ALGORITHM_OFFSET..IV_LEN_OFFSET]
            .try_into()
            .unwrap(),
    )
    .into();
    let iv_padding_len: usize = u16::from_le_bytes(
        masked_key[IV_LEN_OFFSET..IV_PADDING_OFFSET]
            .try_into()
            .unwrap(),
    )
    .into();
    let metadata_len: usize = u16::from_le_bytes(
        masked_key[IV_PADDING_OFFSET..METADATA_LEN_OFFSET]
            .try_into()
            .unwrap(),
    )
    .into();

    let metadata_offset = RESERVED_OFFSET + iv_len + iv_padding_len;

    if masked_key.len() < metadata_offset + metadata_len {
        return None;
    }

    let metadata = &masked_key[metadata_offset..metadata_offset + metadata_len];
    let mut decoder = MborDecoder::new(metadata, false);

    let metadata = DdiMaskedKeyMetadata::mbor_decode(&mut decoder);
    if let Err(e) = &metadata {
        tracing::error!("mbor_decode error {:?}", e);

        return None;
    }

    metadata.ok()
}

pub fn verify_masked_key_attributes(
    masked_key: &[u8],
    expected_attrs: MaskedKeyAttributes,
) -> bool {
    if let Some(metadata) = extract_metadata_from_masked_key(masked_key) {
        if let Ok(attrs) = MaskedKeyAttributes::try_from(&metadata.key_attributes) {
            return attrs.contains(expected_attrs);
        }
    }

    false
}
