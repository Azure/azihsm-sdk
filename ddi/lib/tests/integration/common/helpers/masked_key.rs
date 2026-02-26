// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
