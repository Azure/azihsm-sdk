// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

/// Size of the masked key attributes flags in bytes.
const MASKED_KEY_ATTRIBUTES_FLAGS_SIZE: usize = size_of::<u64>();

bitflags::bitflags! {
    /// Masked key attributes flags.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    struct HsmMaskedKeyAttributes: u64 {
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

/// HSM masked key metadata.
struct HsmMaskedKeyMetadata {
    attrs: HsmMaskedKeyAttributes,
    label: Vec<u8>,
    kind: HsmKeyKind,
    bits: u16,
    curve: Option<HsmEccCurve>,
}

/// HSM masked key operations.
pub(crate) struct HsmMaskedKey;

impl HsmMaskedKey {
    /// Converts a masked key blob into key properties.
    ///
    /// # Arguments
    ///
    /// * `masked_key` - The masked key data to be converted
    ///
    /// # Returns
    ///
    /// Returns the key properties extracted from the masked key.
    pub(crate) fn to_key_props(masked_key: &[u8]) -> HsmResult<HsmKeyProps> {
        let metadata = Self::parse_metadata(masked_key)?;
        let mut key_props = Self::key_props(&metadata, HsmKeyClass::Secret)?;
        key_props.set_masked_key(masked_key);
        Ok(key_props)
    }

    /// Converts a masked key blob into a key pair's properties.
    ///
    /// # Arguments
    ///
    /// * `masked_key` - The masked key data to be converted
    ///
    /// # Returns
    ///
    /// Returns a tuple containing the private and public key properties.
    pub(crate) fn to_key_pair_props(
        masked_key: &[u8],
        pub_key_der: &[u8],
    ) -> HsmResult<(HsmKeyProps, HsmKeyProps)> {
        let metadata = Self::parse_metadata(masked_key)?;

        let mut priv_key_props = Self::key_props(&metadata, HsmKeyClass::Private)?;
        let mut pub_key_props = Self::key_props(&metadata, HsmKeyClass::Public)?;

        priv_key_props.set_masked_key(masked_key);
        priv_key_props.set_pub_key_der(pub_key_der);
        pub_key_props.set_pub_key_der(pub_key_der);

        Ok((priv_key_props, pub_key_props))
    }

    /// Parses the masked key metadata from the masked key blob.
    ///
    /// # Arguments
    ///
    /// * `masked_key` - The masked key data to be parsed
    ///
    /// # Returns
    ///
    /// Returns the parsed masked key metadata.
    fn parse_metadata(masked_key: &[u8]) -> HsmResult<HsmMaskedKeyMetadata> {
        let metadata = DdiMaskedKeyMetadata::try_from(masked_key).map_err(|e| match e {
            MaskedKeyError::InvalidLength => HsmError::IndexOutOfRange,
            _ => HsmError::InternalError,
        })?;

        HsmMaskedKeyMetadata::try_from(metadata)
    }

    fn key_props(metadata: &HsmMaskedKeyMetadata, class: HsmKeyClass) -> HsmResult<HsmKeyProps> {
        let mut flags = HsmKeyFlags::default();

        if metadata.attrs.contains(HsmMaskedKeyAttributes::LOCAL) {
            flags |= HsmKeyFlags::LOCAL;
        }

        if metadata.attrs.contains(HsmMaskedKeyAttributes::SESSION) {
            flags |= HsmKeyFlags::SESSION;
        }

        // Handle individual sign/verify flags
        if metadata.attrs.contains(HsmMaskedKeyAttributes::SIGN) {
            match class {
                HsmKeyClass::Private => {
                    flags |= HsmKeyFlags::SIGN;
                }
                HsmKeyClass::Public => {}
                HsmKeyClass::Secret => {
                    flags |= HsmKeyFlags::SIGN;
                }
            }
        }

        if metadata.attrs.contains(HsmMaskedKeyAttributes::VERIFY) {
            match class {
                HsmKeyClass::Private => {}
                HsmKeyClass::Public => {
                    flags |= HsmKeyFlags::VERIFY;
                }
                HsmKeyClass::Secret => {
                    flags |= HsmKeyFlags::VERIFY;
                }
            }
        }

        // Handle individual encrypt/decrypt flags
        if metadata.attrs.contains(HsmMaskedKeyAttributes::ENCRYPT) {
            match class {
                HsmKeyClass::Private => {}
                HsmKeyClass::Public => {
                    flags |= HsmKeyFlags::ENCRYPT;
                }
                HsmKeyClass::Secret => {
                    flags |= HsmKeyFlags::ENCRYPT;
                }
            }
        }

        if metadata.attrs.contains(HsmMaskedKeyAttributes::DECRYPT) {
            match class {
                HsmKeyClass::Private => {
                    flags |= HsmKeyFlags::DECRYPT;
                }
                HsmKeyClass::Public => {}
                HsmKeyClass::Secret => {
                    flags |= HsmKeyFlags::DECRYPT;
                }
            }
        }

        // Handle wrap/unwrap flags
        if metadata.attrs.contains(HsmMaskedKeyAttributes::WRAP) {
            match class {
                HsmKeyClass::Private => {}
                HsmKeyClass::Public => {
                    flags |= HsmKeyFlags::WRAP;
                }
                HsmKeyClass::Secret => {
                    flags |= HsmKeyFlags::WRAP;
                }
            }
        }

        if metadata.attrs.contains(HsmMaskedKeyAttributes::UNWRAP) {
            match class {
                HsmKeyClass::Private | HsmKeyClass::Secret => {
                    flags |= HsmKeyFlags::UNWRAP;
                }
                HsmKeyClass::Public => {
                    flags |= HsmKeyFlags::WRAP;
                }
            }
        }

        if metadata.attrs.contains(HsmMaskedKeyAttributes::DERIVE) {
            flags |= HsmKeyFlags::DERIVE;
        }

        if matches!(class, HsmKeyClass::Private | HsmKeyClass::Secret) {
            flags |= HsmKeyFlags::SENSITIVE
        }
        flags |= HsmKeyFlags::EXTRACTABLE;

        let kind = match (class, metadata.kind) {
            // Only the private half of an RSA pair carries the CRT form; the
            // public key of a CRT pair is a plain RSA public key.
            (HsmKeyClass::Public, HsmKeyKind::RsaCrt) => HsmKeyKind::Rsa,
            (_, kind) => kind,
        };

        Ok(HsmKeyProps::new(
            class,
            kind,
            metadata.bits as u32,
            metadata.curve,
            flags,
            metadata.label.clone(),
        ))
    }
}

impl TryFrom<DdiMaskedKeyMetadata> for HsmMaskedKeyMetadata {
    type Error = HsmError;

    /// Converts DDI masked key metadata to HSM masked key metadata.
    fn try_from(value: DdiMaskedKeyMetadata) -> Result<Self, Self::Error> {
        let attrs = HsmMaskedKeyAttributes::try_from(value.key_attributes)?;
        let (kind, bits, curve) = match value.key_type {
            DdiKeyType::RsaUnwrap => (HsmKeyKind::Rsa, 2048, None), // Special internal key type for RSA unwrapping
            DdiKeyType::Rsa2kPrivate => (HsmKeyKind::Rsa, 2048, None),
            DdiKeyType::Rsa3kPrivate => (HsmKeyKind::Rsa, 3072, None),
            DdiKeyType::Rsa4kPrivate => (HsmKeyKind::Rsa, 4096, None),
            DdiKeyType::Rsa2kPrivateCrt => (HsmKeyKind::RsaCrt, 2048, None),
            DdiKeyType::Rsa3kPrivateCrt => (HsmKeyKind::RsaCrt, 3072, None),
            DdiKeyType::Rsa4kPrivateCrt => (HsmKeyKind::RsaCrt, 4096, None),
            DdiKeyType::Ecc256Private => (HsmKeyKind::Ecc, 256, Some(HsmEccCurve::P256)),
            DdiKeyType::Ecc384Private => (HsmKeyKind::Ecc, 384, Some(HsmEccCurve::P384)),
            DdiKeyType::Ecc521Private => (HsmKeyKind::Ecc, 521, Some(HsmEccCurve::P521)),
            DdiKeyType::Aes128 => (HsmKeyKind::Aes, 128, None),
            DdiKeyType::Aes192 => (HsmKeyKind::Aes, 192, None),
            DdiKeyType::Aes256 => (HsmKeyKind::Aes, 256, None),
            DdiKeyType::AesGcmBulk256 | DdiKeyType::AesGcmBulk256Unapproved => {
                (HsmKeyKind::AesGcm, 256, None)
            }
            DdiKeyType::AesXtsBulk256 => (HsmKeyKind::AesXts, 256, None),
            DdiKeyType::Secret256 => (HsmKeyKind::SharedSecret, 256, None),
            DdiKeyType::Secret384 => (HsmKeyKind::SharedSecret, 384, None),
            DdiKeyType::Secret521 => (HsmKeyKind::SharedSecret, 521, None),
            DdiKeyType::HmacSha256 => (HsmKeyKind::HmacSha256, 256, None),
            DdiKeyType::HmacSha384 => (HsmKeyKind::HmacSha384, 384, None),
            DdiKeyType::HmacSha512 => (HsmKeyKind::HmacSha512, 512, None),
            _ => return Err(HsmError::InternalError),
        };

        Ok(HsmMaskedKeyMetadata {
            attrs,
            label: value.key_label.as_slice().to_vec(),
            kind,
            bits,
            curve,
        })
    }
}

impl TryFrom<DdiMaskedKeyAttributes> for HsmMaskedKeyAttributes {
    type Error = HsmError;

    fn try_from(attrs: DdiMaskedKeyAttributes) -> Result<Self, Self::Error> {
        let buf = &attrs.blob;
        if buf.len() < MASKED_KEY_ATTRIBUTES_FLAGS_SIZE {
            return Err(HsmError::InternalError);
        }

        // Parse as 64-bit flags directly
        let flags = u64::from_le_bytes(
            buf[..MASKED_KEY_ATTRIBUTES_FLAGS_SIZE]
                .try_into()
                .map_err(|_| HsmError::InternalError)?,
        );
        Ok(HsmMaskedKeyAttributes::from_bits_truncate(flags))
    }
}
