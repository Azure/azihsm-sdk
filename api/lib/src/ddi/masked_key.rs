// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use zerocopy::*;

use super::*;

bitflags::bitflags! {
    /// Masked key attributes flags.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    struct HsmMaskedKeyAttributes : u16 {
        const LOCAL = 1 << 0;
        const IMPORTED = 1 << 1;
        const SIGN_VERIFY = 1 << 2;
        const ENCRYPT_DECRYPT = 1 << 3;
        const UNWRAP = 1 << 4;
        const DERIVE = 1 << 5;
        const SESSION = 1 << 6;
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
        let (header, remaining) = Self::parse_header(masked_key)?;
        let (aes_header, _) = Self::parse_aes_header(remaining)?;
        let metadata = Self::parse_key_metadata(header, aes_header, remaining)?;
        Ok(metadata)
    }

    /// Parses the masked key header from the masked key blob.
    ///
    /// # Arguments
    ///
    /// * `masked_key` - The masked key data to be parsed
    ///
    /// # Returns
    ///
    /// Returns the parsed masked key header and remaining data.
    fn parse_header(masked_key: &[u8]) -> HsmResult<(&MaskedKeyHeader, &[u8])> {
        if masked_key.len() < size_of::<MaskedKeyHeader>() {
            return Err(HsmError::IndexOutOfRange);
        }

        let (header, remaining) = MaskedKeyHeader::try_ref_from_prefix(masked_key)
            .map_err(|_| HsmError::InternalError)?;

        if header.version != 1 {
            return Err(HsmError::InternalError);
        }

        if !matches!(header.algorithm, MaskingKeyAlgorithm::AesCbc256Hmac384) {
            return Err(HsmError::UnsupportedAlgorithm);
        }

        Ok((header, remaining))
    }

    /// Parses the AES-specific masked key header from the masked key blob.
    ///
    /// # Arguments
    ///
    /// * `remaining` - The remaining masked key data after the general header
    ///
    /// # Returns
    ///
    /// Returns the parsed AES masked key header and remaining data.
    fn parse_aes_header(remaining: &[u8]) -> HsmResult<(&MaskedKeyAesHeader, &[u8])> {
        if remaining.len() < size_of::<MaskedKeyAesHeader>() {
            return Err(HsmError::IndexOutOfRange);
        }

        let (aes_header, remaining) = MaskedKeyAesHeader::try_ref_from_prefix(remaining)
            .map_err(|_| HsmError::InternalError)?;

        Self::validate_aes_header(aes_header)?;

        Ok((aes_header, remaining))
    }

    /// Parses the masked key metadata from the masked key blob.
    ///
    /// # Arguments
    ///
    /// * `header` - The general masked key header
    /// * `aes_key_header` - The AES-specific masked key header
    /// * `data` - The remaining masked key data
    ///
    /// # Returns
    ///
    /// Returns the parsed masked key metadata.
    fn parse_key_metadata(
        header: &MaskedKeyHeader,
        aes_key_header: &MaskedKeyAesHeader,
        data: &[u8],
    ) -> HsmResult<HsmMaskedKeyMetadata> {
        if data.len() < Self::metadata_size(aes_key_header) {
            return Err(HsmError::IndexOutOfRange);
        }

        let aes_masked_key = MaskedKeyAes::new(*header, aes_key_header.into(), data);

        let mut decoder = MborDecoder::new(aes_masked_key.metadata(), false);
        let metadata =
            DdiMaskedKeyMetadata::mbor_decode(&mut decoder).map_hsm_err(HsmError::InternalError)?;

        HsmMaskedKeyMetadata::try_from(metadata)
    }

    /// Validates the AES masked key header.
    ///
    /// # Arguments
    ///
    /// * `header` - The AES masked key header to be validated
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the header is valid, otherwise returns an error.
    fn validate_aes_header(header: &MaskedKeyAesHeader) -> HsmResult<()> {
        if header.encrypted_key_len == 0 || header.metadata_len == 0 || header.tag_len == 0 {
            return Err(HsmError::InternalError);
        }

        if header.iv_len != AES_CBC_IV_SIZE as u16 && header.iv_len != AES_GCM_IV_SIZE as u16 {
            return Err(HsmError::InternalError);
        }

        // Check if the lengths are padded correctly
        if !(header.iv_len + header.post_iv_pad_len).is_multiple_of(4)
            || !(header.metadata_len + header.post_metadata_pad_len).is_multiple_of(4)
            || !(header.encrypted_key_len + header.post_encrypted_key_pad_len).is_multiple_of(4)
        {
            return Err(HsmError::InternalError);
        }

        Ok(())
    }

    /// Calculates the total size of the metadata section in the masked key blob.
    fn metadata_size(header: &MaskedKeyAesHeader) -> usize {
        header.iv_len as usize
            + header.post_iv_pad_len as usize
            + header.metadata_len as usize
            + header.post_metadata_pad_len as usize
            + header.encrypted_key_len as usize
            + header.post_encrypted_key_pad_len as usize
            + header.tag_len as usize
    }

    fn key_props(metadata: &HsmMaskedKeyMetadata, class: HsmKeyClass) -> HsmResult<HsmKeyProps> {
        let mut flags = HsmKeyFlags::default();

        // check if both generated and imported are not set
        if metadata.attrs.contains(HsmMaskedKeyAttributes::LOCAL)
            && metadata.attrs.contains(HsmMaskedKeyAttributes::IMPORTED)
        {
            return Err(HsmError::InternalError);
        }

        if metadata.attrs.contains(HsmMaskedKeyAttributes::LOCAL) {
            flags |= HsmKeyFlags::LOCAL;
        }

        if metadata.attrs.contains(HsmMaskedKeyAttributes::SESSION) {
            flags |= HsmKeyFlags::SESSION;
        }

        if metadata.attrs.contains(HsmMaskedKeyAttributes::SIGN_VERIFY) {
            match class {
                HsmKeyClass::Private => {
                    flags |= HsmKeyFlags::SIGN;
                }
                HsmKeyClass::Public => {
                    flags |= HsmKeyFlags::VERIFY;
                }
                HsmKeyClass::Secret => {
                    flags |= HsmKeyFlags::SIGN;
                    flags |= HsmKeyFlags::VERIFY;
                }
            }
        }

        if metadata
            .attrs
            .contains(HsmMaskedKeyAttributes::ENCRYPT_DECRYPT)
        {
            match class {
                HsmKeyClass::Private => {
                    flags |= HsmKeyFlags::DECRYPT;
                }
                HsmKeyClass::Public => {
                    flags |= HsmKeyFlags::ENCRYPT;
                }
                HsmKeyClass::Secret => {
                    flags |= HsmKeyFlags::ENCRYPT;
                    flags |= HsmKeyFlags::DECRYPT;
                }
            }
        }

        if metadata.attrs.contains(HsmMaskedKeyAttributes::UNWRAP) {
            match class {
                HsmKeyClass::Private => {
                    flags |= HsmKeyFlags::UNWRAP;
                }
                HsmKeyClass::Public => {
                    flags |= HsmKeyFlags::WRAP;
                }
                HsmKeyClass::Secret => {
                    flags |= HsmKeyFlags::WRAP;
                    flags |= HsmKeyFlags::UNWRAP;
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

        Ok(HsmKeyProps::new(
            class,
            metadata.kind,
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
            DdiKeyType::Rsa2kPrivate => (HsmKeyKind::Rsa, 2048, None),
            DdiKeyType::Rsa3kPrivate => (HsmKeyKind::Rsa, 3072, None),
            DdiKeyType::Rsa4kPrivate => (HsmKeyKind::Rsa, 4096, None),
            DdiKeyType::Ecc256Private => (HsmKeyKind::Ecc, 256, Some(HsmEccCurve::P256)),
            DdiKeyType::Ecc384Private => (HsmKeyKind::Ecc, 384, Some(HsmEccCurve::P384)),
            DdiKeyType::Ecc521Private => (HsmKeyKind::Ecc, 521, Some(HsmEccCurve::P521)),
            DdiKeyType::Aes128 => (HsmKeyKind::Aes, 128, None),
            DdiKeyType::Aes192 => (HsmKeyKind::Aes, 192, None),
            DdiKeyType::Aes256 => (HsmKeyKind::Aes, 256, None),
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
        if buf.len() < 2 {
            return Err(HsmError::InternalError);
        }
        let flags = u16::from_le_bytes([buf[0], buf[1]]);
        HsmMaskedKeyAttributes::from_bits(flags).ok_or(HsmError::InternalError)
    }
}
