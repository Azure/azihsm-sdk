// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto::aead_envelope;
use azihsm_ddi_tbor_types::*;
use zerocopy::little_endian::U16 as Le16;
use zerocopy::little_endian::U64 as Le64;
use zerocopy::*;

use super::*;

/// Size of the masked key attributes flags in bytes.
const MASKED_KEY_ATTRIBUTES_FLAGS_SIZE: usize = size_of::<u64>();

/// Byte length of the TBOR masked-key metadata (the AEAD envelope's AAD).
const TBOR_MASKED_KEY_METADATA_LEN: usize = 192;
/// Magic identifying authenticated TBOR masked-key metadata.
const TBOR_MASKED_KEY_METADATA_MAGIC: [u8; 4] = *b"MKEY";
/// Supported TBOR masked-key metadata format version.
const TBOR_MASKED_KEY_METADATA_VERSION: u16 = 1;
/// Reserved trailing bytes of the metadata (must decode as all-zero).
const TBOR_MASKED_KEY_RESERVED_LEN: usize = 38;
/// Bit offset of the `KeyScope` field packed into `usage_flags`.
const TBOR_KEY_SCOPE_SHIFT: u32 = 17;
/// 3-bit mask selecting the `KeyScope` field within `usage_flags`.
const TBOR_KEY_SCOPE_MASK: u64 = 0b111;
/// `KeyScope::Session` value in the packed scope field.
const TBOR_KEY_SCOPE_SESSION: u64 = 0b001;

/// std/OpenSSL stores `n | e | d | p | q | dp | dq | qInv`.
#[cfg(feature = "emu")]
const fn rsa_crt_payload_len(key_bytes: usize) -> usize {
    key_bytes * 9 / 2 + 4
}

/// Uno stores the PKA operand `p | q | dp | dq | n | n1q | n2p | e`.
#[cfg(not(feature = "emu"))]
const fn rsa_crt_payload_len(key_bytes: usize) -> usize {
    key_bytes * 5 + 4
}

/// Key-kind discriminant recorded in the TBOR masked-key metadata
/// `key_kind` field. Values mirror the firmware `HsmVaultKeyKind`
/// (`fw/pal/traits/src/vault.rs`).
#[derive(Clone, Copy)]
enum TborMaskedKeyKind {
    Rsa2kPrivate,
    Rsa3kPrivate,
    Rsa4kPrivate,
    Rsa2kPrivateCrt,
    Rsa3kPrivateCrt,
    Rsa4kPrivateCrt,
    EccP256,
    EccP384,
    EccP521,
    Aes128,
    Aes192,
    Aes256,
    Secret256,
    Secret384,
    Secret521,
    SdSealing,
    VarLenHmacSha256,
    VarLenHmacSha384,
    VarLenHmacSha512,
}

impl TryFrom<u8> for TborMaskedKeyKind {
    type Error = HsmError;

    fn try_from(value: u8) -> HsmResult<Self> {
        Ok(match value {
            KEY_KIND_RSA2K_PRIVATE => Self::Rsa2kPrivate,
            KEY_KIND_RSA3K_PRIVATE => Self::Rsa3kPrivate,
            KEY_KIND_RSA4K_PRIVATE => Self::Rsa4kPrivate,
            KEY_KIND_RSA2K_PRIVATE_CRT => Self::Rsa2kPrivateCrt,
            KEY_KIND_RSA3K_PRIVATE_CRT => Self::Rsa3kPrivateCrt,
            KEY_KIND_RSA4K_PRIVATE_CRT => Self::Rsa4kPrivateCrt,
            KEY_KIND_ECC256_PRIVATE => Self::EccP256,
            KEY_KIND_ECC384_PRIVATE => Self::EccP384,
            KEY_KIND_ECC521_PRIVATE => Self::EccP521,
            KEY_KIND_AES128 => Self::Aes128,
            KEY_KIND_AES192 => Self::Aes192,
            KEY_KIND_AES256 => Self::Aes256,
            KEY_KIND_SECRET256 => Self::Secret256,
            KEY_KIND_SECRET384 => Self::Secret384,
            KEY_KIND_SECRET521 => Self::Secret521,
            KEY_KIND_SD_SEALING => Self::SdSealing,
            KEY_KIND_VAR_LEN_HMAC_SHA256 => Self::VarLenHmacSha256,
            KEY_KIND_VAR_LEN_HMAC_SHA384 => Self::VarLenHmacSha384,
            KEY_KIND_VAR_LEN_HMAC_SHA512 => Self::VarLenHmacSha512,
            _ => return Err(HsmError::MaskedKeyDecodeFailed),
        })
    }
}

impl TborMaskedKeyKind {
    /// Maps a TBOR vault kind to its API key metadata.
    fn key_metadata(self) -> (HsmKeyKind, u16, Option<HsmEccCurve>) {
        match self {
            Self::Rsa2kPrivate => (HsmKeyKind::Rsa, 2048, None),
            Self::Rsa3kPrivate => (HsmKeyKind::Rsa, 3072, None),
            Self::Rsa4kPrivate => (HsmKeyKind::Rsa, 4096, None),
            Self::Rsa2kPrivateCrt => (HsmKeyKind::RsaCrt, 2048, None),
            Self::Rsa3kPrivateCrt => (HsmKeyKind::RsaCrt, 3072, None),
            Self::Rsa4kPrivateCrt => (HsmKeyKind::RsaCrt, 4096, None),
            Self::EccP256 => (HsmKeyKind::Ecc, 256, Some(HsmEccCurve::P256)),
            Self::EccP384 => (HsmKeyKind::Ecc, 384, Some(HsmEccCurve::P384)),
            Self::EccP521 => (HsmKeyKind::Ecc, 521, Some(HsmEccCurve::P521)),
            Self::Aes128 => (HsmKeyKind::Aes, 128, None),
            Self::Aes192 => (HsmKeyKind::Aes, 192, None),
            Self::Aes256 => (HsmKeyKind::Aes, 256, None),
            Self::Secret256 => (HsmKeyKind::SharedSecret, 256, None),
            Self::Secret384 => (HsmKeyKind::SharedSecret, 384, None),
            Self::Secret521 => (HsmKeyKind::SharedSecret, 521, None),
            Self::SdSealing => (HsmKeyKind::Sealing, 384, None),
            Self::VarLenHmacSha256 => (HsmKeyKind::HmacSha256, 256, None),
            Self::VarLenHmacSha384 => (HsmKeyKind::HmacSha384, 384, None),
            Self::VarLenHmacSha512 => (HsmKeyKind::HmacSha512, 512, None),
        }
    }

    /// Validates the PAL-specific plaintext layout inside a masked envelope.
    fn payload_len_valid(self, bits: u16, payload_len: usize) -> bool {
        let key_bytes = usize::from(bits).div_ceil(8);
        let expected_len = match self {
            Self::Rsa2kPrivate | Self::Rsa3kPrivate | Self::Rsa4kPrivate => key_bytes * 2 + 4,
            Self::Rsa2kPrivateCrt | Self::Rsa3kPrivateCrt | Self::Rsa4kPrivateCrt => {
                rsa_crt_payload_len(key_bytes)
            }
            Self::EccP256 | Self::EccP384 | Self::EccP521 => key_bytes.next_multiple_of(4),
            _ => key_bytes,
        };
        payload_len == expected_len
    }
}

/// TBOR masked-key metadata: the fixed-layout authenticated header (AAD)
/// of the AEAD-GCM-256 masked-key envelope, mirroring the firmware
/// `MaskedKeyMetadata`. Parsed zero-copy from the envelope's AAD.
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct TborMaskedKeyMetadata {
    magic: [u8; 4],
    version: Le16,
    key_kind: u8,
    key_label_len: u8,
    usage_flags: Le64,
    svn: Le64,
    owner_seed_id: Le16,
    key_label: [u8; TBOR_KEY_LABEL_MAX_LEN],
    reserved: [u8; TBOR_MASKED_KEY_RESERVED_LEN],
}

const _: () = assert!(size_of::<TborMaskedKeyMetadata>() == TBOR_MASKED_KEY_METADATA_LEN);

impl TborMaskedKeyMetadata {
    /// Validates the authenticated metadata framing and zero padding.
    fn validate(&self) -> HsmResult<()> {
        let label_padding = self
            .key_label
            .get(self.key_label_len as usize..)
            .ok_or(HsmError::MaskedKeyDecodeFailed)?;
        if self.magic != TBOR_MASKED_KEY_METADATA_MAGIC
            || self.version.get() != TBOR_MASKED_KEY_METADATA_VERSION
            || !label_padding.iter().all(|&byte| byte == 0)
            || !self.reserved.iter().all(|&byte| byte == 0)
        {
            return Err(HsmError::MaskedKeyDecodeFailed);
        }
        Ok(())
    }

    /// Returns the caller-supplied label after metadata validation.
    fn label(&self) -> HsmResult<Vec<u8>> {
        self.key_label
            .get(..self.key_label_len as usize)
            .ok_or(HsmError::MaskedKeyDecodeFailed)
            .map(<[u8]>::to_vec)
    }

    /// Decodes usage flags and surfaces TBOR session scope as an API flag.
    fn attrs(&self) -> HsmMaskedKeyAttributes {
        let raw_attrs = self.usage_flags.get();
        let mut attrs = HsmMaskedKeyAttributes::from_bits_truncate(raw_attrs);
        let scope = (raw_attrs >> TBOR_KEY_SCOPE_SHIFT) & TBOR_KEY_SCOPE_MASK;
        if scope == TBOR_KEY_SCOPE_SESSION {
            attrs |= HsmMaskedKeyAttributes::SESSION;
        }
        attrs
    }
}

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

    pub(crate) fn tbor_scope(masked_key: &[u8]) -> HsmResult<u8> {
        Self::parse_tbor_metadata(masked_key)?;
        let envelope =
            aead_envelope::inspect(masked_key).map_err(|_| HsmError::MaskedKeyDecodeFailed)?;
        let metadata = TborMaskedKeyMetadata::ref_from_bytes(envelope.aad)
            .map_err(|_| HsmError::MaskedKeyDecodeFailed)?;
        Ok(((metadata.usage_flags.get() >> TBOR_KEY_SCOPE_SHIFT) & TBOR_KEY_SCOPE_MASK) as u8)
    }

    /// Verifies the device stamped the `requested` masking scope into the
    /// returned masked key. Firmware selects the masking key from the
    /// requested scope, so a mismatch means the request was not honored.
    pub(crate) fn verify_scope(masked_key: &[u8], requested: u8) -> HsmResult<()> {
        if Self::tbor_scope(masked_key)? != requested {
            return Err(HsmError::InvalidKeyProps);
        }
        Ok(())
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
        // TBOR blobs are AEAD-GCM-256 envelopes tagged with an "AEAD" magic;
        // MBOR blobs use the legacy AES-CBC masked-key header instead.
        if masked_key.starts_with(b"AEAD") {
            return Self::parse_tbor_metadata(masked_key);
        }

        let (header, remaining) = Self::parse_header(masked_key)?;
        let (aes_header, _) = Self::parse_aes_header(remaining)?;
        let metadata = Self::parse_key_metadata(header, aes_header, remaining)?;
        Ok(metadata)
    }

    /// Parses a TBOR masked-key blob (an AEAD-GCM-256 envelope) into
    /// [`HsmMaskedKeyMetadata`].
    ///
    /// Validates the envelope algorithm and the authenticated metadata
    /// (magic, version, key kind, label, and reserved padding) and checks
    /// the masked payload length against the key kind.
    /// Every device-supplied length is bounds-checked, so a malformed blob
    /// is rejected with [`HsmError::MaskedKeyDecodeFailed`] rather than
    /// panicking.
    fn parse_tbor_metadata(masked_key: &[u8]) -> HsmResult<HsmMaskedKeyMetadata> {
        let envelope =
            aead_envelope::inspect(masked_key).map_err(|_| HsmError::MaskedKeyDecodeFailed)?;
        if !matches!(envelope.alg, aead_envelope::AeadAlg::AesGcm256)
            || envelope.aad.len() != TBOR_MASKED_KEY_METADATA_LEN
        {
            return Err(HsmError::MaskedKeyDecodeFailed);
        }

        let metadata = TborMaskedKeyMetadata::ref_from_bytes(envelope.aad)
            .map_err(|_| HsmError::MaskedKeyDecodeFailed)?;
        metadata.validate()?;

        let tbor_kind = TborMaskedKeyKind::try_from(metadata.key_kind)?;
        let (kind, bits, curve) = tbor_kind.key_metadata();
        if !tbor_kind.payload_len_valid(bits, envelope.payload.len()) {
            return Err(HsmError::MaskedKeyDecodeFailed);
        }

        Ok(HsmMaskedKeyMetadata {
            attrs: metadata.attrs(),
            label: metadata.label()?,
            kind,
            bits,
            curve,
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn unchecked_ecc_blob(scope: u8) -> Vec<u8> {
        let mut blob = vec![0; 20 + TBOR_MASKED_KEY_METADATA_LEN + 48 + 16];
        blob[..8].copy_from_slice(b"AEAD\x03\x00\x00\xc0");
        blob[20..24].copy_from_slice(b"MKEY");
        blob[24..26].copy_from_slice(&1u16.to_le_bytes());
        blob[26] = KEY_KIND_ECC384_PRIVATE;
        let usage = HsmMaskedKeyAttributes::SIGN.bits()
            | HsmMaskedKeyAttributes::LOCAL.bits()
            | (u64::from(scope) << TBOR_KEY_SCOPE_SHIFT);
        blob[28..36].copy_from_slice(&usage.to_le_bytes());
        blob
    }

    #[test]
    fn masked_ecc_signing_info_reports_all_supported_scopes_without_authenticating() {
        for scope in [
            HsmKeyScope::Session,
            HsmKeyScope::Ephemeral,
            HsmKeyScope::Local,
            HsmKeyScope::SecurityDomain,
        ] {
            let blob = unchecked_ecc_blob(scope as u8);
            assert_eq!(
                HsmEccSignAlgo::masked_key_info(&blob),
                Ok((scope, HsmEccCurve::P384))
            );
            assert_eq!(HsmMaskedKey::tbor_scope(&blob), Ok(scope as u8));
        }
    }

    #[test]
    fn masked_ecc_signing_info_rejects_invalid_framing_scope_and_usage() {
        let blob = unchecked_ecc_blob(HsmKeyScope::Local as u8);
        for length in 0..blob.len() {
            assert!(HsmEccSignAlgo::masked_key_info(&blob[..length]).is_err());
        }
        for scope in [0, 5, 6, 7] {
            assert_eq!(
                HsmEccSignAlgo::masked_key_info(&unchecked_ecc_blob(scope)),
                Err(HsmError::InvalidKeyProps)
            );
        }
        for offset in [0, 4, 5, 20, 24, 26, 211] {
            let mut invalid = blob.clone();
            invalid[offset] = 0xff;
            assert!(HsmEccSignAlgo::masked_key_info(&invalid).is_err());
        }
        let mut no_sign = blob;
        no_sign[28..36].copy_from_slice(
            &((3u64 << TBOR_KEY_SCOPE_SHIFT) | HsmMaskedKeyAttributes::DERIVE.bits()).to_le_bytes(),
        );
        assert_eq!(
            HsmEccSignAlgo::masked_key_info(&no_sign),
            Err(HsmError::InvalidKey)
        );
    }

    #[test]
    fn masked_sealing_key_props_decode_metadata() {
        let mut blob = unchecked_ecc_blob(HsmKeyScope::Local as u8);
        blob[26] = KEY_KIND_SD_SEALING;
        let usage = HsmMaskedKeyAttributes::DERIVE.bits()
            | HsmMaskedKeyAttributes::LOCAL.bits()
            | (3u64 << TBOR_KEY_SCOPE_SHIFT);
        blob[28..36].copy_from_slice(&usage.to_le_bytes());
        let props = HsmMaskedKey::to_key_props(&blob).expect("sealing key metadata");
        assert_eq!(props.kind(), HsmKeyKind::Sealing);
        assert_eq!(props.class(), HsmKeyClass::Secret);
        assert_eq!(props.bits(), 384);
        assert!(props.can_derive());
        assert!(!props.can_sign());
        for length in 0..blob.len() {
            assert!(HsmMaskedKey::to_key_props(&blob[..length]).is_err());
        }
        blob.push(0);
        assert!(HsmMaskedKey::to_key_props(&blob).is_err());
    }

    #[test]
    fn rsa_crt_payload_len_matches_backend() {
        #[cfg(feature = "emu")]
        assert_eq!([256, 384, 512].map(rsa_crt_payload_len), [1156, 1732, 2308]);

        #[cfg(not(feature = "emu"))]
        assert_eq!([256, 384, 512].map(rsa_crt_payload_len), [1284, 1924, 2564]);
    }
}
