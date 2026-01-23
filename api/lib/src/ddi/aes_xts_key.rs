// Copyright (C) Microsoft Corporation. All rights reserved.

//! AES-XTS key helpers at the DDI layer.
//!
//! This module contains the shared on-wire format for representing an AES-XTS key
//! as a single blob (`header || part1 || part2`) and the DDI helpers that operate
//! on those blobs.
//!
//! The same key-pair blob format is used to carry either two *wrapped* halves or two
//! *masked* halves. Higher layers treat this as an opaque byte blob.

use core::mem::size_of;

use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::TryFromBytes;

use super::*;

/// Unwraps an AES-XTS key from a key-pair wrapped blob at the DDI layer.
///
/// The `wrapped_key` format is: `header || key1_wrapped_blob || key2_wrapped_blob`.
/// The header is a fixed 16 bytes (little-endian fields) and the two key blobs are
/// RSA-wrapped AES key payloads.
///
/// This function parses/validates the header, splits the two key blobs, unwraps both halves
/// using `unwrapping_key`, and returns the two key handles plus combined XTS properties.
///
/// On success, the returned `HsmKeyProps.masked_key` contains a *single* encoded blob
/// `header || part1_masked || part2_masked`.
pub(crate) fn aes_xts_unwrap_key(
    unwrapping_key: &HsmRsaPrivateKey,
    hash_algo: HsmHashAlgo,
    wrapped_key: &[u8],
    key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyHandle, HsmKeyProps)> {
    // Get Key1 and Key2 wrapped blobs.
    let (key1_wrapped_blob, key2_wrapped_blob) = HsmAesXtsKeyPairBlob::parse_blob(wrapped_key)?;

    let (handle1, dev_key_props1) = ddi::rsa_aes_unwrap_key(
        unwrapping_key,
        key1_wrapped_blob,
        hash_algo,
        key_props.clone(),
    )?;

    let (handle2, dev_key_props2) = ddi::rsa_aes_unwrap_key(
        unwrapping_key,
        key2_wrapped_blob,
        hash_algo,
        key_props.clone(),
    )?;
    // Build combined AES-XTS key properties.
    let dev_props = match build_xts_props(&dev_key_props1, &dev_key_props2) {
        Ok(p) => p,
        Err(e) => {
            // Best-effort cleanup to avoid leaking keys if the two halves are inconsistent.
            let _ = ddi::delete_key(&unwrapping_key.session(), handle1);
            let _ = ddi::delete_key(&unwrapping_key.session(), handle2);
            return Err(e);
        }
    };

    Ok((handle1, handle2, dev_props))
}

/// Unmasks an AES-XTS key from a key-pair masked blob at the DDI layer.
///
/// The `masked_key` format is: `header || key1_masked_blob || key2_masked_blob`.
///
/// This function unmasks both halves and returns two key handles plus combined XTS properties.
/// On success, the returned `HsmKeyProps.masked_key` contains the same encoded key-pair blob.
pub(crate) fn aes_xts_unmask_key(
    session: &HsmSession,
    masked_key: &[u8],
) -> HsmResult<(HsmKeyHandle, HsmKeyHandle, HsmKeyProps)> {
    let (key1_masked_blob, key2_masked_blob) = HsmAesXtsKeyPairBlob::parse_blob(masked_key)?;

    let (handle1, key1_props) = ddi::unmask_key(session, key1_masked_blob)?;

    let (handle2, key2_props) = match ddi::unmask_key(session, key2_masked_blob) {
        Ok(v) => v,
        Err(e) => {
            let _ = ddi::delete_key(session, handle1);
            return Err(e);
        }
    };

    // Build combined AES-XTS key properties.
    let xts_props = match build_xts_props(&key1_props, &key2_props) {
        Ok(p) => p,
        Err(e) => {
            // Best-effort cleanup to avoid leaking keys if the two halves are inconsistent.
            let _ = ddi::delete_key(session, handle1);
            let _ = ddi::delete_key(session, handle2);
            return Err(e);
        }
    };

    Ok((handle1, handle2, xts_props))
}

/// Builds a combined `HsmKeyProps` for an AES-XTS key from the device-returned per-half props.
///
/// This validates that both halves match on key metadata (class/kind/bits/flags/label/etc)
/// and encodes the two per-half `masked_key` blobs into a single key-pair blob.
///
/// The device is treated as the source of truth for key attributes.
pub(crate) fn build_xts_props(
    dev_key1_props: &HsmKeyProps,
    dev_key2_props: &HsmKeyProps,
) -> HsmResult<HsmKeyProps> {
    // Check if both keys have same properties except masked_key.
    validate_xts_props_pair(dev_key1_props, dev_key2_props)?;

    //get encoded masked key
    let encoded_masked_key =
        HsmAesXtsKeyPairBlob::get_encoded_xts_masked_key(dev_key1_props, dev_key2_props)?;

    // Represent the combined XTS key as 512 bits and store both halves in a single
    // encoded masked_key blob.
    let mut xts_props = HsmKeyProps::new(
        dev_key1_props.class(),
        dev_key1_props.kind(),
        dev_key1_props.bits() + dev_key2_props.bits(),
        dev_key1_props.ecc_curve(),
        dev_key1_props.flags(),
        dev_key1_props.label().to_vec(),
    );
    xts_props.set_masked_key(encoded_masked_key.as_ref());
    Ok(xts_props)
}

/// Validates that both halves of an AES-XTS key have matching properties.
///
/// Ensures the two halves represent the same key type and attributes, which is
/// required for a valid AES-XTS key pair. The `masked_key` field is intentionally
/// excluded from this comparison as it will differ between the two halves.
///
/// # Arguments
///
/// * `key1_props` - Properties of the first AES-XTS key half
/// * `key2_props` - Properties of the second AES-XTS key half
///
/// # Returns
///
/// Returns `Ok(())` if the properties match.
///
/// # Errors
///
/// Returns `HsmError::InternalError` if the two halves have mismatched properties
/// (class, kind, bits, curve, flags, or label).
fn validate_xts_props_pair(key1_props: &HsmKeyProps, key2_props: &HsmKeyProps) -> HsmResult<()> {
    // Ensure the two halves represent the same key type/attributes.
    // We intentionally ignore `masked_key` (which will differ per-half).
    if key1_props.class() != key2_props.class()
        || key1_props.kind() != key2_props.kind()
        || key1_props.bits() != key2_props.bits()
        || key1_props.ecc_curve() != key2_props.ecc_curve()
        || key1_props.flags() != key2_props.flags()
        || key1_props.label() != key2_props.label()
    {
        return Err(HsmError::InternalError);
    }

    Ok(())
}

#[repr(C, packed)]
#[derive(Debug, Default, Clone, Copy, IntoBytes, KnownLayout, TryFromBytes, Immutable)]
/// Fixed-size header for AES-XTS key-pair blobs.
///
/// The header is stored as little-endian byte arrays so the on-wire format remains stable
/// across host endianness.
pub struct HsmAesXtsKeyPairHeader {
    // Stored as little-endian bytes (agnostic to host endianness).
    magic_id: [u8; 8],
    version: [u8; 2],
    key1_len: [u8; 2],
    key2_len: [u8; 2],
    // Current size: 8 + 2 + 2 + 2 + 2 = 16 bytes.
    _reserved: [u8; 2],
}

impl HsmAesXtsKeyPairHeader {
    const LEN: usize = size_of::<Self>();

    /// Magic and version identifiers for the key-pair blob format.
    // Stored as a u64 for easy debug printing/comparisons. in le format:
    // [0x55, 0xAA, b'H', b'S', b'M', b'X', b'T', b'S'].
    const WRAP_BLOB_MAGIC: u64 = 0x55AA_4853_4D58_5453;
    const WRAP_BLOB_VERSION: u16 = 1;

    /// Returns the header magic identifier decoded from little-endian bytes.
    fn magic_id(&self) -> u64 {
        u64::from_le_bytes(self.magic_id)
    }

    /// Returns the header version decoded from little-endian bytes.
    fn version(&self) -> u16 {
        u16::from_le_bytes(self.version)
    }

    /// Returns the byte length of the first payload blob.
    fn key1_len(&self) -> usize {
        u16::from_le_bytes(self.key1_len) as usize
    }

    /// Returns the byte length of the second payload blob.
    fn key2_len(&self) -> usize {
        u16::from_le_bytes(self.key2_len) as usize
    }

    /// Parses the fixed-size header and validates magic/version.
    ///
    /// Returns the decoded header plus the remaining payload slice.
    fn parse_header(blob: &[u8]) -> HsmResult<(HsmAesXtsKeyPairHeader, &[u8])> {
        if blob.len() < Self::LEN {
            Err(HsmError::InvalidArgument)?;
        }

        let (header, payload) = HsmAesXtsKeyPairHeader::try_ref_from_prefix(blob)
            .map_err(|_| HsmError::InvalidArgument)?;

        Self::validate_header(header)?;

        Ok((*header, payload))
    }

    /// Validates header invariants.
    fn validate_header(header: &HsmAesXtsKeyPairHeader) -> HsmResult<()> {
        if header.magic_id() != HsmAesXtsKeyPairHeader::WRAP_BLOB_MAGIC {
            Err(HsmError::InternalError)?;
        }

        if header.version() != HsmAesXtsKeyPairHeader::WRAP_BLOB_VERSION {
            Err(HsmError::InternalError)?;
        }

        Ok(())
    }

    /// Creates a new AES-XTS key-pair blob header with specified payload lengths.
    ///
    /// # Arguments
    ///
    /// * `key1_len` - Byte length of the first key payload blob
    /// * `key2_len` - Byte length of the second key payload blob
    ///
    /// # Returns
    ///
    /// Returns a header initialized with the correct magic, version, and payload lengths.
    ///
    /// # Errors
    ///
    /// Returns `HsmError::InvalidArgument` if either length exceeds `u16::MAX`.
    fn new(key1_len: usize, key2_len: usize) -> HsmResult<Self> {
        if key1_len > u16::MAX as usize || key2_len > u16::MAX as usize {
            Err(HsmError::InvalidArgument)?;
        }

        Ok(HsmAesXtsKeyPairHeader {
            magic_id: HsmAesXtsKeyPairHeader::WRAP_BLOB_MAGIC.to_le_bytes(),
            version: HsmAesXtsKeyPairHeader::WRAP_BLOB_VERSION.to_le_bytes(),
            key1_len: (key1_len as u16).to_le_bytes(),
            key2_len: (key2_len as u16).to_le_bytes(),
            _reserved: [0u8; 2],
        })
    }

    /// Converts the header to a byte vector for serialization.
    ///
    /// # Returns
    ///
    /// Returns the header as a fixed 16-byte vector.
    fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

/// Helper for parsing and validating an AES-XTS key-pair blob.
///
/// The blob contains a fixed-size header followed by two payload blobs.
///
/// The same format is used for key-pair wrapped blobs and key-pair masked blobs.
pub(crate) struct HsmAesXtsKeyPairBlob {}

impl HsmAesXtsKeyPairBlob {
    /// Parses the blob and returns (key1_blob, key2_blob).
    pub(crate) fn parse_blob(blob: &[u8]) -> HsmResult<(&[u8], &[u8])> {
        // Parse the fixed-size header and retain the remainder as the blob payload.
        let (header, payload) = HsmAesXtsKeyPairHeader::parse_header(blob)?;

        let key1_len = header.key1_len();
        let key2_len = header.key2_len();
        let total_len = key1_len + key2_len;

        // The format is exactly: header || key1_blob || key2_blob.
        if payload.len() != total_len {
            Err(HsmError::InvalidArgument)?;
        }

        let (key1_blob, key2_blob) = payload.split_at(key1_len);
        Ok((key1_blob, key2_blob))
    }

    /// Encodes two key blobs into a single key-pair blob.
    ///
    /// Creates a blob in the format: `header || key1_blob || key2_blob`,
    /// where the header contains the magic, version, and lengths of both blobs.
    ///
    /// # Arguments
    ///
    /// * `key1_blob` - The first key payload blob (wrapped or masked)
    /// * `key2_blob` - The second key payload blob (wrapped or masked)
    ///
    /// # Returns
    ///
    /// Returns the combined blob with header and both payloads.
    ///
    /// # Errors
    ///
    /// Returns `HsmError::InvalidArgument` if either blob is empty or if the
    /// length of either blob exceeds `u16::MAX`.
    pub(crate) fn encode_blob(key1_blob: &[u8], key2_blob: &[u8]) -> HsmResult<Vec<u8>> {
        if key1_blob.is_empty() || key2_blob.is_empty() {
            return Err(HsmError::InvalidArgument);
        }

        let header = HsmAesXtsKeyPairHeader::new(key1_blob.len(), key2_blob.len())?;
        let mut encoded_blob = header.to_vec();
        encoded_blob.extend_from_slice(key1_blob);
        encoded_blob.extend_from_slice(key2_blob);
        Ok(encoded_blob)
    }

    /// Extracts and encodes the masked key blobs from two key properties.
    ///
    /// Retrieves the masked key material from each half's properties and encodes
    /// them into a single key-pair blob format.
    ///
    /// # Arguments
    ///
    /// * `key1_props` - Properties of the first AES-XTS key half (must contain masked_key)
    /// * `key2_props` - Properties of the second AES-XTS key half (must contain masked_key)
    ///
    /// # Returns
    ///
    /// Returns the encoded key-pair blob containing both masked key blobs.
    ///
    /// # Errors
    ///
    /// Returns `HsmError::InvalidArgument` if either property does not contain a
    /// masked key or if encoding fails.
    pub(crate) fn get_encoded_xts_masked_key(
        key1_props: &HsmKeyProps,
        key2_props: &HsmKeyProps,
    ) -> HsmResult<Vec<u8>> {
        Self::encode_blob(
            key1_props.masked_key().ok_or(HsmError::InvalidArgument)?,
            key2_props.masked_key().ok_or(HsmError::InvalidArgument)?,
        )
    }
}
