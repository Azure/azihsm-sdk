// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_ddi_types::MaskedKey;
use azihsm_ddi_types::MaskedKeyAes;
use azihsm_ddi_types::MaskedKeyAesHeader;
use azihsm_ddi_types::MaskedKeyAesLayout;
use azihsm_ddi_types::MaskedKeyError;
use azihsm_ddi_types::MaskedKeyHeader;
use azihsm_ddi_types::MaskingKeyAlgorithm;
use zerocopy::TryFromBytes;

use super::helpers::*;
use crate::crypto_env::CryptEnv;

/// Enum to handle different decoded masked key types
#[derive(Debug)]
pub enum DecodedMaskedKey<'a> {
    /// AES-based masked key
    Aes(MaskedKeyAes<'a>),
}

impl<'a> DecodedMaskedKey<'a> {
    /// Returns the AES-specific masked key, if it exists.
    pub fn as_aes(&self) -> Option<&MaskedKeyAes<'a>> {
        match self {
            DecodedMaskedKey::Aes(aes) => Some(aes),
        }
    }

    /// Decrypts the key using the appropriate algorithm
    pub fn decrypt_key<Env: CryptEnv>(
        &self,
        env: &Env,
        key: &[u8],
        output: &mut [u8],
    ) -> Result<usize, MaskedKeyError> {
        match self {
            DecodedMaskedKey::Aes(aes_key) => match aes_key.header().algorithm {
                MaskingKeyAlgorithm::AesCbc256Hmac384 => {
                    let (aes_key_bytes, _) = split_aes_hmac_key(key)?;

                    let iv = aes_key.iv();
                    let encrypted_key = aes_key.encrypted_key();

                    let plaintext_len = env
                        .aescbc256_decrypt(aes_key_bytes, iv, encrypted_key, output)
                        .map_err(|_| MaskedKeyError::AesDecryptionFailed)?;
                    Ok(plaintext_len)
                }
                _ => Err(MaskedKeyError::InvalidMaskingKeyAlgorithm),
            },
        }
    }
}

/// A trait for decoding a `MaskedKey` from a raw byte representation.
pub trait MaskedKeyDecode<'a, Env: CryptEnv>: Sized {
    /// Decodes an `MaskedKey` from a byte slice.
    ///
    /// # Arguments
    /// * `env`: The cryptographic environment used for decoding.
    /// * `masking_key`: A reference to the masking key used for unmasking the secret key.
    /// * `data`: A reference to the byte slice containing the raw masked key data.
    /// * `integrity_check`: Whether to perform integrity checking on the masked key.
    ///
    /// # Returns
    /// * `Result<DecodedMaskedKey<'a>, MaskedKeyError>` - The decoded masked key on success, or an error if decoding fails.
    fn decode(
        env: &Env,
        masking_key: &[u8],
        data: &'a [u8],
        integrity_check: bool,
    ) -> Result<DecodedMaskedKey<'a>, MaskedKeyError>;
}

impl<'a, Env: CryptEnv> MaskedKeyDecode<'a, Env> for MaskedKey<'a> {
    fn decode(
        env: &Env,
        masking_key: &[u8],
        data: &'a [u8],
        integrity_check: bool,
    ) -> Result<DecodedMaskedKey<'a>, MaskedKeyError> {
        if data.len() < size_of::<MaskedKeyHeader>() {
            Err(MaskedKeyError::InvalidLength)?;
        }

        let (header, remaining) = MaskedKeyHeader::try_ref_from_prefix(data)
            .map_err(|_| MaskedKeyError::HeaderDecodeError)?;

        match header.algorithm {
            MaskingKeyAlgorithm::AesCbc256Hmac384 | MaskingKeyAlgorithm::AesGcm256 => {
                let aes_key =
                    decode_aes(env, masking_key, header, data, remaining, integrity_check)?;
                Ok(DecodedMaskedKey::Aes(aes_key))
            }
            _ => Err(MaskedKeyError::InvalidMaskingKeyAlgorithm),
        }
    }
}

/// Decodes an AES-based masked key from a byte slice.
///
/// # Arguments
/// * `env`: The cryptographic environment used for decoding.
/// * `masking_key`: The masking key used for unmasking the secret key.
/// * `header`: The already-parsed masked key header.
/// * `full_data`: The full byte slice containing the masked key data.
/// * `aes_data`: The byte slice containing the AES-specific data.
/// * `integrity_check`: Whether to perform integrity checking on the masked key.
///
/// # Returns
/// * `Result<MaskedKey<'a>, MaskedKeyError>` - The decoded masked key on success.
fn decode_aes<'a, Env: CryptEnv>(
    env: &Env,
    masking_key: &[u8],
    header: &MaskedKeyHeader,
    full_data: &'a [u8],
    aes_data: &'a [u8],
    integrity_check: bool,
) -> Result<MaskedKeyAes<'a>, MaskedKeyError> {
    // Parse the AES payload
    if aes_data.len() < size_of::<MaskedKeyAesHeader>() {
        Err(MaskedKeyError::InvalidLength)?;
    }

    let (aes_header, payload_data) = MaskedKeyAesHeader::try_ref_from_prefix(aes_data)
        .map_err(|_| MaskedKeyError::HeaderDecodeError)?;

    validate_aes_header(aes_header)?;

    let layout = MaskedKeyAesLayout {
        metadata_len: aes_header.metadata_len as usize,
        post_metadata_pad_len: aes_header.post_metadata_pad_len as usize,
        encrypted_key_len: aes_header.encrypted_key_len as usize,
        post_encrypted_key_pad_len: aes_header.post_encrypted_key_pad_len as usize,
        iv_len: aes_header.iv_len as usize,
        post_iv_pad_len: aes_header.post_iv_pad_len as usize,
        tag_len: aes_header.tag_len as usize,
    };

    // Calculate the total expected length from the payload fields.
    let expected_payload_len = aes_header.iv_len as usize
        + aes_header.post_iv_pad_len as usize
        + aes_header.metadata_len as usize
        + aes_header.post_metadata_pad_len as usize
        + aes_header.encrypted_key_len as usize
        + aes_header.post_encrypted_key_pad_len as usize
        + aes_header.tag_len as usize;

    // Ensure the payload data length matches the expected length.
    if payload_data.len() != expected_payload_len {
        return Err(MaskedKeyError::InvalidLength);
    }

    let mut current_offset = size_of::<MaskedKeyHeader>() + size_of::<MaskedKeyAesHeader>();

    // Skip to the tag
    current_offset += aes_header.iv_len as usize
        + aes_header.post_iv_pad_len as usize
        + aes_header.metadata_len as usize
        + aes_header.post_metadata_pad_len as usize
        + aes_header.encrypted_key_len as usize
        + aes_header.post_encrypted_key_pad_len as usize;

    if integrity_check {
        if current_offset + aes_header.tag_len as usize <= full_data.len() {
            // Create slice for tag.
            let tag = &full_data[current_offset..current_offset + aes_header.tag_len as usize];

            // Verify the integrity of masked key.
            match header.algorithm {
                MaskingKeyAlgorithm::AesCbc256Hmac384 => {
                    let (_, hmac_key) = split_aes_hmac_key(masking_key)?;

                    let expected_tag = env
                        .hmac384_tag(hmac_key, &full_data[..current_offset])
                        .map_err(|_| MaskedKeyError::HmacTagGenerationFailed)?;
                    if expected_tag != tag {
                        Err(MaskedKeyError::HmacTagVerificationFailed)?;
                    }
                }
                MaskingKeyAlgorithm::AesGcm256 => {
                    todo!("GCM tag verification not implemented yet");
                }
                _ => return Err(MaskedKeyError::InvalidMaskingKeyAlgorithm),
            }
        } else {
            return Err(MaskedKeyError::InvalidLength);
        }
    }

    // Construct the MaskedKey struct with the layout and payload data
    Ok(MaskedKeyAes::new(*header, layout, aes_data))
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_types::MaskingKeyAlgorithm;
    use zerocopy::IntoBytes;

    use super::*;
    use crate::masked_key::CryptoTestEnv;
    use crate::masked_key::AES256_HMAC384_COMBO_KEY;

    #[test]
    fn test_masked_key_decode() {
        let mut data = vec![0u8; 3072];

        // Create the new header structure (only version and algorithm)
        let header = MaskedKeyHeader {
            version: 1,
            algorithm: MaskingKeyAlgorithm::AesCbc256Hmac384,
        };

        // Create the AES payload structure with length information
        let payload = MaskedKeyAesHeader {
            iv_len: 16,
            post_iv_pad_len: 0,
            metadata_len: 32,
            post_metadata_pad_len: 0,
            encrypted_key_len: 48, // CBC padded length
            post_encrypted_key_pad_len: 0,
            tag_len: 48,
            reserved: [0u8; 34],
        };

        // Write header and payload to buffer
        let header_bytes = header.as_bytes();
        let payload_bytes = payload.as_bytes();

        data[..header_bytes.len()].copy_from_slice(header_bytes);
        data[header_bytes.len()..header_bytes.len() + payload_bytes.len()]
            .copy_from_slice(payload_bytes);

        // Fill the rest of the data with dummy values.
        data[header_bytes.len() + payload_bytes.len()..].fill(0xFF);

        let env = CryptoTestEnv::new();

        // Compute the HMAC tag for the data.
        // The tag should be computed over header + payload + all data except the tag itself
        let tag_start = header_bytes.len()
            + payload_bytes.len()
            + payload.iv_len as usize
            + payload.post_iv_pad_len as usize
            + payload.metadata_len as usize
            + payload.post_metadata_pad_len as usize
            + payload.encrypted_key_len as usize
            + payload.post_encrypted_key_pad_len as usize;

        let (_, hmac_key) = split_aes_hmac_key(&AES256_HMAC384_COMBO_KEY).unwrap();
        let tag = env.hmac384_tag(hmac_key, &data[..tag_start]).unwrap();
        data[tag_start..tag_start + payload.tag_len as usize]
            .copy_from_slice(&tag[..payload.tag_len as usize]);

        let total_len = tag_start + payload.tag_len as usize;

        // Use the new MaskedKey::decode method
        let decoded = MaskedKey::decode(&env, &AES256_HMAC384_COMBO_KEY, &data[..total_len], true);
        assert!(decoded.is_ok());
        let decoded = decoded.unwrap();

        // Get the AES key from the decoded enum
        let aes_key = decoded.as_aes().expect("Should be AES key");

        // Verify the header matches
        assert_eq!(aes_key.header(), &header);

        // Test that the layout-based accessor methods work correctly
        assert_eq!(aes_key.layout().iv_len, payload.iv_len as usize);
        assert_eq!(aes_key.layout().metadata_len, payload.metadata_len as usize);
        assert_eq!(
            aes_key.layout().encrypted_key_len,
            payload.encrypted_key_len as usize
        );
        assert_eq!(aes_key.layout().tag_len, payload.tag_len as usize);

        // Test that we can access the IV, encrypted key, and tag using the accessor methods
        let iv = aes_key.iv();
        let encrypted_key = aes_key.encrypted_key();
        let tag_slice = aes_key.tag();

        assert_eq!(iv.len(), payload.iv_len as usize);
        assert_eq!(encrypted_key.len(), payload.encrypted_key_len as usize);
        assert_eq!(tag_slice.len(), payload.tag_len as usize);
        assert_eq!(tag_slice, &tag[..payload.tag_len as usize]);
    }

    #[test]
    fn test_masked_key_decode_insufficient_data() {
        let env = CryptoTestEnv::new();
        let result = MaskedKey::decode(&env, &AES256_HMAC384_COMBO_KEY, &[], true);
        assert!(matches!(result, Err(MaskedKeyError::InvalidLength)));
    }

    #[test]
    fn test_masked_key_decode_invalid_length() {
        let env = CryptoTestEnv::new();
        let mut data = vec![0u8; std::mem::size_of::<MaskedKeyHeader>() + 1];
        let header = MaskedKeyHeader {
            version: 1,
            algorithm: MaskingKeyAlgorithm::AesCbc256Hmac384,
        };

        // Only copy the header bytes that fit in the buffer
        let header_bytes = header.as_bytes();
        data[..header_bytes.len()].copy_from_slice(header_bytes);

        let result = MaskedKey::decode(&env, &AES256_HMAC384_COMBO_KEY, &data, true);
        assert!(matches!(result, Err(MaskedKeyError::InvalidLength)));
    }
}
