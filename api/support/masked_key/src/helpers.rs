// Copyright (C) Microsoft Corporation. All rights reserved.

use mcr_ddi_types::MaskedKeyAesHeader;
use mcr_ddi_types::MaskedKeyError;
use mcr_ddi_types::AES_CBC_256_KEY_SIZE;
use mcr_ddi_types::AES_CBC_IV_SIZE;
use mcr_ddi_types::AES_GCM_IV_SIZE;
use mcr_ddi_types::HMAC384_KEY_SIZE;

/// Splits a combined AES-HMAC key into separate AES and HMAC components.
///
/// # Arguments
/// * `key` - The combined key containing both AES and HMAC key material
///
/// # Returns
/// * `Ok((aes_key, hmac_key))` - Tuple containing the AES key and HMAC key slices
/// * `Err(MaskedKeyError::AesHmacComboKeyInvalid)` - If the key length is incorrect
pub fn split_aes_hmac_key(key: &[u8]) -> Result<(&[u8], &[u8]), MaskedKeyError> {
    if key.len() != (AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE) {
        Err(MaskedKeyError::AesHmacComboKeyInvalid)?;
    }
    let aes_key = &key[..AES_CBC_256_KEY_SIZE];
    let hmac_key = &key[AES_CBC_256_KEY_SIZE..];
    Ok((aes_key, hmac_key))
}

/// Validates the AES header to ensure it has correct lengths and padding.
pub(crate) fn validate_aes_header(header: &MaskedKeyAesHeader) -> Result<(), MaskedKeyError> {
    if header.encrypted_key_len == 0 || header.metadata_len == 0 || header.tag_len == 0 {
        Err(MaskedKeyError::InvalidLength)?;
    }

    if header.iv_len != AES_CBC_IV_SIZE as u16 && header.iv_len != AES_GCM_IV_SIZE as u16 {
        Err(MaskedKeyError::InvalidLength)?;
    }

    // Check if the lengths are padded correctly
    if !(header.iv_len + header.post_iv_pad_len).is_multiple_of(4)
        || !(header.metadata_len + header.post_metadata_pad_len).is_multiple_of(4)
        || !(header.encrypted_key_len + header.post_encrypted_key_pad_len).is_multiple_of(4)
    {
        Err(MaskedKeyError::InvalidLength)?;
    }

    Ok(())
}
