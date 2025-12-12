// Copyright (C) Microsoft Corporation. All rights reserved.

use crypto_env::CryptEnv;
use mcr_ddi_types::MaskedKey;
use mcr_ddi_types::MaskedKeyError;
use mcr_ddi_types::MaskingKeyAlgorithm;
use mcr_ddi_types::PreEncodeMaskedKeyType;
use mcr_ddi_types::AES_CBC_IV_SIZE;

use crate::*;

/// A trait for encoding a `MaskedKey` into a raw byte representation.
pub trait MaskedKeyEncode<Env: CryptEnv> {
    /// Encodes a `MaskedKey` into a byte slice.
    ///
    /// # Arguments
    /// * `env`: The cryptographic environment used for encoding.
    /// * `pre_encoded_key`: A mutable reference to the pre-encoded masked key structure.
    /// * `plaintext_key`: The key to be masked.
    /// * `masking_key`: The key to be used for encrypting the plaintext key.
    /// * `metadata`: Metadata associated with the masked key.
    ///
    /// # Returns
    /// * `Result<(), MaskedKeyError>` - Ok if encoding is successful, or an error if it fails.
    fn encode(
        env: &Env,
        pre_encoded_key: &mut PreEncodeMaskedKeyType<'_>,
        plaintext_key: &[u8],
        masking_key: &[u8],
        metadata: &[u8],
    ) -> Result<(), MaskedKeyError>;
}

impl<Env: CryptEnv> MaskedKeyEncode<Env> for MaskedKey<'_> {
    fn encode(
        env: &Env,
        pre_encoded_key: &mut PreEncodeMaskedKeyType<'_>,
        plaintext_key: &[u8],
        masking_key: &[u8],
        metadata: &[u8],
    ) -> Result<(), MaskedKeyError> {
        match pre_encoded_key.algo() {
            MaskingKeyAlgorithm::AesCbc256Hmac384 => {
                encode_aescbc256(env, pre_encoded_key, plaintext_key, masking_key, metadata)?;
            }
            _ => Err(MaskedKeyError::InvalidMaskingKeyAlgorithm)?,
        }

        Ok(())
    }
}

/// Encodes a masked key using AES-CBC-256 with HMAC-384.
fn encode_aescbc256<Env: CryptEnv>(
    env: &Env,
    pre_encoded_key: &mut PreEncodeMaskedKeyType<'_>,
    plaintext_key: &[u8],
    masking_key: &[u8],
    metadata: &[u8],
) -> Result<(), MaskedKeyError> {
    // Extract the AES-specific key for type-safe operations
    let PreEncodeMaskedKeyType::Aes(aes_key) = pre_encoded_key;

    // Encrypt the plaintext key using AES-CBC-256.
    let mut iv_tmp = [0u8; AES_CBC_IV_SIZE];
    let (aes_key_bytes, hmac_key) = split_aes_hmac_key(masking_key)?;
    env.aescbc256_encrypt(
        aes_key_bytes,
        plaintext_key,
        &mut iv_tmp,
        aes_key.encrypted_key_mut(),
    )
    .map_err(|_| MaskedKeyError::AesEncryptionFailed)?;

    aes_key.iv_mut().copy_from_slice(&iv_tmp);

    // Copy the metadata.
    let metadata_mut = aes_key.metadata_mut();
    if metadata.len() != metadata_mut.len() {
        Err(MaskedKeyError::MetadataEncodeError)?;
    }
    metadata_mut.copy_from_slice(metadata);

    // Lastly, generate the HMAC tag for the masked key structure.
    let data_to_tag = aes_key.tagged_data();
    let tag = env
        .hmac384_tag(hmac_key, data_to_tag)
        .map_err(|_| MaskedKeyError::HmacTagGenerationFailed)?;
    aes_key.tag_mut().copy_from_slice(&tag);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::vec;

    use mcr_ddi_mbor::MborByteArray;
    use mcr_ddi_mbor::MborEncode;
    use mcr_ddi_mbor::MborEncoder;
    use mcr_ddi_mbor::MborLen;
    use mcr_ddi_mbor::MborLenAccumulator;
    use mcr_ddi_types::DdiKeyType;
    use mcr_ddi_types::DdiMaskedKeyAttributes;
    use mcr_ddi_types::DdiMaskedKeyMetadata;
    use mcr_ddi_types::AES_CBC_IV_SIZE;
    use mcr_ddi_types::AES_CBC_TAG_SIZE;

    use super::*;
    use crate::decode::MaskedKeyDecode;
    use crate::CryptoTestEnv;

    fn encode_metadata(metadata: &DdiMaskedKeyMetadata) -> Vec<u8> {
        // Get mbor encoded lenght for metadata
        let mut accumulator = MborLenAccumulator::default();
        metadata.mbor_len(&mut accumulator);
        let metadata_len = accumulator.len();

        // Mbor encode metadata
        let mut encoded_metadata = vec![0u8; metadata_len];

        let mut encoder = MborEncoder::new(&mut encoded_metadata, false);
        metadata.mbor_encode(&mut encoder).unwrap();
        encoded_metadata
    }

    #[test]
    fn test_get_encoded_length_aes_cbc256_hmac384() {
        let metadata = DdiMaskedKeyMetadata {
            svn: Some(1),
            key_type: DdiKeyType::Ecc256Private,
            key_attributes: DdiMaskedKeyAttributes { blob: [0u8; 32] },
            bks2_index: None,
            key_tag: None,
            key_label: MborByteArray::from_slice(b"DummyOne").unwrap(),
        };
        let encoded_metadata = encode_metadata(&metadata);
        let encoded_length = MaskedKey::encoded_length(
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            encoded_metadata.len(),
            32,
        );
        assert!(encoded_length > 0);
    }

    #[test]
    fn test_get_encoded_length_aes_gcm256() {
        let metadata = DdiMaskedKeyMetadata {
            svn: Some(1),
            key_type: DdiKeyType::Ecc256Private,
            key_attributes: DdiMaskedKeyAttributes { blob: [0u8; 32] },
            bks2_index: None,
            key_tag: None,
            key_label: MborByteArray::from_slice(b"DummyTwo").unwrap(),
        };
        let encoded_metadata = encode_metadata(&metadata);
        let encoded_length =
            MaskedKey::encoded_length(MaskingKeyAlgorithm::AesGcm256, encoded_metadata.len(), 32);
        assert!(encoded_length > 0);
    }

    #[test]
    fn test_pre_encode_aes_cbc256_hmac384() {
        let env = CryptoTestEnv::new();
        let metadata = DdiMaskedKeyMetadata {
            svn: Some(1),
            key_type: DdiKeyType::Ecc256Private,
            key_attributes: DdiMaskedKeyAttributes { blob: [0u8; 32] },
            bks2_index: None,
            key_tag: None,
            key_label: MborByteArray::from_slice(b"DummyThree").unwrap(),
        };

        let encoded_metadata = encode_metadata(&metadata);

        // Get the encoded length for the masked key.
        let plaintext_key_len = 32;
        let encrypted_key_len = env.aescbc256_enc_data_len(plaintext_key_len);
        let encoded_length = MaskedKey::encoded_length(
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            encoded_metadata.len(),
            encrypted_key_len,
        );
        assert!(encoded_length > 0);
        assert!(encoded_length.is_multiple_of(4));

        // Create a buffer of the required length.
        let mut buffer = vec![0u8; encoded_length];
        let result = MaskedKey::pre_encode(
            1,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            encoded_metadata.len(),
            encrypted_key_len,
            &mut buffer,
        );
        assert!(result.is_ok());
        let mut pre_encoded = result.unwrap();

        // Extract the AES key for testing
        let PreEncodeMaskedKeyType::Aes(aes_key) = &mut pre_encoded;

        assert_eq!(aes_key.iv().len(), AES_CBC_IV_SIZE);
        assert_eq!(aes_key.encrypted_key().len(), encrypted_key_len);
        assert_eq!(aes_key.metadata().len(), 74);
        assert_eq!(aes_key.tag().len(), AES_CBC_TAG_SIZE);

        aes_key.iv_mut().fill(0xAA);
        assert_eq!(aes_key.iv(), vec![0xAA; AES_CBC_IV_SIZE]);

        aes_key.encrypted_key_mut().fill(0xBB);
        assert_eq!(
            aes_key.encrypted_key(),
            vec![0xBB; aes_key.encrypted_key().len()]
        );

        aes_key.metadata_mut().fill(0xCC);
        assert_eq!(aes_key.metadata(), vec![0xCC; aes_key.metadata().len()]);

        aes_key.tag_mut().fill(0xDD);
        assert_eq!(aes_key.tag(), vec![0xDD; AES_CBC_TAG_SIZE]);
    }

    #[test]
    fn test_encode_decode_aes_cbc256_hmac384() {
        let env = CryptoTestEnv::new();
        let metadata = DdiMaskedKeyMetadata {
            svn: Some(1),
            key_type: DdiKeyType::Ecc256Private,
            key_attributes: DdiMaskedKeyAttributes { blob: [0u8; 32] },
            bks2_index: None,
            key_tag: None,
            key_label: MborByteArray::from_slice(b"DummyFive").unwrap(),
        };

        let encoded_metadata = encode_metadata(&metadata);

        let plaintext_key_len = 32;
        let encrypted_key_len = env.aescbc256_enc_data_len(plaintext_key_len);
        let encoded_length = MaskedKey::encoded_length(
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            encoded_metadata.len(),
            encrypted_key_len,
        );
        assert!(encoded_length.is_multiple_of(4));
        let mut buffer = vec![0u8; encoded_length];
        let result = MaskedKey::pre_encode(
            1,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            encoded_metadata.len(),
            encrypted_key_len,
            &mut buffer,
        );
        assert!(result.is_ok());
        let mut pre_encoded = result.unwrap();

        // Extract the AES key for testing
        let PreEncodeMaskedKeyType::Aes(aes_key) = &pre_encoded;

        assert_eq!(aes_key.iv().len(), AES_CBC_IV_SIZE);
        assert_eq!(aes_key.encrypted_key().len(), encrypted_key_len);
        assert_eq!(aes_key.tag().len(), AES_CBC_TAG_SIZE);

        let env = CryptoTestEnv::new();
        // Encode the MaskedKey
        let plaintext_key = vec![1u8; plaintext_key_len];
        let result = MaskedKey::encode(
            &env,
            &mut pre_encoded,
            plaintext_key.as_slice(),
            &AES256_HMAC384_COMBO_KEY,
            &encoded_metadata,
        );
        assert!(result.is_ok());

        // Decode the MaskedKey from the byte slice.
        let result = MaskedKey::decode(&env, &AES256_HMAC384_COMBO_KEY, buffer.as_slice(), true);
        assert!(result.is_ok());
        let decoded_key = result.unwrap(); // Keep the DecodedMaskedKey enum

        // Extract the AES key for individual field verification
        let aes_key = decoded_key.as_aes().unwrap();
        let algorithm = aes_key.header().algorithm;
        let version = aes_key.header().version;
        assert_eq!(algorithm, MaskingKeyAlgorithm::AesCbc256Hmac384);
        assert_eq!(version, 1);
        assert_eq!(aes_key.iv().len(), AES_CBC_IV_SIZE);
        assert_eq!(aes_key.tag().len(), AES_CBC_TAG_SIZE);

        // Decrypt the key to verify correctness.
        // Call decrypt_key on the DecodedMaskedKey enum, not on MaskedKeyAes
        let mut decrypted_key = vec![0u8; plaintext_key_len];
        let decrypt_result =
            decoded_key.decrypt_key(&env, &AES256_HMAC384_COMBO_KEY, &mut decrypted_key);
        assert!(decrypt_result.is_ok());
        assert_eq!(decrypted_key, plaintext_key);
    }

    #[test]
    fn test_encode_decode_aes_cbc256_hmac384_too_small_buffer() {
        let env = CryptoTestEnv::new();
        let metadata = DdiMaskedKeyMetadata {
            svn: Some(1),
            key_type: DdiKeyType::Ecc256Private,
            key_attributes: DdiMaskedKeyAttributes { blob: [0u8; 32] },
            bks2_index: None,
            key_tag: None,
            // max size 128 bytes
            key_label: MborByteArray::from_slice(b"DummyFive").unwrap(),
        };

        let encoded_metadata = encode_metadata(&metadata);

        let plaintext_key_len = 32;
        let encrypted_key_len = env.aescbc256_enc_data_len(plaintext_key_len);
        let encoded_length = MaskedKey::encoded_length(
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            encoded_metadata.len(),
            encrypted_key_len,
        );
        assert!(encoded_length.is_multiple_of(4));
        let mut buffer = vec![0u8; encoded_length - 1];
        let result = MaskedKey::pre_encode(
            1,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            encoded_metadata.len(),
            encrypted_key_len,
            &mut buffer,
        );

        assert!(matches!(result, Err(MaskedKeyError::InvalidLength)));
    }

    #[test]
    fn test_encode_decode_aes_cbc256_hmac384_wrong_combo_key() {
        let env = CryptoTestEnv::new();
        let metadata = DdiMaskedKeyMetadata {
            svn: Some(1),
            key_type: DdiKeyType::Ecc256Private,
            key_attributes: DdiMaskedKeyAttributes { blob: [0u8; 32] },
            bks2_index: None,
            key_tag: None,
            // max size 128 bytes
            key_label: MborByteArray::from_slice(b"DummyFive").unwrap(),
        };

        let encoded_metadata = encode_metadata(&metadata);

        let plaintext_key_len = 32;
        let encrypted_key_len = env.aescbc256_enc_data_len(plaintext_key_len);
        let encoded_length = MaskedKey::encoded_length(
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            encoded_metadata.len(),
            encrypted_key_len,
        );
        assert!(encoded_length.is_multiple_of(4));
        let mut buffer = vec![0u8; encoded_length];
        let result = MaskedKey::pre_encode(
            1,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            encoded_metadata.len(),
            encrypted_key_len,
            &mut buffer,
        );
        assert!(result.is_ok());
        let mut pre_encoded = result.unwrap();

        // Extract the AES key for testing
        let PreEncodeMaskedKeyType::Aes(aes_key) = &pre_encoded;

        assert_eq!(aes_key.iv().len(), AES_CBC_IV_SIZE);
        assert_eq!(aes_key.encrypted_key().len(), encrypted_key_len);
        assert_eq!(aes_key.tag().len(), AES_CBC_TAG_SIZE);

        let wrong_combo_key = vec![0xFF; 80];

        let env = CryptoTestEnv::new();
        // Encode the MaskedKey
        let plaintext_key = vec![1u8; plaintext_key_len];
        let result = MaskedKey::encode(
            &env,
            &mut pre_encoded,
            plaintext_key.as_slice(),
            &wrong_combo_key,
            &encoded_metadata,
        );
        assert!(result.is_ok());

        // Decode the MaskedKey from the byte slice.
        let result = MaskedKey::decode(&env, &wrong_combo_key, buffer.as_slice(), true);
        assert!(result.is_ok());
        let decoded_key = result.unwrap(); // Keep the DecodedMaskedKey enum

        // Extract the AES key for individual field verification
        let aes_key = decoded_key.as_aes().unwrap();
        let algorithm = aes_key.header().algorithm;
        let version = aes_key.header().version;
        assert_eq!(algorithm, MaskingKeyAlgorithm::AesCbc256Hmac384);
        assert_eq!(version, 1);
        assert_eq!(aes_key.iv().len(), AES_CBC_IV_SIZE);
        assert_eq!(aes_key.tag().len(), AES_CBC_TAG_SIZE);

        // Pass the wrong combo key to the decrypt_key function
        let mut decrypted_key = vec![0u8; plaintext_key_len];
        let decrypt_result = decoded_key.decrypt_key(&env, &[0u8; 80], &mut decrypted_key);
        assert!(decrypt_result.is_ok());
        assert_ne!(decrypted_key, plaintext_key);
    }
}
