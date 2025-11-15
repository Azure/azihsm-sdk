// Copyright (C) Microsoft Corporation. All rights reserved.

use std::sync::Arc;

use mcr_ddi_types::DdiAesKeySize;
use mcr_ddi_types::DdiAesOp;
use mcr_ddi_types::DdiKeyProperties;
use parking_lot::RwLock;

use crate::crypto::Algo;
use crate::crypto::DecryptOp;
use crate::crypto::EncryptOp;
use crate::crypto::Key;
use crate::crypto::KeyDeleteOp;
use crate::crypto::KeyGenOp;
use crate::crypto::KeyId;
use crate::crypto::SafeInnerAccess;
use crate::ddi;
use crate::types::KeyProps;
use crate::AzihsmError;
use crate::Session;
use crate::AZIHSM_AES_DECRYPT_FAILED;
use crate::AZIHSM_AES_ENCRYPT_FAILED;
use crate::AZIHSM_AES_KEYGEN_FAILED;
use crate::AZIHSM_DELETE_KEY_FAILED;
use crate::AZIHSM_ERROR_INVALID_ARGUMENT;
use crate::AZIHSM_ILLEGAL_KEY_PROPERTY;
use crate::AZIHSM_KEY_ALREADY_EXISTS;
use crate::AZIHSM_KEY_NOT_INITIALIZED;
use crate::AZIHSM_KEY_PROPERTY_NOT_PRESENT;
use crate::AZIHSM_OPERATION_NOT_SUPPORTED;

/// AES block size and IV length in bytes
pub(crate) const AES_CBC_BLOCK_IV_LENGTH: usize = 16;

impl TryFrom<&KeyProps> for DdiAesKeySize {
    type Error = AzihsmError;

    fn try_from(props: &KeyProps) -> Result<DdiAesKeySize, Self::Error> {
        let key_len_bits = props.bit_len().ok_or(AZIHSM_KEY_PROPERTY_NOT_PRESENT)?;

        match key_len_bits {
            128 => Ok(DdiAesKeySize::Aes128),
            192 => Ok(DdiAesKeySize::Aes192),
            256 => Ok(DdiAesKeySize::Aes256),
            _ => Err(AZIHSM_ILLEGAL_KEY_PROPERTY),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AesCbcKey(Arc<RwLock<AesCbcKeyInner>>);

#[derive(Debug)]
struct AesCbcKeyInner {
    id: Option<KeyId>,
    props: KeyProps,
    _masked_key: Option<Vec<u8>>,
}

impl AesCbcKey {
    pub fn new(props: KeyProps) -> Self {
        AesCbcKey(Arc::new(RwLock::new(AesCbcKeyInner {
            id: None,
            props,
            _masked_key: None,
        })))
    }

    fn with_inner<R>(&self, f: impl FnOnce(&AesCbcKeyInner) -> R) -> R {
        self.0.with_inner(f)
    }

    #[allow(unused)]
    fn with_inner_mut<R>(&self, f: impl FnOnce(&mut AesCbcKeyInner) -> R) -> R {
        self.0.with_inner_mut(f)
    }

    pub fn id(&self) -> Option<KeyId> {
        self.with_inner(|inner| inner.id)
    }
}

impl Key for AesCbcKey {}

impl KeyDeleteOp for AesCbcKey {
    fn delete_key(&mut self, session: &Session) -> Result<(), AzihsmError> {
        let mut inner = self.0.write();

        let key_id = inner.id.ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;

        ddi::delete_key(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            key_id.0,
        )
        .map_err(|_| AZIHSM_DELETE_KEY_FAILED)?;

        // Clear the key ID to indicate it's deleted
        inner.id = None;

        Ok(())
    }
}

impl KeyGenOp for AesCbcKey {
    fn generate_key(&mut self, session: &Session) -> Result<(), AzihsmError> {
        let mut inner = self.0.write();

        // Check if already generated
        if inner.id.is_some() {
            Err(AZIHSM_KEY_ALREADY_EXISTS)?;
        }

        // Get DDI key size and properties
        let ddi_key_size = DdiAesKeySize::try_from(&inner.props)?;
        let ddi_key_props = DdiKeyProperties::try_from(&inner.props)?;

        let resp = ddi::aes_generate_key(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            ddi_key_size,
            None,
            ddi_key_props,
        )
        .map_err(|_| AZIHSM_AES_KEYGEN_FAILED)?;

        inner.id = Some(KeyId(resp.data.key_id));

        Ok(())
    }

    fn generate_key_pair(&mut self, _session: &Session) -> Result<(), AzihsmError> {
        // AES is a symmetric algorithm - it doesn't support key pairs
        Err(AZIHSM_OPERATION_NOT_SUPPORTED)
    }
}

pub struct AesCbcAlgo {
    pub iv: [u8; AES_CBC_BLOCK_IV_LENGTH],
    pub pkcs7_pad: bool,
}

impl AesCbcAlgo {
    /// Create a new AES CBC algorithm instance
    pub fn new(iv: [u8; AES_CBC_BLOCK_IV_LENGTH], pkcs7_pad: bool) -> Self {
        Self { iv, pkcs7_pad }
    }

    /// Calculate the output length for encryption with optional padding
    fn calculate_encrypt_len(&self, input_len: usize) -> usize {
        if self.pkcs7_pad {
            // With PKCS#7 padding, we always add at least 1 byte of padding
            // Round up to next block boundary
            let blocks = (input_len / AES_CBC_BLOCK_IV_LENGTH) + 1;
            blocks * AES_CBC_BLOCK_IV_LENGTH
        } else {
            // No padding - input must already be block-aligned
            input_len
        }
    }

    /// Apply PKCS#7 padding to input data
    fn apply_pkcs7_padding(&self, input: &[u8], output: &mut Vec<u8>) {
        output.extend_from_slice(input);
        let padding_len = AES_CBC_BLOCK_IV_LENGTH - (input.len() % AES_CBC_BLOCK_IV_LENGTH);
        for _ in 0..padding_len {
            output.push(padding_len as u8);
        }
    }

    /// Remove PKCS#7 padding from decrypted data
    fn remove_pkcs7_padding(&self, data: &mut Vec<u8>) -> Result<(), AzihsmError> {
        if data.is_empty() {
            Err(AZIHSM_AES_DECRYPT_FAILED)?;
        }

        let padding_len = *data.last().unwrap() as usize;

        // Validate padding length
        if padding_len == 0 || padding_len > AES_CBC_BLOCK_IV_LENGTH || padding_len > data.len() {
            Err(AZIHSM_AES_DECRYPT_FAILED)?;
        }

        // Validate padding bytes
        let start_idx = data.len() - padding_len;
        for &byte in &data[start_idx..] {
            if byte != padding_len as u8 {
                return Err(AZIHSM_AES_DECRYPT_FAILED);
            }
        }

        // Remove padding
        data.truncate(start_idx);
        Ok(())
    }
}

impl Algo for AesCbcAlgo {}

impl EncryptOp for AesCbcAlgo {
    fn ciphertext_len(&self, pt_len: usize) -> usize {
        self.calculate_encrypt_len(pt_len)
    }

    fn encrypt(
        &mut self,
        session: &Session,
        key: KeyId,
        pt: &[u8],
        ct: &mut [u8],
    ) -> Result<usize, AzihsmError> {
        let mut input_data = Vec::new();

        if self.pkcs7_pad {
            // Apply PKCS#7 padding
            self.apply_pkcs7_padding(pt, &mut input_data);

            // Verify output buffer is large enough
            if ct.len() < input_data.len() {
                Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
            }
        } else {
            // No padding - input must be block-aligned
            if !pt.len().is_multiple_of(AES_CBC_BLOCK_IV_LENGTH) {
                Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
            }

            if pt.len() != ct.len() {
                Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
            }

            input_data.extend_from_slice(pt);
        }

        let resp = ddi::aes_enc_dec(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            key.0,
            DdiAesOp::Encrypt,
            &input_data,
            &self.iv,
        )
        .map_err(|_| AZIHSM_AES_ENCRYPT_FAILED)?;

        let response_len = resp.data.msg.len();
        if response_len > ct.len() {
            Err(AZIHSM_AES_ENCRYPT_FAILED)?;
        }

        ct[..response_len].copy_from_slice(&resp.data.msg.data()[..response_len]);
        self.iv
            .copy_from_slice(&resp.data.iv.data()[..AES_CBC_BLOCK_IV_LENGTH]);

        Ok(response_len)
    }
}

impl DecryptOp for AesCbcAlgo {
    fn plaintext_len(&self, ct_len: usize) -> usize {
        if self.pkcs7_pad {
            // With padding, plaintext will be smaller than ciphertext
            // Return the ciphertext length as upper bound
            ct_len
        } else {
            // Without padding, plaintext length equals ciphertext length
            ct_len
        }
    }

    fn decrypt(
        &mut self,
        session: &Session,
        key: KeyId,
        ct: &[u8],
        pt: &mut [u8],
    ) -> Result<usize, AzihsmError> {
        // Ciphertext must be block-aligned
        if !ct.len().is_multiple_of(AES_CBC_BLOCK_IV_LENGTH) {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        if !self.pkcs7_pad && pt.len() != ct.len() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        let resp = ddi::aes_enc_dec(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            key.0,
            DdiAesOp::Decrypt,
            ct,
            &self.iv,
        )
        .map_err(|_| AZIHSM_AES_DECRYPT_FAILED)?;

        let mut decrypted_data = resp.data.msg.data()[..resp.data.msg.len()].to_vec();

        if self.pkcs7_pad {
            // Remove PKCS#7 padding
            self.remove_pkcs7_padding(&mut decrypted_data)?;
        }

        if decrypted_data.len() > pt.len() {
            return Err(AZIHSM_AES_DECRYPT_FAILED);
        }

        pt[..decrypted_data.len()].copy_from_slice(&decrypted_data);
        self.iv
            .copy_from_slice(&resp.data.iv.data()[..AES_CBC_BLOCK_IV_LENGTH]);

        Ok(decrypted_data.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::test_helpers::create_test_session;

    #[test]
    fn test_aes_cbc_key_gen_128_bit() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create AES key with 128-bit properties using builder
        let key_props = KeyProps::builder()
            .bit_len(128)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);

        // Verify initial state
        assert!(
            aes_key.id().is_none(),
            "Key ID should be None before generation"
        );

        // Generate the key using session
        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES 128-bit key");

        // Verify key was generated successfully
        assert!(
            aes_key.id().is_some(),
            "Key ID should be set after generation"
        );

        // Delete the key.
        session
            .delete_key(&mut aes_key)
            .expect("Failed to delete AES key");

        // Clean up
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_aes_cbc_key_gen_already_exists() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create AES key with 128-bit properties using builder
        let key_props = KeyProps::builder()
            .bit_len(128)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);

        // Generate the key first time - should succeed
        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES key first time");

        // Try to generate again - should fail
        let result = session.generate_key(&mut aes_key);
        assert!(result.is_err(), "Second key generation should fail");
        assert_eq!(result.unwrap_err(), AZIHSM_KEY_ALREADY_EXISTS);

        // Clean up
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_aes_cbc_key_gen_pair_not_supported() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create AES key with 128-bit properties using builder
        let key_props = KeyProps::builder().bit_len(128).build();

        let mut aes_key = AesCbcKey::new(key_props);

        // Try to generate key pair - should fail for AES
        let result = session.generate_key_pair(&mut aes_key);
        assert!(
            result.is_err(),
            "Key pair generation should not be supported for AES"
        );
        assert_eq!(result.unwrap_err(), AZIHSM_OPERATION_NOT_SUPPORTED);

        // Clean up
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_aes_cbc_encrypt_decrypt() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create AES key with 128-bit properties
        let key_props = KeyProps::builder()
            .bit_len(128)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);

        // Generate the key
        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES key");

        let key_id = aes_key
            .id()
            .expect("Key should have an ID after generation");

        // Test data - must be 16 bytes (AES block size) for CBC mode
        let plaintext = b"1234567890123456"; // 16 bytes
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        // Initialize IV (16 bytes for AES)
        let iv = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];

        // Create AES CBC algorithm instance
        let mut aes_cbc = AesCbcAlgo::new(iv, false);

        // Encrypt the plaintext
        aes_cbc
            .encrypt(&session, key_id, plaintext, &mut ciphertext)
            .expect("Failed to encrypt data");

        // Verify that ciphertext is different from plaintext
        assert_ne!(
            &ciphertext[..],
            &plaintext[..],
            "Ciphertext should be different from plaintext"
        );

        // Reset IV for decryption (CBC mode modifies the IV)
        aes_cbc.iv = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];

        // Decrypt the ciphertext
        aes_cbc
            .decrypt(&session, key_id, &ciphertext, &mut decrypted)
            .expect("Failed to decrypt data");

        // Verify that decrypted data matches original plaintext
        assert_eq!(
            &decrypted[..],
            &plaintext[..],
            "Decrypted data should match original plaintext"
        );

        // Clean up
        session
            .delete_key(&mut aes_key)
            .expect("Failed to delete AES key");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_aes_cbc_encrypt_different_lengths() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create and generate AES key
        let key_props = KeyProps::builder()
            .bit_len(256)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);
        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES key");

        let key_id = aes_key.id().unwrap();

        // Test data with different length (should fail)
        let plaintext = b"1234567890123456"; // 16 bytes
        let mut ciphertext = vec![0u8; 8]; // Wrong length - 8 bytes

        let iv = [0u8; 16];
        let mut aes_cbc = AesCbcAlgo::new(iv, false);

        // Encrypt should fail due to length mismatch
        let result = aes_cbc.encrypt(&session, key_id, plaintext, &mut ciphertext);
        assert!(result.is_err(), "Encrypt should fail with length mismatch");
        assert_eq!(result.unwrap_err(), AZIHSM_ERROR_INVALID_ARGUMENT);

        // Clean up
        session
            .delete_key(&mut aes_key)
            .expect("Failed to delete key");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_aes_cbc_decrypt_different_lengths() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create and generate AES key
        let key_props = KeyProps::builder()
            .bit_len(192)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);
        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES key");

        let key_id = aes_key.id().unwrap();

        // Test data with different length (should fail)
        let ciphertext = vec![0u8; 16]; // 16 bytes
        let mut plaintext = vec![0u8; 32]; // Wrong length - 32 bytes

        let iv = [0u8; 16];
        let mut aes_cbc = AesCbcAlgo::new(iv, false);

        // Decrypt should fail due to length mismatch
        let result = aes_cbc.decrypt(&session, key_id, &ciphertext, &mut plaintext);
        assert!(result.is_err(), "Decrypt should fail with length mismatch");
        assert_eq!(result.unwrap_err(), AZIHSM_ERROR_INVALID_ARGUMENT);

        // Clean up
        session
            .delete_key(&mut aes_key)
            .expect("Failed to delete key");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_aes_cbc_multiple_blocks() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create and generate AES key
        let key_props = KeyProps::builder()
            .bit_len(256)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);
        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES key");

        let key_id = aes_key.id().unwrap();

        // Test data with multiple blocks (32 bytes = 2 AES blocks)
        let plaintext = b"12345678901234561234567890123456"; // 32 bytes
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        let iv = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];

        let mut aes_cbc = AesCbcAlgo::new(iv, false);

        // Encrypt multiple blocks
        aes_cbc
            .encrypt(&session, key_id, plaintext, &mut ciphertext)
            .expect("Failed to encrypt multiple blocks");

        // Verify encryption changed the data
        assert_ne!(&ciphertext[..], &plaintext[..]);

        // Reset IV for decryption
        aes_cbc.iv = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];

        // Decrypt multiple blocks
        aes_cbc
            .decrypt(&session, key_id, &ciphertext, &mut decrypted)
            .expect("Failed to decrypt multiple blocks");

        // Verify round-trip success
        assert_eq!(&decrypted[..], &plaintext[..]);

        // Clean up
        session
            .delete_key(&mut aes_key)
            .expect("Failed to delete key");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_aes_cbc_pkcs7_encrypt_decrypt() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create AES key with 128-bit properties
        let key_props = KeyProps::builder()
            .bit_len(128)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);

        // Generate the key
        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES key");

        let key_id = aes_key
            .id()
            .expect("Key should have an ID after generation");

        // Test data - 15 bytes (not block-aligned, will be padded to 16 bytes)
        let plaintext = b"123456789012345"; // 15 bytes
        let expected_ct_len = 16; // Will be padded to 16 bytes
        let mut ciphertext = vec![0u8; expected_ct_len];
        let mut decrypted = vec![0u8; plaintext.len()];

        // Initialize IV
        let iv = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];

        // Create AES CBC algorithm instance with PKCS#7 padding
        let mut aes_cbc = AesCbcAlgo::new(iv, true);

        // Encrypt the plaintext
        aes_cbc
            .encrypt(&session, key_id, plaintext, &mut ciphertext)
            .expect("Failed to encrypt data with PKCS#7 padding");

        // Verify that ciphertext is different from plaintext
        assert_ne!(
            &ciphertext[..plaintext.len()],
            &plaintext[..],
            "Ciphertext should be different from plaintext"
        );

        // Reset IV for decryption (CBC mode modifies the IV)
        aes_cbc.iv = iv;

        // Decrypt the ciphertext
        aes_cbc
            .decrypt(&session, key_id, &ciphertext, &mut decrypted)
            .expect("Failed to decrypt data with PKCS#7 padding");

        // Verify that decrypted data matches original plaintext
        assert_eq!(
            &decrypted[..],
            &plaintext[..],
            "Decrypted data should match original plaintext"
        );

        // Clean up
        session
            .delete_key(&mut aes_key)
            .expect("Failed to delete AES key");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_aes_cbc_pkcs7_different_input_sizes() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create AES key
        let key_props = KeyProps::builder()
            .bit_len(256)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);
        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES key");

        let key_id = aes_key.id().unwrap();
        let iv = [0u8; AES_CBC_BLOCK_IV_LENGTH];

        // Test different input sizes that require different amounts of padding
        let test_cases = vec![
            (b"1".as_slice(), 16),                 // 1 byte -> 16 bytes (15 bytes padding)
            (b"12345".as_slice(), 16),             // 5 bytes -> 16 bytes (11 bytes padding)
            (b"123456789012345".as_slice(), 16),   // 15 bytes -> 16 bytes (1 byte padding)
            (b"1234567890123456".as_slice(), 32),  // 16 bytes -> 32 bytes (16 bytes padding)
            (b"12345678901234567".as_slice(), 32), // 17 bytes -> 32 bytes (15 bytes padding)
        ];

        for (i, (plaintext, expected_ct_len)) in test_cases.into_iter().enumerate() {
            let mut aes_cbc = AesCbcAlgo::new(iv, true);

            // Calculate expected ciphertext length
            let calculated_len = aes_cbc.ciphertext_len(plaintext.len());
            assert_eq!(
                calculated_len, expected_ct_len,
                "Test case {}: Expected ciphertext length mismatch",
                i
            );

            let mut ciphertext = vec![0u8; calculated_len];
            let mut decrypted = vec![0u8; plaintext.len()];

            // Encrypt
            aes_cbc
                .encrypt(&session, key_id, plaintext, &mut ciphertext)
                .unwrap_or_else(|_| panic!("Test case {}: Failed to encrypt", i));

            // Reset IV and decrypt
            aes_cbc.iv = iv;
            aes_cbc
                .decrypt(&session, key_id, &ciphertext, &mut decrypted)
                .unwrap_or_else(|_| panic!("Test case {}: Failed to decrypt", i));

            // Verify round-trip
            assert_eq!(
                &decrypted[..],
                plaintext,
                "Test case {}: Round-trip failed",
                i
            );
        }

        // Clean up
        session
            .delete_key(&mut aes_key)
            .expect("Failed to delete key");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_aes_cbc_pkcs7_empty_input() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create AES key
        let key_props = KeyProps::builder()
            .bit_len(128)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);
        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES key");

        let key_id = aes_key.id().unwrap();

        // Test empty input - should be padded to 16 bytes
        let plaintext = b"";
        let expected_ct_len = 16; // Empty input gets full block of padding
        let mut ciphertext = vec![0u8; expected_ct_len];
        let mut decrypted = vec![0u8; 0];

        let iv = [0u8; AES_CBC_BLOCK_IV_LENGTH];
        let mut aes_cbc = AesCbcAlgo::new(iv, true);

        // Encrypt empty input
        aes_cbc
            .encrypt(&session, key_id, plaintext, &mut ciphertext)
            .expect("Failed to encrypt empty input with PKCS#7 padding");

        // Reset IV and decrypt
        aes_cbc.iv = iv;
        aes_cbc
            .decrypt(&session, key_id, &ciphertext, &mut decrypted)
            .expect("Failed to decrypt empty input with PKCS#7 padding");

        // Verify that decrypted data is empty
        assert_eq!(decrypted.len(), 0, "Decrypted empty input should be empty");

        // Clean up
        session
            .delete_key(&mut aes_key)
            .expect("Failed to delete key");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_aes_cbc_pkcs7_large_input() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create AES key
        let key_props = KeyProps::builder()
            .bit_len(192)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);
        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES key");

        let key_id = aes_key.id().unwrap();

        // Test large input (1000 bytes)
        let plaintext = vec![0xAB; 1000];
        let expected_blocks = (1000 / 16) + 1; // 62 full blocks + 1 padded block = 63 blocks
        let expected_ct_len = expected_blocks * 16; // 63 * 16 = 1008 bytes

        let iv = [0xCD; AES_CBC_BLOCK_IV_LENGTH];
        let mut aes_cbc = AesCbcAlgo::new(iv, true);

        let calculated_len = aes_cbc.ciphertext_len(plaintext.len());
        assert_eq!(calculated_len, expected_ct_len);

        let mut ciphertext = vec![0u8; calculated_len];
        let mut decrypted = vec![0u8; plaintext.len()];

        // Encrypt large input
        aes_cbc
            .encrypt(&session, key_id, &plaintext, &mut ciphertext)
            .expect("Failed to encrypt large input with PKCS#7 padding");

        // Reset IV and decrypt
        aes_cbc.iv = iv;
        aes_cbc
            .decrypt(&session, key_id, &ciphertext, &mut decrypted)
            .expect("Failed to decrypt large input with PKCS#7 padding");

        // Verify round-trip
        assert_eq!(
            &decrypted[..],
            &plaintext[..],
            "Large input round-trip failed"
        );

        // Clean up
        session
            .delete_key(&mut aes_key)
            .expect("Failed to delete key");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_pkcs7_padding_validation() {
        // Test the internal padding methods directly
        let iv = [0u8; AES_CBC_BLOCK_IV_LENGTH];
        let aes_cbc = AesCbcAlgo::new(iv, true);

        // Test apply_pkcs7_padding
        let test_cases = vec![
            (
                vec![0x01],
                vec![
                    0x01, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
                    0x0F, 0x0F, 0x0F,
                ],
            ), // 1 byte -> 15 bytes padding
            (
                vec![0x01, 0x02, 0x03, 0x04, 0x05],
                vec![
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
                    0x0B, 0x0B, 0x0B,
                ],
            ), // 5 bytes -> 11 bytes padding
            (
                vec![0x01; 15],
                vec![
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01,
                ],
            ), // 15 bytes -> 1 byte padding
            (
                vec![0x01; 16],
                vec![0x01; 16].into_iter().chain(vec![0x10; 16]).collect(),
            ), // 16 bytes -> 16 bytes padding (full block)
        ];

        for (i, (input, expected)) in test_cases.into_iter().enumerate() {
            let mut output = Vec::new();
            aes_cbc.apply_pkcs7_padding(&input, &mut output);
            assert_eq!(
                output, expected,
                "Test case {}: Padding application failed",
                i
            );

            // Test remove_pkcs7_padding
            let mut padded_data = expected.clone();
            aes_cbc
                .remove_pkcs7_padding(&mut padded_data)
                .unwrap_or_else(|_| panic!("Test case {}: Failed to remove padding", i));
            assert_eq!(
                padded_data, input,
                "Test case {}: Padding removal failed",
                i
            );
        }
    }

    #[test]
    fn test_pkcs7_padding_validation_invalid_padding() {
        let iv = [0u8; AES_CBC_BLOCK_IV_LENGTH];
        let aes_cbc = AesCbcAlgo::new(iv, true);

        // Test various invalid padding scenarios
        let invalid_cases = vec![
            vec![],                       // Empty data
            vec![0x00],                   // Zero padding length
            vec![0x11],                   // Padding length > block size
            vec![0x01, 0x02],             // Wrong padding byte (should be 0x01, 0x01)
            vec![0x01, 0x01, 0x01, 0x02], // Mixed padding bytes
            vec![0x05, 0x05, 0x05, 0x05], // Padding length > actual length
        ];

        for (i, mut invalid_data) in invalid_cases.into_iter().enumerate() {
            let result = aes_cbc.remove_pkcs7_padding(&mut invalid_data);
            assert!(
                result.is_err(),
                "Test case {}: Should reject invalid padding",
                i
            );
            assert_eq!(
                result.unwrap_err(),
                AZIHSM_AES_DECRYPT_FAILED,
                "Test case {}: Wrong error code",
                i
            );
        }
    }

    #[test]
    fn test_aes_cbc_unpadded_vs_padded_comparison() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create AES key
        let key_props = KeyProps::builder()
            .bit_len(256)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);
        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES key");

        let key_id = aes_key.id().unwrap();

        // Test data that is exactly one block (16 bytes)
        let plaintext = b"1234567890123456"; // Exactly 16 bytes
        let iv = [0x12; AES_CBC_BLOCK_IV_LENGTH];

        // Test unpadded mode
        let mut aes_cbc_unpadded = AesCbcAlgo::new(iv, false);
        let mut ct_unpadded = vec![0u8; 16]; // Same size as input

        aes_cbc_unpadded
            .encrypt(&session, key_id, plaintext, &mut ct_unpadded)
            .expect("Failed to encrypt in unpadded mode");

        // Test padded mode
        let mut aes_cbc_padded = AesCbcAlgo::new(iv, true);
        let mut ct_padded = vec![0u8; 32]; // Will be 32 bytes due to padding

        aes_cbc_padded
            .encrypt(&session, key_id, plaintext, &mut ct_padded)
            .expect("Failed to encrypt in padded mode");

        // Verify that padded mode produces longer ciphertext
        assert_ne!(
            ct_unpadded.len(),
            ct_padded.len(),
            "Padded and unpadded should produce different lengths"
        );
        assert_eq!(ct_padded.len(), 32, "Padded should be 32 bytes");
        assert_eq!(ct_unpadded.len(), 16, "Unpadded should be 16 bytes");

        // Verify both decrypt correctly
        let mut pt_unpadded = vec![0u8; 16];
        aes_cbc_unpadded.iv = iv;
        aes_cbc_unpadded
            .decrypt(&session, key_id, &ct_unpadded, &mut pt_unpadded)
            .expect("Failed to decrypt unpadded");

        let mut pt_padded = vec![0u8; 16];
        aes_cbc_padded.iv = iv;
        aes_cbc_padded
            .decrypt(&session, key_id, &ct_padded, &mut pt_padded)
            .expect("Failed to decrypt padded");

        assert_eq!(&pt_unpadded[..], &plaintext[..]);
        assert_eq!(&pt_padded[..], &plaintext[..]);

        // Clean up
        session
            .delete_key(&mut aes_key)
            .expect("Failed to delete key");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_aes_cbc_pkcs7_insufficient_output_buffer() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create AES key
        let key_props = KeyProps::builder()
            .bit_len(128)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);
        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES key");

        let key_id = aes_key.id().unwrap();

        // Test data that will be padded from 15 to 16 bytes
        let plaintext = b"123456789012345"; // 15 bytes
        let mut small_buffer = vec![0u8; 10]; // Too small for padded output

        let iv = [0u8; AES_CBC_BLOCK_IV_LENGTH];
        let mut aes_cbc = AesCbcAlgo::new(iv, true);

        // Should fail due to insufficient output buffer
        let result = aes_cbc.encrypt(&session, key_id, plaintext, &mut small_buffer);
        assert!(result.is_err(), "Should fail with insufficient buffer");
        assert_eq!(result.unwrap_err(), AZIHSM_ERROR_INVALID_ARGUMENT);

        // Clean up
        session
            .delete_key(&mut aes_key)
            .expect("Failed to delete key");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_aes_cbc_unpadded_block_alignment_requirement() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create AES key
        let key_props = KeyProps::builder()
            .bit_len(128)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);
        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES key");

        let key_id = aes_key.id().unwrap();

        // Test data that is NOT block-aligned
        let plaintext = b"12345"; // 5 bytes - not a multiple of 16
        let mut ciphertext = vec![0u8; 16];

        let iv = [0u8; AES_CBC_BLOCK_IV_LENGTH];
        let mut aes_cbc = AesCbcAlgo::new(iv, false); // No padding

        // Should fail because input is not block-aligned
        let result = aes_cbc.encrypt(&session, key_id, plaintext, &mut ciphertext);
        assert!(
            result.is_err(),
            "Should fail with non-block-aligned input in unpadded mode"
        );
        assert_eq!(result.unwrap_err(), AZIHSM_ERROR_INVALID_ARGUMENT);

        // Clean up
        session
            .delete_key(&mut aes_key)
            .expect("Failed to delete key");
        session.close().expect("Failed to close session");
    }
}
