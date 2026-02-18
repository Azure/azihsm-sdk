// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Adapter implementing crypto_env::CryptEnv for the SIM, built on the shared crypto crate.

use azihsm_ddi_types::AES_BLOCK_SIZE;
use azihsm_ddi_types::AES_CBC_256_KEY_SIZE;
use azihsm_ddi_types::AES_CBC_IV_SIZE;
use azihsm_ddi_types::HMAC384_KEY_SIZE;
use azihsm_ddi_types::HMAC384_TAG_SIZE;

use crate::crypto::aes::AesAlgo;
use crate::crypto::aes::AesKey;
use crate::crypto::aes::AesOp;
use crate::crypto::rand::rand_bytes;
use crate::crypto::sha::hmac_sha_384;
use crate::crypto_env::CryptEnv;
use crate::errors::ManticoreError;

/// Size of BK3 in bytes
pub const BK3_SIZE_BYTES: usize = 48;

/// HMAC-256 tag/key size in bytes (SHA-256 output size)
pub const HMAC256_TAG_SIZE: usize = 32;

/// Size of BK (Boot Key) combining AES-CBC-256 and HMAC-384 keys
pub const BK_AES_CBC_256_HMAC384_SIZE_BYTES: usize = AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE;

/// Size of MK (Masking Key) combining AES-CBC-256 and HMAC-384 keys
pub const MK_AES_CBC_256_HMAC384_SIZE_BYTES: usize = AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE;

/// Size of MK (Masking Key) combining AES-CBC-256 and HMAC-256 keys
pub const MK_AES_CBC_256_HMAC256_SIZE_BYTES: usize = AES_CBC_256_KEY_SIZE + HMAC256_TAG_SIZE;

/// Sealed BK3 size limit - from FW
pub const SEALED_BK3_SIZE: usize = 512;

/// BKS1 and BKS2 size - from FW
pub const BK_SEED_SIZE_BYTES: usize = 32;

/// Size of session seed
pub const SESSION_SEED_SIZE_BYTES: usize = 48;

/// Simulated cryptographic environment for testing and simulation purposes.
pub struct SimCryptEnv;

impl CryptEnv for SimCryptEnv {
    fn hmac384_tag(
        &self,
        key: &[u8],
        data: &[u8],
    ) -> Result<[u8; HMAC384_TAG_SIZE], ManticoreError> {
        hmac_sha_384(key, data)
    }

    fn aescbc256_enc_data_len(&self, plaintext_len: usize) -> usize {
        // AES-CBC with zero-byte padding rounds up to next 16-byte boundary
        plaintext_len.div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE
    }

    fn aescbc256_encrypt(
        &self,
        key: &[u8],
        plaintext: &[u8],
        iv_out: &mut [u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, ManticoreError> {
        let aes_key = AesKey::from_bytes(key)?;

        let mut iv = [0u8; AES_CBC_IV_SIZE];
        rand_bytes(&mut iv).map_err(|_| ManticoreError::RngError)?;

        // Pad plaintext to the next 16-byte boundary with zeros
        let padded_len = self.aescbc256_enc_data_len(plaintext.len());
        let mut padded_plaintext = vec![0u8; padded_len];
        padded_plaintext[..plaintext.len()].copy_from_slice(plaintext);

        let result = aes_key
            .encrypt(&padded_plaintext, AesAlgo::Cbc, Some(&iv))
            .map_err(|_| ManticoreError::AesEncryptFailed)?;

        if ciphertext.len() < result.cipher_text.len() {
            return Err(ManticoreError::OutputBufferTooSmall);
        }

        ciphertext[..result.cipher_text.len()].copy_from_slice(&result.cipher_text);
        iv_out.copy_from_slice(&iv);

        Ok(result.cipher_text.len())
    }

    fn aescbc256_decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, ManticoreError> {
        let aes_key = AesKey::from_bytes(key)?;

        let result = aes_key
            .decrypt(ciphertext, AesAlgo::Cbc, Some(iv))
            .map_err(|_| ManticoreError::AesDecryptFailed)?;

        // The decrypted data includes zero-byte padding
        let decrypted_data = result.plain_text;

        // The caller knows the expected length and provides a buffer of that size
        // If decrypted data is shorter or longer than expected, something is wrong
        if decrypted_data.len() != self.aescbc256_enc_data_len(plaintext.len()) {
            tracing::debug!(
                decrypted_len = decrypted_data.len(),
                expected_len = self.aescbc256_enc_data_len(plaintext.len()),
                "Decrypted data length does not match expected length"
            );
            return Err(ManticoreError::AesDecryptFailed);
        }

        // Sanity check: verify that truncated bytes (padding) are all zeros
        if decrypted_data.len() > plaintext.len() {
            let padding_bytes = &decrypted_data[plaintext.len()..];
            if !padding_bytes.iter().all(|&byte| byte == 0) {
                tracing::debug!("Decrypted data padding is not all zeros");
                return Err(ManticoreError::AesDecryptFailed);
            }
        }

        // Return only the expected length (truncating any padding)
        plaintext.copy_from_slice(&decrypted_data[..plaintext.len()]);
        Ok(plaintext.len())
    }

    fn kbkdf_sha384(
        &self,
        key: &[u8],
        label: Option<&[u8]>,
        context: Option<&[u8]>,
        out_len: usize,
        output: &mut [u8],
    ) -> Result<(), ManticoreError> {
        // api\support\lib does not have kbkdf support
        // We use api\ddi\sim\src\crypto implementation
        use crate::crypto::secret::SecretKey;
        use crate::crypto::secret::SecretOp;
        use crate::crypto::sha::HashAlgorithm;

        let secret_key = SecretKey::from_bytes(key).map_err(|_| ManticoreError::KbkdfError)?;

        let output_vec = secret_key
            .kbkdf_counter_hmac_derive(
                HashAlgorithm::Sha384,
                label,
                context,
                true, /*use_seperator, default value*/
                true, /*use_l, default value*/
                out_len,
            )
            .map_err(|_| ManticoreError::KbkdfError)?;
        if output.len() < output_vec.len() {
            Err(ManticoreError::InvalidArgument)?
        }
        output[..output_vec.len()].copy_from_slice(&output_vec);

        Ok(())
    }

    fn generate_random(&self, output: &mut [u8]) -> Result<(), ManticoreError> {
        rand_bytes(output).map_err(|_| ManticoreError::RngError)
    }
}
