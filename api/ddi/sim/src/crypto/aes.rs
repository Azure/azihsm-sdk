// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for AES Cryptographic Keys.

#[cfg(all(feature = "use-openssl", feature = "use-symcrypt"))]
compile_error!("OpenSSL and non-OpenSSL cannot be enabled at the same time.");

#[cfg(feature = "fuzzing")]
use arbitrary::Arbitrary;
use mcr_ddi_types::DdiAesKeySize;
use mcr_ddi_types::DdiAesOp;
#[cfg(feature = "use-openssl")]
use openssl;
#[cfg(feature = "use-openssl")]
use openssl::cipher::Cipher;
#[cfg(feature = "use-openssl")]
use openssl::cipher::CipherRef;
#[cfg(feature = "use-openssl")]
use openssl::cipher_ctx::CipherCtx;
#[cfg(feature = "use-openssl")]
use openssl::rand::rand_bytes;
#[cfg(feature = "use-openssl")]
use openssl::symm::Crypter;
#[cfg(feature = "use-openssl")]
use openssl::symm::Mode;
#[cfg(feature = "use-symcrypt")]
use symcrypt::cipher::AesExpandedKey;
#[cfg(feature = "use-symcrypt")]
use symcrypt::cipher::BlockCipherType;
#[cfg(feature = "use-symcrypt")]
use symcrypt::gcm::GcmExpandedKey;
#[cfg(feature = "use-symcrypt")]
use symcrypt::symcrypt_random;

#[cfg(feature = "use-symcrypt")]
use crate::crypto::cng::*;
use crate::errors::ManticoreError;
use crate::mask::KeySerialization;
use crate::table::entry::Kind;

/// The size of an AES GCM tag.
const AES_GCM_TAG_SIZE: usize = 16;
#[cfg(feature = "use-openssl")]
/// The size of the AES CBC IV.
const AES_CBC_IV_SIZE: usize = 16;

// 5649 section 3
const PADDED_UPPER_AIV: u64 = 0xA65959A600000000;
// RFC 3394 section 2.2.3
const UNPADDED_AIV: u64 = 0xA6A6A6A6A6A6A6A6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AivPadding {
    None,
    Length(usize),
}

/// Supported AES algo.
#[derive(Debug, Clone, PartialEq)]
pub enum AesAlgo {
    /// CBC mode.
    Cbc,
}

/// Supported AES mode.
#[cfg_attr(feature = "fuzzing", derive(Arbitrary))]
#[derive(Debug, Clone, PartialEq)]
pub enum AesMode {
    /// Encrypt
    Encrypt,

    /// Decrypt
    Decrypt,
}

impl TryFrom<DdiAesOp> for AesMode {
    type Error = ManticoreError;

    fn try_from(value: DdiAesOp) -> Result<Self, Self::Error> {
        match value {
            DdiAesOp::Encrypt => Ok(AesMode::Encrypt),
            DdiAesOp::Decrypt => Ok(AesMode::Decrypt),
            _ => Err(ManticoreError::InvalidArgument),
        }
    }
}

/// Supported AES Key size.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AesKeySize {
    /// 128-bit key.
    Aes128,

    /// 192-bit key.
    Aes192,

    /// 256-bit key.
    Aes256,

    /// Bulk XTS 256-bit key.
    AesXtsBulk256,

    /// Bulk GCM 256-bit key.
    AesGcmBulk256,

    /// Bulk GCM 256-bit Unapproved key.
    AesGcmBulk256Unapproved,
}

impl TryFrom<DdiAesKeySize> for AesKeySize {
    type Error = ManticoreError;

    fn try_from(value: DdiAesKeySize) -> Result<Self, Self::Error> {
        match value {
            DdiAesKeySize::Aes128 => Ok(AesKeySize::Aes128),
            DdiAesKeySize::Aes192 => Ok(AesKeySize::Aes192),
            DdiAesKeySize::Aes256 => Ok(AesKeySize::Aes256),
            DdiAesKeySize::AesXtsBulk256 => Ok(AesKeySize::AesXtsBulk256),
            DdiAesKeySize::AesGcmBulk256 => Ok(AesKeySize::AesGcmBulk256),
            DdiAesKeySize::AesGcmBulk256Unapproved => Ok(AesKeySize::AesGcmBulk256Unapproved),
            _ => Err(ManticoreError::InvalidArgument),
        }
    }
}

impl AesKeySize {
    /// Check if the key size is a bulk key type.
    ///
    /// Returns `true` if the key size is one of the bulk key types, otherwise returns `false`.
    pub fn is_bulk_key(&self) -> bool {
        matches!(
            self,
            AesKeySize::AesXtsBulk256
                | AesKeySize::AesGcmBulk256
                | AesKeySize::AesGcmBulk256Unapproved
        )
    }
}

/// Result of the `encrypt/ decrypt`.
#[derive(Debug, PartialEq)]
pub struct AesEncryptDecryptResult {
    /// Output data
    pub data: Vec<u8>,

    /// Output IV
    pub iv: Vec<u8>,
}

/// Result of the `encrypt`.
pub struct AesEncryptResult {
    /// Cipher text.
    pub cipher_text: Vec<u8>,

    /// Output IV (only available for CBC).
    pub iv: Option<Vec<u8>>,
}

/// Result of the `decrypt`.
pub struct AesDecryptResult {
    /// Plain text.
    pub plain_text: Vec<u8>,

    /// Output IV (only available for CBC).
    pub iv: Option<Vec<u8>>,
}

/// Result of the AES GCM encrypt/decrypt
/// on the fast path
#[derive(Default, Clone)]
pub struct FPAesGcmEncryptDecryptResult {
    /// Output Tag.
    pub tag: Option<[u8; 16usize]>,

    /// Length of the encrypted or decrypted buffer
    pub final_size: usize,
}

/// Result of the AES XTS encrypt/decrypt
/// on the fast path
#[derive(Default, Clone)]
pub struct FPAesXtsEncryptDecryptResult {
    /// Size of the encrypted or decrypted buffer
    pub final_size: usize,
}

/// Trait for AES operations.
pub trait AesOp {
    /// Create a `AesKey` instance from a raw key.
    fn from_bytes(bytes: &[u8]) -> Result<Self, ManticoreError>
    where
        Self: Sized;

    /// Create a `AesKey` instance from a raw bulk key.
    fn from_bulk_bytes(bytes: &[u8], size: AesKeySize) -> Result<Self, ManticoreError>
    where
        Self: Sized;

    /// AES encryption.
    fn encrypt(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
    ) -> Result<AesEncryptResult, ManticoreError>;

    /// AES decryption.
    fn decrypt(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
    ) -> Result<AesDecryptResult, ManticoreError>;

    /// AES GCM encryption on the fast path
    fn aes_gcm_encrypt_mb(
        &self,
        plaintext_buffers: &[Vec<u8>],
        iv: Option<&[u8]>,
        aad: Option<&[u8]>,
        encrypted_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesGcmEncryptDecryptResult, ManticoreError>;

    /// AES GCM decryption on the fast path
    fn aes_gcm_decrypt_mb(
        &self,
        encrypted_buffers: &[Vec<u8>],
        iv: Option<&[u8]>,
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
        decrypted_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesGcmEncryptDecryptResult, ManticoreError>;

    /// AES XTS encryption on the fast path
    fn aes_xts_encrypt_mb(
        &self,
        key2: AesKey,
        dul: usize,
        tweak: [u8; 16usize],
        plaintext_buffers: &[Vec<u8>],
        encrypted_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesXtsEncryptDecryptResult, ManticoreError>;

    /// AES XTS decryption on the fast path
    fn aes_xts_decrypt_mb(
        &self,
        key2: AesKey,
        dul: usize,
        tweak: [u8; 16usize],
        encrypted_buffers: &[Vec<u8>],
        cleartext_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesXtsEncryptDecryptResult, ManticoreError>;

    #[allow(unused)]
    /// AES wrap with padding.
    fn wrap_pad(&self, data: &[u8]) -> Result<AesEncryptResult, ManticoreError>;

    /// AES unwrap with padding.
    fn unwrap_pad(&self, data: &[u8]) -> Result<AesDecryptResult, ManticoreError>;

    /// Get key size.
    fn size(&self) -> AesKeySize;
}

/// AES Key.
#[derive(Debug, Clone)]
pub struct AesKey {
    key: Vec<u8>,
    size: AesKeySize,
}

impl KeySerialization<AesKey> for AesKey {
    fn serialize(&self) -> Result<Vec<u8>, ManticoreError> {
        Ok(self.key.clone())
    }

    fn deserialize(raw: &[u8], expected_type: Kind) -> Result<AesKey, ManticoreError> {
        match expected_type {
            Kind::Aes128 | Kind::Aes192 | Kind::Aes256 => AesKey::from_bytes(raw),
            Kind::AesXtsBulk256 => AesKey::from_bulk_bytes(raw, AesKeySize::AesXtsBulk256),
            Kind::AesGcmBulk256 => AesKey::from_bulk_bytes(raw, AesKeySize::AesGcmBulk256),
            Kind::AesGcmBulk256Unapproved => {
                AesKey::from_bulk_bytes(raw, AesKeySize::AesGcmBulk256Unapproved)
            }
            _ => {
                tracing::error!(error=?ManticoreError::DerAndKeyTypeMismatch, ?expected_type, "Expected type should be AES when deserializing masked key for AesKey");
                Err(ManticoreError::DerAndKeyTypeMismatch)
            }
        }
    }
}

#[cfg(feature = "use-openssl")]
/// Generate an AES key.
pub fn generate_aes(key_size: AesKeySize) -> Result<AesKey, ManticoreError> {
    let buf_len = match key_size {
        AesKeySize::Aes128 => 16,
        AesKeySize::Aes192 => 24,
        AesKeySize::Aes256 => 32,
        AesKeySize::AesXtsBulk256 => 32,
        AesKeySize::AesGcmBulk256 => 32,
        AesKeySize::AesGcmBulk256Unapproved => 32,
    };

    let mut buf = [0u8; 32];
    let buf_slice = &mut buf[..buf_len];
    rand_bytes(buf_slice).map_err(|openssl_error_stack| {
        tracing::error!(?openssl_error_stack);
        ManticoreError::AesGenerateError
    })?;

    Ok(AesKey {
        key: buf_slice.to_vec(),
        size: key_size,
    })
}

#[cfg(feature = "use-symcrypt")]
/// Generate an AES key.
pub fn generate_aes(key_size: AesKeySize) -> Result<AesKey, ManticoreError> {
    let buf_len = match key_size {
        AesKeySize::Aes128 => 16,
        AesKeySize::Aes192 => 24,
        AesKeySize::Aes256 => 32,
        AesKeySize::AesXtsBulk256 => 32,
        AesKeySize::AesGcmBulk256 => 32,
        AesKeySize::AesGcmBulk256Unapproved => 32,
    };
    let mut buf = [0u8; 32];
    let buf_slice = &mut buf[..buf_len];
    symcrypt_random(buf_slice);
    Ok(AesKey {
        key: buf_slice.to_vec(),
        size: key_size,
    })
}

#[cfg(feature = "use-openssl")]
fn get_cipher(size: &AesKeySize, mode: &AesAlgo) -> Result<&'static CipherRef, ManticoreError> {
    let cipher = match (size, mode) {
        (AesKeySize::Aes128, AesAlgo::Cbc) => Cipher::aes_128_cbc(),
        (AesKeySize::Aes192, AesAlgo::Cbc) => Cipher::aes_192_cbc(),
        (AesKeySize::Aes256, AesAlgo::Cbc) => Cipher::aes_256_cbc(),
        _ => Err(ManticoreError::InvalidArgument)?,
    };

    Ok(cipher)
}

impl AesKey {
    /// As specified by RFC 3394 section 2.2.1
    ///
    /// Optimized to use the output as the intermediate storage rather than having an additional allocation.
    fn base_key_wrap(&self, input: &[u8], aiv: u64) -> Result<AesEncryptResult, ManticoreError> {
        if input.len() % 8 != 0 {
            Err(ManticoreError::AesEncryptError)?;
        }

        let mut output = vec![0u8; input.len() + 8];

        // initialize
        let n = input.len() / 8;
        let mut a = aiv;
        output[8..(n + 1) * 8].copy_from_slice(&input[..n * 8]);

        // intermediate calculation
        for j in 0..6 {
            for i in 0..n {
                let b = u64::from_le_bytes(
                    output[(i + 1) * 8..(i + 2) * 8]
                        .try_into()
                        .map_err(|_| ManticoreError::AesEncryptError)?,
                );
                let (msb, lsb) = self.aes_ecb(true, a, b)?;
                output[(i + 1) * 8..(i + 2) * 8].copy_from_slice(&lsb.to_le_bytes());
                a = msb ^ (((n * j) + (i + 1)) as u64).swap_bytes();
            }
        }

        // output
        output[0..8].copy_from_slice(&a.to_le_bytes());

        Ok(AesEncryptResult {
            cipher_text: output,
            iv: None, // No IV for key wrap
        })
    }

    fn base_key_unwrap(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<AivPadding, ManticoreError> {
        if input.len() % 8 != 0 {
            Err(ManticoreError::AesDecryptError)? // Unaligned input buffer length
        }

        if input.len() != output.len() + 8 {
            // Output buffer must be 8 bytes shorter than input buffer
            Err(ManticoreError::AesDecryptError)?
        }

        // initialize
        let n = input.len() / 8 - 1;
        let mut a = u64::from_le_bytes(input[0..8].try_into().unwrap());
        output[0..n * 8].copy_from_slice(&input[8..(n + 1) * 8]);

        // intermediate calculation
        for j in (0..6).rev() {
            for i in (0..n).rev() {
                let b = u64::from_le_bytes(output[i * 8..(i + 1) * 8].try_into().unwrap());
                let (msb, lsb) =
                    self.aes_ecb(false, a ^ (((n * j) + (i + 1)) as u64).swap_bytes(), b)?;
                a = msb;
                output[i * 8..(i + 1) * 8].copy_from_slice(&lsb.to_le_bytes());
            }
        }
        AesKey::check_aiv(output, a)
    }

    fn aes_ecb(&self, encrypt: bool, a: u64, b: u64) -> Result<(u64, u64), ManticoreError> {
        //Input block will be 16 bytes.
        let block = [a.to_le_bytes(), b.to_le_bytes()].concat();
        let output_block = if encrypt {
            let encrypted_block = self.encrypt(&block, AesAlgo::Cbc, None)?;
            encrypted_block.cipher_text
        } else {
            let decrypted_block = self.decrypt(&block, AesAlgo::Cbc, None)?;
            decrypted_block.plain_text
        };
        // let cipher_text = result.cipher_text;
        let x = u64::from_le_bytes(
            output_block[0..8]
                .try_into()
                .map_err(|_| ManticoreError::AesEncryptError)?,
        );
        let y = u64::from_le_bytes(
            output_block[8..16]
                .try_into()
                .map_err(|_| ManticoreError::AesEncryptError)?,
        );
        Ok((x, y))
    }

    fn check_aiv(output: &[u8], aiv: u64) -> Result<AivPadding, ManticoreError> {
        if output.len() % 8 != 0 {
            Err(ManticoreError::InvalidArgument)? //Unaligned output length
        }
        // check AIV
        if aiv == UNPADDED_AIV {
            return Ok(AivPadding::None);
        }
        if aiv & 0xffffffffu64 != PADDED_UPPER_AIV >> 32 {
            Err(ManticoreError::AesDecryptError)? //Invalid AIV padding
        }
        // check data size
        let n = output.len() / 8;
        let mli = ((aiv >> 32) as u32).swap_bytes() as usize;
        if mli <= 8 * (n - 1) || mli > 8 * n {
            Err(ManticoreError::AesDecryptError)? //Invalid MLI
        }

        // check zero padding
        // safely check rightmost bytes are 0 to avoid potential padding oracle attacks
        let mut acc = 0;
        for x in &output[mli..] {
            acc |= *x;
        }
        if acc == 0 {
            Ok(AivPadding::Length(mli))
        } else {
            Err(ManticoreError::AesDecryptError)?
        }
    }
}

impl AesOp for AesKey {
    /// Create a `AesKey` instance from a raw key.
    ///
    /// # Arguments
    /// * `bytes` - The raw key.
    ///
    /// # Returns
    /// * `AesKey` - The created instance.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidArgument` - If the raw key has invalid size.
    fn from_bytes(bytes: &[u8]) -> Result<Self, ManticoreError> {
        let size = match bytes.len() {
            16 => AesKeySize::Aes128,
            24 => AesKeySize::Aes192,
            32 => AesKeySize::Aes256,
            _ => Err(ManticoreError::AesInvalidKeyLength)?,
        };

        Ok(Self {
            key: bytes.to_vec(),
            size,
        })
    }

    /// Create a `AesKey` instance from a raw bulk key.
    ///
    /// # Arguments
    /// * `bytes` - The raw bulk key.
    /// * `size` - The type of bulk key.
    ///
    /// # Returns
    /// * `AesKey` - The created instance.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidArgument` - If the raw key has invalid size.
    fn from_bulk_bytes(bytes: &[u8], size: AesKeySize) -> Result<Self, ManticoreError> {
        if bytes.len() != 32 {
            Err(ManticoreError::AesInvalidKeyLength)?
        }

        Ok(Self {
            key: bytes.to_vec(),
            size,
        })
    }

    /// Get key size.
    fn size(&self) -> AesKeySize {
        self.size
    }

    /// AES encryption on fast path
    ///
    /// # Arguments
    /// * `plaintext_buffers` - The data to be encrypted.
    /// * `iv` - The IV value.
    /// * `aad` - Additional authenticated data (only available for GCM).
    ///
    /// # Returns
    /// * `FPAesGcmEncryptDecryptResult` - The encryption result.
    /// * `encrypted_buffers` - Encrypted data
    ///
    /// # Errors
    /// * `ManticoreError::AesEncryptError` - If the encryption fails.
    #[cfg(feature = "use-openssl")]
    fn aes_gcm_encrypt_mb(
        &self,
        plaintext_buffers: &[Vec<u8>],
        iv: Option<&[u8]>,
        aad: Option<&[u8]>,
        encrypted_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesGcmEncryptDecryptResult, ManticoreError> {
        tracing::debug!("AES GCM Encrypt MB: Beginning");
        let mut encrypted_size = 0;
        let cipher = openssl::symm::Cipher::aes_256_gcm();
        let mut crypter =
            Crypter::new(cipher, Mode::Encrypt, &self.key, iv).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::AesEncryptError
            })?;

        // If aad is provided as input, use it
        if let Some(actual_aad) = aad {
            tracing::debug!("AES GCM Encrypt MB: AAD provided. Updating");
            crypter
                .aad_update(actual_aad)
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    ManticoreError::AesEncryptError
                })?;
        }

        for (plaintext, encrypted_buffer) in
            plaintext_buffers.iter().zip(encrypted_buffers.iter_mut())
        {
            //encrypted_buffer.resize(plaintext.len(), 0); // Ensure buffer is correctly sized
            let count =
                crypter
                    .update(plaintext, encrypted_buffer)
                    .map_err(|openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        ManticoreError::AesEncryptError
                    })?;
            encrypted_buffer.truncate(count); // Truncate in case the output is shorter (unlikely for GCM)
            encrypted_size += encrypted_buffer.len();
        }

        // Finalize encryption (may not be needed for each buffer, but to capture any final state)
        let mut final_block = vec![0; cipher.block_size()];
        let _final_count = crypter
            .finalize(&mut final_block)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::AesEncryptError
            })?;

        let mut tag = [0u8; AES_GCM_TAG_SIZE];
        crypter.get_tag(&mut tag).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::AesEncryptError
        })?;

        tracing::debug!(
            "AES GCM Encrypt MB: Success. Encrypted size: {}",
            encrypted_size,
        );
        Ok(FPAesGcmEncryptDecryptResult {
            final_size: encrypted_size,
            tag: Some(tag),
        })
    }

    #[cfg(feature = "use-symcrypt")]
    fn aes_gcm_encrypt_mb(
        &self,
        plaintext_buffers: &[Vec<u8>],
        iv: Option<&[u8]>,
        aad: Option<&[u8]>,
        encrypted_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesGcmEncryptDecryptResult, ManticoreError> {
        let gcm_state = GcmExpandedKey::new(&self.key, BlockCipherType::AesBlock).map_err(
            |symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::AesEncryptError
            },
        )?;
        let nonce: [u8; 12] = match iv {
            Some(iv) => iv.try_into().map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::AesEncryptError
            })?,
            None => return Err(ManticoreError::AesEncryptError),
        };
        let auth_data = match aad {
            Some(aad) => aad.to_vec(),
            None => Vec::new(),
        };

        let mut encrypted_size = 0usize;
        let mut buffer: Vec<u8> = plaintext_buffers.iter().flatten().copied().collect();
        let mut tag = [0u8; AES_GCM_TAG_SIZE];
        gcm_state.encrypt_in_place(&nonce, &auth_data, &mut buffer, &mut tag);
        for (chunk, encrypted_buffer) in buffer
            .as_slice()
            .chunks(buffer.len().div_ceil(encrypted_buffers.len()))
            .zip(encrypted_buffers.iter_mut())
        {
            *encrypted_buffer = chunk.to_vec();
            encrypted_size += chunk.len();
        }

        Ok(FPAesGcmEncryptDecryptResult {
            final_size: encrypted_size,
            tag: Some(tag),
        })
    }

    /// AES decryption on fast path
    ///
    /// # Arguments
    /// * `encrypted_buffers` - The data to be decrypted.
    /// * `iv` - The IV value.
    /// * `aad` - Additional authenticated data (only available for GCM).
    /// * `tag` - Tag to be used for decryption
    ///
    /// # Returns
    /// * `FPAesGcmEncryptDecryptResult` - The encryption result.
    /// * `decrypted_buffers` - cleartext data
    ///
    /// # Errors
    /// * `ManticoreError::AesDecryptError` - If the encryption fails.
    #[cfg(feature = "use-openssl")]
    fn aes_gcm_decrypt_mb(
        &self,
        encrypted_buffers: &[Vec<u8>],
        iv: Option<&[u8]>,
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
        decrypted_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesGcmEncryptDecryptResult, ManticoreError> {
        tracing::debug!("AES GCM Decrypt MB: Beginning");
        let mut decrypted_size = 0;
        if tag.is_none() {
            Err(ManticoreError::AesDecryptError)?;
        }
        let cipher = openssl::symm::Cipher::aes_256_gcm();
        let mut crypter =
            Crypter::new(cipher, Mode::Decrypt, &self.key, iv).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::AesDecryptError
            })?;

        // If aad is provided as input, use it
        if let Some(actual_aad) = aad {
            tracing::debug!("AES GCM Decrypt MB: AAD provided. Updating");
            crypter
                .aad_update(actual_aad)
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    ManticoreError::AesDecryptError
                })?;
        }

        if tag.is_some() {
            tracing::debug!("AES GCM Decrypt MB: Tag provided. Updating");
        }
        crypter
            .set_tag(tag.unwrap())
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::AesDecryptError
            })?;

        for (encrypted, decrypted_buffer) in
            encrypted_buffers.iter().zip(decrypted_buffers.iter_mut())
        {
            //decrypted_buffer.resize(encrypted.len(), 0); // Ensure buffer is correctly sized
            let count =
                crypter
                    .update(encrypted, decrypted_buffer)
                    .map_err(|openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        ManticoreError::AesDecryptError
                    })?;
            decrypted_buffer.truncate(count); // Truncate to actual decrypted data length
            decrypted_size += decrypted_buffer.len();
        }

        let mut final_chunk = vec![0; cipher.block_size()];
        let _final_count = crypter
            .finalize(&mut final_chunk)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::AesDecryptError
            })?;
        tracing::debug!(
            "AES GCM Decrypt MB: Success. Decrypted size: {}",
            decrypted_size
        );
        Ok(FPAesGcmEncryptDecryptResult {
            final_size: decrypted_size,
            tag: None,
        })
    }

    #[cfg(feature = "use-symcrypt")]
    fn aes_gcm_decrypt_mb(
        &self,
        encrypted_buffers: &[Vec<u8>],
        iv: Option<&[u8]>,
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
        decrypted_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesGcmEncryptDecryptResult, ManticoreError> {
        let gcm_state = GcmExpandedKey::new(&self.key, BlockCipherType::AesBlock).map_err(
            |symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::AesDecryptError
            },
        )?;
        let nonce: [u8; 12] = match iv {
            Some(iv) => iv[0..12].try_into().map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::AesEncryptError
            })?,
            None => return Err(ManticoreError::AesEncryptError),
        };
        let auth_data = match aad {
            Some(aad) => aad.to_vec(),
            None => Vec::new(),
        };
        let tag_data = match tag {
            Some(tag) => tag.to_vec(),
            None => Vec::new(),
        };

        let mut decrypted_size = 0usize;
        let mut buffer: Vec<u8> = encrypted_buffers.iter().flatten().copied().collect();
        gcm_state
            .decrypt_in_place(&nonce, &auth_data, &mut buffer, &tag_data)
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::AesDecryptError
            })?;
        for (chunk, decrypted_buffer) in buffer
            .as_slice()
            .chunks(buffer.len().div_ceil(decrypted_buffers.len()))
            .zip(decrypted_buffers.iter_mut())
        {
            *decrypted_buffer = chunk.to_vec();
            decrypted_size += chunk.len();
        }

        Ok(FPAesGcmEncryptDecryptResult {
            final_size: decrypted_size,
            tag: None,
        })
    }

    #[cfg(feature = "use-openssl")]
    fn aes_xts_encrypt_mb(
        &self,
        key2: AesKey,
        dul: usize,
        tweak: [u8; 16usize],
        plaintext_buffers: &[Vec<u8>],
        encrypted_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesXtsEncryptDecryptResult, ManticoreError> {
        let mut total_encrypted_size = 0;
        let cipher = openssl::symm::Cipher::aes_256_xts();
        let mut full_key = Vec::with_capacity(self.key.len() + key2.key.len());
        full_key.extend_from_slice(&self.key);
        full_key.extend_from_slice(&key2.key);

        for (data, output) in plaintext_buffers.iter().zip(encrypted_buffers.iter_mut()) {
            let mut crypter = Crypter::new(cipher, Mode::Encrypt, &full_key, Some(&tweak))
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    ManticoreError::AesEncryptError
                })?;
            output.clear();
            output.extend(vec![0u8; dul + cipher.block_size()]);
            let mut count = crypter
                .update(data, output)
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    ManticoreError::AesEncryptError
                })?;
            count += crypter
                .finalize(&mut output[count..])
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    ManticoreError::AesEncryptError
                })?;
            output.truncate(count);
            total_encrypted_size += output.len();
        }

        Ok(FPAesXtsEncryptDecryptResult {
            final_size: total_encrypted_size,
        })
    }

    #[cfg(feature = "use-symcrypt")]
    fn aes_xts_encrypt_mb(
        &self,
        key2: AesKey,
        dul: usize,
        tweak: [u8; 16usize],
        plaintext_buffers: &[Vec<u8>],
        encrypted_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesXtsEncryptDecryptResult, ManticoreError> {
        if self.key == key2.key {
            Err(ManticoreError::AesEncryptError)?;
        }

        // Create algorithm handle for this operation
        let alg_handle = CngAlgoHandle::new()?;

        // Create key handles for this operation
        let key1_handle = CngKeyHandle::new(alg_handle.handle(), &self.key)?;
        let key2_handle = CngKeyHandle::new(alg_handle.handle(), &key2.key)?;

        if dul % 16 != 0 {
            Err(ManticoreError::AesEncryptError)?;
        }

        let mut total_processed = 0;

        for (i, (plaintext, encrypted)) in plaintext_buffers
            .iter()
            .zip(encrypted_buffers.iter_mut())
            .enumerate()
        {
            if plaintext.len() < 16 || plaintext.len() % 16 != 0 {
                Err(ManticoreError::AesEncryptError)?;
            }

            // Calculate tweak for this buffer (using dul as data unit length and buffer index)
            let mut buffer_tweak = tweak;
            let tweak_increment = (i * dul / 16) as u64; // Increment based on data unit position

            // Add the increment to the tweak (treating it as a little-endian counter)
            let mut carry = tweak_increment;
            for byte in buffer_tweak.iter_mut() {
                let sum = *byte as u64 + carry;
                *byte = sum as u8;
                carry = sum >> 8;
                if carry == 0 {
                    break;
                }
            }

            encrypted.resize(plaintext.len(), 0);
            encrypt_single_buffer(
                key1_handle.handle(),
                key2_handle.handle(),
                plaintext,
                &buffer_tweak,
                encrypted,
            )?;

            total_processed += plaintext.len();
        }
        Ok(FPAesXtsEncryptDecryptResult {
            final_size: total_processed,
        })
    }

    #[cfg(feature = "use-openssl")]
    fn aes_xts_decrypt_mb(
        &self,
        key2: AesKey,
        dul: usize,
        tweak: [u8; 16usize],
        encrypted_buffers: &[Vec<u8>],
        cleartext_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesXtsEncryptDecryptResult, ManticoreError> {
        let cipher = openssl::symm::Cipher::aes_256_xts();
        let mut total_decrypted_size = 0;
        let mut full_key = Vec::with_capacity(self.key.len() + key2.key.len());
        full_key.extend_from_slice(&self.key);
        full_key.extend_from_slice(&key2.key);

        for (data, output) in encrypted_buffers.iter().zip(cleartext_buffers.iter_mut()) {
            let mut crypter = Crypter::new(cipher, Mode::Decrypt, &full_key, Some(&tweak))
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    ManticoreError::AesDecryptError
                })?;
            output.clear();
            output.extend(vec![0u8; dul + cipher.block_size()]);
            let mut count = crypter
                .update(data, output)
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    ManticoreError::AesDecryptError
                })?;
            count += crypter
                .finalize(&mut output[count..])
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    ManticoreError::AesDecryptError
                })?;
            output.truncate(count);
            total_decrypted_size += output.len();
        }

        Ok(FPAesXtsEncryptDecryptResult {
            final_size: total_decrypted_size,
        })
    }

    #[cfg(feature = "use-symcrypt")]
    fn aes_xts_decrypt_mb(
        &self,
        key2: AesKey,
        dul: usize,
        tweak: [u8; 16usize],
        encrypted_buffers: &[Vec<u8>],
        cleartext_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesXtsEncryptDecryptResult, ManticoreError> {
        // Create algorithm handle for this operation
        let alg_handle = CngAlgoHandle::new()?;

        // Create key handles for this operation
        let key1_handle = CngKeyHandle::new(alg_handle.handle(), &self.key)?;
        let key2_handle = CngKeyHandle::new(alg_handle.handle(), &key2.key)?;

        let mut total_processed = 0;

        if dul % 16 != 0 {
            Err(ManticoreError::AesDecryptError)?;
        }

        for (i, (encrypted, cleartext)) in encrypted_buffers
            .iter()
            .zip(cleartext_buffers.iter_mut())
            .enumerate()
        {
            if encrypted.len() < 16 || encrypted.len() % 16 != 0 {
                Err(ManticoreError::AesDecryptError)?;
            }

            // Calculate tweak for this buffer (using dul as data unit length and buffer index)
            let mut buffer_tweak = tweak;
            let tweak_increment = (i * dul / 16) as u64; // Increment based on data unit position

            // Add the increment to the tweak (treating it as a little-endian counter)
            let mut carry = tweak_increment;
            for byte in buffer_tweak.iter_mut() {
                let sum = *byte as u64 + carry;
                *byte = sum as u8;
                carry = sum >> 8;
                if carry == 0 {
                    break;
                }
            }

            cleartext.resize(encrypted.len(), 0);
            decrypt_single_buffer(
                key1_handle.handle(),
                key2_handle.handle(),
                encrypted,
                &buffer_tweak,
                cleartext,
            )?;

            total_processed += encrypted.len();
        }

        Ok(FPAesXtsEncryptDecryptResult {
            final_size: total_processed,
        })
    }

    /// AES encryption.
    ///
    /// # Arguments
    /// * `data` - The data to be encrypted.
    /// * `algo` - AES algo (CBC or GCM).
    /// * `iv` - The IV value.
    ///
    /// # Returns
    /// * `AesEncryptResult` - The encryption result.
    ///
    /// # Errors
    /// * `ManticoreError::AesEncryptError` - If the encryption fails.
    #[cfg(feature = "use-openssl")]
    fn encrypt(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
    ) -> Result<AesEncryptResult, ManticoreError> {
        let cipher = get_cipher(&self.size, &algo)?;
        let mut ctx = CipherCtx::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::AesEncryptError
        })?;
        let mut cipher_text = vec![0; data.len() + cipher.block_size()];

        ctx.encrypt_init(Some(cipher), None, None)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::AesEncryptError
            })?;

        ctx.encrypt_init(None, Some(&self.key), iv)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::AesEncryptError
            })?;

        // Do not support padding
        ctx.set_padding(false);

        let result = ctx.cipher_update(data, Some(&mut cipher_text));

        let count = result.map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::AesEncryptError
        })?;

        let rest = ctx
            .cipher_final(&mut cipher_text[count..])
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::AesEncryptError
            })?;

        cipher_text.truncate(count + rest);

        let iv = match algo {
            AesAlgo::Cbc if cipher_text.len() >= AES_CBC_IV_SIZE => {
                // The size of cipher text should be always 16-byte aligned.
                let last_block = &cipher_text[(cipher_text.len() - AES_CBC_IV_SIZE)..];
                Some(last_block.to_vec())
            }
            // The cipher text is empty
            AesAlgo::Cbc => None,
        };

        Ok(AesEncryptResult { cipher_text, iv })
    }

    #[cfg(feature = "use-symcrypt")]
    fn encrypt(
        &self,
        data: &[u8],
        _algo: AesAlgo,
        iv: Option<&[u8]>,
    ) -> Result<AesEncryptResult, ManticoreError> {
        if data.len() % 16 != 0 {
            Err(ManticoreError::AesEncryptError)?;
        }
        let mut cipher_text = vec![0u8; data.len()];
        let mut chaining_value: [u8; 16] = match iv {
            Some(init_vec) => init_vec.try_into().map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::AesEncryptError
            })?,
            None => [0u8; 16],
        };
        let aes_cbc = AesExpandedKey::new(&self.key).map_err(|symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            ManticoreError::AesEncryptError
        })?;
        aes_cbc
            .aes_cbc_encrypt(&mut chaining_value, data, &mut cipher_text)
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::AesEncryptError
            })?;
        let iv = Some(chaining_value.to_vec());
        Ok(AesEncryptResult { cipher_text, iv })
    }

    /// AES decryption.
    ///
    /// # Arguments
    /// * `data` - The data to be encrypted.
    /// * `algo` - AES algo (CBC).
    /// * `iv` - The IV value.
    ///
    /// # Returns
    /// * `AesDecryptResult` - The decryption result.
    ///
    /// # Errors
    /// * `ManticoreError::AesDecryptError` - If the decryption fails.
    #[cfg(feature = "use-openssl")]
    fn decrypt(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
    ) -> Result<AesDecryptResult, ManticoreError> {
        let cipher = get_cipher(&self.size, &algo)?;
        let mut ctx = CipherCtx::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::AesDecryptError
        })?;
        let mut plain_text = vec![0; data.len() + cipher.block_size()];

        ctx.decrypt_init(Some(cipher), None, None)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::AesDecryptError
            })?;

        ctx.decrypt_init(None, Some(&self.key), iv)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::AesDecryptError
            })?;

        // Do not support padding
        ctx.set_padding(false);

        let count =
            ctx.cipher_update(data, Some(&mut plain_text))
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    ManticoreError::AesDecryptError
                })?;

        let rest = ctx
            .cipher_final(&mut plain_text[count..])
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::AesDecryptError
            })?;

        plain_text.truncate(count + rest);

        let iv = if algo == AesAlgo::Cbc {
            if data.len() >= AES_CBC_IV_SIZE {
                // The data size should be always 16-byte aligned.
                let last_block = &data[(data.len() - AES_CBC_IV_SIZE)..];
                Some(last_block.to_vec())
            } else {
                // The data is empty
                None
            }
        } else {
            None
        };

        Ok(AesDecryptResult { plain_text, iv })
    }

    #[cfg(feature = "use-symcrypt")]
    fn decrypt(
        &self,
        data: &[u8],
        _algo: AesAlgo,
        iv: Option<&[u8]>,
    ) -> Result<AesDecryptResult, ManticoreError> {
        let mut plain_text: Vec<u8> = vec![0u8; data.len()];
        let mut chaining_value: [u8; 16] = match iv {
            Some(init_vec) => init_vec.try_into().map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::AesDecryptError
            })?,
            None => [0u8; 16],
        };
        let aes_cbc = AesExpandedKey::new(&self.key).map_err(|symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            ManticoreError::AesDecryptError
        })?;
        aes_cbc
            .aes_cbc_decrypt(&mut chaining_value, data, &mut plain_text)
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::AesDecryptError
            })?;
        let iv = Some(chaining_value.to_vec());
        Ok(AesDecryptResult { plain_text, iv })
    }

    /// AES key wrap with padding (RFC-5649) KW2.
    /// <https://datatracker.ietf.org/doc/html/rfc5649>
    ///
    /// # Arguments
    /// * `data` - The data to be wrapped.
    ///
    /// # Returns
    /// * `AesEncryptResult` - The encryption result.
    ///
    /// # Errors
    /// * `ManticoreError::AesEncryptError` - If the encryption fails.
    #[allow(unused)]
    fn wrap_pad(&self, data: &[u8]) -> Result<AesEncryptResult, ManticoreError> {
        if self.key.len() != 16 && self.key.len() != 24 && self.key.len() != 32 {
            Err(ManticoreError::InvalidArgument)?;
        }

        // compute aiv according to RFC 5649 section 3
        let m = data.len();
        let mli = m as u64;
        let aiv = (PADDED_UPPER_AIV | mli).swap_bytes();

        if data.len() % 8 == 0 {
            // no padding
            return self.base_key_wrap(data, aiv);
        }

        // append padding
        let r = data.len().next_multiple_of(8);
        let mut p = vec![0u8; r];

        p[0..data.len()].copy_from_slice(data);

        // special case
        if p.len() == 8 {
            let mut output = vec![0u8; 16];
            let p64 = u64::from_le_bytes(p[0..8].try_into().unwrap());
            let (c0, c1) = self.aes_ecb(true, aiv, p64)?;
            output[0..8].copy_from_slice(&c0.to_le_bytes());
            output[8..16].copy_from_slice(&c1.to_le_bytes());
            Ok(AesEncryptResult {
                cipher_text: output,
                iv: None, // No IV for key wrap
            })
        } else {
            self.base_key_wrap(&p, aiv)
        }
    }

    /// AES key unwrap with padding (RFC-5649).
    /// <https://datatracker.ietf.org/doc/html/rfc5649>
    ///
    /// # Arguments
    /// * `data` - The data to be unwrapped.
    ///
    /// # Returns
    /// * `AesDecryptResult` - The decryption result.
    ///
    /// # Errors
    /// * `ManticoreError::AesDecryptError` - If the decryption fails.
    fn unwrap_pad(&self, data: &[u8]) -> Result<AesDecryptResult, ManticoreError> {
        if data.len() < 16 {
            Err(ManticoreError::InvalidArgument)?;
        }

        let mut output = vec![0u8; data.len() - 8];

        if data.len() == 16 {
            // special case
            let c0 = u64::from_le_bytes(data[0..8].try_into().unwrap());
            let c1 = u64::from_le_bytes(data[8..16].try_into().unwrap());
            let (a, p1) = self.aes_ecb(false, c0, c1)?;
            // let mut output = vec![0u8; 8];
            output[0..8].copy_from_slice(&p1.to_le_bytes());
            let plen = match AesKey::check_aiv(output.as_slice(), a)? {
                AivPadding::None => Err(ManticoreError::AesDecryptError)?,
                AivPadding::Length(size) => size,
            };
            return Ok(AesDecryptResult {
                plain_text: output[0..plen].to_vec(),
                iv: None, // No IV for key unwrap
            });
        }

        match self.base_key_unwrap(data, output.as_mut_slice())? {
            AivPadding::None => Err(ManticoreError::AesDecryptError)?,
            AivPadding::Length(plen) => Ok(AesDecryptResult {
                plain_text: output[0..plen].to_vec(),
                iv: None, // No IV for key unwrap
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use hex;
    use test_with_tracing::test;

    use super::*;

    struct AesTestParam<'a> {
        size: AesKeySize,
        algo: AesAlgo,
        key: &'a str,
        iv: &'a str,
        plain: &'a str,
        cipher: &'a str,
    }

    #[cfg(target_os = "windows")]
    fn test_cng_aes_xts(plaintext_size: usize, dul: usize) {
        use rand::Rng;
        // Generate random keys
        let key1 = AesKey::from_bytes(&rand::thread_rng().gen::<[u8; 32]>()).unwrap();
        let key2 = AesKey::from_bytes(&rand::thread_rng().gen::<[u8; 32]>()).unwrap();

        // Generate random plaintext
        let mut plaintext = vec![0u8; plaintext_size];
        rand::thread_rng().fill(&mut plaintext[..]);

        // Prepare buffers
        let tweak = [0x01; 16];
        let split_vector_into_chunks = |original_vec: Vec<u8>, chunk_size: usize| -> Vec<Vec<u8>> {
            original_vec
                .chunks(chunk_size) // Split the vector into chunks
                .map(|chunk| chunk.to_vec()) // Convert each chunk into a Vec<u8>
                .collect() // Collect the chunks into a Vec<Vec<u8>>
        };

        let chunk_len = plaintext.len();
        let plaintext_buffers = split_vector_into_chunks(plaintext, chunk_len);
        let mut encrypted_buffers: Vec<Vec<u8>> = plaintext_buffers
            .iter()
            .map(|inner| vec![0; inner.len()])
            .collect();
        let mut decrypted_buffers: Vec<Vec<u8>> = plaintext_buffers
            .iter()
            .map(|inner| vec![0; inner.len()])
            .collect();

        // Encrypt
        let enc_result = key1.aes_xts_encrypt_mb(
            key2.clone(),
            dul,
            tweak,
            &plaintext_buffers,
            &mut encrypted_buffers,
        );
        assert!(
            enc_result.is_ok(),
            "Encryption failed: {:?}",
            enc_result.err()
        );

        // Decrypt
        let dec_result =
            key1.aes_xts_decrypt_mb(key2, dul, tweak, &encrypted_buffers, &mut decrypted_buffers);
        assert!(dec_result.is_ok());

        let plaintext_buf = plaintext_buffers.into_iter().flatten().collect::<Vec<u8>>();

        let decrypted_buf: Vec<u8> = decrypted_buffers.into_iter().flatten().collect();

        // Compare
        assert_eq!(plaintext_buf, decrypted_buf);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_xts_encrypt_decrypt_roundtrip() {
        test_cng_aes_xts(528, 512);
        test_cng_aes_xts(544, 4096);
        test_cng_aes_xts(1024, 512);
        test_cng_aes_xts(16, 4096);
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_xts_encrypt_decrypt_unaligned_data_527_dul_512() {
        test_cng_aes_xts(527, 512);
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_xts_encrypt_decrypt_invalid_data_15_dul_4096() {
        test_cng_aes_xts(15, 4096);
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_xts_encrypt_decrypt_unaligned_data_17_dul_4096() {
        test_cng_aes_xts(17, 4096);
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_xts_encrypt_decrypt_unaligned_data_17_dul_17() {
        test_cng_aes_xts(17, 17);
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic]
    fn test_xts_encrypt_decrypt_unaligned_data_544_dul_17() {
        test_cng_aes_xts(544, 17);
    }

    fn test_aes(params: AesTestParam<'_>) {
        let key = hex::decode(params.key).unwrap();
        let iv = hex::decode(params.iv).unwrap();
        let plain = hex::decode(params.plain).unwrap();
        let cipher = hex::decode(params.cipher).unwrap();

        let result = if params.size.is_bulk_key() {
            AesKey::from_bulk_bytes(&key, params.size)
        } else {
            AesKey::from_bytes(&key)
        };
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.size, params.size);

        let result = key.encrypt(&plain, params.algo.clone(), Some(&iv));
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.cipher_text, cipher);

        let result = key.decrypt(&cipher, params.algo, Some(&iv));
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.plain_text, plain);
    }

    #[test]
    fn test_aes_128_cbc() {
        let params = AesTestParam {
            size: AesKeySize::Aes128,
            algo: AesAlgo::Cbc,
            key: "2b7e151628aed2a6abf7158809cf4f3c",
            iv: "000102030405060708090a0b0c0d0e0f",
            plain: "6bc1bee22e409f96e93d7e117393172a",
            cipher: "7649abac8119b246cee98e9b12e9197d",
        };

        test_aes(params);
    }

    #[test]
    fn test_aes_192_cbc() {
        let params = AesTestParam {
            size: AesKeySize::Aes192,
            algo: AesAlgo::Cbc,
            key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            iv: "000102030405060708090a0b0c0d0e0f",
            plain: "6bc1bee22e409f96e93d7e117393172a",
            cipher: "4f021db243bc633d7178183a9fa071e8",
        };

        test_aes(params);
    }

    #[test]
    fn test_aes_256_cbc() {
        let params = AesTestParam {
            size: AesKeySize::Aes256,
            algo: AesAlgo::Cbc,
            key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            iv: "000102030405060708090a0b0c0d0e0f",
            plain: "6bc1bee22e409f96e93d7e117393172a",
            cipher: "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
        };

        test_aes(params);
    }

    #[test]
    fn test_aes_cbc_empty_input() {
        let params = AesTestParam {
            size: AesKeySize::Aes256,
            algo: AesAlgo::Cbc,
            key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            iv: "000102030405060708090a0b0c0d0e0f",
            plain: "",
            cipher: "",
        };

        test_aes(params);
    }

    #[test]
    fn test_aes_cbc_output_iv() {
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let expected_plain = [1u8; 2048];

        let result = AesKey::from_bytes(&key);
        assert!(result.is_ok());
        let key = result.unwrap();

        // Test encryption
        let result = key.encrypt(&expected_plain, AesAlgo::Cbc, Some(&iv));
        assert!(result.is_ok());
        let result = result.unwrap();
        let expected_cipher = result.cipher_text;
        assert!(result.iv.is_some());
        let expected_iv = result.iv.unwrap();

        let result = key.encrypt(&expected_plain[..1024], AesAlgo::Cbc, Some(&iv));
        assert!(result.is_ok());
        let result = result.unwrap();
        let cipher_1 = result.cipher_text;
        assert!(result.iv.is_some());
        let output_iv_1 = result.iv.unwrap();

        let result = key.encrypt(&expected_plain[1024..], AesAlgo::Cbc, Some(&output_iv_1));
        assert!(result.is_ok());
        let result = result.unwrap();
        let cipher_2 = result.cipher_text;
        assert!(result.iv.is_some());
        let output_iv_2 = result.iv.unwrap();

        let cipher = [&cipher_1[..], &cipher_2[..]].concat();

        assert_eq!(output_iv_2, expected_iv);
        assert_eq!(cipher, expected_cipher);

        // Test decryption
        let result = key.decrypt(&cipher, AesAlgo::Cbc, Some(&iv));
        assert!(result.is_ok());
        let result = result.unwrap();
        let output_plain = result.plain_text;
        assert!(result.iv.is_some());
        let expected_iv = result.iv.unwrap();
        assert_eq!(output_plain, expected_plain);

        let result = key.decrypt(&cipher[..1024], AesAlgo::Cbc, Some(&iv));
        assert!(result.is_ok());
        let result = result.unwrap();
        let plain_1 = result.plain_text;
        assert!(result.iv.is_some());
        let output_iv_1 = result.iv.unwrap();

        let result = key.decrypt(&cipher[1024..], AesAlgo::Cbc, Some(&output_iv_1));
        assert!(result.is_ok());
        let result = result.unwrap();
        let plain_2 = result.plain_text;
        assert!(result.iv.is_some());
        let output_iv_2 = result.iv.unwrap();

        let plain = [&plain_1[..], &plain_2[..]].concat();

        assert_eq!(output_iv_2, expected_iv);
        assert_eq!(plain, expected_plain);
    }

    #[test]
    fn test_rfc5649_aes_wrap_pad() {
        let wrapping_key =
            hex::decode("2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c")
                .unwrap();
        let plain_text = hex::decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();

        let result = AesKey::from_bytes(&wrapping_key);
        assert!(result.is_ok());
        let key = result.unwrap();

        // Test wrapping
        let result = key.wrap_pad(&plain_text);
        assert!(result.is_ok());
        let result = result.unwrap();
        let cipher_text = result.cipher_text;

        // Test unwrapping
        let result = key.unwrap_pad(&cipher_text);
        assert!(result.is_ok());
        let result = result.unwrap();

        let output_plain = result.plain_text;
        assert_eq!(output_plain, plain_text);
    }

    #[cfg(all(test, target_os = "linux"))]
    #[test]
    fn test_openssl_wrap_pad_compatibility() {
        use openssl::cipher::Cipher;
        use openssl::cipher_ctx::CipherCtx;
        use openssl::cipher_ctx::CipherCtxFlags;

        let wrapping_key =
            hex::decode("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
                .unwrap();
        let plain_text = hex::decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();

        // Use OpenSSL to wrap the plaintext
        let cipher = Cipher::aes_256_wrap_pad();
        let mut ctx = CipherCtx::new().unwrap();
        ctx.set_flags(CipherCtxFlags::FLAG_WRAP_ALLOW);
        ctx.encrypt_init(Some(cipher), Some(&wrapping_key), None)
            .unwrap();

        let mut wrapped = vec![0u8; plain_text.len() + 16];
        let count = ctx.cipher_update(&plain_text, Some(&mut wrapped)).unwrap();
        let rest = ctx.cipher_final(&mut wrapped[count..]).unwrap();
        wrapped.truncate(count + rest);

        // Now unwrap using AesKey's unwrap_pad
        let key = AesKey::from_bytes(&wrapping_key).unwrap();
        let result = key.unwrap_pad(&wrapped);
        assert!(result.is_ok(), "unwrap_pad failed");

        let unwrapped_data = result.unwrap().plain_text;

        assert_eq!(
            unwrapped_data, plain_text,
            "Unwrapped plaintext does not match original"
        );
    }

    #[cfg(all(test, target_os = "linux"))]
    #[test]
    fn test_openssl_unwrap_pad_compatibility() {
        use openssl::cipher::Cipher;
        use openssl::cipher_ctx::CipherCtx;
        use openssl::cipher_ctx::CipherCtxFlags;

        let wrapping_key =
            hex::decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
                .unwrap();
        let plain_text = hex::decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();

        // Use AesKey's wrap_pad to wrap the plaintext
        let key = AesKey::from_bytes(&wrapping_key).unwrap();
        let wrap_result = key.wrap_pad(&plain_text);
        assert!(wrap_result.is_ok(), "wrap_pad failed");
        let wrapped_data = wrap_result.unwrap().cipher_text;

        // Now unwrap using OpenSSL
        let cipher = Cipher::aes_256_wrap_pad();
        let mut ctx = CipherCtx::new().unwrap();
        ctx.set_flags(CipherCtxFlags::FLAG_WRAP_ALLOW);
        ctx.decrypt_init(Some(cipher), Some(&wrapping_key), None)
            .unwrap();

        let padding = 8 - wrapped_data.len() % 8;
        let mut unwrapped_data = vec![0u8; wrapped_data.len() + padding + cipher.block_size() * 2];
        let count = ctx
            .cipher_update(&wrapped_data, Some(&mut unwrapped_data))
            .unwrap();
        let rest = ctx.cipher_final(&mut unwrapped_data[count..]).unwrap();
        unwrapped_data.truncate(count + rest);

        // Compare the unwrapped data with the original plaintext
        assert_eq!(
            unwrapped_data, plain_text,
            "OpenSSL unwrapped plaintext does not match original"
        );
    }
}
