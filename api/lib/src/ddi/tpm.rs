// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_crypto::*;
use azihsm_tpm::*;

use crate::HsmError;

const MIN_SEALED_BK3_SIZE: usize = 4;
const AZIHSM_KEY_IV_RECORD_HEADER_SIZE: usize = 3; // record_size(2) + version(1)
const RSA_KEY_BITS: u16 = 2048;
const AES_KEY_BITS: u16 = 128;
const AES_BLOCK_SIZE: usize = 16;
const AZIHSM_KEY_IV_RECORD_VERSION: u8 = 1;
const U16_SIZE: usize = std::mem::size_of::<u16>();
const U8_SIZE: usize = std::mem::size_of::<u8>();

/// Helper for unsealing TPM-sealed backup keys.
///
/// This struct encapsulates TPM operations for unsealing backup keys (BK3)
/// that were sealed by UEFI firmware during partition initialization.
struct TpmBk3Unsealer {
    tpm: Tpm,
}

impl TpmBk3Unsealer {
    /// Opens a connection to the TPM device.
    ///
    /// # Returns
    ///
    /// * `Ok(TpmBk3Unsealer)` - Successfully opened TPM connection
    /// * `Err(HsmError)` - Failed to access TPM device
    fn open() -> Result<Self, HsmError> {
        let tpm = Tpm::open().map_err(|_| HsmError::InternalError)?;
        Ok(Self { tpm })
    }

    /// Unseals a TPM-sealed backup key (BK3) and returns the masked backup key.
    ///
    /// sealed_bk3 layout: [sealed_aes_len:u16 LE][sealed_aes_secret][encrypted_data_len:u16 LE][encrypted_data]
    ///
    /// sealed_aes_secret layout: [private_len:u16 LE][private_blob][public_len:u16 LE][public_blob]
    ///
    /// AZIHSM_KEY_IV_RECORD layout: [record_size:u16 LE][version:u8][key_len:u8][key][iv_len:u8][iv]
    ///
    /// TPM2B layout: [size:u16 BE][payload]
    ///
    /// This method handles the complete unsealing workflow:
    /// 1. Parse the sealed BK3 format
    /// 2. Unseal the AES key/IV structure using TPM
    /// 3. Decrypt the encrypted data with AES-CBC
    /// 4. Remove PKCS7 padding
    ///
    /// # Arguments
    ///
    /// * `sealed_bk3` - The TPM-sealed backup key data
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The unsealed masked backup key
    /// * `Err(HsmError)` - If parsing, unsealing, or decryption fails
    fn unseal_bk3(&self, sealed_bk3: &[u8]) -> Result<Vec<u8>, HsmError> {
        // Validate and parse sealed_bk3
        if sealed_bk3.len() < MIN_SEALED_BK3_SIZE {
            return Err(HsmError::InvalidArgument);
        }

        let mut offset = 0;
        let sealed_aes_len =
            u16::from_le_bytes([sealed_bk3[offset], sealed_bk3[offset + 1]]) as usize;
        offset += U16_SIZE;

        if sealed_aes_len + offset + U16_SIZE > sealed_bk3.len() {
            return Err(HsmError::InvalidArgument);
        }
        let sealed_aes_secret = &sealed_bk3[offset..offset + sealed_aes_len];
        offset += sealed_aes_len;

        let encrypted_data_len =
            u16::from_le_bytes([sealed_bk3[offset], sealed_bk3[offset + 1]]) as usize;
        offset += U16_SIZE;

        if encrypted_data_len + offset > sealed_bk3.len() {
            return Err(HsmError::InvalidArgument);
        }
        let encrypted_data = &sealed_bk3[offset..offset + encrypted_data_len];

        // Unseal AES key/IV structure
        let aes_key_struct = self.unseal_null_hierarchy(sealed_aes_secret)?;

        // Parse AZIHSM_KEY_IV_RECORD
        if aes_key_struct.len() < AZIHSM_KEY_IV_RECORD_HEADER_SIZE + U8_SIZE {
            return Err(HsmError::InvalidArgument);
        }

        let record_size = u16::from_le_bytes([aes_key_struct[0], aes_key_struct[1]]) as usize;
        let record_version = aes_key_struct[2];
        if record_version != AZIHSM_KEY_IV_RECORD_VERSION {
            return Err(HsmError::InvalidArgument);
        }
        if record_size + U16_SIZE != aes_key_struct.len() {
            return Err(HsmError::InvalidArgument);
        }

        let mut offset = AZIHSM_KEY_IV_RECORD_HEADER_SIZE;
        let key_len = aes_key_struct[offset] as usize;
        offset += U8_SIZE;

        if key_len != (AES_KEY_BITS as usize / 8) {
            return Err(HsmError::InvalidArgument);
        }
        if key_len + offset + U8_SIZE > aes_key_struct.len() {
            return Err(HsmError::InvalidArgument);
        }
        let aes_key_bytes = &aes_key_struct[offset..offset + key_len];
        offset += key_len;

        let iv_len = aes_key_struct[offset] as usize;
        offset += U8_SIZE;

        if iv_len != AES_BLOCK_SIZE {
            return Err(HsmError::InvalidArgument);
        }
        if iv_len + offset > aes_key_struct.len() {
            return Err(HsmError::InvalidArgument);
        }
        let iv_bytes = &aes_key_struct[offset..offset + iv_len];

        // Decrypt with AES-CBC
        let aes_key = AesKey::from_bytes(aes_key_bytes).map_err(|_| HsmError::InternalError)?;
        let mut algo = AesCbcAlgo::with_padding(iv_bytes);

        let mut output = vec![0u8; encrypted_data.len() + AES_BLOCK_SIZE];
        let len = algo
            .decrypt(&aes_key, encrypted_data, Some(&mut output))
            .map_err(|_| HsmError::InternalError)?;

        output.truncate(len);

        // Remove PKCS7 padding
        Self::pkcs7_unpad(&output)
    }

    /// Unseals data using the TPM NULL hierarchy.
    ///
    /// # Arguments
    ///
    /// * `sealed_data` - TPM-sealed data containing TPM2B_PRIVATE and TPM2B_PUBLIC blobs
    ///   Format: [private_len:u16 LE][private_blob][public_len:u16 LE][public_blob].
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The unsealed data
    /// * `Err(HsmError)` - If unsealing fails
    fn unseal_null_hierarchy(&self, sealed_data: &[u8]) -> Result<Vec<u8>, HsmError> {
        if sealed_data.len() < U16_SIZE {
            return Err(HsmError::InvalidArgument);
        }

        // Parse sealed_data into TPM2B_PRIVATE and TPM2B_PUBLIC
        let mut offset = 0;

        let private_len =
            u16::from_le_bytes([sealed_data[offset], sealed_data[offset + 1]]) as usize;
        offset += U16_SIZE;

        if private_len + offset + U16_SIZE > sealed_data.len() {
            return Err(HsmError::InvalidArgument);
        }
        let private_blob = &sealed_data[offset..offset + private_len];
        offset += private_len;

        let public_len =
            u16::from_le_bytes([sealed_data[offset], sealed_data[offset + 1]]) as usize;
        offset += U16_SIZE;

        if public_len + offset > sealed_data.len() {
            return Err(HsmError::InvalidArgument);
        }
        let public_blob = &sealed_data[offset..offset + public_len];

        // Create NULL primary
        let policy = Tpm2bBytes(Vec::new());
        let primary = self.create_null_primary(&policy)?;

        // Load sealed object
        let loaded = self
            .tpm
            .load(primary.handle, &policy.0, private_blob, public_blob)
            .map_err(|_| HsmError::InternalError)?;

        // Unseal data
        self.tpm
            .unseal(loaded.handle, &policy.0)
            .map_err(|_| HsmError::InternalError)
    }

    /// Creates a TPM NULL hierarchy primary key for unsealing.
    ///
    /// # Arguments
    ///
    /// * `policy` - TPM authorization policy (empty for NULL hierarchy)
    ///
    /// # Returns
    ///
    /// * `Ok(CreatedPrimary)` - The created primary key
    /// * `Err(HsmError)` - If key creation fails
    fn create_null_primary(&self, policy: &Tpm2bBytes) -> Result<CreatedPrimary, HsmError> {
        let obj_attrs = TpmaObjectBits::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_no_da(true)
            .with_restricted(true)
            .with_decrypt(true);

        let public_template = TpmtPublic {
            type_alg: TpmAlgId::Rsa.into(),
            name_alg: TpmAlgId::Sha256.into(),
            object_attributes: obj_attrs.into(),
            auth_policy: policy.clone(),
            detail: TpmtPublicDetail::RsaDetail(RsaDetail {
                symmetric: SymDefObject {
                    alg: TpmAlgId::Aes.into(),
                    key_bits: AES_KEY_BITS,
                    mode: TpmAlgId::Cfb.into(),
                },
                scheme: RsaScheme::Null,
                key_bits: RSA_KEY_BITS,
                exponent: 0, // 0 means default: 65537
            }),
            unique: Tpm2bBytes(Vec::new()),
        };

        self.tpm
            .create_primary(Hierarchy::Null, Tpm2b::new(public_template), &[])
            .map_err(|_| HsmError::InternalError)
    }

    /// Removes PKCS7 padding from decrypted data.
    ///
    /// # Arguments
    ///
    /// * `padded` - Data with PKCS7 padding
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Data with padding removed
    /// * `Err(HsmError)` - If padding is invalid
    fn pkcs7_unpad(padded: &[u8]) -> Result<Vec<u8>, HsmError> {
        if padded.is_empty() || !padded.len().is_multiple_of(AES_BLOCK_SIZE) {
            return Err(HsmError::InvalidArgument);
        }

        let pad_len = padded[padded.len() - 1] as usize;

        if pad_len == 0 || pad_len > AES_BLOCK_SIZE {
            return Err(HsmError::InvalidArgument);
        }

        // Verify padding bytes
        for i in 0..pad_len {
            if padded[padded.len() - 1 - i] != pad_len as u8 {
                return Err(HsmError::InvalidArgument);
            }
        }

        Ok(padded[..padded.len() - pad_len].to_vec())
    }
}

/// Unseals a TPM-sealed backup key (BK3).
///
/// # Arguments
///
/// * `sealed_bk3` - The TPM-sealed backup key data
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The unsealed masked backup key
/// * `Err(HsmError)` - If TPM access fails or unsealing fails
pub(crate) fn unseal_tpm_backup_key(sealed_bk3: &[u8]) -> Result<Vec<u8>, HsmError> {
    let unsealer = TpmBk3Unsealer::open()?;
    unsealer.unseal_bk3(sealed_bk3)
}
