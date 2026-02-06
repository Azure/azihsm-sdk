// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TPM backup key unsealing operations.
//!
//! This module provides functionality for unsealing backup keys (BK3) that
//! were sealed by UEFI firmware using the TPM NULL hierarchy. It handles
//! the complete workflow of creating a TPM primary key, loading and unsealing
//! the sealed object, and decrypting the resulting AES-CBC encrypted data.

use azihsm_crypto::*;
use azihsm_tpm::*;
use zerocopy::*;

use crate::HsmError;

const MIN_SEALED_BK3_SIZE: usize = 4;
const RSA_KEY_BITS: u16 = 2048;
const TPM_PRIMARY_AES_KEY_BITS: u16 = 128; // AES-128-CFB for TPM primary key symmetric protection
const AES_BLOCK_SIZE: usize = 16;
const BK3_AES_KEY_SIZE: usize = 32; // AES-256-CBC key size for BK3 data encryption
const AZIHSM_KEY_IV_RECORD_VERSION: u8 = 1;

/// Packed AES key/IV record matching AZIHSM_KEY_IV_RECORD from UEFI firmware.
///
/// Defined in AziHsmDxe.h in hyperv.uefi:
/// https://microsoft.visualstudio.com/OS/_git/hyperv.uefi?path=/MsvmPkg/AziHsmDxe/AziHsmDxe.h
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, TryFromBytes, KnownLayout, Immutable)]
struct AzihsmKeyIvRecord {
    /// Record size (does not include the size of this field itself)
    record_size: [u8; 2],
    /// Key version
    key_version: u8,
    /// Length of key in bytes
    key_size: u8,
    /// AES-256 key
    key: [u8; BK3_AES_KEY_SIZE],
    /// Length of IV in bytes
    iv_size: u8,
    /// AES IV
    iv: [u8; AES_BLOCK_SIZE],
}

impl AzihsmKeyIvRecord {
    /// Parses and validates an AZIHSM_KEY_IV_RECORD from a byte slice.
    ///
    /// Uses `try_ref_from_prefix` to tolerate trailing bytes beyond the
    /// fixed-size struct layout.
    fn from_bytes_validated(data: &[u8]) -> Result<&Self, HsmError> {
        let (record, _remaining) =
            Self::try_ref_from_prefix(data).map_err(|_| HsmError::InvalidArgument)?;

        if record.key_version != AZIHSM_KEY_IV_RECORD_VERSION {
            return Err(HsmError::InvalidArgument);
        }

        let record_size = u16::from_le_bytes(record.record_size) as usize;
        if record_size + size_of::<u16>() != data.len() {
            return Err(HsmError::InvalidArgument);
        }

        if record.key_size as usize > BK3_AES_KEY_SIZE {
            return Err(HsmError::InvalidArgument);
        }

        if record.iv_size as usize != AES_BLOCK_SIZE {
            return Err(HsmError::InvalidArgument);
        }

        Ok(record)
    }
}

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
        offset += size_of::<u16>();

        if sealed_aes_len + offset + size_of::<u16>() > sealed_bk3.len() {
            return Err(HsmError::InvalidArgument);
        }
        let sealed_aes_secret = &sealed_bk3[offset..offset + sealed_aes_len];
        offset += sealed_aes_len;

        let encrypted_data_len =
            u16::from_le_bytes([sealed_bk3[offset], sealed_bk3[offset + 1]]) as usize;
        offset += size_of::<u16>();

        if encrypted_data_len + offset > sealed_bk3.len() {
            return Err(HsmError::InvalidArgument);
        }
        let encrypted_data = &sealed_bk3[offset..offset + encrypted_data_len];

        // Unseal AES key/IV structure
        let aes_key_struct = self.unseal_null_hierarchy(sealed_aes_secret)?;

        // Parse AZIHSM_KEY_IV_RECORD
        let record = AzihsmKeyIvRecord::from_bytes_validated(&aes_key_struct)?;

        // Decrypt with AES-CBC — use key_size to slice the actual key bytes,
        // since the key array is fixed at 32 bytes but the actual key may be smaller.
        let aes_key = AesKey::from_bytes(&record.key[..record.key_size as usize])
            .map_err(|_| HsmError::InternalError)?;
        let mut algo = AesCbcAlgo::with_padding(&record.iv);

        let mut output = vec![0u8; encrypted_data.len() + AES_BLOCK_SIZE];
        let len = algo
            .decrypt(&aes_key, encrypted_data, Some(&mut output))
            .map_err(|_| HsmError::InternalError)?;

        output.truncate(len);
        Ok(output)
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
        if sealed_data.len() < size_of::<u16>() {
            return Err(HsmError::InvalidArgument);
        }

        // Parse sealed_data into TPM2B_PRIVATE and TPM2B_PUBLIC
        // Unpacking is based on packing implemented on AziHsmTpmSealBuffer in AziHsmBKS3.c
        // https://microsoft.visualstudio.com/OS/_git/hyperv.uefi?path=/MsvmPkg/AziHsmDxe/AziHsmBKS3.c
        let mut offset = 0;

        let private_len =
            u16::from_le_bytes([sealed_data[offset], sealed_data[offset + 1]]) as usize;
        offset += size_of::<u16>();

        if private_len + offset + size_of::<u16>() > sealed_data.len() {
            return Err(HsmError::InvalidArgument);
        }
        let private_blob = &sealed_data[offset..offset + private_len];
        offset += private_len;

        let public_len =
            u16::from_le_bytes([sealed_data[offset], sealed_data[offset + 1]]) as usize;
        offset += size_of::<u16>();

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
            .map_err(|_| {
                // Best-effort flush of the primary handle if load fails
                let _ = self.tpm.flush_context(primary.handle);
                HsmError::InternalError
            })?;

        // Unseal data
        let unsealed = self.tpm.unseal(loaded.handle, &policy.0).map_err(|_| {
            // Best-effort flush of both handles if unseal fails
            let _ = self.tpm.flush_context(loaded.handle);
            let _ = self.tpm.flush_context(primary.handle);
            HsmError::InternalError
        })?;

        // Best-effort flush of both handles after successful unseal
        let _ = self.tpm.flush_context(loaded.handle);
        let _ = self.tpm.flush_context(primary.handle);

        Ok(unsealed)
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
                    key_bits: TPM_PRIMARY_AES_KEY_BITS,
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
