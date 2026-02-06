// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Module for Live Migration Key Derivation.

// [TODO]  Remove when module is used.
#![allow(unused_imports)]
#![allow(dead_code)]

use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_mbor::MborDecode;
use azihsm_ddi_mbor::MborDecoder;
use azihsm_ddi_mbor::MborEncode;
use azihsm_ddi_mbor::MborEncoder;
use azihsm_ddi_mbor::MborLen;
use azihsm_ddi_mbor::MborLenAccumulator;
use azihsm_ddi_types::DdiDeviceKind;
use azihsm_ddi_types::DdiKeyAvailability;
use azihsm_ddi_types::DdiKeyProperties;
use azihsm_ddi_types::DdiKeyType;
use azihsm_ddi_types::DdiKeyUsage;
use azihsm_ddi_types::DdiMaskedKeyAttributes;
use azihsm_ddi_types::DdiMaskedKeyMetadata;
use azihsm_ddi_types::MaskedKey;
use azihsm_ddi_types::MaskingKeyAlgorithm;
use azihsm_ddi_types::AES_CBC_256_KEY_SIZE;
use azihsm_ddi_types::HMAC384_KEY_SIZE;

use crate::crypto_env::CryptEnv;
use crate::errors::ManticoreError;
use crate::masked_key::DecodedMaskedKey;
use crate::masked_key::MaskedKeyDecode;
use crate::masked_key::MaskedKeyEncode;

pub(crate) const BK3_SIZE_BYTES: usize = 48;
pub(crate) const FW_SECRET_SIZE_BYTES: usize = 48;
pub(crate) const MK_SEED_SIZE_BYTES: usize = 48;
pub(crate) const BK_SEED_SIZE_BYTES: usize = 32;
pub(crate) const SESSION_SEED_SIZE_BYTES: usize = 48;
pub(crate) const PARTITION_BK_LABEL: &[u8] = b"PARTITION_BK";
pub(crate) const SESSION_BK_LABEL: &[u8] = b"SESSION_BK";
pub(crate) const MK_DEFAULT_LABEL: &[u8] = b"MK_DEFAULT";
pub(crate) const EPHMR_KEY_DEFAULT_LABEL: &[u8] = b"EPHEMERAL_KEY_DEFAULT";
pub(crate) const EPHMR_MASKING_KEY_DEFAULT_LABEL: &[u8] = b"EPHEMERAL_MK_DEFAULT";
pub(crate) const BK_AES_CBC_256_HMAC384_SIZE_BYTES: usize = AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE;
pub(crate) const MK_AES_CBC_256_HMAC384_SIZE_BYTES: usize = AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE;
pub(crate) const EMPH_MK_AES_CBC_256_HMAC384_SIZE_BYTES: usize =
    AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE;
pub(crate) const METADATA_MAX_SIZE_BYTES: usize = 72;

/// Live Migration Key Derivation implementation
///
/// Provides key derivation functionality for HSM live migration operations,
/// including backup key generation, backup masking key generation, and masking key restoration.
pub struct LMKeyDerive;

impl LMKeyDerive {
    /// Generate Partition Backup Key (BK) using the provided seeds BKS1, BKS2, and backup key BK3.
    ///
    /// # Arguments
    ///
    /// * `crypto_env` - The cryptographic environment to use.
    /// * `algo` - Indicates the type of the BK to be generated.
    /// * `bks1` - The first backup seed (BKS1).
    /// * `bks2` - The second backup seed (BKS2).
    /// * `bk3` - The backup key (BK3).
    /// * `bk_partition_len` - In/out parameter for the length of the partition backup key.
    ///   On input, it specifies the bk_out buffer size.
    ///   On output, it will contain the actual length of the generated backup key.
    /// * `bk_partition_out` - Output buffer for the generated partition backup key.
    ///
    /// # Returns
    /// * `Ok(())` - If the backup key is successfully generated.
    /// * `Err(ManticoreError)` - If there is an error during the generation process.
    pub fn bk_partition_gen<Env: CryptEnv>(
        crypto_env: &Env,
        algo: MaskingKeyAlgorithm,
        bks1: &[u8; BK_SEED_SIZE_BYTES],
        bks2: &[u8; BK_SEED_SIZE_BYTES],
        bk3: &[u8; BK3_SIZE_BYTES],
        bk_partition_len: &mut usize,
        bk_partition_out: &mut [u8],
    ) -> Result<(), ManticoreError> {
        // Check BK algo. Only AesCbc256Hmac384 is supported for now.
        if algo != MaskingKeyAlgorithm::AesCbc256Hmac384 {
            Err(ManticoreError::InvalidAlgorithm)?;
        }

        if *bk_partition_len < BK_AES_CBC_256_HMAC384_SIZE_BYTES
            || bk_partition_out.len() < BK_AES_CBC_256_HMAC384_SIZE_BYTES
        {
            *bk_partition_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES;
            Err(ManticoreError::OutputBufferTooSmall)?;
        }

        // BKS12 is the concatenation of BKS1 and BKS2 and is used as KBKDF context.
        let mut bks1_2 = [0u8; BK_SEED_SIZE_BYTES * 2];
        bks1_2[..BK_SEED_SIZE_BYTES].copy_from_slice(bks1);
        bks1_2[BK_SEED_SIZE_BYTES..].copy_from_slice(bks2);

        // Derive BK via KBKDF using BK3 as key and BKS1_2 as context.
        crypto_env.kbkdf_sha384(
            bk3,
            Some(PARTITION_BK_LABEL),
            Some(&bks1_2),
            BK_AES_CBC_256_HMAC384_SIZE_BYTES,
            &mut bk_partition_out[..BK_AES_CBC_256_HMAC384_SIZE_BYTES],
        )?;

        *bk_partition_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES;

        Ok(())
    }

    /// Generate Partition or Session Backup Masking Key (BMK).
    ///
    /// # Arguments
    /// * `env` - The cryptographic environment to use.
    /// * `algo` - The crypto algorithm to use for the masking the masking key.
    /// * `bk` - The Partition/Session backup key. This key is used to encrypt the generated Partition/Session masking key.
    /// * `metadata` - The metadata to be associated with the masking key.
    /// * `bmk_len` - In/out parameter for the length of the Partition/Session BMK.
    /// * `bmk_out` - Output buffer for the encoded Partition/Session BMK.
    ///
    /// # Returns
    /// * `Ok(())` - If the Partition/Session BMK is successfully generated.
    /// * `Err(ManticoreError)` - If there is an error during the generation process.
    pub fn bmk_gen<Env: CryptEnv>(
        env: &Env,
        algo: MaskingKeyAlgorithm,
        bk: &[u8],
        metadata: &[u8],
        bmk_len: &mut usize,
        bmk_out: &mut [u8],
    ) -> Result<(), ManticoreError> {
        // Check BMK algo. Only AesCbc256Hmac384 is supported for now.
        if algo != MaskingKeyAlgorithm::AesCbc256Hmac384 {
            Err(ManticoreError::InvalidAlgorithm)?;
        }

        // Validate BK length
        if bk.len() < BK_AES_CBC_256_HMAC384_SIZE_BYTES {
            Err(ManticoreError::InvalidKeyLength)?;
        }

        // Get the encrypted key length
        let encrypted_key_len = env.aescbc256_enc_data_len(MK_AES_CBC_256_HMAC384_SIZE_BYTES);

        let encoded_length = MaskedKey::encoded_length(
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            metadata.len(),
            encrypted_key_len,
        );

        if *bmk_len < encoded_length || bmk_out.len() < encoded_length {
            *bmk_len = encoded_length;
            Err(ManticoreError::OutputBufferTooSmall)?;
        }

        // 1. Generate random seed for masking key.
        let mut masking_key_seed = [0u8; MK_SEED_SIZE_BYTES];
        env.generate_random(&mut masking_key_seed)?;

        // 2. Derive masking key using KBKDF.
        let mut masking_key = [0u8; MK_AES_CBC_256_HMAC384_SIZE_BYTES];
        env.kbkdf_sha384(
            &masking_key_seed,
            Some(MK_DEFAULT_LABEL),
            None,
            MK_AES_CBC_256_HMAC384_SIZE_BYTES,
            &mut masking_key,
        )?;

        // 3. Pre-encode the masking key.
        let mut pre_encoded = MaskedKey::pre_encode(
            1,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            metadata.len(),
            encrypted_key_len,
            bmk_out[..encoded_length].as_mut(),
        )
        .map_err(|_| ManticoreError::MaskedKeyPreEncodeFailed)?;

        // 4. Encode the masking key into bmk_out.
        MaskedKey::encode(env, &mut pre_encoded, masking_key.as_slice(), bk, metadata)
            .map_err(|_| ManticoreError::MaskedKeyEncodeFailed)?;

        *bmk_len = encoded_length;

        Ok(())
    }

    /// Encode masked key metadata into MBOR format.
    ///
    /// # Arguments
    /// * `device_kind` - The kind of device (e.g., Physical, Virtual).
    /// * `svn` - The security version number (optional).
    /// * `key_kind` - The type of the key.
    /// * `key_attributes` - Attributes associated with the key.
    /// * `bks2_index` - The index of the BKS2 (optional).
    /// * `key_tag` - A tag associated with the key (optional).
    /// * `key_label` - A label for the key.
    /// * `metadata_len` - In/out parameter for the length of the encoded metadata.
    /// * `encoded_metadata` - Output buffer for the encoded metadata.
    ///
    /// # Returns
    /// * `Ok(())` - If the metadata is successfully encoded.
    /// * `Err(ManticoreError)` - If there is an error during the encoding process.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_masked_key_metadata(
        device_kind: DdiDeviceKind,
        svn: Option<u64>,
        key_kind: DdiKeyType,
        key_attributes: DdiMaskedKeyAttributes,
        bks2_index: Option<u16>,
        key_tag: Option<u16>,
        key_label: &[u8],
        metadata_len: &mut usize,
        encoded_metadata: &mut [u8],
        key_length: u16,
    ) -> Result<(), ManticoreError> {
        // Mbor encode the metadata.
        let metadata = DdiMaskedKeyMetadata {
            svn,
            key_type: key_kind,
            key_attributes,
            bks2_index,
            key_tag,
            key_label: MborByteArray::<128>::from_slice(key_label)
                .map_err(|_| ManticoreError::MborEncodeFailed)?,
            key_length,
        };

        let mut accumulator = MborLenAccumulator::default();
        metadata.mbor_len(&mut accumulator);
        let len = accumulator.len();

        if len > *metadata_len || len > encoded_metadata.len() {
            *metadata_len = len;
            Err(ManticoreError::OutputBufferTooSmall)?;
        }

        let (pre_encode, _) = match device_kind {
            DdiDeviceKind::Physical => (true, true),
            _ => (false, false),
        };

        let mut encoder = MborEncoder::new(&mut encoded_metadata[..len], pre_encode);
        metadata
            .mbor_encode(&mut encoder)
            .map_err(|_| ManticoreError::MetadataEncodeFailed)?;

        if encoder.position() != len {
            Err(ManticoreError::MetadataEncodeFailed)?;
        }

        *metadata_len = len;
        Ok(())
    }

    /// Decode masked key metadata from MBOR format.
    ///
    /// # Arguments
    /// * `device_kind` - The kind of device (e.g., Physical, Virtual).
    /// * `encoded_metadata` - The encoded metadata in MBOR format.
    ///
    /// # Returns
    /// * `Ok(DdiMaskedKeyMetadata)` - The decoded metadata.
    /// * `Err(ManticoreError)` - If there is an error during the decoding process.
    pub fn decode_masked_key_metadata(
        device_kind: DdiDeviceKind,
        encoded_metadata: &[u8],
    ) -> Result<DdiMaskedKeyMetadata, ManticoreError> {
        let (pre_encode, _) = match device_kind {
            DdiDeviceKind::Physical => (true, true),
            _ => (false, false),
        };

        let mut decoder = MborDecoder::new(encoded_metadata, pre_encode);
        let metadata = DdiMaskedKeyMetadata::mbor_decode(&mut decoder)
            .map_err(|_| ManticoreError::MetadataDecodeFailed)?;

        Ok(metadata)
    }

    /// Restore the Backup Masking Key (BMK).
    ///
    /// # Arguments
    /// * `env` - The cryptographic environment to use.
    /// * `bk` - The backup key.
    /// * `bmk` - The masked key containing the encrypted masking key.
    ///
    /// # Returns
    /// * `Ok(DecodedMaskedKey)` - The decoded masking key.
    /// * `Err(ManticoreError)` - If there is an error during the restoration process.
    ///
    /// # Note
    /// decrypt_key is expected to be called on the returned DecodedMaskedKey to decrypt the masking key with BK.
    pub fn bmk_restore<'a, Env: CryptEnv>(
        env: &Env,
        bk: &[u8],
        bmk: &'a [u8],
    ) -> Result<DecodedMaskedKey<'a>, ManticoreError> {
        MaskedKey::decode(env, bk, bmk, true).map_err(|_| ManticoreError::MaskedKeyDecodeFailed)
    }

    /// Generate an ephemeral key for masking BK3.
    ///
    /// # Arguments
    /// * `env` - The cryptographic environment to use.
    /// * `algo` - The crypto algorithm to use for the ephemeral key generation.
    /// * `ephemeral_key_len` - The length of the ephemeral key to be generated.
    /// * `ephemeral_key_out` - Output buffer for the generated ephemeral key.
    ///
    /// # Returns
    /// * `Ok(())` - If the ephemeral key is successfully generated.
    /// * `Err(ManticoreError)` - If there is an error during the generation process.
    pub fn ephemeral_key_gen<Env: CryptEnv>(
        env: &Env,
        algo: MaskingKeyAlgorithm,
        ephemeral_key_len: usize,
        ephemeral_key_out: &mut [u8],
    ) -> Result<(), ManticoreError> {
        // Check ephemeral key algo. Only AesCbc256Hmac384 is supported for now.
        if algo != MaskingKeyAlgorithm::AesCbc256Hmac384 {
            Err(ManticoreError::InvalidAlgorithm)?;
        }

        // Validate ephemeral key length.
        if ephemeral_key_len != (AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE) {
            Err(ManticoreError::InvalidKeyLength)?;
        }

        // Validate output buffer size.
        if ephemeral_key_out.len() < ephemeral_key_len {
            Err(ManticoreError::OutputBufferTooSmall)?;
        }

        // Generate random seed for ephemeral key.
        let mut ephemeral_key_seed = [0u8; MK_SEED_SIZE_BYTES];
        env.generate_random(&mut ephemeral_key_seed)?;

        // Derive ephemeral key using KBKDF.
        env.kbkdf_sha384(
            &ephemeral_key_seed,
            Some(EPHMR_KEY_DEFAULT_LABEL),
            None,
            ephemeral_key_len,
            ephemeral_key_out,
        )?;

        Ok(())
    }

    /// Mask the BK3 (MBK3) with the ephemeral key.
    ///
    /// # Arguments
    /// * `env` - The cryptographic environment to use.
    /// * `algo` - The crypto algorithm to use for the masking the BK3.
    /// * `ephemeral_key` - The secret key to use for masking the BK3.
    /// * `bk3` - The backup key 3 (BK3) to be masked.
    /// * `metadata` - The metadata to be associated with the masked BK3.
    /// * `mbk3_len` - In/out parameter for the length of the masked BK3.
    /// * `mbk3_out` - Output buffer for the masked BK3.
    ///
    /// # Returns
    /// * `Ok(())` - If the BMK is successfully generated.
    /// * `Err(ManticoreError)` - If there is an error during the generation process.
    pub fn masked_bk3_gen<Env: CryptEnv>(
        env: &Env,
        algo: MaskingKeyAlgorithm,
        ephemeral_key: &[u8],
        bk3: &[u8],
        metadata: &[u8],
        mbk3_len: &mut usize,
        mbk3_out: &mut [u8],
    ) -> Result<(), ManticoreError> {
        // Check ephemeral key type. Only AesCbc256Hmac384 is supported for now.
        if algo != MaskingKeyAlgorithm::AesCbc256Hmac384 {
            Err(ManticoreError::InvalidAlgorithm)?;
        }

        // Validate ephemeral key length.
        if ephemeral_key.len() != (AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE) {
            Err(ManticoreError::InvalidKeyLength)?;
        }

        // Get the encrypted key length
        let encrypted_key_len = env.aescbc256_enc_data_len(bk3.len());

        let encoded_length = MaskedKey::encoded_length(
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            metadata.len(),
            encrypted_key_len,
        );

        if *mbk3_len < encoded_length || mbk3_out.len() < encoded_length {
            *mbk3_len = encoded_length;
            Err(ManticoreError::OutputBufferTooSmall)?;
        }

        // 1. Pre-encode BK3.
        let mut pre_encoded = MaskedKey::pre_encode(
            1,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            metadata.len(),
            encrypted_key_len,
            mbk3_out[..encoded_length].as_mut(),
        )
        .map_err(|_| ManticoreError::MaskedKeyPreEncodeFailed)?;

        // 2. Encode the BK3 in mbk3_out buffer.
        MaskedKey::encode(env, &mut pre_encoded, bk3, ephemeral_key, metadata)
            .map_err(|_| ManticoreError::MaskedKeyEncodeFailed)?;

        *mbk3_len = encoded_length;

        Ok(())
    }

    /// Mask the Ephemeral Key (EPHMRK) with a temporary secret key generated from the BK seeds and UEFI key.
    ///
    /// # Arguments
    /// * `env` - The cryptographic environment to use.
    /// * `algo` - The crypto algorithm to use for the masking the EPHMRK.
    /// * `ephemeral_key` - The key to be masked (aka EPHMRK)
    /// * `bks1` - The first backup seed (BKS1).
    /// * `bks2` - The second backup seed (BKS2).
    /// * `fw_secret` - The firmware secret for generating the temporary secret key. This is used to mask the EPHMRK.
    /// * `metadata` - The metadata to be associated with the masked EPHMRK.
    /// * `memphk_len` - In/out parameter for the length of the masked EPHMRK.
    /// * `memphk_out` - Output buffer for the masked EPHMRK.
    ///
    /// # Returns
    /// * `Ok(())` - If the EPHMRK is successfully generated.
    /// * `Err(ManticoreError)` - If there is an error during the generation process.
    #[allow(clippy::too_many_arguments)]
    pub fn masked_emphk_gen<Env: CryptEnv>(
        env: &Env,
        algo: MaskingKeyAlgorithm,
        ephemeral_key: &[u8],
        bks1: &[u8; BK_SEED_SIZE_BYTES],
        bks2: &[u8; BK_SEED_SIZE_BYTES],
        fw_secret: &[u8; FW_SECRET_SIZE_BYTES],
        metadata: &[u8],
        memphk_len: &mut usize,
        memphk_out: &mut [u8],
    ) -> Result<(), ManticoreError> {
        // Check ephemeral key type. Only AesCbc256Hmac384 is supported for now.
        if algo != MaskingKeyAlgorithm::AesCbc256Hmac384 {
            Err(ManticoreError::InvalidAlgorithm)?;
        }

        let encrypted_key_len = env.aescbc256_enc_data_len(ephemeral_key.len());

        let encoded_length = MaskedKey::encoded_length(
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            metadata.len(),
            encrypted_key_len,
        );

        if *memphk_len < encoded_length || memphk_out.len() < encoded_length {
            *memphk_len = encoded_length;
            Err(ManticoreError::OutputBufferTooSmall)?;
        }

        // 1. Derive the temporary masking key using KBKDF of UEFI key & (BKS1 || BKS2).

        // BKS12 is the concatenation of BKS1 and BKS2 and is used as KBKDF context.
        let mut bks1_2 = [0u8; BK_SEED_SIZE_BYTES * 2];
        bks1_2[..BK_SEED_SIZE_BYTES].copy_from_slice(bks1);
        bks1_2[BK_SEED_SIZE_BYTES..].copy_from_slice(bks2);

        let mut masking_key_tmp = [0u8; EMPH_MK_AES_CBC_256_HMAC384_SIZE_BYTES];
        env.kbkdf_sha384(
            fw_secret,
            Some(EPHMR_MASKING_KEY_DEFAULT_LABEL),
            Some(&bks1_2),
            EMPH_MK_AES_CBC_256_HMAC384_SIZE_BYTES,
            &mut masking_key_tmp,
        )?;

        // 2. Pre-encode the ephemeral key.
        let mut pre_encoded = MaskedKey::pre_encode(
            1,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            metadata.len(),
            encrypted_key_len,
            memphk_out[..encoded_length].as_mut(),
        )
        .map_err(|_| ManticoreError::MaskedKeyPreEncodeFailed)?;

        // 3. Encode the ephemeral key into mbk3_out.
        MaskedKey::encode(
            env,
            &mut pre_encoded,
            ephemeral_key,
            &masking_key_tmp,
            metadata,
        )
        .map_err(|_| ManticoreError::MaskedKeyEncodeFailed)?;

        *memphk_len = encoded_length;

        Ok(())
    }

    /// Generate the Session Backup Key using the provided session seed and the Partition backup key.
    ///
    /// # Arguments
    ///
    /// * `crypto_env` - The cryptographic environment to use.
    /// * `algo` - Indicates the type of the BK to be generated.
    /// * `session_seed` - Unique session value.
    /// * `bk_partition` - The partition backup key to derive the session backup key.
    /// * `bk_session_len` - In/out parameter for the length of the session backup key.
    ///   On input, it specifies the bk_session_out buffer size.
    ///   On output, it will contain the actual length of the generated backup key.
    /// * `bk_session_out` - Output buffer for the generated session backup key.
    ///
    /// # Returns
    /// * `Ok(())` - If the session backup key is successfully generated.
    /// * `Err(ManticoreError)` - If there is an error during the generation process.
    #[allow(clippy::too_many_arguments)]
    pub fn bk_session_gen<Env: CryptEnv>(
        crypto_env: &Env,
        algo: MaskingKeyAlgorithm,
        session_seed: &[u8; SESSION_SEED_SIZE_BYTES],
        bk_partition: &[u8],
        bk_session_len: &mut usize,
        bk_session_out: &mut [u8],
    ) -> Result<(), ManticoreError> {
        // Check BK Partition key algo. Only AesCbc256Hmac384 is supported for now.
        if algo != MaskingKeyAlgorithm::AesCbc256Hmac384 {
            Err(ManticoreError::InvalidAlgorithm)?;
        }

        if bk_partition.len() < BK_AES_CBC_256_HMAC384_SIZE_BYTES {
            Err(ManticoreError::InvalidKeyLength)?;
        }

        if *bk_session_len < BK_AES_CBC_256_HMAC384_SIZE_BYTES
            || bk_session_out.len() < BK_AES_CBC_256_HMAC384_SIZE_BYTES
        {
            *bk_session_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES;
            Err(ManticoreError::OutputBufferTooSmall)?;
        }

        // Derive BK Session via KBKDF; HMAC key from bk_partition combo key is used as the the KBKDF key and session seed as the context.

        // Use the HMAC key from the partition backup key as the KBKDF key.
        let key = &bk_partition[AES_CBC_256_KEY_SIZE..(AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE)];
        crypto_env.kbkdf_sha384(
            key,
            Some(SESSION_BK_LABEL),
            Some(session_seed),
            BK_AES_CBC_256_HMAC384_SIZE_BYTES,
            &mut bk_session_out[..BK_AES_CBC_256_HMAC384_SIZE_BYTES],
        )?;

        *bk_session_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_mbor::MborDecode;
    use azihsm_ddi_mbor::MborDecoder;
    use azihsm_ddi_types::MaskedKeyError;

    use super::*;
    use crate::crypto::sha::sha;
    use crate::crypto::sha::HashAlgorithm;
    use crate::table::entry::Kind;

    const TEST_BKS1: [u8; BK_SEED_SIZE_BYTES] = [0x01; BK_SEED_SIZE_BYTES];
    const TEST_BKS2: [u8; BK_SEED_SIZE_BYTES] = [0x02; BK_SEED_SIZE_BYTES];
    const TEST_BK3: [u8; BK3_SIZE_BYTES] = [0x03; BK3_SIZE_BYTES];
    const TEST_SESSION_SEED: [u8; SESSION_SEED_SIZE_BYTES] = [0x04; SESSION_SEED_SIZE_BYTES];
    const TEST_BK_PARTITION: [u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES] =
        [0xAA; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
    const TEST_EPHEMERAL_KEY: [u8; AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE] =
        [0xEE; AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE];
    const TEST_UEFI_KEY: [u8; FW_SECRET_SIZE_BYTES] = [0xFF; FW_SECRET_SIZE_BYTES];
    const TEST_OUTPUT_BUFFER_SIZE: usize = 1024;
    const TEST_METADATA_MAX_SIZE_BYTES: usize = 128;

    enum CryptoFunc {
        Hmac384Tag,
        AesCbc256Encrypt,
        AesCbc256Decrypt,
        KbkdfSha384,
        GenerateRandom,
    }

    struct TestCryptoEnv {
        plaintext: Vec<u8>,
        ciphertext: Vec<u8>,
        hmac384_tag: [u8; 48],
        error: Option<(CryptoFunc, ManticoreError)>,
    }

    impl TestCryptoEnv {
        pub fn new() -> Self {
            TestCryptoEnv {
                plaintext: Vec::new(),
                ciphertext: Vec::new(),
                hmac384_tag: [0u8; 48],
                error: None,
            }
        }
    }
    impl Default for TestCryptoEnv {
        fn default() -> Self {
            TestCryptoEnv::new()
        }
    }

    impl CryptEnv for TestCryptoEnv {
        fn hmac384_tag(&self, _key: &[u8], _data: &[u8]) -> Result<[u8; 48], ManticoreError> {
            if let Some((CryptoFunc::Hmac384Tag, err)) = self.error {
                return Err(err);
            }
            Ok(self.hmac384_tag)
        }

        fn aescbc256_enc_data_len(&self, plaintext_key_len: usize) -> usize {
            plaintext_key_len
        }

        fn aescbc256_encrypt(
            &self,
            _key: &[u8],
            _plaintext: &[u8],
            _iv: &mut [u8],
            ciphertext: &mut [u8],
        ) -> Result<usize, ManticoreError> {
            if let Some((CryptoFunc::AesCbc256Encrypt, err)) = self.error {
                return Err(err);
            }
            Ok(ciphertext.len())
        }

        fn aescbc256_decrypt(
            &self,
            _key: &[u8],
            _iv: &[u8],
            _ciphertext: &[u8],
            plaintext: &mut [u8],
        ) -> Result<usize, ManticoreError> {
            if let Some((CryptoFunc::AesCbc256Decrypt, err)) = self.error {
                return Err(err);
            }
            plaintext.copy_from_slice(self.plaintext.as_slice());
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
            if let Some((CryptoFunc::KbkdfSha384, err)) = self.error {
                return Err(err);
            }

            // Simple KBKDF implementation for testing: fill output with a repeated pattern
            // This is NOT cryptographically secure and is only for test purposes.
            let mut ctr = 1u32;
            let mut written = 0;
            while written < out_len {
                // Compose: [ctr (4 bytes)] + key + label + context
                let mut block = Vec::new();
                block.extend_from_slice(&ctr.to_be_bytes());
                block.extend_from_slice(key);
                if let Some(l) = label {
                    block.extend_from_slice(l);
                }
                if let Some(c) = context {
                    block.extend_from_slice(c);
                }
                // Hash the block (use SHA-384 for test)
                let hash = sha(HashAlgorithm::Sha384, &block)?;
                let to_copy = std::cmp::min(hash.len(), out_len - written);
                output[written..written + to_copy].copy_from_slice(&hash[..to_copy]);
                written += to_copy;
                ctr += 1;
            }
            Ok(())
        }

        fn generate_random(&self, output: &mut [u8]) -> Result<(), ManticoreError> {
            if let Some((CryptoFunc::GenerateRandom, err)) = self.error {
                return Err(err);
            }
            crate::crypto::rand::rand_bytes(output).map_err(|_| ManticoreError::RngError)
        }
    }

    #[test]
    fn test_bk_partition_gen_success() {
        let crypto_env = TestCryptoEnv::new();

        let mut bk_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES;
        let mut bk_out = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];

        let result = LMKeyDerive::bk_partition_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_BKS1,
            &TEST_BKS2,
            &TEST_BK3,
            &mut bk_len,
            &mut bk_out,
        );

        assert!(result.is_ok(), "bk_partition_gen should succeed");
        assert_eq!(bk_len, BK_AES_CBC_256_HMAC384_SIZE_BYTES);

        // Verify the output is not all zeros (indicating successful derivation)
        assert!(
            bk_out.iter().any(|&b| b != 0),
            "Derived BK should not be all zeros"
        );
    }

    #[test]
    fn test_bk_partition_gen_deterministic() {
        let crypto_env = TestCryptoEnv::new();

        // Generate BK twice with same inputs
        let mut bk_len1 = BK_AES_CBC_256_HMAC384_SIZE_BYTES;
        let mut bk_out1 = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];

        let mut bk_len2 = BK_AES_CBC_256_HMAC384_SIZE_BYTES;
        let mut bk_out2 = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];

        let result1 = LMKeyDerive::bk_partition_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_BKS1,
            &TEST_BKS2,
            &TEST_BK3,
            &mut bk_len1,
            &mut bk_out1,
        );

        let result2 = LMKeyDerive::bk_partition_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_BKS1,
            &TEST_BKS2,
            &TEST_BK3,
            &mut bk_len2,
            &mut bk_out2,
        );

        assert!(
            result1.is_ok() && result2.is_ok(),
            "Both BK generations should succeed"
        );
        assert_eq!(bk_out1, bk_out2, "BK derivation should be deterministic");
    }

    #[test]
    fn test_bk_partition_gen_different_inputs_different_outputs() {
        let crypto_env = TestCryptoEnv::new();

        // Different BK3
        let bk3_alt = [0x04; BK3_SIZE_BYTES];

        let mut bk_out1 = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
        let mut bk_out2 = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
        let mut bk_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES;

        let result1 = LMKeyDerive::bk_partition_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_BKS1,
            &TEST_BKS2,
            &TEST_BK3,
            &mut bk_len,
            &mut bk_out1,
        );
        assert!(result1.is_ok(), "bk_partition_gen should succeed");

        let result2 = LMKeyDerive::bk_partition_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_BKS1,
            &TEST_BKS2,
            &bk3_alt,
            &mut bk_len,
            &mut bk_out2,
        );
        assert!(
            result2.is_ok(),
            "bk_partition_gen with different BK3 should succeed"
        );

        assert_ne!(
            bk_out1, bk_out2,
            "Different inputs should produce different BKs"
        );
    }

    #[test]
    fn test_bk_partition_gen_insufficient_buffer() {
        let crypto_env = TestCryptoEnv::new();

        let mut bk_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES - 1; // Too small
        let mut bk_out = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES - 1];

        let result = LMKeyDerive::bk_partition_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_BKS1,
            &TEST_BKS2,
            &TEST_BK3,
            &mut bk_len,
            &mut bk_out,
        );

        assert!(matches!(result, Err(ManticoreError::OutputBufferTooSmall)));
        assert_eq!(bk_len, BK_AES_CBC_256_HMAC384_SIZE_BYTES);
    }

    #[test]
    fn test_bk_session_gen_success() {
        let crypto_env = TestCryptoEnv::new();

        let mut bk_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES;
        let mut bk_out = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];

        let result = LMKeyDerive::bk_session_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_SESSION_SEED,
            TEST_BK_PARTITION.as_ref(),
            &mut bk_len,
            &mut bk_out,
        );

        assert!(result.is_ok(), "bk_session_gen should succeed");
        assert_eq!(bk_len, BK_AES_CBC_256_HMAC384_SIZE_BYTES);

        // Verify the output is not all zeros (indicating successful derivation)
        assert!(
            bk_out.iter().any(|&b| b != 0),
            "Derived Session BK should not be all zeros"
        );
    }

    #[test]
    fn test_bk_session_gen_deterministic() {
        let crypto_env = TestCryptoEnv::new();

        // Generate BK Session twice with same inputs
        let mut bk_len1 = BK_AES_CBC_256_HMAC384_SIZE_BYTES;
        let mut bk_out1 = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];

        let mut bk_len2 = BK_AES_CBC_256_HMAC384_SIZE_BYTES;
        let mut bk_out2 = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];

        let result1 = LMKeyDerive::bk_session_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_SESSION_SEED,
            TEST_BK_PARTITION.as_ref(),
            &mut bk_len1,
            &mut bk_out1,
        );

        let result2 = LMKeyDerive::bk_session_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_SESSION_SEED,
            TEST_BK_PARTITION.as_ref(),
            &mut bk_len2,
            &mut bk_out2,
        );

        assert!(
            result1.is_ok() && result2.is_ok(),
            "Both BK Session generations should succeed"
        );
        assert_eq!(
            bk_out1, bk_out2,
            "BK Session derivation should be deterministic"
        );
    }

    #[test]
    fn test_bk_session_gen_different_inputs_different_outputs() {
        let crypto_env = TestCryptoEnv::new();

        // Different session seed
        let session_alt = [0x05; SESSION_SEED_SIZE_BYTES];

        let mut bk_out1 = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
        let mut bk_out2 = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
        let mut bk_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES;

        let result1 = LMKeyDerive::bk_session_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_SESSION_SEED,
            TEST_BK_PARTITION.as_ref(),
            &mut bk_len,
            &mut bk_out1,
        );
        assert!(result1.is_ok(), "bk_session_gen should succeed");

        let result2 = LMKeyDerive::bk_session_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &session_alt,
            TEST_BK_PARTITION.as_ref(),
            &mut bk_len,
            &mut bk_out2,
        );
        assert!(
            result2.is_ok(),
            "bk_session_gen with different BK3 should succeed"
        );

        assert_ne!(
            bk_out1, bk_out2,
            "Different inputs should produce different BKs"
        );
    }

    #[test]
    fn test_bk_session_gen_insufficient_buffer() {
        let crypto_env = TestCryptoEnv::new();

        let mut bk_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES - 1; // Too small
        let mut bk_out = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES - 1];

        let result = LMKeyDerive::bk_session_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_SESSION_SEED,
            TEST_BK_PARTITION.as_ref(),
            &mut bk_len,
            &mut bk_out,
        );

        assert!(matches!(result, Err(ManticoreError::OutputBufferTooSmall)));
        assert_eq!(bk_len, BK_AES_CBC_256_HMAC384_SIZE_BYTES);
    }

    #[test]
    fn test_bmk_gen_success() {
        let crypto_env = TestCryptoEnv::new();

        // First generate a BK
        let mut bk_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES;
        let mut bk = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];

        let result = LMKeyDerive::bk_partition_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_BKS1,
            &TEST_BKS2,
            &TEST_BK3,
            &mut bk_len,
            &mut bk,
        );
        assert!(result.is_ok(), "BK generation should succeed");

        let mut metadata = [0u8; TEST_METADATA_MAX_SIZE_BYTES];
        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            Some(1),
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"Test BMK",
            &mut metadata.len(),
            &mut metadata,
            bk_len as u16,
        );
        assert!(result.is_ok(), "Metadata encoding should succeed");

        // Get the required length for BMK
        let mut bmk_len = 0;
        let result = LMKeyDerive::bmk_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &bk,
            &metadata[..metadata.len()],
            &mut bmk_len,
            &mut [0u8; 0],
        );
        assert!(
            result.is_err(),
            "BMK generation should fail due to insufficient buffer"
        );
        assert!(matches!(result, Err(ManticoreError::OutputBufferTooSmall)));

        // Now set bmk_len to the required size and try again
        let required_len = bmk_len;
        let mut bmk_out = vec![0u8; bmk_len];
        let result = LMKeyDerive::bmk_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &bk,
            &metadata[..metadata.len()],
            &mut bmk_len,
            &mut bmk_out,
        );

        assert!(result.is_ok(), "BMK generation should succeed");
        assert_eq!(bmk_len, required_len);

        // Verify the output is not all zeros
        assert!(
            bmk_out.iter().any(|&b| b != 0),
            "Generated BMK should not be all zeros"
        );
    }

    #[test]
    fn test_bmk_gen_insufficient_buffer() {
        let crypto_env = TestCryptoEnv::new();
        let bk = [0x01; BK_AES_CBC_256_HMAC384_SIZE_BYTES];

        let mut metadata = [0u8; TEST_METADATA_MAX_SIZE_BYTES];
        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            Some(1),
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"Test BMK",
            &mut metadata.len(),
            &mut metadata,
            bk.len() as u16,
        );
        assert!(result.is_ok(), "Metadata encoding should succeed");

        let mut bmk_len = 10; // Too small
        let mut bmk_out = vec![0u8; 10];

        let result = LMKeyDerive::bmk_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &bk,
            &metadata[..metadata.len()],
            &mut bmk_len,
            &mut bmk_out,
        );

        assert!(matches!(result, Err(ManticoreError::OutputBufferTooSmall)));
        // bmk_len should be updated to the required size
        assert!(bmk_len > 10);
    }

    #[test]
    fn test_bmk_gen_invalid_bk_length() {
        let crypto_env = TestCryptoEnv::new();
        let bk_short = [0x01; BK_AES_CBC_256_HMAC384_SIZE_BYTES - 1]; // Too short

        let mut metadata = [0u8; TEST_METADATA_MAX_SIZE_BYTES];
        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            Some(1),
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"Test BMK",
            &mut metadata.len(),
            &mut metadata,
            bk_short.len() as u16,
        );
        assert!(result.is_ok(), "Metadata encoding should succeed");

        let mut bmk_len = 1000;
        let mut bmk_out = vec![0u8; 1000];

        let result = LMKeyDerive::bmk_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &bk_short,
            &metadata[..metadata.len()],
            &mut bmk_len,
            &mut bmk_out,
        );

        assert!(matches!(result, Err(ManticoreError::InvalidKeyLength)));
    }

    #[test]
    fn test_bmk_restore_success() {
        let crypto_env = TestCryptoEnv::new();

        // Generate BK
        let mut bk_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES;
        let mut bk = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];

        let result = LMKeyDerive::bk_partition_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_BKS1,
            &TEST_BKS2,
            &TEST_BK3,
            &mut bk_len,
            &mut bk,
        );
        assert!(result.is_ok(), "BK generation should succeed");

        let svn = 42;
        let mut metadata = [0u8; TEST_METADATA_MAX_SIZE_BYTES];
        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            Some(svn),
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"Test BMK",
            &mut metadata.len(),
            &mut metadata,
            bk_len as u16,
        );
        assert!(result.is_ok(), "Metadata encoding should succeed");

        // Get the required length for BMK
        let mut bmk_len = 0;
        let result = LMKeyDerive::bmk_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &bk,
            &metadata[..metadata.len()],
            &mut bmk_len,
            &mut [0u8; 0],
        );
        assert!(
            result.is_err(),
            "BMK generation should fail due to insufficient buffer"
        );
        assert!(matches!(result, Err(ManticoreError::OutputBufferTooSmall)));

        // Now set bmk_len to the required size and try again
        let required_len = bmk_len;
        let mut bmk = vec![0u8; bmk_len];
        let result = LMKeyDerive::bmk_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &bk,
            &metadata[..metadata.len()],
            &mut bmk_len,
            &mut bmk,
        );

        assert!(result.is_ok(), "BMK generation should succeed");
        assert_eq!(bmk_len, required_len);

        // Now test restore
        let result = LMKeyDerive::bmk_restore(&crypto_env, &bk, &bmk);

        assert!(result.is_ok(), "BMK restore should succeed");
        let decoded_key = result.unwrap();

        // Extract the AES key for individual field verification
        let aes_key = decoded_key.as_aes().unwrap();

        // Convert the metadata to a DdiMaskedKeyMetadata
        let decoded_data =
            LMKeyDerive::decode_masked_key_metadata(DdiDeviceKind::Physical, aes_key.metadata());
        assert!(decoded_data.is_ok(), "Metadata should decode successfully");
        let decoded_metadata = decoded_data.unwrap();
        assert_eq!(decoded_metadata.key_type, DdiKeyType::AesCbc256Hmac384);
        assert_eq!(decoded_metadata.svn, Some(svn));
        assert_eq!(decoded_metadata.key_label.as_slice(), b"Test BMK");
    }

    #[test]
    fn test_bmk_restore_with_wrong_bk() {
        let mut crypto_env = TestCryptoEnv::new();

        // Generate BK
        let mut bk_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES;
        let mut bk = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];

        let result = LMKeyDerive::bk_partition_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_BKS1,
            &TEST_BKS2,
            &TEST_BK3,
            &mut bk_len,
            &mut bk,
        );
        assert!(result.is_ok());

        let svn: u64 = 100;
        let mut metadata = [0u8; TEST_METADATA_MAX_SIZE_BYTES];
        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            Some(svn),
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"Test BMK",
            &mut metadata.len(),
            &mut metadata,
            bk_len as u16,
        );
        assert!(result.is_ok(), "Metadata encoding should succeed");

        // Get the required length for BMK
        let mut bmk_len = 0;
        let result = LMKeyDerive::bmk_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &bk,
            &metadata[..metadata.len()],
            &mut bmk_len,
            &mut [0u8; 0],
        );
        assert!(
            result.is_err(),
            "BMK generation should fail due to insufficient buffer"
        );
        assert!(matches!(result, Err(ManticoreError::OutputBufferTooSmall)));

        // Now set bmk_len to the required size and try again
        let required_len = bmk_len;
        let mut bmk = vec![0u8; bmk_len];
        let result = LMKeyDerive::bmk_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &bk,
            &metadata[..metadata.len()],
            &mut bmk_len,
            &mut bmk,
        );

        assert!(result.is_ok(), "BMK generation should succeed");
        assert_eq!(bmk_len, required_len);

        // Try to restore with wrong BK
        let wrong_bk = [0xFF; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
        crypto_env.error = Some((
            CryptoFunc::AesCbc256Decrypt,
            ManticoreError::AesDecryptFailed,
        ));
        let result = LMKeyDerive::bmk_restore(&crypto_env, &wrong_bk, &bmk);
        assert!(result.is_ok(), "BMK restore should succeed");
        let decoded_key = result.unwrap();

        let mut decrypted_key = vec![0u8; bmk_len];
        let result = decoded_key.decrypt_key(&crypto_env, &wrong_bk, decrypted_key.as_mut_slice());
        assert!(
            matches!(result, Err(MaskedKeyError::AesDecryptionFailed)),
            "Restore with wrong BK should fail"
        );
    }

    #[test]
    fn test_full_live_migration_workflow() {
        let crypto_env = TestCryptoEnv::new();

        // Step 1: Generate BK (Backup Key)
        let mut bk_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES;
        let mut bk = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];

        let result = LMKeyDerive::bk_partition_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_BKS1,
            &TEST_BKS2,
            &TEST_BK3,
            &mut bk_len,
            &mut bk,
        );
        assert!(result.is_ok(), "Step 1: BK generation should succeed");

        let svn: u64 = 2;
        let mut metadata = [0u8; TEST_METADATA_MAX_SIZE_BYTES];
        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            Some(svn),
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"Test BMK",
            &mut metadata.len(),
            &mut metadata,
            bk_len as u16,
        );
        assert!(result.is_ok(), "Metadata encoding should succeed");

        // Step 2: Generate BMK (Backup Masking Key)
        // Get the required length for BMK
        let mut bmk_len = 0;
        let result = LMKeyDerive::bmk_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &bk,
            &metadata[..metadata.len()],
            &mut bmk_len,
            &mut [0u8; 0],
        );
        assert!(
            result.is_err(),
            "BMK generation should fail due to insufficient buffer"
        );
        assert!(matches!(result, Err(ManticoreError::OutputBufferTooSmall)));

        // Now set bmk_len to the required size and try again
        let required_len = bmk_len;
        let mut bmk = vec![0u8; bmk_len];
        let result = LMKeyDerive::bmk_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &bk,
            &metadata[..metadata.len()],
            &mut bmk_len,
            &mut bmk,
        );

        assert!(result.is_ok(), "Step 2: BMK generation should succeed");
        assert_eq!(bmk_len, required_len);

        // Step 3: Restore MK (Masking Key) from BMK
        let result = LMKeyDerive::bmk_restore(&crypto_env, &bk, &bmk);
        assert!(result.is_ok(), "Step 3: BMK restore should succeed");

        let decoded_key = result.unwrap();

        // Extract the AES key for individual field verification
        let aes_key = decoded_key.as_aes().unwrap();
        let metadata = aes_key.metadata();

        // Convert the metadata to a DdiMaskedKeyMetadata
        let mut decoder = MborDecoder::new(metadata, true);
        let decoded_data = DdiMaskedKeyMetadata::mbor_decode(&mut decoder);
        assert!(decoded_data.is_ok(), "Metadata should decode successfully");
        let decoded_metadata = decoded_data.unwrap();
        assert_eq!(decoded_metadata.key_type, DdiKeyType::AesCbc256Hmac384);
        assert_eq!(decoded_metadata.svn, Some(svn));
        assert_eq!(decoded_metadata.key_label.as_slice(), b"Test BMK");
    }

    #[test]
    fn test_ephemeral_key_gen_invalid_algorithm() {
        let crypto_env = TestCryptoEnv::new();
        let mut output = vec![0u8; 32];

        let result = LMKeyDerive::ephemeral_key_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesGcm256, // Unsupported algorithm
            32,
            &mut output,
        );

        assert!(result.is_err(), "Should return error for invalid algorithm");
        assert!(matches!(result, Err(ManticoreError::InvalidAlgorithm)));
    }

    #[test]
    fn test_ephemeral_key_gen_invalid_key_length() {
        let crypto_env = TestCryptoEnv::new();
        let mut output = vec![0u8; 16]; // Invalid length for AesCbc256Hmac384

        let result = LMKeyDerive::ephemeral_key_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            16, // Invalid length
            &mut output,
        );

        assert!(
            result.is_err(),
            "Should return error for invalid key length"
        );
        assert!(matches!(result, Err(ManticoreError::InvalidKeyLength)));
    }

    #[test]
    fn test_ephemeral_key_gen_insufficient_buffer() {
        let crypto_env = TestCryptoEnv::new();
        let mut output = vec![0u8; AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE - 1];
        let result = LMKeyDerive::ephemeral_key_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE,
            &mut output,
        );
        assert!(
            result.is_err(),
            "Should return error for insufficient buffer"
        );
        assert!(matches!(result, Err(ManticoreError::OutputBufferTooSmall)));
    }

    #[test]
    fn test_ephemeral_key_gen_crypto_env_random_error() {
        let mut crypto_env = TestCryptoEnv::new();
        let mut output = vec![0u8; AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE];

        crypto_env.error = Some((CryptoFunc::GenerateRandom, ManticoreError::InvalidArgument));
        let result = LMKeyDerive::ephemeral_key_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            output.len(),
            &mut output,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_ephemeral_key_gen_crypto_env_kbkdf_error() {
        let mut crypto_env = TestCryptoEnv::new();
        let mut output = vec![0u8; AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE];

        crypto_env.error = Some((CryptoFunc::KbkdfSha384, ManticoreError::KbkdfError));
        let result = LMKeyDerive::ephemeral_key_gen(
            &crypto_env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            output.len(),
            &mut output,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_masked_bk3_gen_success() {
        let env = TestCryptoEnv::new();
        let mut mbk3_out = [0u8; TEST_OUTPUT_BUFFER_SIZE];
        let mut mbk3_len = mbk3_out.len();

        let mut metadata = [0u8; TEST_METADATA_MAX_SIZE_BYTES];
        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            None,
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"Test BK3",
            &mut metadata.len(),
            &mut metadata,
            TEST_BK3.len() as u16,
        );
        assert!(result.is_ok(), "Metadata encoding should succeed");

        let result = LMKeyDerive::masked_bk3_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_EPHEMERAL_KEY,
            &TEST_BK3,
            &metadata[..metadata.len()],
            &mut mbk3_len,
            &mut mbk3_out,
        );

        assert!(result.is_ok());
        assert!(mbk3_len > 0);
        assert!(mbk3_len <= 1024);
        assert!(
            mbk3_out.iter().any(|&b| b != 0),
            "Masked BK3 should not be all zeros"
        );
    }

    #[test]
    fn test_masked_bk3_gen_deterministic() {
        let env = TestCryptoEnv::new();

        let mut metadata = [0u8; TEST_METADATA_MAX_SIZE_BYTES];
        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            None,
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"Test BK3",
            &mut metadata.len(),
            &mut metadata,
            TEST_BK3.len() as u16,
        );
        assert!(result.is_ok(), "Metadata encoding should succeed");

        // First call
        let mut mbk3_out1 = [0u8; TEST_OUTPUT_BUFFER_SIZE];
        let mut mbk3_len1 = mbk3_out1.len();
        let result1 = LMKeyDerive::masked_bk3_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_EPHEMERAL_KEY,
            &TEST_BK3,
            &metadata[..metadata.len()],
            &mut mbk3_len1,
            &mut mbk3_out1,
        );

        // Second call with same inputs
        let mut mbk3_out2 = [0u8; TEST_OUTPUT_BUFFER_SIZE];
        let mut mbk3_len2 = mbk3_out2.len();
        let result2 = LMKeyDerive::masked_bk3_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_EPHEMERAL_KEY,
            &TEST_BK3,
            &metadata[..metadata.len()],
            &mut mbk3_len2,
            &mut mbk3_out2,
        );

        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_eq!(mbk3_len1, mbk3_len2);
        assert!(
            mbk3_out1.iter().any(|&b| b != 0),
            "Masked BK3 should not be all zeros"
        );
        assert_eq!(&mbk3_out1[..mbk3_len1], &mbk3_out2[..mbk3_len2]);
    }

    #[test]
    fn test_masked_bk3_gen_empty_ephemeral_key() {
        let env = TestCryptoEnv::new();
        let empty_ephemeral_key = [];
        let mut mbk3_out = [0u8; TEST_OUTPUT_BUFFER_SIZE];
        let mut mbk3_len = mbk3_out.len();

        let mut metadata = [0u8; TEST_METADATA_MAX_SIZE_BYTES];
        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            None,
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"Test BK3",
            &mut metadata.len(),
            &mut metadata,
            TEST_BK3.len() as u16,
        );
        assert!(result.is_ok(), "Metadata encoding should succeed");

        let result = LMKeyDerive::masked_bk3_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &empty_ephemeral_key,
            &TEST_BK3,
            &metadata[..metadata.len()],
            &mut mbk3_len,
            &mut mbk3_out,
        );

        // Should fail with invalid parameter error
        assert!(result.is_err());
        assert!(matches!(result, Err(ManticoreError::InvalidKeyLength)));
    }

    #[test]
    fn test_masked_bk3_gen_empty_bk3() {
        let env = TestCryptoEnv::new();
        let empty_bk3 = [];
        let mut mbk3_out = [0u8; TEST_OUTPUT_BUFFER_SIZE];
        let mut mbk3_len = mbk3_out.len();

        let mut metadata = [0u8; TEST_METADATA_MAX_SIZE_BYTES];
        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            None,
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"Test BK3",
            &mut metadata.len(),
            &mut metadata,
            empty_bk3.len() as u16,
        );
        assert!(result.is_ok(), "Metadata encoding should succeed");

        let result = LMKeyDerive::masked_bk3_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_EPHEMERAL_KEY,
            &empty_bk3,
            &metadata[..metadata.len()],
            &mut mbk3_len,
            &mut mbk3_out,
        );

        // Should fail with invalid parameter error
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ManticoreError::MaskedKeyPreEncodeFailed)
        ));
    }

    #[test]
    fn test_masked_bk3_gen_small_output_buffer() {
        let env = TestCryptoEnv::new();
        let mut small_buffer = [0u8; 10]; // Very small buffer
        let mut mbk3_len = small_buffer.len();

        let mut metadata = [0u8; TEST_METADATA_MAX_SIZE_BYTES];
        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            None,
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"Test BK3",
            &mut metadata.len(),
            &mut metadata,
            TEST_BK3.len() as u16,
        );
        assert!(result.is_ok(), "Metadata encoding should succeed");

        let result = LMKeyDerive::masked_bk3_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_EPHEMERAL_KEY,
            &TEST_BK3,
            &metadata[..metadata.len()],
            &mut mbk3_len,
            &mut small_buffer,
        );

        // Should fail due to insufficient buffer size
        assert!(result.is_err());
        assert!(matches!(result, Err(ManticoreError::OutputBufferTooSmall)));
    }

    #[test]
    fn test_masked_emphk_gen_success() {
        let env = TestCryptoEnv::new();
        let mut memphk_out = [0u8; TEST_OUTPUT_BUFFER_SIZE];
        let mut memphk_len = memphk_out.len();

        let mut metadata = [0u8; TEST_METADATA_MAX_SIZE_BYTES];
        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            None,
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"Test EMPHK",
            &mut metadata.len(),
            &mut metadata,
            EMPH_MK_AES_CBC_256_HMAC384_SIZE_BYTES as u16,
        );
        assert!(result.is_ok(), "Metadata encoding should succeed");

        let result = LMKeyDerive::masked_emphk_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_EPHEMERAL_KEY,
            &TEST_BKS1,
            &TEST_BKS2,
            &TEST_UEFI_KEY,
            &metadata[..metadata.len()],
            &mut memphk_len,
            &mut memphk_out,
        );

        assert!(result.is_ok());
        assert!(memphk_len > 0);
        assert!(memphk_len <= TEST_OUTPUT_BUFFER_SIZE);
        assert!(
            memphk_out.iter().any(|&b| b != 0),
            "Masked ephemeral key should not be all zeros"
        );
    }

    #[test]
    fn test_masked_emphk_gen_deterministic() {
        let env = TestCryptoEnv::new();

        let mut metadata = [0u8; TEST_METADATA_MAX_SIZE_BYTES];
        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            None,
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"Test EMPHK",
            &mut metadata.len(),
            &mut metadata,
            EMPH_MK_AES_CBC_256_HMAC384_SIZE_BYTES as u16,
        );
        assert!(result.is_ok(), "Metadata encoding should succeed");

        // First call
        let mut memphk_out1 = [0u8; TEST_OUTPUT_BUFFER_SIZE];
        let mut memphk_len1 = memphk_out1.len();
        let result1 = LMKeyDerive::masked_emphk_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_EPHEMERAL_KEY,
            &TEST_BKS1,
            &TEST_BKS2,
            &TEST_UEFI_KEY,
            &metadata[..metadata.len()],
            &mut memphk_len1,
            &mut memphk_out1,
        );

        // Second call with same inputs
        let ephemeral_key2 = [0xFFu8; AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE];
        let mut memphk_out2 = [0u8; TEST_OUTPUT_BUFFER_SIZE];
        let mut memphk_len2 = memphk_out2.len();
        let result2 = LMKeyDerive::masked_emphk_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &ephemeral_key2,
            &TEST_BKS1,
            &TEST_BKS2,
            &TEST_UEFI_KEY,
            &metadata[..metadata.len()],
            &mut memphk_len2,
            &mut memphk_out2,
        );

        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_eq!(memphk_len1, memphk_len2);
    }

    #[test]
    fn test_masked_emphk_gen_small_output_buffer() {
        let env = TestCryptoEnv::new();
        let mut small_buffer = [0u8; 10]; // Very small buffer
        let mut memphk_len = small_buffer.len();

        let mut metadata = [0u8; TEST_METADATA_MAX_SIZE_BYTES];
        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            None,
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"Test EMPHK",
            &mut metadata.len(),
            &mut metadata,
            EMPH_MK_AES_CBC_256_HMAC384_SIZE_BYTES as u16,
        );
        assert!(result.is_ok(), "Metadata encoding should succeed");

        let result = LMKeyDerive::masked_emphk_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_EPHEMERAL_KEY,
            &TEST_BKS1,
            &TEST_BKS2,
            &TEST_UEFI_KEY,
            &metadata[..metadata.len()],
            &mut memphk_len,
            &mut small_buffer,
        );

        // Should fail due to insufficient buffer size
        assert!(result.is_err());
        assert!(matches!(result, Err(ManticoreError::OutputBufferTooSmall)));
    }

    #[test]
    fn test_masked_emphk_gen_crypto_env_kbkdf_error() {
        let mut env = TestCryptoEnv::new();

        let mut memphk_out = [0u8; TEST_OUTPUT_BUFFER_SIZE];
        let mut memphk_len = memphk_out.len();

        let mut metadata = [0u8; TEST_METADATA_MAX_SIZE_BYTES];
        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            None,
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"Test EMPHK",
            &mut metadata.len(),
            &mut metadata,
            EMPH_MK_AES_CBC_256_HMAC384_SIZE_BYTES as u16,
        );
        assert!(result.is_ok(), "Metadata encoding should succeed");

        env.error = Some((CryptoFunc::KbkdfSha384, ManticoreError::KbkdfError));
        let result = LMKeyDerive::masked_emphk_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &TEST_EPHEMERAL_KEY,
            &TEST_BKS1,
            &TEST_BKS2,
            &TEST_UEFI_KEY,
            &metadata[..metadata.len()],
            &mut memphk_len,
            &mut memphk_out,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_encode_decode_masked_key_metadata_success() {
        let svn = Some(1u64);
        let key_kind = DdiKeyType::AesCbc256Hmac384;
        let key_attributes = DdiMaskedKeyAttributes { blob: [0u8; 32] };
        let bks2_index = Some(0u16);
        let key_tag = Some(0x1234u16);
        let key_label = b"test_key_label";
        let mut encoded_metadata = vec![0u8; 256];
        let mut metadata_len = encoded_metadata.len();

        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            svn,
            key_kind,
            key_attributes,
            bks2_index,
            key_tag,
            key_label,
            &mut metadata_len,
            &mut encoded_metadata,
            EMPH_MK_AES_CBC_256_HMAC384_SIZE_BYTES as u16,
        );

        assert!(result.is_ok());
        assert!(metadata_len > 0);
        // Check is buffer is not all zeros
        assert!(encoded_metadata[..metadata_len].iter().any(|&b| b != 0));

        // Now decode it back
        let decode_result = LMKeyDerive::decode_masked_key_metadata(
            DdiDeviceKind::Physical,
            &encoded_metadata[..metadata_len],
        );
        assert!(decode_result.is_ok());

        let decoded = decode_result.unwrap();
        assert_eq!(decoded.svn, svn);
        assert_eq!(decoded.key_type, key_kind);
        assert_eq!(decoded.bks2_index, bks2_index);
        assert_eq!(decoded.key_tag, key_tag);
        assert_eq!(decoded.key_label.as_slice(), key_label);
    }

    #[test]
    fn test_encode_masked_key_metadata_none_svn() {
        let svn = None; // Test with no SVN
        let key_kind = DdiKeyType::Aes256;
        let key_attributes = DdiMaskedKeyAttributes { blob: [0u8; 32] };
        let bks2_index = Some(0u16);
        let key_tag = Some(0x1234u16);
        let key_label = b"test_key";
        let mut encoded_metadata = vec![0u8; 256];
        let mut metadata_len = encoded_metadata.len();

        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            svn,
            key_kind,
            key_attributes,
            bks2_index,
            key_tag,
            key_label,
            &mut metadata_len,
            &mut encoded_metadata,
            Kind::Aes256.size() as u16,
        );

        assert!(result.is_ok());
        assert!(metadata_len > 0);
        // Check is buffer is not all zeros
        assert!(encoded_metadata[..metadata_len].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_encode_masked_key_metadata_none_bks2_index() {
        let svn = Some(1u64);
        let key_kind = DdiKeyType::Aes256;
        let key_attributes = DdiMaskedKeyAttributes { blob: [0u8; 32] };
        let bks2_index = None; // Test with no BKS2 index
        let key_tag = Some(0x1234u16);
        let key_label = b"test_key";
        let mut encoded_metadata = vec![0u8; 256];
        let mut metadata_len = encoded_metadata.len();

        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            svn,
            key_kind,
            key_attributes,
            bks2_index,
            key_tag,
            key_label,
            &mut metadata_len,
            &mut encoded_metadata,
            Kind::Aes256.size() as u16,
        );

        assert!(result.is_ok());
        assert!(metadata_len > 0);
        // Check is buffer is not all zeros
        assert!(encoded_metadata[..metadata_len].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_encode_masked_key_metadata_none_key_tag() {
        let svn = Some(1u64);
        let key_kind = DdiKeyType::Aes256;
        let key_attributes = DdiMaskedKeyAttributes { blob: [0u8; 32] };
        let bks2_index = Some(0u16);
        let key_tag = None; // Test with no key tag
        let key_label = b"test_key";
        let mut encoded_metadata = vec![0u8; 256];
        let mut metadata_len = encoded_metadata.len();

        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            svn,
            key_kind,
            key_attributes,
            bks2_index,
            key_tag,
            key_label,
            &mut metadata_len,
            &mut encoded_metadata,
            Kind::Aes256.size() as u16,
        );

        assert!(result.is_ok());
        assert!(metadata_len > 0);
        // Check is buffer is not all zeros
        assert!(encoded_metadata[..metadata_len].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_encode_masked_key_metadata_small_buffer() {
        let svn = Some(1u64);
        let key_kind = DdiKeyType::Aes256;
        let key_attributes = DdiMaskedKeyAttributes { blob: [0u8; 32] };
        let bks2_index = Some(0u16);
        let key_tag = Some(0x1234u16);
        let key_label = b"test_key";
        let mut metadata_len = 0usize;
        let mut encoded_metadata = vec![0u8; 10]; // Small buffer

        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            svn,
            key_kind,
            key_attributes,
            bks2_index,
            key_tag,
            key_label,
            &mut metadata_len,
            &mut encoded_metadata,
            Kind::Aes256.size() as u16,
        );

        assert!(result.is_err());
        assert!(matches!(result, Err(ManticoreError::OutputBufferTooSmall)));
        assert!(metadata_len > 0);
    }

    #[test]
    fn test_encode_masked_key_metadata_empty_key_label() {
        let svn = Some(1u64);
        let key_kind = DdiKeyType::Aes256;
        let key_attributes = DdiMaskedKeyAttributes { blob: [0u8; 32] };
        let bks2_index = Some(0u16);
        let key_tag = Some(0x1234u16);
        let key_label = b""; // Empty label
        let mut encoded_metadata = vec![0u8; 256];
        let mut metadata_len = encoded_metadata.len();

        let result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            svn,
            key_kind,
            key_attributes,
            bks2_index,
            key_tag,
            key_label,
            &mut metadata_len,
            &mut encoded_metadata,
            Kind::Aes256.size() as u16,
        );

        assert!(result.is_ok());
        assert!(metadata_len > 0);
        // Check is buffer is not all zeros
        assert!(encoded_metadata[..metadata_len].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_decode_masked_key_metadata_empty_buffer() {
        let empty_buffer = &[];
        let result = LMKeyDerive::decode_masked_key_metadata(DdiDeviceKind::Physical, empty_buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_masked_key_metadata_invalid_buffer() {
        let invalid_buffer = &[0x00, 0x01, 0x02]; // Too small/invalid
        let result =
            LMKeyDerive::decode_masked_key_metadata(DdiDeviceKind::Physical, invalid_buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_masked_key_metadata_corrupted_buffer() {
        // Create valid encoded metadata first
        let svn = Some(1u64);
        let key_kind = DdiKeyType::Aes256;
        let key_attributes = DdiMaskedKeyAttributes { blob: [0u8; 32] };
        let bks2_index = Some(0u16);
        let key_tag = Some(0x1234u16);
        let key_label = b"test_key";
        let mut encoded_metadata = vec![0u8; 256];
        let mut metadata_len = encoded_metadata.len();

        let encode_result = LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Physical,
            svn,
            key_kind,
            key_attributes,
            bks2_index,
            key_tag,
            key_label,
            &mut metadata_len,
            &mut encoded_metadata,
            Kind::Aes256.size() as u16,
        );
        assert!(encode_result.is_ok());

        // Corrupt the buffer
        encoded_metadata[0] = 0xFF;
        encoded_metadata[1] = 0xFF;

        let decode_result = LMKeyDerive::decode_masked_key_metadata(
            DdiDeviceKind::Physical,
            &encoded_metadata[..metadata_len],
        );
        assert!(decode_result.is_err());
    }
}
