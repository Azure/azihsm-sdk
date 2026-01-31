// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Module for Function. This is the root level data structure of the HSM.
//! It maintains state relevant at the virtual function level or operations which don't need a session.

use std::sync::Arc;
use std::sync::Weak;

use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_mbor::MborDecode;
use azihsm_ddi_mbor::MborDecoder;
use azihsm_ddi_mbor::MborEncode;
use azihsm_ddi_mbor::MborLen;
use azihsm_ddi_mbor::MborLenAccumulator;
use azihsm_ddi_types::DdiDeviceKind;
use azihsm_ddi_types::DdiKeyType;
use azihsm_ddi_types::DdiMaskedKeyAttributes;
use azihsm_ddi_types::DdiMaskedKeyMetadata;
use azihsm_ddi_types::MaskedKey;
use azihsm_ddi_types::MaskingKeyAlgorithm;
use azihsm_ddi_types::DDI_MAX_KEY_LABEL_LENGTH;
use parking_lot::RwLock;
use tracing::instrument;
use uuid::Uuid;

use crate::crypto::aeshmac::AesHmacKey;
use crate::crypto::aeshmac::AesHmacOp;
use crate::crypto::ecc::EccPrivateOp;
use crate::crypto_env::CryptEnv;
use crate::errors::ManticoreError;
use crate::lmkey_derive::LMKeyDerive;
use crate::mask::KeySerialization;
use crate::mask::KEY_BLOB_MAX_SIZE;
use crate::masked_key::MaskedKeyDecode;
use crate::masked_key::MaskedKeyEncode;
use crate::session::UserSession;
use crate::sim_crypto_env::SimCryptEnv;
use crate::sim_crypto_env::BK3_SIZE_BYTES;
use crate::sim_crypto_env::BK_AES_CBC_256_HMAC384_SIZE_BYTES;
use crate::sim_crypto_env::BK_SEED_SIZE_BYTES;
use crate::sim_crypto_env::MK_AES_CBC_256_HMAC384_SIZE_BYTES;
use crate::sim_crypto_env::SEALED_BK3_SIZE;
use crate::table::entry::key::Key;
use crate::table::entry::Entry;
use crate::table::entry::EntryFlags;
use crate::table::entry::Kind;
use crate::vault::Vault;
use crate::vault::APP_ID_FOR_INTERNAL_KEYS;
use crate::vault::DEFAULT_VAULT_ID;

pub(crate) const METADATA_MAX_SIZE_BYTES: usize = 128;

// Hard coded BK_BOOT. used to mask bk3.
pub(crate) const BK_BOOT: [u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES] = [
    // AES:
    0x05, 0x11, 0x10, 0x68, 0xeb, 0x10, 0x0a, 0xb9, 0x79, 0x05, 0x3d, 0x76, 0x18, 0x69, 0x1b, 0xc7,
    0x59, 0x50, 0x22, 0x5f, 0x97, 0x3f, 0x11, 0xa3, 0x69, 0x60, 0x80, 0xcb, 0x5a, 0x9c, 0xfb, 0x44,
    // HMAC:
    0x56, 0x63, 0x53, 0x05, 0x58, 0xf7, 0x11, 0x52, 0x8e, 0xaf, 0x40, 0x48, 0x53, 0xe3, 0x01, 0x1f,
    0x8d, 0xc1, 0x62, 0x23, 0xa9, 0xd1, 0xa3, 0x68, 0xcb, 0x7f, 0x5f, 0x7c, 0x29, 0x05, 0x8c, 0x8e,
    0x72, 0xa7, 0x2a, 0xda, 0xa5, 0x8e, 0xfa, 0x00, 0xe3, 0x54, 0x5e, 0x91, 0xb8, 0x55, 0xe9, 0x09,
];

// Hard coded BKS1. Used as seed data to derive BK.
pub(crate) const BKS1: [u8; BK_SEED_SIZE_BYTES] = [
    0x9b, 0x4e, 0x4e, 0xb7, 0xad, 0xab, 0xdc, 0xd6, 0xb4, 0xd5, 0x07, 0xeb, 0x68, 0xeb, 0x26, 0x99,
    0x2a, 0xbb, 0xca, 0xb5, 0x5c, 0xfb, 0x77, 0x3b, 0xc4, 0xd0, 0xa8, 0x8c, 0x21, 0x02, 0xb0, 0xac,
];

// Hard coded BKS2. Used as seed data to derive BK.
pub(crate) const BKS2: [u8; BK_SEED_SIZE_BYTES] = [
    0xad, 0x1a, 0x17, 0xe9, 0xed, 0x38, 0x27, 0x5e, 0x8b, 0x30, 0x5d, 0xb8, 0x19, 0xf, 0x82, 0xb6,
    0x2d, 0xa2, 0x5a, 0xc6, 0xf0, 0x70, 0xa3, 0xe1, 0x75, 0x9c, 0x61, 0x92, 0xcc, 0xf4, 0x19, 0xa3,
];

/// Helper function to encode a masked key with given metadata and masking key.
///
/// # Arguments
/// * `key_data` - The raw key data to be masked
/// * `masking_key` - The key used for masking
/// * `metadata` - The metadata for the masked key
///
/// # Returns
/// * `Result<Vec<u8>, ManticoreError>` - The encoded masked key buffer
fn encode_masked_key(
    key_data: &[u8],
    masking_key: &[u8],
    metadata: &DdiMaskedKeyMetadata,
) -> Result<Vec<u8>, ManticoreError> {
    let env = SimCryptEnv;

    // MBOR encode metadata
    let mut accumulator = MborLenAccumulator::default();
    metadata.mbor_len(&mut accumulator);
    let metadata_len = accumulator.len();

    if metadata_len > METADATA_MAX_SIZE_BYTES {
        tracing::error!(
            metadata_len,
            max_allowed = METADATA_MAX_SIZE_BYTES,
            "Metadata length exceeds maximum allowed size"
        );
        return Err(ManticoreError::MaskedKeyPreEncodeFailed);
    }

    let mut encoded_metadata = vec![0u8; metadata_len];
    let mut encoder = azihsm_ddi_mbor::MborEncoder::new(&mut encoded_metadata, false);
    metadata
        .mbor_encode(&mut encoder)
        .map_err(|_| ManticoreError::MaskedKeyPreEncodeFailed)?;

    if encoder.position() != encoded_metadata.len() {
        return Err(ManticoreError::MaskedKeyPreEncodeFailed);
    }

    // Get the encrypted length for the masked key
    let encrypted_key_len = env.aescbc256_enc_data_len(key_data.len());

    // Get the total encoded length for the masked key
    let encoded_length = MaskedKey::encoded_length(
        MaskingKeyAlgorithm::AesCbc256Hmac384,
        metadata_len,
        encrypted_key_len,
    );

    // Create a buffer of the required length
    let mut buffer = vec![0u8; encoded_length];

    // Pre-encode the masked key
    let mut pre_encoded = MaskedKey::pre_encode(
        1,
        MaskingKeyAlgorithm::AesCbc256Hmac384,
        metadata_len,
        encrypted_key_len,
        &mut buffer,
    )
    .map_err(|_| ManticoreError::MaskedKeyPreEncodeFailed)?;

    // Encode the masked key
    MaskedKey::encode(
        &env,
        &mut pre_encoded,
        key_data,
        masking_key,
        &encoded_metadata,
    )
    .map_err(|_| ManticoreError::MaskedKeyEncodeFailed)?;

    Ok(buffer)
}

/// API revision Structure
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ApiRev {
    /// Major version
    pub major: u32,

    /// Minor version
    pub minor: u32,
}

impl PartialOrd for ApiRev {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        if self.major == other.major {
            // If major versions are equal, compare minor versions
            self.minor.partial_cmp(&other.minor)
        } else {
            // Otherwise, compare major versions
            self.major.partial_cmp(&other.major)
        }
    }
}

/// API revision range Structure
#[derive(Debug, PartialEq, Eq)]
pub struct ApiRevRange {
    /// Minimum API revision supported
    pub min: ApiRev,

    /// Maximum API revision supported
    pub max: ApiRev,
}

/// Function is the root level data structure of the HSM.
/// It maintains state relevant at the virtual function level or allows operations which don't need a session.
#[derive(Debug, Clone)]
pub struct Function {
    inner: Arc<RwLock<FunctionInner>>,
}

impl Function {
    /// Creates a new Function instance
    ///
    /// # Arguments
    /// * `table_count` - Maximum number of tables to allowed for use by the function
    ///
    /// # Returns
    /// * `Function` - New Function instance
    #[instrument(name = "Function::new")]
    pub fn new(table_count: usize) -> Result<Self, ManticoreError> {
        let instance = Self {
            inner: Arc::new(RwLock::new(FunctionInner::new(table_count)?)),
        };
        instance.generate_attestation_key()?;

        Ok(instance)
    }

    #[allow(unused)]
    fn with_inner(inner: Arc<RwLock<FunctionInner>>) -> Self {
        Self { inner }
    }

    #[allow(unused)]
    fn as_weak(&self) -> FunctionWeak {
        FunctionWeak::new(Arc::downgrade(&self.inner))
    }

    #[instrument(skip(self))]
    fn generate_attestation_key(&self) -> Result<(), ManticoreError> {
        self.inner.write().generate_attestation_key()
    }

    /// Init the BK3
    pub(crate) fn init_bk3(&self, bk3: [u8; BK3_SIZE_BYTES]) -> Result<Vec<u8>, ManticoreError> {
        self.inner.write().init_bk3(bk3)
    }

    #[allow(dead_code)]
    pub(crate) fn set_sealed_bk3(&self, sealed_bk3: &[u8]) -> Result<(), ManticoreError> {
        // Mock manticore will set the masked BK3, and not involve the TPM
        self.inner.write().set_sealed_bk3(sealed_bk3)
    }

    #[allow(dead_code)]
    pub(crate) fn get_sealed_bk3(&self) -> Result<Vec<u8>, ManticoreError> {
        self.inner.read().get_sealed_bk3()
    }

    /// Provisions the HSM with a masked BK3 (backup key 3), optionally a BMK (backup masking key), and optionally a masked unwrapping key.
    ///
    /// # Arguments
    /// * `masked_bk3` - The raw bytes of the masked BK3 data
    /// * `bmk` - Optional partition backup masking key, should be None before live migration.
    /// * `masked_unwrapping_key` - Optional masked unwrapping key for restoration after live migration.
    ///
    /// # Returns
    /// * `Result<Vec<u8>, ManticoreError>` - The masked BMK on success, or an error
    ///
    /// # Errors
    /// * `ManticoreError::PartitionAlreadyProvisioned` - If the partition is already provisioned
    pub fn provision(
        &self,
        masked_bk3: &[u8],
        bmk: Option<&[u8]>,
        masked_unwrapping_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, ManticoreError> {
        self.inner
            .write()
            .provision(masked_bk3, bmk, masked_unwrapping_key)
    }

    /// Returns the API revision range supported.
    ///
    /// # Returns
    /// * `ApiRevRange` - API revision range supported
    pub fn get_api_rev_range(&self) -> ApiRevRange {
        self.inner.read().get_api_rev_range()
    }

    /// Fetches an existing user session API Rev.
    ///
    /// # Arguments
    /// * `session_id` - Session ID
    /// * `allow_disabled` - Whether to allow fetching disabled sessions
    ///
    /// # Returns
    /// * `UserSession` - User session
    ///
    /// # Errors
    /// * `ManticoreError::SessionNotFound` - If the session ID is invalid.
    pub fn get_user_session_api_rev(
        &self,
        session_id: u16,
        allow_disabled: bool,
    ) -> Result<ApiRev, ManticoreError> {
        self.inner
            .read()
            .get_user_session_api_rev(session_id, allow_disabled)
    }

    /// Close session
    ///
    /// # Arguments
    /// * `session_id` - Session ID
    ///
    /// # Returns
    /// Ok if successfully close, error otherwise
    ///
    /// # Errors
    /// * `ManticoreError::SessionNotFound` - If the session ID is invalid.
    pub fn close_user_session(&self, session_id: u16) -> Result<(), ManticoreError> {
        let vault = self.get_function_state().get_vault(DEFAULT_VAULT_ID)?;
        vault.close_session(session_id)
    }

    /// Fetches an existing app session.
    ///
    /// # Arguments
    /// * `session_id` - Session ID
    /// * `allow_disabled` - Whether to allow fetching disabled sessions
    ///
    /// # Returns
    /// * `AppSession` - App session
    ///
    /// # Errors
    /// * `ManticoreError::SessionNotFound` - If the session ID is invalid.
    pub fn get_user_session(
        &self,
        session_id: u16,
        allow_disabled: bool,
    ) -> Result<UserSession, ManticoreError> {
        // Fetch the session to make sure we are able to fetch it
        let vault = self.inner.read().state.get_vault(DEFAULT_VAULT_ID)?;
        let session_entry = vault.get_session_entry(session_id)?;

        let _api_rev = self
            .inner
            .read()
            .get_user_session_api_rev(session_id, allow_disabled)?;

        let masking_key = match session_entry.key() {
            Key::Session(session_key) => session_key.masking_key,
            _ => Err(ManticoreError::InternalError)?,
        };

        let user_session = UserSession::new(
            session_id,
            session_entry,
            self.get_function_state()
                .get_vault_at(0)?
                .user()
                .credentials
                .id,
            self.get_function_state()
                .get_vault_at(0)?
                .user()
                .short_app_id,
            self.get_function_state().as_weak(),
            self.get_function_state().get_vault_at(0)?.as_weak(),
            masking_key,
        );

        Ok(user_session)
    }

    /// Returns the maximum number of tables allowed for the function.
    ///
    /// # Returns
    /// * `usize` - Maximum number of tables allowed for the function
    pub(crate) fn tables_max(&self) -> usize {
        self.inner.read().tables_max()
    }

    /// Returns the current function state.
    ///
    /// # Returns
    /// * `FunctionState` - Current function state
    pub(crate) fn get_function_state(&self) -> FunctionState {
        self.inner.read().get_function_state()
    }

    /// Perform HSM migration simulation: backup session table, reset function, restore session table.
    /// This simulates live migration by preserving session state across a function reset.
    ///
    /// # Returns
    /// * `Ok(())` - If the migration simulation succeeds
    ///
    /// # Errors
    /// * `ManticoreError::*` - Various errors from backup, reset, or restore operations
    #[tracing::instrument(skip(self))]
    pub(crate) fn simulate_migration(&self) -> Result<(), ManticoreError> {
        self.inner.write().simulate_migration()
    }
}

#[derive(Debug)]
struct FunctionInner {
    state: FunctionState,
}

impl FunctionInner {
    fn new(table_count: usize) -> Result<Self, ManticoreError> {
        Ok(Self {
            state: FunctionState::new(table_count)?,
        })
    }

    fn get_api_rev_range(&self) -> ApiRevRange {
        ApiRevRange {
            min: ApiRev { major: 1, minor: 0 },
            max: ApiRev { major: 1, minor: 0 },
        }
    }

    fn reset_function_state(&mut self) -> Result<(), ManticoreError> {
        tracing::debug!(table = self.state.tables_max(), "Resetting FunctionState");

        self.state.reset()?;

        self.generate_attestation_key()?;

        Ok(())
    }

    /// This function should only be called once during initialization.
    /// Generate a single attestation key (only private key for now), shared by the entire Function
    fn generate_attestation_key(&mut self) -> Result<(), ManticoreError> {
        // We use ECC 384 Private Key for attestation key
        let vault = self.state.get_vault(DEFAULT_VAULT_ID)?;

        let (ecc_private_key, _) =
            crate::crypto::ecc::generate_ecc(crate::crypto::ecc::EccCurve::P384)?;

        // Add the key to the vault without an associated app session
        let flag = EntryFlags::new()
            .with_is_attestation_key(true)
            .with_sign(true)
            .with_verify(true)
            .with_local(true)
            .with_generated(true);

        let private_key_num = vault.add_key(
            APP_ID_FOR_INTERNAL_KEYS,
            Kind::Ecc384Private,
            Key::EccPrivate(ecc_private_key),
            flag,
            0,
        )?;

        // Save the private key num
        self.state.set_attestation_key_num(private_key_num)?;

        Ok(())
    }

    /// This function should only be called once during initialization.
    /// Generate a single RSA key pair shared by the entire Function
    fn generate_unwrapping_key(&mut self) -> Result<(), ManticoreError> {
        // Use the default vault session to generate wrapping keys
        let vault = self.state.get_vault(DEFAULT_VAULT_ID)?;

        // Generate the RSA key, we use RSA 2k for wrapping
        let (rsa_private_key, _) = crate::crypto::rsa::generate_rsa(2048)?;

        // Store key in vault without an associated app session
        let key_flags = EntryFlags::new()
            .with_unwrap(true)
            .with_wrap(true)
            .with_local(true)
            .with_generated(true);

        let private_key_id = vault.add_key(
            APP_ID_FOR_INTERNAL_KEYS,
            Kind::Rsa2kPrivate,
            Key::RsaPrivate(rsa_private_key),
            key_flags,
            0,
        )?;

        // Save the key num on FunctionState
        self.state.set_unwrapping_key_num(private_key_id)?;

        Ok(())
    }

    /// Restore unwrapping key from masked data
    fn restore_unwrapping_key(
        &mut self,
        masked_unwrapping_key: &[u8],
        masking_key_bytes: &[u8],
    ) -> Result<(), ManticoreError> {
        tracing::debug!("Restoring unwrapping key from masked data");

        // unmask the unwrapping key using the masking key bytes provided
        let key_num = self.state.unmask_and_import_key_internal(
            masked_unwrapping_key,
            0,                        // session_id can be ignored for partition keys
            APP_ID_FOR_INTERNAL_KEYS, // Use the internal app_id for unwrapping keys
            masking_key_bytes,        // Provide themasking key bytes
        )?;

        // Save the key num on FunctionState
        self.state.set_unwrapping_key_num(key_num)?;

        tracing::debug!(
            key_num,
            "Successfully restored unwrapping key from masked data"
        );

        Ok(())
    }
    /// Store masking key in the vault and set the key number in state
    fn store_masking_key(&mut self, masking_key_bytes: &[u8]) -> Result<u16, ManticoreError> {
        let vault = self.state.get_vault(DEFAULT_VAULT_ID)?;

        // Convert to AesHmac key
        let masking_key = crate::crypto::aeshmac::AesHmacKey::from_bytes(masking_key_bytes)?;

        // Store key in vault without an associated app session
        let key_flags = EntryFlags::new()
            .with_encrypt(true)
            .with_decrypt(true)
            .with_generated(true);

        let key_id = vault.add_key(
            APP_ID_FOR_INTERNAL_KEYS,
            Kind::AesHmac640,
            Key::AesHmac(masking_key.clone()),
            key_flags,
            0,
        )?;

        // Save the key num on FunctionState
        self.state.set_masking_key_num(key_id)?;
        Ok(key_id)
    }

    fn init_bk3(&mut self, bk3: [u8; BK3_SIZE_BYTES]) -> Result<Vec<u8>, ManticoreError> {
        tracing::debug!(bk3_len = bk3.len(), "Initializing BK3");

        let metadata = DdiMaskedKeyMetadata {
            svn: Some(0),
            key_type: DdiKeyType::Secret384,
            key_attributes: DdiMaskedKeyAttributes { blob: [0u8; 32] },
            bks2_index: None,
            key_tag: None,
            key_label: MborByteArray::from_slice(b"BK3")
                .map_err(|_| ManticoreError::InternalError)?,
            key_length: BK3_SIZE_BYTES as u16,
        };

        encode_masked_key(&bk3, &BK_BOOT, &metadata)
    }

    fn set_sealed_bk3(&mut self, sealed_bk3: &[u8]) -> Result<(), ManticoreError> {
        self.state.set_sealed_bk3_data(sealed_bk3)?;
        tracing::debug!(sealed_bk3_len = sealed_bk3.len(), "Stored sealed BK3 data");

        Ok(())
    }

    fn get_sealed_bk3(&self) -> Result<Vec<u8>, ManticoreError> {
        self.state.get_sealed_bk3_data()
    }

    fn provision(
        &mut self,
        masked_bk3: &[u8],
        bmk: Option<&[u8]>,
        masked_unwrapping_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, ManticoreError> {
        if self.state.is_provisioned() {
            return Err(ManticoreError::PartitionAlreadyProvisioned);
        }

        // Decode the masked BK3 from raw bytes
        let env = SimCryptEnv;
        let decoded_masked_bk3 =
            MaskedKey::decode(&env, &BK_BOOT, masked_bk3, true).map_err(|err| {
                tracing::error!("MaskedKey::decode error {:?}", err);
                ManticoreError::MaskedKeyDecodeFailed
            })?;

        // Decrypt BK3 from the decoded masked key using BK_BOOT
        let mut unmasked_bk3 = [0u8; BK3_SIZE_BYTES];
        decoded_masked_bk3
            .decrypt_key(&env, &BK_BOOT, &mut unmasked_bk3)
            .map_err(|err| {
                tracing::error!("MaskedKey::decrypt_key error {:?}", err);
                ManticoreError::MaskedKeyDecodeFailed
            })?;

        // Derive a backup key from BK3 to mask the original masking key
        let mut bk_partition_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES;
        let mut bk_partition = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
        LMKeyDerive::bk_partition_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &BKS1,
            &BKS2,
            &unmasked_bk3,
            &mut bk_partition_len,
            &mut bk_partition,
        )
        .map_err(|err| {
            tracing::error!("bk_partition_gen error {:?}", err);
            ManticoreError::InternalError
        })?;

        // Get the bmk as a vec
        let bmk_vec = match bmk {
            Some(bmk) => bmk.to_vec(),
            None => {
                // Generate new bmk
                let mut metadata_len = METADATA_MAX_SIZE_BYTES;
                let mut metadata = [0u8; METADATA_MAX_SIZE_BYTES];
                LMKeyDerive::encode_masked_key_metadata(
                    DdiDeviceKind::Virtual,
                    Some(1),
                    DdiKeyType::AesCbc256Hmac384,
                    DdiMaskedKeyAttributes { blob: [0u8; 32] },
                    Some(0),
                    None,
                    b"PARTITION_BK",
                    &mut metadata_len,
                    &mut metadata,
                    BK_AES_CBC_256_HMAC384_SIZE_BYTES as u16,
                )
                .map_err(|err| {
                    tracing::error!("encode_masked_key_metadata error {:?}", err);
                    ManticoreError::InternalError
                })?;

                // Get the required length for BMK
                let mut bmk_len = 0;
                let _ = LMKeyDerive::bmk_gen(
                    &env,
                    MaskingKeyAlgorithm::AesCbc256Hmac384,
                    &bk_partition,
                    &metadata[..metadata_len],
                    &mut bmk_len,
                    &mut [0u8; 0],
                );

                // Now generate the bmk
                let mut bmk_vec = vec![0u8; bmk_len];
                LMKeyDerive::bmk_gen(
                    &env,
                    MaskingKeyAlgorithm::AesCbc256Hmac384,
                    &bk_partition,
                    &metadata[..metadata_len],
                    &mut bmk_len,
                    &mut bmk_vec,
                )
                .map_err(|err| {
                    tracing::error!("bmk_gen error {:?}", err);
                    ManticoreError::InternalError
                })?;

                bmk_vec
            }
        };

        // Decode bmk to get partition mk
        let decoded_mk =
            LMKeyDerive::bmk_restore(&env, &bk_partition, &bmk_vec).map_err(|err| {
                tracing::error!("bmk_restore error {:?}", err);
                ManticoreError::InternalError
            })?;

        let mut mk = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
        let _unmasked_mk_length = decoded_mk
            .decrypt_key(&env, &bk_partition, &mut mk)
            .map_err(|err| {
                tracing::error!("decoded_mk decrypt_key error {:?}", err);
                ManticoreError::InternalError
            })?;

        // Handle unwrapping key restoration or generation
        // Note: the unwrapping key is stored in the vault and its key num is saved in FunctionState
        // After this point, no failure should be allowed.
        match masked_unwrapping_key {
            Some(data) if !data.is_empty() => self.restore_unwrapping_key(data, &mk)?,
            _ => self.generate_unwrapping_key()?,
        }

        // All cryptographic operations completed successfully - now commit state changes
        // these should not fail as we just checked provisioned state
        self.get_function_state().set_bk_partition(bk_partition)?;
        self.store_masking_key(&mk)?;

        Ok(bmk_vec)
    }

    fn get_user_session_api_rev(
        &self,
        session_id: u16,
        allow_disabled: bool,
    ) -> Result<ApiRev, ManticoreError> {
        self.state
            .get_user_session_api_rev(session_id, allow_disabled)
    }

    fn tables_max(&self) -> usize {
        self.state.tables_max()
    }

    fn get_function_state(&self) -> FunctionState {
        self.state.clone()
    }

    /// Perform HSM migration simulation: backup session table, reset function, restore session table.
    /// This simulates live migration by preserving session state across a function reset.
    ///
    /// # Returns
    /// * `Ok(())` - If the migration simulation succeeds
    ///
    /// # Errors
    /// * `ManticoreError::*` - Various errors from backup, reset, or restore operations
    fn simulate_migration(&mut self) -> Result<(), ManticoreError> {
        // Step 1: Backup session table state
        let vault = self.state.get_vault(DEFAULT_VAULT_ID)?;
        let session_backup = vault.backup_session_table();

        // Step 2: Reset function (just like DdiResetFunction)
        self.reset_function_state()?;

        // Step 3: Restore session table state
        let vault = self.state.get_vault(DEFAULT_VAULT_ID)?;
        vault.restore_session_table(session_backup);

        Ok(())
    }
}

struct FunctionWeak {
    #[allow(unused)]
    weak: Weak<RwLock<FunctionInner>>,
}

impl FunctionWeak {
    #[allow(unused)]
    fn new(weak: Weak<RwLock<FunctionInner>>) -> Self {
        Self { weak }
    }

    #[allow(unused)]
    fn upgrade(&self) -> Option<Function> {
        self.weak.upgrade().map(Function::with_inner)
    }
}

/// FunctionState stores all the state needed at the Function level.
#[derive(Debug, Clone)]
pub(crate) struct FunctionState {
    inner: Arc<RwLock<FunctionStateInner>>,
}

impl FunctionState {
    #[instrument(name = "FunctionState::new")]
    fn new(tables_max: usize) -> Result<Self, ManticoreError> {
        Ok(Self {
            inner: Arc::new(RwLock::new(FunctionStateInner::new(tables_max)?)),
        })
    }

    fn get_user_session_api_rev(
        &self,
        session_id: u16,
        allow_disabled: bool,
    ) -> Result<ApiRev, ManticoreError> {
        self.inner
            .read()
            .get_user_session_api_rev(session_id, allow_disabled)
    }

    fn with_inner(inner: Arc<RwLock<FunctionStateInner>>) -> Self {
        Self { inner }
    }

    fn tables_max(&self) -> usize {
        self.inner.read().tables_max
    }

    /// Reset the FunctionState while preserving sealed BK3 data
    fn reset(&mut self) -> Result<(), ManticoreError> {
        self.inner.write().reset()
    }

    #[allow(unused)]
    fn tables_available(&self) -> usize {
        self.inner.read().tables_available()
    }

    /// Set attestation key's key num. Should only be called once.
    ///
    /// # Arguments
    /// * `key_num` - The key num of generated attestation key
    ///
    /// # Errors
    /// * [ManticoreError::InvalidArgument] - The key is already set.
    #[instrument(skip(self))]
    pub fn set_attestation_key_num(&mut self, key_num: u16) -> Result<(), ManticoreError> {
        self.inner.write().set_attestation_key_num(key_num)
    }

    /// Get attestation key's key num.
    ///
    /// # Returns
    /// * `u16` - The key num of generated attestation key
    ///
    /// # Errors
    /// * [ManticoreError::KeyNotFound] - The key is not set.
    pub(crate) fn get_attestation_key_num(&self) -> Result<u16, ManticoreError> {
        self.inner.read().get_attestation_key_num()
    }

    /// Set wrapping key's key num. Should only be called once.
    ///
    /// # Arguments
    /// * `key_num` - The key num of private RSA 2k key
    ///
    /// # Errors
    /// * [ManticoreError::InvalidArgument] - The key is already set.
    pub fn set_unwrapping_key_num(&mut self, key_num: u16) -> Result<(), ManticoreError> {
        self.inner.write().set_unwrapping_key_num(key_num)
    }

    /// Get wrapping key's key num.
    ///
    /// # Returns
    /// * `u16` - The key num of private RSA 2k key
    ///
    /// # Errors
    /// * [ManticoreError::KeyNotFound] - The key is not set.
    pub(crate) fn get_unwrapping_key_num(&self) -> Result<u16, ManticoreError> {
        self.inner.read().get_unwrapping_key_num()
    }

    /// Set Masking key's num. Should only be called once.
    ///
    /// # Arguments
    /// * `key_num` - The key num of masking key
    ///
    /// # Errors
    /// * [ManticoreError::InvalidArgument] - The key is already set.
    fn set_masking_key_num(&mut self, key_num: u16) -> Result<(), ManticoreError> {
        self.inner.write().set_masking_key_num(key_num)
    }

    /// Check if the HSM has been provisioned.
    /// Note: this
    ///
    /// # Returns
    /// * `bool` - True if provisioned, false otherwise
    pub(crate) fn is_provisioned(&self) -> bool {
        self.inner.read().is_provisioned()
    }

    /// Get backup key for the partition
    ///
    /// # Returns
    /// * `Vec<u8>` - bk_partition of BK_AES_CBC_256_HMAC384_SIZE_BYTES length
    ///
    /// # Errors
    /// * [ManticoreError::PartitionNotProvisioned] - The bk is not set.
    pub(crate) fn get_bk_partition(&self) -> Result<Vec<u8>, ManticoreError> {
        self.inner.read().get_bk_partition()
    }

    /// Set backup key for partition. Should only be called once.
    /// This is `pub(crate)` for use in dispatcher tests.
    ///
    /// # Arguments
    /// * `bk_partition` - bk_partition of BK_AES_CBC_256_HMAC384_SIZE_BYTES length
    pub(crate) fn set_bk_partition(
        &mut self,
        bk_partition: [u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES],
    ) -> Result<(), ManticoreError> {
        self.inner.write().set_bk_partition(bk_partition)
    }

    /// Helper method to get the vault object given the vault id.
    ///
    /// # Arguments
    /// * `vault_id` - The vault id.
    ///
    /// # Returns
    /// * `Vault` - The vault object.
    ///
    /// # Errors
    /// * `ManticoreError::VaultNotFound` - The vault was not found.
    pub(crate) fn get_vault(&self, vault_id: Uuid) -> Result<Vault, ManticoreError> {
        self.inner.read().get_vault(vault_id)
    }

    fn as_weak(&self) -> FunctionStateWeak {
        FunctionStateWeak::new(Arc::downgrade(&self.inner))
    }

    /// Helper method to get the vault object given the vault index.
    ///
    /// # Arguments
    /// * `index` - The vault index.
    ///
    /// # Returns
    /// * `Vault` - The vault object.
    ///
    /// # Errors
    /// * `ManticoreError::VaultNotFound` - The vault was not found.
    #[allow(unused)]
    pub(crate) fn get_vault_at(&self, index: usize) -> Result<Vault, ManticoreError> {
        self.inner.read().get_vault_at(index)
    }

    pub(crate) fn set_sealed_bk3_data(&self, data: &[u8]) -> Result<(), ManticoreError> {
        if self.inner.read().sealed_bk3_data.is_some() {
            return Err(ManticoreError::KeyAlreadyExists);
        }
        if data.len() > SEALED_BK3_SIZE {
            return Err(ManticoreError::SealedBk3TooLarge);
        }

        let mut array = [0u8; SEALED_BK3_SIZE];
        array[..data.len()].copy_from_slice(data);

        let mut inner = self.inner.write();
        inner.sealed_bk3_data = Some(array);
        inner.sealed_bk3_actual_len = Some(data.len());
        Ok(())
    }

    pub(crate) fn get_sealed_bk3_data(&self) -> Result<Vec<u8>, ManticoreError> {
        let inner = self.inner.read();
        match (&inner.sealed_bk3_data, &inner.sealed_bk3_actual_len) {
            (Some(array), Some(len)) => Ok(array[..*len].to_vec()),
            _ => Err(ManticoreError::SealedBk3NotPresent),
        }
    }

    /// Mask an entry with the masking key to create a masked key buffer
    ///
    /// # Arguments
    /// * `entry` - The entry to mask
    /// * `virtual_session_id` - Optional virtual session ID for session-only keys
    /// * `session_masking_key` - If entry is a session key, will be used to mask the key
    ///
    /// # Returns
    /// * `Result<Vec<u8>, ManticoreError>` - The masked key buffer
    pub(crate) fn mask_vault_entry(
        &self,
        entry: &Entry,
        virtual_session_id: Option<u16>,
        session_masking_key: Option<&AesHmacKey>,
    ) -> Result<Vec<u8>, ManticoreError> {
        self.inner
            .read()
            .mask_vault_entry(entry, virtual_session_id, session_masking_key)
    }

    /// Unmask a masked key buffer and add it to the vault
    ///
    /// # Arguments
    /// * `blob` - The masked key buffer to unmask
    /// * `session_masking_key` - If entry is a session key, will be used to unmask the key
    ///
    /// # Returns
    /// * `Result<u16, ManticoreError>` - The key number of the added key
    ///   Unmask a key and import it to vault with app ID verification and session ID verification for session-only keys
    pub(crate) fn unmask_and_import_key(
        &self,
        blob: &[u8],
        session_id: u16,
        app_id: Uuid,
        session_masking_key: Option<&AesHmacKey>,
    ) -> Result<u16, ManticoreError> {
        self.inner
            .read()
            .unmask_and_import_key(blob, session_id, app_id, session_masking_key)
    }

    /// Unmask and import a key with an external masking key (for restoration scenarios)
    pub(crate) fn unmask_and_import_key_internal(
        &self,
        blob: &[u8],
        session_id: u16,
        app_id: Uuid,
        external_masking_key_bytes: &[u8],
    ) -> Result<u16, ManticoreError> {
        self.inner.read().unmask_and_import_key_internal(
            blob,
            session_id,
            app_id,
            external_masking_key_bytes,
        )
    }

    pub(crate) fn get_certificate(&mut self) -> Result<Vec<u8>, ManticoreError> {
        self.inner.write().get_certificate()
    }
}

#[derive(Debug)]
struct FunctionStateInner {
    tables_max: usize,
    tables_used: usize,
    vaults: Vec<Vault>,
    // The key num of attestation key (only private key for now)
    // This key should be stored in vault DEFAULT_VAULT_ID
    attestation_key_num: Option<u16>,
    /// The Attestation Key Cert, returned by GetCertificate command.
    /// Cached here so we return the same cert each time, producing stable hash.
    /// Lazy generated on first call to [Self::get_certificate]
    attestation_key_cert: Option<Vec<u8>>,
    wrapping_key_num: Option<u16>,
    masking_key_num: Option<u16>,
    // Store sealed BK3 as fixed-size array
    sealed_bk3_data: Option<[u8; SEALED_BK3_SIZE]>,
    sealed_bk3_actual_len: Option<usize>,
    bk_partition: Option<[u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES]>,
}

impl Drop for FunctionStateInner {
    fn drop(&mut self) {
        tracing::trace!("Dropping FunctionStateInner");
    }
}

impl FunctionStateInner {
    fn new(table_count: usize) -> Result<Self, ManticoreError> {
        let mut vaults = Vec::with_capacity(table_count);
        let default_vault = Vault::new(DEFAULT_VAULT_ID, table_count)?;
        vaults.push(default_vault);

        Ok(Self {
            tables_max: table_count,
            tables_used: table_count,
            vaults,
            attestation_key_num: None,
            attestation_key_cert: None,
            wrapping_key_num: None,
            masking_key_num: None,
            sealed_bk3_data: None,
            sealed_bk3_actual_len: None,
            bk_partition: None,
        })
    }

    fn get_user_session_api_rev(
        &self,
        session_id: u16,
        allow_disabled: bool,
    ) -> Result<ApiRev, ManticoreError> {
        let vault = self.get_vault(DEFAULT_VAULT_ID)?;
        let entry = vault.get_session_entry_unchecked(session_id)?;

        if allow_disabled || !entry.disabled() {
            if let Key::Session(session_key) = entry.key() {
                return Ok(session_key.api_rev);
            }
        }

        tracing::error!(
            session_id,
            "Cannot find UserSession with the given session ID"
        );
        Err(ManticoreError::SessionNotFound)
    }

    fn tables_available(&self) -> usize {
        self.tables_max - self.tables_used
    }

    fn set_attestation_key_num(&mut self, key_num: u16) -> Result<(), ManticoreError> {
        if self.attestation_key_num.is_some() {
            // Attest key can only be set once
            Err(ManticoreError::KeyAlreadyExists)?
        }

        self.attestation_key_num = Some(key_num);
        Ok(())
    }

    fn get_attestation_key_num(&self) -> Result<u16, ManticoreError> {
        match self.attestation_key_num {
            Some(key_num) => Ok(key_num),
            None => Err(ManticoreError::KeyNotFound)?,
        }
    }

    fn set_unwrapping_key_num(&mut self, key_num: u16) -> Result<(), ManticoreError> {
        if self.wrapping_key_num.is_some() {
            // Wrapping key can only be set once
            Err(ManticoreError::KeyAlreadyExists)?
        }

        self.wrapping_key_num = Some(key_num);
        Ok(())
    }

    fn get_unwrapping_key_num(&self) -> Result<u16, ManticoreError> {
        match self.wrapping_key_num {
            Some(key_num) => Ok(key_num),
            None => {
                // Check if partition is provisioned
                if self.is_provisioned() {
                    // Partition is provisioned but unwrapping key is missing (shouldn't happen)
                    Err(ManticoreError::KeyNotFound)
                } else {
                    // Partition needs provisioning first
                    Err(ManticoreError::PartitionNotProvisioned)
                }
            }
        }
    }

    fn set_masking_key_num(&mut self, key_num: u16) -> Result<(), ManticoreError> {
        if self.masking_key_num.is_some() {
            // Masking key can only be set once
            Err(ManticoreError::KeyAlreadyExists)?
        }

        self.masking_key_num = Some(key_num);
        Ok(())
    }

    fn get_masking_key_num(&self) -> Result<u16, ManticoreError> {
        match self.masking_key_num {
            Some(key_num) => Ok(key_num),
            None => Err(ManticoreError::KeyNotFound),
        }
    }

    fn set_bk_partition(
        &mut self,
        bk_partition: [u8; MK_AES_CBC_256_HMAC384_SIZE_BYTES],
    ) -> Result<(), ManticoreError> {
        self.bk_partition = Some(bk_partition);
        Ok(())
    }

    fn get_bk_partition(&self) -> Result<Vec<u8>, ManticoreError> {
        match self.bk_partition {
            Some(bk_partition) => Ok(bk_partition.to_vec()),
            None => Err(ManticoreError::PartitionNotProvisioned),
        }
    }

    fn is_provisioned(&self) -> bool {
        self.masking_key_num.is_some()
    }

    fn get_vault(&self, vault_id: Uuid) -> Result<Vault, ManticoreError> {
        self.vaults
            .iter()
            .find(|&vault| vault.id() == vault_id)
            .cloned()
            .ok_or_else(|| {
                tracing::error!(vault_id = ?vault_id, "Cannot find Vault with given vault ID");
                ManticoreError::VaultNotFound
            })
    }

    fn get_vault_at(&self, index: usize) -> Result<Vault, ManticoreError> {
        self.vaults
            .get(index)
            .cloned()
            .ok_or(ManticoreError::VaultNotFound)
    }

    fn get_partition_masking_key_bytes(&self) -> Result<Vec<u8>, ManticoreError> {
        // Get the masking key number
        let masking_key_num = match self.get_masking_key_num() {
            Ok(key_num) => key_num,
            Err(_) => {
                tracing::warn!("Failed to retrieve masking key, returning empty vector");
                return Ok(Vec::new());
            }
        };

        // Get the masking key entry from the vault
        let vault = self.get_vault(DEFAULT_VAULT_ID)?;
        let masking_key_entry = vault.get_key_entry(masking_key_num)?;

        if !matches!(masking_key_entry.kind(), Kind::AesHmac640) {
            tracing::error!(error = ?ManticoreError::InternalError, masking_key_num, kind = ?masking_key_entry.kind(), "Masking key entry should be AesHmac640 key (HMAC384 only)");
            return Err(ManticoreError::InternalError);
        }

        match masking_key_entry.key() {
            Key::AesHmac(key) => {
                // Serialize to get the raw combined key bytes
                key.serialize()
            }
            _ => {
                tracing::error!(error = ?ManticoreError::InternalError, kind = ?masking_key_entry.kind(), "Masking key entry should contain AesHmac key");
                Err(ManticoreError::InternalError)
            }
        }
    }

    fn mask_vault_entry(
        &self,
        entry: &Entry,
        virtual_session_id: Option<u16>,
        session_masking_key: Option<&AesHmacKey>,
    ) -> Result<Vec<u8>, ManticoreError> {
        const ERR: ManticoreError = ManticoreError::MaskedKeyPreEncodeFailed;

        // Get whether this is session only
        let session_only = entry.session_only();

        // Get partition or session masking key bytes
        let masking_key_bytes = if session_only {
            // Use session masking key
            session_masking_key.ok_or(ERR)?.serialize()?
        } else {
            self.get_partition_masking_key_bytes()?
        };

        // The session id or key tag of the entry to be masked
        // For session-only keys, use the provided virtual_session_id
        // For persistent keys, use the entry's key_tag
        let sess_id_or_key_tag = if session_only {
            virtual_session_id.unwrap_or(0)
        } else {
            entry.key_tag().unwrap_or(0)
        };

        let app_id = entry.app_id();

        // Serialize the key from the entry
        // Note the format is currently different from the FW implementation
        let plaintext_key = entry.key().serialize()?;

        if plaintext_key.len() > KEY_BLOB_MAX_SIZE {
            tracing::error!(
                error = ?ERR,
                key_size = plaintext_key.len(),
                max_allowed = KEY_BLOB_MAX_SIZE,
                "Sealed key size exceeds maximum allowed size"
            );
            Err(ERR)?
        }

        let metadata = DdiMaskedKeyMetadata {
            svn: Some(1),
            key_type: azihsm_ddi_types::DdiKeyType::try_from(entry.kind()).map_err(|_| ERR)?,
            key_attributes: DdiMaskedKeyAttributes {
                blob: {
                    let mut blob = [0u8; 32];
                    blob[0..8].copy_from_slice(&(u64::from(entry.flags())).to_le_bytes());
                    blob[8..10].copy_from_slice(&sess_id_or_key_tag.to_le_bytes());
                    blob[10..26].copy_from_slice(&app_id.into_bytes());
                    blob
                },
            },
            bks2_index: None,
            key_tag: entry.key_tag(),
            key_label: MborByteArray::<DDI_MAX_KEY_LABEL_LENGTH>::from_slice(&[])
                .map_err(|_| ERR)?,
            key_length: plaintext_key.len() as u16,
        };

        encode_masked_key(&plaintext_key, &masking_key_bytes, &metadata)
    }

    /// Unmask a key and import it to vault with app ID verification and session ID verification for session-only keys
    fn unmask_and_import_key(
        &self,
        blob: &[u8],
        session_id: u16,
        app_id: Uuid,
        session_masking_key: Option<&AesHmacKey>,
    ) -> Result<u16, ManticoreError> {
        const ERR: ManticoreError = ManticoreError::MaskedKeyDecodeFailed;

        let session_only = Self::is_session_only_masked_key(blob)?;
        // Use known masking bytes or get partition or session masking key bytes
        let masking_key_bytes = if session_only {
            // Get session masking key
            session_masking_key.ok_or(ERR)?.serialize()?
        } else {
            // Get partition masking key
            self.get_partition_masking_key_bytes()?
        };

        self.unmask_and_import_key_internal(blob, session_id, app_id, &masking_key_bytes)
    }

    /// Determines if a masked key blob represents a session-only key by partially decoding its metadata
    ///
    /// # Arguments
    /// * `blob` - The masked key blob to check
    ///
    /// # Returns
    /// * `Result<bool, ManticoreError>` - True if the key is session-only, false otherwise
    fn is_session_only_masked_key(blob: &[u8]) -> Result<bool, ManticoreError> {
        const ERR: ManticoreError = ManticoreError::MaskedKeyDecodeFailed;

        // Partial decode to determine whether this is a session or partition key
        let env = SimCryptEnv;
        let decoded_key = MaskedKey::decode(&env, &[], blob, false).map_err(|err| {
            tracing::error!("MaskedKey error {:?}", err);
            ERR
        })?;
        let aes_key = decoded_key.as_aes().ok_or(ERR)?;

        let metadata_slice = aes_key.metadata();
        let mut decoder = MborDecoder::new(metadata_slice, false);

        let metadata = DdiMaskedKeyMetadata::mbor_decode(&mut decoder).map_err(|err| {
            tracing::error!("mbor_decode error {:?}", err);
            ERR
        })?;

        let flags_bytes = &metadata.key_attributes.blob[0..8];
        let flags = EntryFlags::from(u64::from_le_bytes([
            flags_bytes[0],
            flags_bytes[1],
            flags_bytes[2],
            flags_bytes[3],
            flags_bytes[4],
            flags_bytes[5],
            flags_bytes[6],
            flags_bytes[7],
        ]));
        Ok(flags.session())
    }

    fn unmask_and_import_key_internal(
        &self,
        blob: &[u8],
        session_id: u16,
        app_id: Uuid,
        masking_key_bytes: &[u8],
    ) -> Result<u16, ManticoreError> {
        const ERR: ManticoreError = ManticoreError::MaskedKeyDecodeFailed;
        tracing::debug!("Unmasking and importing key with verification");
        let env = SimCryptEnv;

        // Use the masking key to decode the masked key
        let decoded_key =
            MaskedKey::decode(&env, masking_key_bytes, blob, true).map_err(|err| {
                tracing::error!("MaskedKey::decode error {:?}", err);
                ERR
            })?;

        let aes_key = decoded_key.as_aes().ok_or(ERR)?;

        let metadata_bytes = aes_key.metadata();
        let mut decoder = MborDecoder::new(metadata_bytes, false);
        let metadata: DdiMaskedKeyMetadata =
            MborDecode::mbor_decode(&mut decoder).map_err(|err| {
                tracing::error!("mbor_decode error {:?}", err);
                ERR
            })?;

        // Extract original entry information from metadata
        let flags_bytes = &metadata.key_attributes.blob[0..8];
        let flags = EntryFlags::from(u64::from_le_bytes([
            flags_bytes[0],
            flags_bytes[1],
            flags_bytes[2],
            flags_bytes[3],
            flags_bytes[4],
            flags_bytes[5],
            flags_bytes[6],
            flags_bytes[7],
        ]));

        let sess_id_or_key_tag_bytes = &metadata.key_attributes.blob[8..10];
        let sess_id_or_key_tag =
            u16::from_le_bytes([sess_id_or_key_tag_bytes[0], sess_id_or_key_tag_bytes[1]]);

        let app_id_bytes = &metadata.key_attributes.blob[10..26];
        let extracted_app_id = Uuid::from_bytes(app_id_bytes.try_into().map_err(|err| {
            tracing::error!("app_id_bytes.try_into() error {:?}", err);
            ERR
        })?);

        if flags.session() {
            // Verify session ID matches
            if sess_id_or_key_tag != session_id {
                tracing::error!(
                    expected_session_id = session_id,
                    found_session_id = sess_id_or_key_tag,
                    "Session ID mismatch"
                );
                return Err(ManticoreError::SessionNotFound);
            }
        }

        if extracted_app_id != app_id {
            tracing::error!(
                expected_app_id = ?app_id,
                found_app_id = ?extracted_app_id,
                "App ID mismatch"
            );
            return Err(ManticoreError::AppNotFound);
        }

        let kind = Kind::try_from(metadata.key_type)?;
        tracing::debug!(?kind, "Deserializing key");

        // Allocate buffer with the expected key size for this kind
        // Note: this is currently different from the FW implementation
        let expected_key_len = kind.serde_size();

        let mut decrypted_key = vec![0u8; expected_key_len];
        let actual_len = decoded_key
            .decrypt_key(&env, masking_key_bytes, &mut decrypted_key)
            .map_err(|err| {
                tracing::error!("decrypt_key error {:?}", err);
                ERR
            })?;

        if actual_len != expected_key_len {
            tracing::error!(error = ?ERR, expected = expected_key_len, actual = actual_len, "Decrypted key length mismatch");
            return Err(ERR);
        }

        let key = Key::deserialize(&decrypted_key, kind)?;

        let vault = self.get_vault(DEFAULT_VAULT_ID)?;
        let key_num = vault.add_key(extracted_app_id, kind, key, flags, sess_id_or_key_tag)?;

        tracing::debug!(
            key_num,
            session_id,
            app_id = ?app_id,
            "Key unmasked and imported successfully"
        );
        Ok(key_num)
    }

    fn get_certificate(&mut self) -> Result<Vec<u8>, ManticoreError> {
        if let Some(cert) = &self.attestation_key_cert {
            return Ok(cert.clone());
        }

        // Retrieve Attestation private Key to derive pub key from (TEST-only)
        // TODO: Return the AK cert and TEE report
        let vault = self.get_vault(DEFAULT_VAULT_ID)?;

        let entry = vault.get_key_entry(self.get_attestation_key_num()?)?;

        if let Key::EccPrivate(key) = entry.key() {
            // TEST-ONLY: create a X509 certificate from the ecc private key for now.
            let ak_cert = key.create_pub_key_cert()?;

            // Cache the cert for future calls
            if self.attestation_key_cert.is_none() {
                self.attestation_key_cert = Some(ak_cert.clone());
            }

            Ok(ak_cert)
        } else {
            // Throw error if key type if not EccPrivateKey
            tracing::error!(err = ?ManticoreError::InternalError, "Attestation key should be ECC private key");
            Err(ManticoreError::InternalError)?
        }
    }

    /// Reset the FunctionStateInner while preserving sealed BK3 data
    fn reset(&mut self) -> Result<(), ManticoreError> {
        // Preserve sealed BK3 data
        let sealed_bk3_data = self.sealed_bk3_data;
        let sealed_bk3_actual_len = self.sealed_bk3_actual_len;
        let tables_max = self.tables_max;

        // Reset to new state
        *self = Self::new(tables_max)?;

        // Restore preserved sealed BK3 data
        self.sealed_bk3_data = sealed_bk3_data;
        self.sealed_bk3_actual_len = sealed_bk3_actual_len;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FunctionStateWeak {
    weak: Weak<RwLock<FunctionStateInner>>,
}

impl FunctionStateWeak {
    fn new(weak: Weak<RwLock<FunctionStateInner>>) -> Self {
        Self { weak }
    }

    pub(crate) fn upgrade(&self) -> Option<FunctionState> {
        self.weak.upgrade().map(FunctionState::with_inner)
    }
}

#[cfg(test)]
mod tests {

    use test_with_tracing::test;

    use super::*;
    use crate::crypto::rsa::generate_rsa;
    use crate::masked_key::MaskedKeyDecode;
    use crate::table::entry::key::Key;
    use crate::table::entry::Kind;
    use crate::vault::tests::*;

    fn create_function(table_count: usize) -> Function {
        let result = Function::new(table_count);
        assert!(result.is_ok());

        result.unwrap()
    }

    #[test]
    fn test_get_api_rev_range() {
        let function = create_function(1);
        let api_rev_range = function.get_api_rev_range();
        let expected_api_rev_range = ApiRevRange {
            min: ApiRev { major: 1, minor: 0 },
            max: ApiRev { major: 1, minor: 0 },
        };

        assert_eq!(api_rev_range, expected_api_rev_range);

        assert!(api_rev_range.min.major <= api_rev_range.max.major);

        if api_rev_range.min.major == api_rev_range.max.major {
            assert!(api_rev_range.min.minor <= api_rev_range.max.minor);
        }
    }

    #[test]
    fn test_function_new() {
        let function = create_function(1);
        assert_eq!(function.tables_max(), 1);
        assert!(function
            .inner
            .read()
            .state
            .inner
            .read()
            .attestation_key_num
            .is_some());

        // Before provision, unwrapping key should not be available
        let result = function.get_function_state().get_unwrapping_key_num();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ManticoreError::PartitionNotProvisioned
        ));

        // Check attestation key
        let result = function.get_function_state().get_attestation_key_num();
        assert!(result.is_ok());
        let key_num = result.unwrap();

        let result = function.get_function_state().get_vault(DEFAULT_VAULT_ID);
        assert!(result.is_ok());
        let vault = result.unwrap();

        let result = vault.get_key_entry(key_num);
        assert!(result.is_ok());
        let entry = result.unwrap();

        // Check flags
        // Attestation key can only be used to sign/verify
        assert!(!entry.allow_derive());
        assert!(!entry.allow_encrypt_decrypt());
        assert!(entry.allow_sign_verify());
        assert!(!entry.allow_unwrap());

        assert!(entry.generated());
        assert!(!entry.imported());
        assert!(!entry.session_only());

        assert_eq!(entry.app_id(), APP_ID_FOR_INTERNAL_KEYS);
        assert_eq!(entry.kind(), Kind::Ecc384Private);
        assert!(matches!(entry.key(), Key::EccPrivate { .. }));

        // After provision, unwrapping key should be available
        // Create some dummy BK3 data for testing
        let dummy_bk3 = function.init_bk3([0u8; BK3_SIZE_BYTES]).unwrap();
        let provision_result = function.provision(&dummy_bk3, None, None);
        assert!(provision_result.is_ok());

        // Now unwrapping key should be available
        let result = function.get_function_state().get_unwrapping_key_num();
        assert!(result.is_ok());
        let key_num = result.unwrap();

        let result = vault.get_key_entry(key_num);
        assert!(result.is_ok());
        let entry = result.unwrap();

        // Check flags
        // Unwrapping key can only be used to unwrap
        assert!(!entry.allow_derive());
        assert!(!entry.allow_encrypt_decrypt());
        assert!(!entry.allow_sign_verify());
        assert!(entry.allow_unwrap());

        assert!(entry.generated());
        assert!(!entry.imported());
        assert!(!entry.session_only());

        assert_eq!(entry.app_id(), APP_ID_FOR_INTERNAL_KEYS);
        assert_eq!(entry.kind(), Kind::Rsa2kPrivate);
        assert!(matches!(entry.key(), Key::RsaPrivate { .. }));
    }

    #[test]
    fn test_get_user_session() {
        let function = create_function(2);
        let api_rev = function.get_api_rev_range().max;

        let result = function.get_function_state().get_vault(DEFAULT_VAULT_ID);
        assert!(result.is_ok());
        let vault = result.unwrap();

        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let session_id = session_result.session_id;

        {
            let result = function.get_user_session(session_id + 10, false);
            assert!(result.is_err(), "result {:?}", result);
        }

        {
            let result = function.get_user_session(session_id, false);
            assert!(result.is_ok());
        }

        {
            let result = function.get_user_session(session_id, true);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_get_user_session_api_rev() {
        let function = create_function(2);
        let api_rev = function.get_api_rev_range().max;

        let result = function.get_function_state().get_vault(DEFAULT_VAULT_ID);
        assert!(result.is_ok());
        let vault = result.unwrap();

        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let session_id = session_result.session_id;

        {
            let result = function.get_user_session_api_rev(session_id + 10, false);
            assert!(result.is_err(), "result {:?}", result);
        }

        {
            let result = function.get_user_session_api_rev(session_id, false);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), api_rev);
        }

        {
            let result = function.get_user_session_api_rev(session_id, true);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), api_rev);
        }
    }

    #[test]
    fn test_close_user_session() {
        let function = create_function(2);
        let api_rev = function.get_api_rev_range().max;

        let result = function.get_function_state().get_vault(DEFAULT_VAULT_ID);
        assert!(result.is_ok());
        let vault = result.unwrap();

        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let session_id = session_result.session_id;

        {
            let result = function.close_user_session(session_id + 10);
            assert!(result.is_err(), "result {:?}", result);
        }

        {
            let result = function.close_user_session(session_id);
            assert!(result.is_ok());
        }

        {
            let result = function.close_user_session(session_id);
            assert!(result.is_err(), "result {:?}", result); // already closed by previous test
        }
    }

    #[test]
    fn test_get_vault() {
        let function = create_function(2);
        let result = function.get_function_state().get_vault(DEFAULT_VAULT_ID);
        assert!(result.is_ok());
        let result = function
            .get_function_state()
            .get_vault(Uuid::from_bytes([5; 16]));
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_simulate_migration_success() {
        let function = create_function(2);
        let api_rev = function.get_api_rev_range().max;

        // Provision the function first to enable unwrapping key
        let dummy_bk3 = function.init_bk3([0u8; BK3_SIZE_BYTES]).unwrap();
        let provision_result = function.provision(&dummy_bk3, None, None);
        assert!(provision_result.is_ok());

        let result = function.get_function_state().get_vault(DEFAULT_VAULT_ID);
        assert!(result.is_ok());
        let vault = result.unwrap();

        // Establish credential and open session
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let session_id = session_result.session_id;

        // Verify session exists before migration
        assert!(function.get_user_session(session_id, false).is_ok());

        // Perform migration simulation
        let result = function.simulate_migration();
        assert!(result.is_ok(), "Migration simulation should succeed");

        // After migration, session ID should be preserved but require renegotiation
        let session_result = function.get_user_session(session_id, false);
        assert!(
            session_result.is_err(),
            "Session should require renegotiation after migration"
        );

        // Verify function state was reset (new attestation keys generated)
        let new_attestation_key = function.get_function_state().get_attestation_key_num();
        assert!(new_attestation_key.is_ok());

        // After reset, unwrapping key should not be available until reprovisioning
        let new_unwrapping_key = function.get_function_state().get_unwrapping_key_num();
        assert!(new_unwrapping_key.is_err());
        assert!(matches!(
            new_unwrapping_key.unwrap_err(),
            ManticoreError::PartitionNotProvisioned
        ));
    }

    #[test]
    fn test_simulate_migration_preserves_session_allocation() {
        let function = create_function(4);
        let api_rev = function.get_api_rev_range().max;

        let result = function.get_function_state().get_vault(DEFAULT_VAULT_ID);
        assert!(result.is_ok());
        let vault = result.unwrap();

        // Establish credential and open multiple sessions
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let session1 = session_result.session_id;
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let session2 = session_result.session_id;

        // Verify sessions exist before migration
        assert!(function.get_user_session(session1, false).is_ok());
        assert!(function.get_user_session(session2, false).is_ok());

        // Perform migration simulation
        let result = function.simulate_migration();
        assert!(result.is_ok(), "Migration simulation should succeed");

        // After migration, both sessions should require renegotiation but IDs preserved
        let session1_err = function.get_user_session(session1, false);
        let session2_err = function.get_user_session(session2, false);

        assert!(
            matches!(session1_err, Err(ManticoreError::SessionNeedsRenegotiation)),
            "Session1 should require renegotiation"
        );
        assert!(
            matches!(session2_err, Err(ManticoreError::SessionNeedsRenegotiation)),
            "Session2 should require renegotiation"
        );

        // Try to reestablish and reopen sessions
        let result_after = function.get_function_state().get_vault(DEFAULT_VAULT_ID);
        assert!(result_after.is_ok());
        let vault_after = result_after.unwrap();

        // Establish credential and open multiple sessions
        helper_establish_credential(&vault_after, TEST_CRED_ID, TEST_CRED_PIN);
        let session_after1 = helper_reopen_session(
            &vault_after,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            api_rev,
            session1,
            None,
        )
        .unwrap();
        let session_after2 = helper_reopen_session(
            &vault_after,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            api_rev,
            session2,
            None,
        )
        .unwrap();

        assert_eq!(
            session_after1.session_id, session1,
            "Session1 ID should match after reopen"
        );
        assert_eq!(
            session_after2.session_id, session2,
            "Session2 ID should match after reopen"
        );

        //close the sessions after test
        let _ = function.close_user_session(session1);
        let _ = function.close_user_session(session2);
    }

    #[test]
    fn test_simulate_migration_clears_session_keys() {
        let function = create_function(2);
        let api_rev = function.get_api_rev_range().max;

        let result = function.get_function_state().get_vault(DEFAULT_VAULT_ID);
        assert!(result.is_ok());
        let vault = result.unwrap();

        // Establish credential and open session
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let session_id = session_result.session_id;

        // Create a session-only key
        let key_flags = EntryFlags::default().with_session(true);
        let key_id = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Aes256,
                Key::Aes(
                    crate::crypto::aes::generate_aes(crate::crypto::aes::AesKeySize::Aes256)
                        .unwrap(),
                ),
                key_flags,
                session_id,
            )
            .unwrap();

        // Verify key exists before migration
        assert!(vault.get_key_entry(key_id).is_ok());

        // Perform migration simulation
        let result = function.simulate_migration();
        assert!(result.is_ok(), "Migration simulation should succeed");

        // After migration, session-only keys should be cleared (new vault)
        let vault_after = function
            .get_function_state()
            .get_vault(DEFAULT_VAULT_ID)
            .unwrap();
        let key_result = vault_after.get_key_entry(key_id);
        assert!(
            key_result.is_err(),
            "Session-only keys should be cleared after migration"
        );
    }

    #[test]
    fn test_simulate_migration_clears_persistent_key() {
        let function = create_function(2);
        let api_rev = function.get_api_rev_range().max;

        // Provision the function first to enable unwrapping key
        let dummy_bk3 = function.init_bk3([0u8; BK3_SIZE_BYTES]).unwrap();
        let provision_result = function.provision(&dummy_bk3, None, None);
        assert!(provision_result.is_ok());

        let result = function.get_function_state().get_vault(DEFAULT_VAULT_ID);
        assert!(result.is_ok());
        let vault = result.unwrap();

        // Establish credential and open session
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let session_id = session_result.session_id;

        // Get initial key numbers
        let _initial_attestation_key = function
            .get_function_state()
            .get_attestation_key_num()
            .unwrap();
        let _initial_unwrapping_key = function
            .get_function_state()
            .get_unwrapping_key_num()
            .unwrap();

        // Add a persistent key (not session-only)
        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let persistent_key_id = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key),
                EntryFlags::default(), // persistent key
                0,
            )
            .unwrap();

        // Verify key exists before migration
        assert!(vault.get_key_entry(persistent_key_id).is_ok());

        // Perform migration simulation
        let result = function.simulate_migration();
        assert!(result.is_ok(), "Migration simulation should succeed");

        // All user keys should be cleared (new vault)
        let vault_after = function
            .get_function_state()
            .get_vault(DEFAULT_VAULT_ID)
            .unwrap();
        let key_result = vault_after.get_key_entry(persistent_key_id);
        assert!(
            key_result.is_err(),
            "All user keys should be cleared after migration"
        );

        // Session should require renegotiation
        let session_result = function.get_user_session(session_id, false);
        assert!(
            matches!(
                session_result,
                Err(ManticoreError::SessionNeedsRenegotiation)
            ),
            "Session should require renegotiation after migration"
        );
    }

    #[test]
    fn test_simulate_migration_no_sessions() {
        let function = create_function(2);

        // Perform migration simulation without any sessions.
        let result = function.simulate_migration();
        assert!(
            result.is_ok(),
            "Migration simulation for function API should succeed without any sessions"
        );
    }

    #[test]
    fn test_simulate_migration_multiple_calls() {
        let function = create_function(2);
        let api_rev = function.get_api_rev_range().max;

        let result = function.get_function_state().get_vault(DEFAULT_VAULT_ID);
        assert!(result.is_ok());
        let vault = result.unwrap();

        // Establish credential and open session
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let session_id = session_result.session_id;

        // First migration simulation
        let result1 = function.simulate_migration();
        assert!(
            result1.is_ok(),
            "First migration simulation should succeed."
        );

        // Second migration simulation
        let result2 = function.simulate_migration();
        assert!(
            result2.is_ok(),
            "Second migration simulation should succeed."
        );

        // Session should still require renegotiation
        let session_err = function.get_user_session(session_id, false);
        assert!(
            session_err.is_err(),
            "Session should require renegotiation after multiple migrations."
        );

        // Reopen the original session using the same session ID after migrations
        let vault_after = function
            .get_function_state()
            .get_vault(DEFAULT_VAULT_ID)
            .unwrap();
        // Reestablish credential and reopen session
        helper_establish_credential(&vault_after, TEST_CRED_ID, TEST_CRED_PIN);
        let reopen_result = helper_reopen_session(
            &vault_after,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            api_rev,
            session_id,
            None,
        );
        assert!(
            reopen_result.is_ok(),
            "Should be able to reopen session with original session ID after multiple migrations."
        );

        // Verify the reopened session works with the original session ID
        let reopened_session_result = function.get_user_session(session_id, false);
        assert!(
            reopened_session_result.is_ok(),
            "Reopened session with original ID should work after multiple migrations."
        );

        // Verify we can get the API revision for the reopened session
        let reopened_api_rev_result = function.get_user_session_api_rev(session_id, false);
        assert!(reopened_api_rev_result.is_ok());
        assert_eq!(reopened_api_rev_result.unwrap(), api_rev);
    }

    #[test]
    fn test_simulate_migration_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let function = Arc::new(create_function(4));
        let api_rev = function.get_api_rev_range().max;

        let result = function.get_function_state().get_vault(DEFAULT_VAULT_ID);
        assert!(result.is_ok());
        let vault = result.unwrap();

        // Establish credential and open session
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let session_id = session_result.session_id;

        // Test concurrent migrations (should be serialized by RwLock)
        let function1 = Arc::clone(&function);
        let function2 = Arc::clone(&function);

        let handle1 = thread::spawn(move || -> Result<(), ManticoreError> {
            for _i in 0..5 {
                function1.simulate_migration()?;
            }
            Ok(())
        });

        let handle2 = thread::spawn(move || -> Result<(), ManticoreError> {
            for _i in 0..5 {
                function2.simulate_migration()?;
            }
            Ok(())
        });

        let result1 = handle1.join().unwrap();
        let result2 = handle2.join().unwrap();

        // Both should succeed (serialized by write lock)
        assert!(
            result1.is_ok(),
            "First concurrent migration thread should succeed."
        );
        assert!(
            result2.is_ok(),
            "Second concurrent migration thread should succeed."
        );

        // Session should require renegotiation
        let session_result = function.get_user_session(session_id, false);
        assert!(
            session_result.is_err(),
            "Session should require renegotiation after concurrent migrations."
        );
    }

    // This test helps achieve 100% test coverage
    #[test]
    fn test_ensure_code_coverage() {
        let function = create_function(2);

        let function_weak = function.as_weak();
        let _function_weak_upgrade = function_weak.upgrade();

        let fs_weak = function.get_function_state().as_weak();

        assert_eq!(function.inner.read().state.tables_available(), 0);

        let _upgraded_fs = fs_weak.upgrade();
    }

    #[test]
    fn test_masked_key_encode_decode() {
        // Test MaskedKey encode/decode functions
        let test_data = [0x42u8; 48]; // 48 bytes of test data (BK3 size)
        let masking_key = [0x55u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES]; // 80 bytes masking key

        let env = SimCryptEnv;

        // Create metadata for the test key
        let metadata = DdiMaskedKeyMetadata {
            svn: Some(0),
            key_type: DdiKeyType::AesCbc256Hmac384,
            key_attributes: DdiMaskedKeyAttributes { blob: [0u8; 32] },
            bks2_index: None,
            key_tag: None,
            key_label: MborByteArray::from_slice(b"TEST")
                .map_err(|_| ManticoreError::InternalError)
                .unwrap(),
            key_length: BK_AES_CBC_256_HMAC384_SIZE_BYTES as u16,
        };

        let buffer = encode_masked_key(&test_data, &masking_key, &metadata).unwrap();

        let decoded = MaskedKey::decode(&env, &masking_key, &buffer, true).unwrap();

        let mut unmasked_data = [0u8; 48];
        decoded
            .decrypt_key(&env, &masking_key, &mut unmasked_data)
            .unwrap();

        assert_eq!(unmasked_data, test_data);
    }

    #[test]
    fn test_masked_key_encode_decode_variable_lengths() {
        let masking_key = [0x55u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
        let env = SimCryptEnv;

        let requested_lengths = vec![13, 16, 32, 48];

        let mut kind_sizes = vec![
            Kind::Rsa2kPublic.size(),
            Kind::Rsa3kPublic.size(),
            Kind::Rsa4kPublic.size(),
            Kind::Rsa2kPrivate.size(),
            Kind::Rsa3kPrivate.size(),
            Kind::Rsa4kPrivate.size(),
            Kind::Rsa2kPrivateCrt.size(),
            Kind::Rsa3kPrivateCrt.size(),
            Kind::Rsa4kPrivateCrt.size(),
            Kind::Ecc256Public.size(),
            Kind::Ecc384Public.size(),
            Kind::Ecc521Public.size(),
            Kind::Ecc256Private.size(),
            Kind::Ecc384Private.size(),
            Kind::Ecc521Private.size(),
            Kind::Aes128.size(),
            Kind::Aes192.size(),
            Kind::Aes256.size(),
            Kind::AesXtsBulk256.size(),
            Kind::AesGcmBulk256.size(),
            Kind::AesGcmBulk256Unapproved.size(),
            Kind::AesHmac640.size(),
            Kind::Secret256.size(),
            Kind::Secret384.size(),
            Kind::Secret521.size(),
            Kind::Session.size(),
            Kind::HmacSha256.size(),
            Kind::HmacSha384.size(),
            Kind::HmacSha512.size(),
            Kind::Rsa2kPublic.serde_size(),
            Kind::Rsa3kPublic.serde_size(),
            Kind::Rsa4kPublic.serde_size(),
            Kind::Rsa2kPrivate.serde_size(),
            Kind::Rsa3kPrivate.serde_size(),
            Kind::Rsa4kPrivate.serde_size(),
            Kind::Rsa2kPrivateCrt.serde_size(),
            Kind::Rsa3kPrivateCrt.serde_size(),
            Kind::Rsa4kPrivateCrt.serde_size(),
            Kind::Ecc256Public.serde_size(),
            Kind::Ecc384Public.serde_size(),
            Kind::Ecc521Public.serde_size(),
            Kind::Ecc256Private.serde_size(),
            Kind::Ecc384Private.serde_size(),
            Kind::Ecc521Private.serde_size(),
            Kind::Aes128.serde_size(),
            Kind::Aes192.serde_size(),
            Kind::Aes256.serde_size(),
            Kind::AesXtsBulk256.serde_size(),
            Kind::AesGcmBulk256.serde_size(),
            Kind::AesGcmBulk256Unapproved.serde_size(),
            Kind::AesHmac640.serde_size(),
            Kind::Secret256.serde_size(),
            Kind::Secret384.serde_size(),
            Kind::Secret521.serde_size(),
            Kind::Session.serde_size(),
            Kind::HmacSha256.serde_size(),
            Kind::HmacSha384.serde_size(),
            Kind::HmacSha512.serde_size(),
        ];
        kind_sizes.sort();
        kind_sizes.dedup();

        let mut all_lengths = requested_lengths;
        for size in kind_sizes {
            if !all_lengths.contains(&size) {
                all_lengths.push(size);
            }
        }
        all_lengths.sort();

        let mut successful_lengths = Vec::new();
        let mut failed_lengths = Vec::new();

        for length in &all_lengths {
            let mut test_data = vec![0u8; *length];
            for (i, byte) in test_data.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }

            let metadata = DdiMaskedKeyMetadata {
                svn: Some(0),
                key_type: DdiKeyType::AesCbc256Hmac384,
                key_attributes: DdiMaskedKeyAttributes { blob: [0u8; 32] },
                bks2_index: None,
                key_tag: None,
                key_label: MborByteArray::from_slice(format!("LEN{}", length).as_bytes())
                    .map_err(|_| ManticoreError::InternalError)
                    .unwrap(),
                key_length: BK_AES_CBC_256_HMAC384_SIZE_BYTES as u16,
            };

            match encode_masked_key(&test_data, &masking_key, &metadata) {
                Ok(buffer) => {
                    let decoded = MaskedKey::decode(&env, &masking_key, &buffer, true).unwrap();

                    let mut unmasked_data = vec![0u8; *length];
                    decoded
                        .decrypt_key(&env, &masking_key, &mut unmasked_data)
                        .unwrap();

                    assert_eq!(unmasked_data, test_data, "Mismatch for length {}", length);
                    successful_lengths.push(*length);
                }
                Err(_) => {
                    failed_lengths.push(*length);
                }
            }
        }

        for length in &all_lengths {
            assert!(
                successful_lengths.contains(length),
                "Length {} should work with zero-padding but failed",
                length
            );
        }

        let requested_lengths = vec![13, 16, 32, 48];
        for length in requested_lengths {
            assert!(
                successful_lengths.contains(&length),
                "Requested length {} should work but failed",
                length
            );
        }

        assert_eq!(
            successful_lengths.len(),
            all_lengths.len(),
            "Not all lengths were successfully tested"
        );

        assert!(
            failed_lengths.is_empty(),
            "Some lengths failed unexpectedly: {:?}",
            failed_lengths
        );
    }
}
