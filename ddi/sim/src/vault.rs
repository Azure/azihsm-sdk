// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for Vault.

use std::sync::Arc;
use std::sync::Weak;

use azihsm_ddi_types::DdiDeviceKind;
use azihsm_ddi_types::DdiKeyType;
use azihsm_ddi_types::DdiMaskedKeyAttributes;
use azihsm_ddi_types::MaskingKeyAlgorithm;
use parking_lot::RwLock;
use tracing::instrument;
use uuid::Uuid;

use crate::credentials::*;
use crate::crypto::aes::AesAlgo;
use crate::crypto::aes::AesKey;
use crate::crypto::aes::AesOp;
use crate::crypto::aeshmac::AesHmacKey;
use crate::crypto::aeshmac::AesHmacOp;
use crate::crypto::ecc::EccOp;
use crate::crypto::ecc::EccPrivateOp;
use crate::crypto::ecc::EccPublicKey;
use crate::crypto::hmac::HmacKey;
use crate::crypto::hmac::HmacOp;
use crate::crypto::rand::rand_bytes;
use crate::crypto::secret::SecretKey;
use crate::crypto::secret::SecretOp;
use crate::crypto::sha::HashAlgorithm;
use crate::errors::ManticoreError;
use crate::function::ApiRev;
use crate::function::METADATA_MAX_SIZE_BYTES;
use crate::lmkey_derive::LMKeyDerive;
use crate::session_table::SessionTable;
use crate::sim_crypto_env::SimCryptEnv;
use crate::sim_crypto_env::BK_AES_CBC_256_HMAC384_SIZE_BYTES;
use crate::sim_crypto_env::SESSION_SEED_SIZE_BYTES;
use crate::table::entry::key::Key;
use crate::table::entry::key::SessionKey;
use crate::table::entry::Entry;
use crate::table::entry::EntryFlags;
use crate::table::entry::Kind;
use crate::table::Table;
use crate::vault::Key::EccPrivate;

/// The default vault ID.
/// Guests are blocked from creating a vault with this ID in create_vault.
pub(crate) const DEFAULT_VAULT_ID: Uuid = Uuid::from_bytes([
    0xE0, 0x1D, 0x5E, 0xA3, 0x64, 0x51, 0x43, 0x9D, 0xA5, 0x5C, 0x23, 0xDE, 0xD8, 0x56, 0xEF, 0xA3,
]);

/// The default app ID.
/// Guests are blocked from creating an app with this ID in add_app.
pub(crate) const APP_ID_FOR_INTERNAL_KEYS: Uuid = DEFAULT_VAULT_ID;

pub(crate) const MAX_SESSIONS: usize = 8;

struct KeyNumber(u16);

impl KeyNumber {
    fn new(table_index: u8, entry_index: u8) -> Self {
        Self(((table_index as u16) << 8) | (entry_index as u16))
    }

    fn table(&self) -> u8 {
        (self.0 >> 8) as u8
    }

    fn entry(&self) -> u8 {
        (self.0 & 0xff) as u8
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SessionResult {
    pub(crate) session_id: u16,
    pub(crate) short_app_id: u8,
    pub(crate) bmk: Vec<u8>,
}

/// The Vault.
#[derive(Debug, Clone)]
pub(crate) struct Vault {
    inner: Arc<RwLock<VaultInner>>,
}

impl Vault {
    /// Creates a new vault.
    ///
    /// # Arguments
    /// * `id` - The vault ID.
    /// * `table_count` - The number of tables to use.
    ///
    /// # Returns
    /// * The new vault.
    pub(crate) fn new(id: Uuid, table_count: usize) -> Result<Self, ManticoreError> {
        tracing::debug!(id = ?id, table_count, "Creating vault");
        Ok(Self {
            inner: Arc::new(RwLock::new(VaultInner::new(id, table_count)?)),
        })
    }

    fn with_inner(inner: Arc<RwLock<VaultInner>>) -> Self {
        Self { inner }
    }

    /// Creates a weak reference to the vault.
    ///
    /// # Returns
    /// * The weak reference to the vault.
    pub(crate) fn as_weak(&self) -> VaultWeak {
        VaultWeak::new(Arc::downgrade(&self.inner))
    }

    /// Gets the vault ID.
    ///
    /// # Returns
    /// * The vault ID.
    pub(crate) fn id(&self) -> Uuid {
        self.inner.read().id()
    }

    pub(crate) fn user(&self) -> UserCredentials {
        self.inner.read().user
    }

    /// Add a new key to the vault.
    ///
    /// # Arguments
    /// * `app_id` - The ID of the app to add the key to.
    /// * `kind` - The kind of the key.
    /// * `key` - The key to add.
    /// * `flags` - The flags of the key.
    /// * `sess_id` - The ID of App Session that owns the session_only key.
    ///
    /// # Returns
    /// * The key number of the added key.
    ///
    /// # Errors
    /// * `ManticoreError::AppNotFound`: If the app does not exist.
    /// * `ManticoreError::NotEnoughSpace`: If there is not enough space in the vault.
    #[instrument(skip_all, fields(id = ?self.id(), sess_id_or_key_tag = sess_id_or_key_tag))]
    pub(crate) fn add_key(
        &self,
        app_id: Uuid,
        kind: Kind,
        key: Key,
        flags: EntryFlags,
        sess_id_or_key_tag: u16,
    ) -> Result<u16, ManticoreError> {
        self.inner
            .write()
            .add_key(app_id, kind, key, flags, sess_id_or_key_tag)
    }

    /// Remove a key from the vault.
    ///
    /// # Arguments
    /// * `key_num` - The key number of the key to remove.
    ///
    /// # Returns
    /// * Ok if the key was removed successfully.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidKeyNumber`: If the key number's table is invalid.
    /// * `ManticoreError::InvalidKeyIndex` - If the jey number's index is invalid.
    /// * `ManticoreError::CannotDeleteKeyInUse` - The key could not be immediately deleted since the key is currently in use. Please try again later. However, the was disabled and new tasks cannot use the key anymore.
    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn remove_key(&self, key_num: u16) -> Result<(), ManticoreError> {
        self.inner.read().remove_key(key_num)
    }

    /// Get a key from the vault.
    ///
    /// # Arguments
    /// * `key_num` - The key number of the key to get.
    ///
    /// # Returns
    /// * The key `Entry`.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidKeyNumber`: If the key number's table is invalid.
    /// * `ManticoreError::InvalidKeyIndex` - If the key number's index is invalid.
    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn get_key_entry(&self, key_num: u16) -> Result<Entry, ManticoreError> {
        self.inner.read().get_key_entry(key_num)
    }

    /// Get a session entry from the vault by session ID.
    ///
    /// # Arguments
    /// * `session_id` - The virtual session ID to look up.
    ///
    /// # Returns
    /// * The key `Entry` for the session.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidArgument` - If the session ID is invalid.
    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn get_session_entry(&self, session_id: u16) -> Result<Entry, ManticoreError> {
        self.inner.read().get_session_entry(session_id)
    }

    /// Get a session entry from the vault by session ID without checking if it's disabled.
    /// This method allows access to sessions that have been disabled and are in the process
    /// of being closed. This is primarily used for cleanup operations and API revision
    /// validation during session closure where access to disabled sessions is required.
    ///
    /// # Arguments
    /// * `session_id` - The virtual session ID to look up.
    ///
    /// # Returns
    /// * The key `Entry` for the session (even if disabled).
    ///
    /// # Errors
    /// * `ManticoreError::InvalidArgument` - If the session ID is invalid.
    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn get_session_entry_unchecked(
        &self,
        session_id: u16,
    ) -> Result<Entry, ManticoreError> {
        self.inner.read().get_session_entry_unchecked(session_id)
    }

    /// Get nonce from the vault.
    ///
    /// # Returns
    /// * The nonce.
    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn get_nonce(&self) -> [u8; 32] {
        self.inner.read().get_nonce()
    }

    /// Get establish credential encryption key id.
    ///
    /// # Returns
    /// * The establish credential encryption key id.
    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn get_establish_cred_encryption_key_id(&self) -> Result<u16, ManticoreError> {
        self.inner.read().get_establish_cred_encryption_key_id()
    }

    /// Get session encryption key id.
    ///
    /// # Returns
    /// * The session encryption key id.
    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn get_session_encryption_key_id(&self) -> Result<u16, ManticoreError> {
        self.inner.read().get_session_encryption_key_id()
    }

    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn get_key_num_by_tag(
        &self,
        app_id: Uuid,
        key_tag: u16,
    ) -> Result<u16, ManticoreError> {
        self.inner.read().get_key_num_by_tag(app_id, key_tag)
    }

    /// Establish credential.
    ///
    /// # Returns
    /// * Ok if successful.
    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn establish_credential(
        &self,
        encrypted_credential: EncryptedCredential,
        client_pub_key: &[u8],
    ) -> Result<(), ManticoreError> {
        self.inner
            .write()
            .establish_credential(encrypted_credential, client_pub_key)
    }

    /// Open Session.
    ///
    /// # Arguments
    /// * `encrypted_credential` - Encrypted credentials
    /// * `client_pub_key` - Client public key
    /// * `api_rev` - API revision
    /// * `bk_partition` - Partition backup key, used to derive the bk_session to decrypt bmk
    ///
    /// # Returns
    /// * Ok if successful.
    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn open_session(
        &self,
        encrypted_credential: EncryptedSessionCredential,
        client_pub_key: &[u8],
        api_rev: ApiRev,
        bk_partition: &[u8],
    ) -> Result<SessionResult, ManticoreError> {
        self.inner
            .write()
            .open_session(encrypted_credential, client_pub_key, api_rev, bk_partition)
    }

    /// Reopen Session - reestablish a session that requires renegotiation.
    ///
    /// # Arguments
    /// * `encrypted_credential` - Encrypted credentials
    /// * `client_pub_key` - Client public key
    /// * `api_rev` - API revision
    /// * `reopen_sess_id` - Virtual session ID to reopen
    /// * `bmk` - Backup session masking key
    /// * `bk_partition` - Partition backup key, used to derive the bk_session to decrypt bmk
    ///
    /// # Returns
    /// * `Ok((session_id, short_app_id))` if successful.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidArgument` - If the session doesn't exist or doesn't need renegotiation
    /// * Other errors from credential validation or session creation
    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn reopen_session(
        &self,
        encrypted_credential: EncryptedSessionCredential,
        client_pub_key: &[u8],
        api_rev: ApiRev,
        reopen_sess_id: u16,
        bmk: Option<&[u8]>,
        bk_partition: &[u8],
    ) -> Result<SessionResult, ManticoreError> {
        self.inner.write().reopen_session(
            encrypted_credential,
            client_pub_key,
            api_rev,
            reopen_sess_id,
            bmk,
            bk_partition,
        )
    }

    /// Close Session - close session and clean up all session-related resources.
    ///
    /// # Arguments
    /// * `session_id` - Virtual session ID to close
    ///
    /// # Returns
    /// * Ok if successful.
    ///
    /// # Errors
    /// * `ManticoreError::SessionNotFound` - If the session ID is invalid.
    /// * `ManticoreError::CannotDeleteKeyInUse` - If session keys cannot be deleted.
    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn close_session(&self, session_id: u16) -> Result<(), ManticoreError> {
        self.inner.write().close_session(session_id)
    }

    /// Get Target Session ID - translate virtual session ID to physical session ID.
    ///
    /// # Arguments
    /// * `virtual_session_id` - The virtual session ID to translate
    ///
    /// # Returns
    /// * `Ok(physical_session_id)` - The corresponding physical session ID
    ///
    /// # Errors
    /// * `ManticoreError::SessionNotFound` - If the virtual session ID is invalid or not found.
    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn get_target_session_id(
        &self,
        virtual_session_id: u16,
    ) -> Result<u16, ManticoreError> {
        self.inner.read().get_target_session_id(virtual_session_id)
    }

    /// Change the user's PIN.
    ///
    /// # Arguments
    /// * `new_pin` - The new encrypted PIN.
    /// * `client_pub_key` - The client's public key.
    ///
    /// # Returns
    /// * Ok if successful.
    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn change_pin(
        &self,
        new_pin: EncryptedPin,
        client_pub_key: &[u8],
    ) -> Result<(), ManticoreError> {
        self.inner.write().change_pin(new_pin, client_pub_key)
    }

    /// Backup session table state for migration simulation.
    ///
    /// # Returns
    /// * `u8` - Mask representing which sessions are currently active
    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn backup_session_table(&self) -> u8 {
        self.inner.read().session_table.backup()
    }

    /// Restore session table state after migration simulation.
    ///
    /// # Arguments
    /// * `mask` - Mask representing which sessions to restore
    #[instrument(skip(self), fields(id = ?self.id()))]
    pub(crate) fn restore_session_table(&self, mask: u8) {
        self.inner.write().session_table.restore(mask);
    }
}

#[derive(Debug)]
struct VaultInner {
    id: Uuid,
    tables: Vec<Table>,
    user: UserCredentials,
    establish_cred_encryption_key_id: Option<u16>,
    session_encryption_key_id: Option<u16>,
    nonce: [u8; 32],
    session_table: SessionTable,
}

impl Drop for VaultInner {
    fn drop(&mut self) {
        tracing::debug!(id = ?self.id, "Dropping vault");
    }
}

impl VaultInner {
    fn new(id: Uuid, table_count: usize) -> Result<Self, ManticoreError> {
        let mut tables = Vec::with_capacity(table_count);
        for _ in 0..table_count {
            tables.push(Table::new());
        }

        let mut rand_buf = [0; 32];
        rand_bytes(&mut rand_buf).map_err(|err| {
            tracing::error!(error = ?err, "Failed to generate random bytes for new vault");
            ManticoreError::InternalError
        })?;
        let nonce = rand_buf;

        let mut vault_inner = Self {
            id,
            tables,
            user: UserCredentials {
                credentials: Credentials::new(Uuid::nil(), Role::User, [0; 16]),
                short_app_id: 0,
            },
            establish_cred_encryption_key_id: None,
            session_encryption_key_id: None,
            nonce,
            session_table: SessionTable::new(),
        };

        vault_inner.generate_establish_cred_encryption_key_id()?;

        vault_inner.generate_session_encryption_key_id()?;

        Ok(vault_inner)
    }

    fn id(&self) -> Uuid {
        self.id
    }

    fn add_key(
        &mut self,
        app_id: Uuid,
        kind: Kind,
        key: Key,
        flags: EntryFlags,
        sess_id_or_key_tag: u16,
    ) -> Result<u16, ManticoreError> {
        if app_id != self.user.credentials.id && app_id != APP_ID_FOR_INTERNAL_KEYS {
            tracing::error!(error = ?ManticoreError::AppNotFound, id = ?app_id, "App not found with given ID");
            Err(ManticoreError::AppNotFound)?
        }

        // Cannot create a session_only key for the internal app
        if app_id == APP_ID_FOR_INTERNAL_KEYS && flags.session_only() {
            tracing::error!(id = ?app_id, sess_id_or_key_tag, "Cannot create a session_only key for the internal app");
            Err(ManticoreError::InvalidArgument)?
        }

        // For session-only keys, convert virtual session ID to physical session ID
        let actual_sess_id_or_key_tag = if flags.session_only() {
            self.session_table
                .get_target_session(sess_id_or_key_tag)
                .ok_or_else(|| {
                    tracing::error!(err = ?ManticoreError::InvalidArgument, ?sess_id_or_key_tag, "Target session not found");
                    ManticoreError::InvalidArgument})?
        } else {
            sess_id_or_key_tag
        };

        if !flags.session_only() && actual_sess_id_or_key_tag != 0 {
            let key_tag_exists = self.get_key_num_by_tag(app_id, actual_sess_id_or_key_tag);
            if key_tag_exists.is_ok() {
                tracing::error!(key_tag = ?actual_sess_id_or_key_tag, "Key tag already exists");
                Err(ManticoreError::KeyTagAlreadyExists)?
            }
        }

        // Try to add the key to the first table that has space
        let key_num = self
            .tables
            .iter_mut()
            .enumerate()
            .find_map(|(table_index, table)| {
                table
                    .add(app_id, kind, key.clone(), flags, actual_sess_id_or_key_tag)
                    .map(|entry_index| KeyNumber::new(table_index as u8, entry_index))
                    .ok()
            })
            .ok_or_else(|| {
                tracing::error!("Not enough space for new key");
                ManticoreError::NotEnoughSpace
            })?;

        Ok(key_num.0)
    }

    fn remove_key(&self, key_num: u16) -> Result<(), ManticoreError> {
        let key_num = KeyNumber(key_num);
        let table_index = key_num.table() as usize;
        let entry_index = key_num.entry();

        if table_index >= self.tables.len() {
            tracing::error!(
                key_num = key_num.0,
                "Invalid key number: table index out of bounds"
            );
            Err(ManticoreError::InvalidKeyNumber)?
        }

        tracing::debug!(table_index, entry_index, "Removing entry from table");
        self.tables[table_index].remove(entry_index)
    }

    /// Remove all session-only keys for a given physical session ID.
    /// This is a helper function used by close_session.
    #[instrument(skip(self))]
    fn remove_session_only_keys_by_physical_session_id(
        &mut self,
        physical_sess_id: u16,
    ) -> Result<u16, ManticoreError> {
        let mut removed_count = 0;
        let mut failed_delete_count: u8 = 0;

        for table in self.tables.iter_mut() {
            match table.remove_all_session_only_keys(physical_sess_id) {
                Ok(count) => removed_count += count,
                Err(error) => {
                    tracing::error!(error = ?error, physical_sess_id, "remove_session_only_keys_by_physical_id failed");
                    failed_delete_count += 1;
                }
            }
        }

        tracing::debug!(failed_delete_count, removed_count);
        match failed_delete_count {
            0 => Ok(removed_count),
            1 => Err(ManticoreError::CannotDeleteKeyInUse),
            _ => Err(ManticoreError::CannotDeleteSomeKeysInUse),
        }
    }

    fn get_key_entry(&self, key_num: u16) -> Result<Entry, ManticoreError> {
        let key_num = KeyNumber(key_num);
        let table_index = key_num.table() as usize;
        let entry_index = key_num.entry();

        if table_index >= self.tables.len() {
            tracing::error!(
                key_num = key_num.0,
                "Invalid key number: table index out of bounds"
            );
            Err(ManticoreError::InvalidKeyNumber)?
        }

        self.tables[table_index].get(entry_index)
    }

    fn get_key_entry_unchecked(&self, key_num: u16) -> Result<Entry, ManticoreError> {
        let key_num = KeyNumber(key_num);
        let table_index = key_num.table() as usize;
        let entry_index = key_num.entry();

        if table_index >= self.tables.len() {
            tracing::error!(
                key_num = key_num.0,
                "Invalid key number: table index out of bounds"
            );
            Err(ManticoreError::InvalidKeyNumber)?
        }

        self.tables[table_index].get_unchecked(entry_index)
    }

    fn get_nonce(&self) -> [u8; 32] {
        self.nonce
    }

    fn reset_nonce(&mut self) -> Result<(), ManticoreError> {
        let mut rand_buf = [0; 32];
        rand_bytes(&mut rand_buf)?;

        let nonce = rand_buf;

        self.nonce = nonce;
        Ok(())
    }

    fn get_establish_cred_encryption_key_id(&self) -> Result<u16, ManticoreError> {
        self.establish_cred_encryption_key_id
            .ok_or(ManticoreError::KeyNotFound)
    }

    fn clear_establish_cred_encryption_key_id(&mut self) -> Result<(), ManticoreError> {
        let key_id = self
            .establish_cred_encryption_key_id
            .ok_or(ManticoreError::KeyNotFound)?;

        self.remove_key(key_id)?;

        self.establish_cred_encryption_key_id = None;
        Ok(())
    }

    fn get_session_encryption_key_id(&self) -> Result<u16, ManticoreError> {
        // Check if credentials is not already set
        if self.user.credentials.id.is_nil() || self.user.credentials.pin.eq(&[0; 16]) {
            Err(ManticoreError::CredentialsNotEstablished)?;
        }

        self.session_encryption_key_id
            .ok_or(ManticoreError::KeyNotFound)
    }

    fn generate_establish_cred_encryption_key_id(&mut self) -> Result<(), ManticoreError> {
        // Generate the ECC 384 key
        let (ecc_key, _) = crate::crypto::ecc::generate_ecc(crate::crypto::ecc::EccCurve::P384)?;

        // Store key in vault without an associated app session
        let key_flags = EntryFlags::new()
            .with_allow_derive(true)
            .with_generated(true);

        let private_key_id = self.add_key(
            APP_ID_FOR_INTERNAL_KEYS,
            Kind::Ecc384Private,
            Key::EccPrivate(ecc_key),
            key_flags,
            0, //sess_id_or_key_tag
        )?;

        self.establish_cred_encryption_key_id = Some(private_key_id);

        Ok(())
    }

    fn generate_session_encryption_key_id(&mut self) -> Result<(), ManticoreError> {
        // Generate the ECC 384 key
        let (ecc_key, _) = crate::crypto::ecc::generate_ecc(crate::crypto::ecc::EccCurve::P384)?;

        // Store key in vault without an associated app session
        let key_flags = EntryFlags::new()
            .with_allow_derive(true)
            .with_generated(true);

        let private_key_id = self.add_key(
            APP_ID_FOR_INTERNAL_KEYS,
            Kind::Ecc384Private,
            Key::EccPrivate(ecc_key),
            key_flags,
            0, //sess_id_or_key_tag
        )?;

        self.session_encryption_key_id = Some(private_key_id);

        Ok(())
    }

    fn set_user_new_credential(&mut self, id: &[u8], pin: &[u8]) -> Result<(), ManticoreError> {
        if id.len() != 16 || pin.len() != 16 {
            Err(ManticoreError::InvalidAppCredentials)?;
        }

        if id.eq(&[0; 16]) || pin.eq(&[0; 16]) {
            Err(ManticoreError::InvalidAppCredentials)?;
        }

        self.user.credentials.id =
            Uuid::from_slice(id).map_err(|_| ManticoreError::InvalidAppCredentials)?;
        self.user.credentials.pin.copy_from_slice(pin);

        Ok(())
    }

    fn establish_credential(
        &mut self,
        encrypted_credential: EncryptedCredential,
        client_pub_key: &[u8],
    ) -> Result<(), ManticoreError> {
        let key_id = self.get_establish_cred_encryption_key_id()?;
        {
            let entry = self.get_key_entry(key_id)?;

            // Check if sent nonce is same
            if encrypted_credential.nonce != self.get_nonce() {
                Err(ManticoreError::NonceMismatch)?;
            }

            // Check if credentials are already set
            if !self.user.credentials.id.is_nil() && !self.user.credentials.pin.eq(&[0; 16]) {
                Err(ManticoreError::VaultAppLimitReached)?;
            }

            if let EccPrivate(private_key) = entry.key() {
                let public_key = EccPublicKey::from_der(client_pub_key, Some(Kind::Ecc384Public))?;
                let secret_bytes = private_key.derive(&public_key)?;
                let secret_key = SecretKey::from_bytes(&secret_bytes)?;
                let current_nonce = self.get_nonce();
                let keys = secret_key.hkdf_derive(
                    HashAlgorithm::Sha384,
                    None,
                    Some(&current_nonce),
                    80,
                )?;

                let hmac_key = &keys[32..];

                let mut id_pin_iv_nonce = [0; 80];
                id_pin_iv_nonce[..16].copy_from_slice(&encrypted_credential.id);
                id_pin_iv_nonce[16..32].copy_from_slice(&encrypted_credential.pin);
                id_pin_iv_nonce[32..48].copy_from_slice(&encrypted_credential.iv);
                id_pin_iv_nonce[48..].copy_from_slice(&current_nonce);

                let hmac_key = HmacKey::from_bytes(hmac_key)?;
                let calculated_tag = hmac_key.hmac(&id_pin_iv_nonce, HashAlgorithm::Sha384)?;
                if calculated_tag != encrypted_credential.tag {
                    Err(ManticoreError::PinDecryptionFailed)?;
                }

                self.reset_nonce()?;

                let aes_key = AesKey::from_bytes(&keys[..32])?;

                let aes_result = aes_key.decrypt(
                    &encrypted_credential.id,
                    AesAlgo::Cbc,
                    Some(&encrypted_credential.iv),
                )?;
                let decrypted_id = aes_result.plain_text;
                let iv = aes_result.iv;

                let aes_result =
                    aes_key.decrypt(&encrypted_credential.pin, AesAlgo::Cbc, iv.as_deref())?;
                let decrypted_pin = aes_result.plain_text;

                self.set_user_new_credential(&decrypted_id, &decrypted_pin)?;
            } else {
                Err(ManticoreError::InternalError)?;
            }
        }

        self.clear_establish_cred_encryption_key_id()?;
        Ok(())
    }

    fn verify_user_credential(&self, id: [u8; 16], pin: [u8; 16]) -> Result<(), ManticoreError> {
        if id.eq(&[0; 16]) || pin.eq(&[0; 16]) {
            Err(ManticoreError::InvalidAppCredentials)?;
        }

        let id = Uuid::from_bytes(id);
        let user_cred = Credentials::new(id, Role::User, pin);

        if self.user.credentials != user_cred {
            Err(ManticoreError::InvalidAppCredentials)?;
        }

        Ok(())
    }

    /// Verify encrypted credentials and extract user ID and PIN.
    /// Return the session seed data.
    /// This contains the common credential verification logic shared by open_session and reopen_session.
    ///
    /// # Arguments
    /// * `encrypted_credential` - Encrypted credentials
    /// * `client_pub_key` - Client public key
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` Vec<u8> session_seed, if credentials are valid
    ///
    /// # Errors
    /// * Various credential validation errors
    fn verify_encrypted_session_credentials(
        &mut self,
        encrypted_credential: EncryptedSessionCredential,
        client_pub_key: &[u8],
    ) -> Result<Vec<u8>, ManticoreError> {
        let key_id = self.get_session_encryption_key_id()?;
        let entry = self.get_key_entry(key_id)?;

        // Check if sent nonce is same
        if encrypted_credential.nonce != self.get_nonce() {
            Err(ManticoreError::NonceMismatch)?;
        }

        // Check if credential is already set
        if self.user.credentials.id.is_nil() || self.user.credentials.pin.eq(&[0; 16]) {
            Err(ManticoreError::CredentialsNotEstablished)?;
        }

        if let EccPrivate(private_key) = entry.key() {
            let public_key = EccPublicKey::from_der(client_pub_key, Some(Kind::Ecc384Public))?;
            let secret_bytes = private_key.derive(&public_key)?;
            let secret_key = SecretKey::from_bytes(&secret_bytes)?;
            let current_nonce = self.get_nonce();
            let keys =
                secret_key.hkdf_derive(HashAlgorithm::Sha384, None, Some(&current_nonce), 80)?;

            let hmac_key = &keys[32..];

            let mut id_pin_seed_iv_nonce = [0; 128];
            id_pin_seed_iv_nonce[..16].copy_from_slice(&encrypted_credential.id);
            id_pin_seed_iv_nonce[16..32].copy_from_slice(&encrypted_credential.pin);
            id_pin_seed_iv_nonce[32..80].copy_from_slice(&encrypted_credential.seed);
            id_pin_seed_iv_nonce[80..96].copy_from_slice(&encrypted_credential.iv);
            id_pin_seed_iv_nonce[96..].copy_from_slice(&current_nonce);

            let hmac_key = HmacKey::from_bytes(hmac_key)?;
            let calculated_tag = hmac_key.hmac(&id_pin_seed_iv_nonce, HashAlgorithm::Sha384)?;
            if calculated_tag != encrypted_credential.tag {
                Err(ManticoreError::PinDecryptionFailed)?;
            }

            self.reset_nonce()?;

            let aes_key = AesKey::from_bytes(&keys[..32])?;

            let aes_result = aes_key.decrypt(
                &encrypted_credential.id,
                AesAlgo::Cbc,
                Some(&encrypted_credential.iv),
            )?;
            let decrypted_id = aes_result.plain_text;
            let iv = aes_result.iv;

            let aes_result =
                aes_key.decrypt(&encrypted_credential.pin, AesAlgo::Cbc, iv.as_deref())?;
            let decrypted_pin = aes_result.plain_text;
            let iv = aes_result.iv;

            let aes_result =
                aes_key.decrypt(&encrypted_credential.seed, AesAlgo::Cbc, iv.as_deref())?;
            let decrypted_seed = aes_result.plain_text;

            let mut id = [0; 16];
            let mut pin = [0; 16];

            id.copy_from_slice(&decrypted_id);
            pin.copy_from_slice(&decrypted_pin);

            self.verify_user_credential(id, pin)?;
            Ok(decrypted_seed)
        } else {
            Err(ManticoreError::InternalError)
        }
    }

    /// Create a new physical session and return its key number.
    /// This creates the session key entry but doesn't map it to a virtual session ID.
    ///
    /// # Arguments
    /// * `api_rev` - API revision
    /// * `mk_session` - Masking key for the session
    ///
    /// # Returns
    /// * `Ok(physical_session_key_num)` if successful
    ///
    /// # Errors
    /// * Session limit errors and key creation errors
    fn create_physical_session(
        &mut self,
        api_rev: ApiRev,
        mk_session: &[u8],
    ) -> Result<u16, ManticoreError> {
        if self.get_session_count() >= MAX_SESSIONS {
            Err(ManticoreError::VaultSessionLimitReached)?;
        }

        // Mark the keys as generated.
        let entry_flags = EntryFlags::new().with_generated(true);

        let key_kind = Kind::Session;

        let masking_key = AesHmacKey::from_bytes(mk_session)?;
        let session_data = SessionKey {
            api_rev,
            masking_key,
        };

        let sess_key_num = self.add_key(
            APP_ID_FOR_INTERNAL_KEYS,
            key_kind,
            Key::Session(session_data),
            entry_flags,
            0,
        )?;

        Ok(sess_key_num)
    }

    /// Create a new backup session masking key, used in open_session
    ///
    /// # Arguments
    /// * `bk_session` - Backup key for the session, used to encrypt the session masking key
    ///
    /// # Returns
    /// * `Ok(session_bmk)` if successful
    fn generate_session_bmk(&self, bk_session: &[u8]) -> Result<Vec<u8>, ManticoreError> {
        let env = SimCryptEnv;

        // Generate BMK
        let mut metadata_len = METADATA_MAX_SIZE_BYTES;
        let mut metadata = [0u8; METADATA_MAX_SIZE_BYTES];
        LMKeyDerive::encode_masked_key_metadata(
            DdiDeviceKind::Virtual,
            Some(1),
            DdiKeyType::AesCbc256Hmac384,
            DdiMaskedKeyAttributes { blob: [0u8; 32] },
            Some(0),
            None,
            b"SMK",
            &mut metadata_len,
            &mut metadata,
            bk_session.len() as u16,
        )
        .map_err(|err| {
            tracing::error!("encode_masked_key_metadata error {:?}", err);
            ManticoreError::InternalError
        })?;

        // Get the required length for BMK
        let mut session_bmk_len = 0;
        let _ = LMKeyDerive::bmk_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            bk_session,
            &metadata[..metadata_len],
            &mut session_bmk_len,
            &mut [0u8; 0],
        );

        // Now generate the session BMK
        let mut session_bmk = vec![0u8; session_bmk_len];
        LMKeyDerive::bmk_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            bk_session,
            &metadata[..metadata_len],
            &mut session_bmk_len,
            &mut session_bmk,
        )
        .map_err(|err| {
            tracing::error!("bmk_gen error {:?}", err);
            ManticoreError::InternalError
        })?;

        Ok(session_bmk)
    }

    /// Open session.
    /// This includes steps to decrypt credential information,
    /// and use the session_seed to generate session masking key (session_mk)
    ///
    /// # Arguments
    /// * `encrypted_credential` - encrypted blob including credentials and session seed
    /// * `client_pub_key` - public key data from client necessary to decrypt credentials
    /// * `api_rev` - ApiRevision for the session to support
    /// * `bk_partition` - Backup Key for the partition passed from the vault;
    ///   used to derive the bk_session (session backup key)
    ///
    /// # Returns
    /// * `Ok(SessionResult)` if successful
    fn open_session(
        &mut self,
        encrypted_credential: EncryptedSessionCredential,
        client_pub_key: &[u8],
        api_rev: ApiRev,
        bk_partition: &[u8],
    ) -> Result<SessionResult, ManticoreError> {
        let session_seed_vec =
            self.verify_encrypted_session_credentials(encrypted_credential, client_pub_key)?;

        let mut session_seed = [0u8; SESSION_SEED_SIZE_BYTES];
        if session_seed.len() != session_seed_vec.len() {
            Err(ManticoreError::InternalError)?
        }
        session_seed.copy_from_slice(&session_seed_vec);

        // Derive bk_session from bk_partition
        let env = SimCryptEnv;
        let mut bk_session_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES;
        let mut bk_session = vec![0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
        LMKeyDerive::bk_session_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &session_seed,
            bk_partition,
            &mut bk_session_len,
            &mut bk_session,
        )
        .map_err(|err| {
            tracing::error!("bk_session_gen error {:?}", err);
            ManticoreError::InternalError
        })?;

        let session_bmk = self.generate_session_bmk(&bk_session)?;

        // Decode bmk to get the session_mk
        let session_mk =
            LMKeyDerive::bmk_restore(&env, &bk_session, &session_bmk).map_err(|err| {
                tracing::error!("bmk_restore error {:?}", err);
                ManticoreError::InternalError
            })?;

        let mut decoded_session_mk = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
        let _unmasked_mk_length = session_mk
            .decrypt_key(&env, &bk_session, &mut decoded_session_mk)
            .map_err(|err| {
                tracing::error!("decoded_mk decrypt_key error {:?}", err);
                ManticoreError::InternalError
            })?;

        let sess_key_num = self.create_physical_session(api_rev, &decoded_session_mk)?;
        let virtual_session_id = self.session_table.create_session(sess_key_num)?;

        Ok(SessionResult {
            session_id: virtual_session_id,
            short_app_id: self.user.short_app_id,
            bmk: session_bmk,
        })
    }

    /// Re-open session.
    /// This includes steps to decrypt credential information,
    /// and use the session_seed to decrypt the session masking key from backup masking key
    ///
    /// # Arguments
    /// * `encrypted_credential` - encrypted blob including credentials and session seed
    /// * `client_pub_key` - public key data from client necessary to decrypt credentials
    /// * `api_rev` - ApiRevision for the session to support
    /// * `reopen_sess_id` - virtual session id to reopen
    /// * `bmk` - Backup session masking key, needs to be decrypted using bk_session
    /// * `bk_partition` - Backup Key for the partition, used to derive the bk_session (session backup key)
    ///
    /// # Returns
    /// * `Ok(SessionResult)` if successful
    fn reopen_session(
        &mut self,
        encrypted_credential: EncryptedSessionCredential,
        client_pub_key: &[u8],
        api_rev: ApiRev,
        reopen_sess_id: u16,
        bmk: Option<&[u8]>,
        bk_partition: &[u8],
    ) -> Result<SessionResult, ManticoreError> {
        // Check renegotiation requirement first
        if !self.session_table.needs_renegotiation(reopen_sess_id) {
            return Err(ManticoreError::InvalidArgument);
        }

        // Verify credentials and get session seed
        let session_seed_vec =
            self.verify_encrypted_session_credentials(encrypted_credential, client_pub_key)?;

        let mut session_seed = [0u8; SESSION_SEED_SIZE_BYTES];
        if session_seed.len() != session_seed_vec.len() {
            Err(ManticoreError::InternalError)?
        }
        session_seed.copy_from_slice(&session_seed_vec);

        // Create bk_session
        let env = SimCryptEnv;
        let mut bk_session_len = BK_AES_CBC_256_HMAC384_SIZE_BYTES;
        let mut bk_session = vec![0u8; bk_session_len];
        LMKeyDerive::bk_session_gen(
            &env,
            MaskingKeyAlgorithm::AesCbc256Hmac384,
            &session_seed,
            bk_partition,
            &mut bk_session_len,
            &mut bk_session,
        )
        .map_err(|err| {
            tracing::error!("bk_session_gen error {:?}", err);
            ManticoreError::InternalError
        })?;

        let session_bmk = match bmk {
            None => self.generate_session_bmk(&bk_session)?,
            Some(bmk) => bmk.to_vec(),
        };

        // Decode bmk to get the session_mk
        let session_mk =
            LMKeyDerive::bmk_restore(&env, &bk_session, &session_bmk).map_err(|err| {
                tracing::error!("bmk_restore error {:?}", err);
                ManticoreError::InternalError
            })?;

        let mut decoded_session_mk = [0u8; BK_AES_CBC_256_HMAC384_SIZE_BYTES];
        let _unmasked_mk_length = session_mk
            .decrypt_key(&env, &bk_session, &mut decoded_session_mk)
            .map_err(|err| {
                tracing::error!("decoded_mk decrypt_key error {:?}", err);
                ManticoreError::InternalError
            })?;

        // Get session_seed from verify_encrypted_session_credentials
        let physical_session_key_num =
            self.create_physical_session(api_rev, &decoded_session_mk)?;

        // Now recreate the session
        self.session_table
            .recreate_session(reopen_sess_id, physical_session_key_num);

        Ok(SessionResult {
            session_id: reopen_sess_id,
            short_app_id: self.user.short_app_id,
            bmk: session_bmk,
        })
    }

    fn get_session_count(&self) -> usize {
        self.tables
            .iter()
            .map(|table| table.get_session_count())
            .sum()
    }

    fn close_session(&mut self, virtual_session_id: u16) -> Result<(), ManticoreError> {
        // Check if the session needs renegotiation (e.g., after backup/restore)
        if self.session_table.needs_renegotiation(virtual_session_id) {
            // Session needs renegotiation - just clean up the session table entry
            tracing::debug!("Session needs renegotiation");
            self.session_table.delete(virtual_session_id);
            return Ok(());
        }

        let session_key_num = self
            .session_table
            .get_target_session(virtual_session_id)
            .ok_or(ManticoreError::SessionNotFound)?;

        self.remove_session_only_keys_by_physical_session_id(session_key_num)?;
        self.remove_key(session_key_num)?;

        self.session_table.delete(virtual_session_id);
        Ok(())
    }

    fn get_target_session_id(&self, virtual_session_id: u16) -> Result<u16, ManticoreError> {
        self.session_table
            .get_target_session(virtual_session_id)
            .ok_or(ManticoreError::SessionNotFound)
    }

    fn change_pin(
        &mut self,
        new_pin: EncryptedPin,
        client_pub_key: &[u8],
    ) -> Result<(), ManticoreError> {
        let key_id = self.get_session_encryption_key_id()?;
        {
            let entry = self.get_key_entry(key_id)?;

            // Check if sent nonce is same
            if new_pin.nonce != self.get_nonce() {
                Err(ManticoreError::NonceMismatch)?;
            }

            // Check if credential is already set
            if self.user.credentials.id.is_nil() || self.user.credentials.pin.eq(&[0; 16]) {
                Err(ManticoreError::InvalidArgument)?;
            }

            if let EccPrivate(private_key) = entry.key() {
                let public_key = EccPublicKey::from_der(client_pub_key, Some(Kind::Ecc384Public))?;
                let secret_bytes = private_key.derive(&public_key)?;
                let secret_key = SecretKey::from_bytes(&secret_bytes)?;
                let current_nonce = self.get_nonce();
                let keys = secret_key.hkdf_derive(
                    HashAlgorithm::Sha384,
                    None,
                    Some(&current_nonce),
                    80,
                )?;

                let hmac_key = &keys[32..];

                let mut pin_iv_nonce = [0; 64];
                pin_iv_nonce[..16].copy_from_slice(&new_pin.pin);
                pin_iv_nonce[16..32].copy_from_slice(&new_pin.iv);
                pin_iv_nonce[32..64].copy_from_slice(&current_nonce);

                let hmac_key = HmacKey::from_bytes(hmac_key)?;
                let calculated_tag = hmac_key.hmac(&pin_iv_nonce, HashAlgorithm::Sha384)?;
                if calculated_tag != new_pin.tag {
                    Err(ManticoreError::PinDecryptionFailed)?;
                }

                self.reset_nonce()?;

                let aes_key = AesKey::from_bytes(&keys[..32])?;
                let decrypted_pin = aes_key
                    .decrypt(&new_pin.pin, AesAlgo::Cbc, Some(&new_pin.iv))?
                    .plain_text;

                let mut new_pin = [0; 16];
                new_pin.copy_from_slice(&decrypted_pin);

                // Get the user's ID
                let id = self.user.credentials.id.as_bytes().to_vec();

                // Set the new pin for the user
                self.set_user_new_credential(id.as_slice(), &new_pin)?;

                Ok(())
            } else {
                Err(ManticoreError::InternalError)
            }
        }
    }

    fn get_key_num_by_tag(&self, app_id: Uuid, key_tag: u16) -> Result<u16, ManticoreError> {
        for (table_index, table) in self.tables.iter().enumerate() {
            if let Ok(entry_index) = table.get_index_by_name(app_id, key_tag) {
                let key_num = KeyNumber::new(table_index as u8, entry_index);
                return Ok(key_num.0);
            }
        }

        tracing::debug!(key_tag, "Key not found by tag");
        Err(ManticoreError::KeyNotFound)
    }

    fn get_session_entry(&self, session_id: u16) -> Result<Entry, ManticoreError> {
        // Check if the session needs renegotiation first
        if self.session_table.needs_renegotiation(session_id) {
            return Err(ManticoreError::SessionNeedsRenegotiation);
        }

        let session_key_num = self
            .session_table
            .get_target_session(session_id)
            .ok_or(ManticoreError::InvalidArgument)?;

        self.get_key_entry(session_key_num)
    }

    fn get_session_entry_unchecked(&self, session_id: u16) -> Result<Entry, ManticoreError> {
        // Check if the session needs renegotiation first
        if self.session_table.needs_renegotiation(session_id) {
            return Err(ManticoreError::SessionNeedsRenegotiation);
        }

        let session_key_num = self
            .session_table
            .get_target_session(session_id)
            .ok_or(ManticoreError::InvalidArgument)?;

        self.get_key_entry_unchecked(session_key_num)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct VaultWeak {
    weak: Weak<RwLock<VaultInner>>,
}

impl VaultWeak {
    fn new(weak: Weak<RwLock<VaultInner>>) -> Self {
        Self { weak }
    }

    pub(crate) fn upgrade(&self) -> Option<Vault> {
        self.weak.upgrade().map(Vault::with_inner)
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use std::cmp::min;
    use std::thread;
    use std::time::Duration;

    use test_with_tracing::test;

    use super::*;
    use crate::credentials::Role;
    use crate::crypto::ecc::generate_ecc;
    use crate::crypto::ecc::EccCurve;
    use crate::crypto::ecc::EccPrivateKey;
    use crate::crypto::rsa::generate_rsa;
    use crate::crypto::rsa::RsaOp;
    use crate::table::KEY_LAZY_DELETE_TIMEOUT_IN_SECONDS;
    use crate::table::MAX_TABLE_BYTES;
    use crate::table::MAX_TABLE_KEY_COUNT;

    pub(crate) const TEST_ECC_384_PRIVATE_KEY: [u8; 185] = [
        0x30, 0x81, 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b,
        0x02, 0x01, 0x01, 0x04, 0x30, 0xce, 0xbc, 0xbb, 0x90, 0x3d, 0x9a, 0x1d, 0x46, 0xd9, 0x59,
        0x15, 0x16, 0xf9, 0x7d, 0xbe, 0x6f, 0xf6, 0x44, 0xa3, 0x2d, 0xa4, 0x7b, 0x73, 0xfb, 0x6e,
        0xad, 0xa5, 0x09, 0x9a, 0x83, 0x2a, 0x67, 0x07, 0xd2, 0x25, 0xd3, 0x8e, 0x67, 0x52, 0xcd,
        0x09, 0x90, 0xa8, 0x31, 0x06, 0x66, 0xc0, 0xe4, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0xe4,
        0x20, 0x9a, 0xd7, 0x07, 0xa4, 0x88, 0x1a, 0xff, 0xf0, 0x12, 0x61, 0x92, 0xc7, 0x9d, 0x83,
        0x77, 0x49, 0x21, 0xcc, 0x5d, 0xf3, 0xb9, 0x21, 0xc4, 0x3d, 0xae, 0xaa, 0x58, 0xb8, 0x34,
        0x2b, 0x38, 0x3c, 0xda, 0xb2, 0x88, 0xf0, 0xe4, 0xb9, 0x56, 0x14, 0x11, 0x15, 0x75, 0xba,
        0xbb, 0x23, 0x7c, 0x67, 0xf7, 0xd1, 0x97, 0x63, 0xc7, 0xb8, 0x56, 0xd3, 0x22, 0xb2, 0xba,
        0xba, 0x1a, 0xc6, 0xb4, 0xea, 0x0d, 0xad, 0xa2, 0x56, 0x29, 0xd5, 0xca, 0x0f, 0x4a, 0x4e,
        0xee, 0x17, 0xb0, 0xb2, 0xf4, 0xb1, 0x58, 0xba, 0xae, 0xa1, 0x58, 0x9c, 0x10, 0x07, 0xf7,
        0x0e, 0xc7, 0x62, 0x42, 0xe0,
    ];

    pub(crate) const TEST_ECC_384_PUBLIC_KEY: [u8; 120] = [
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xe4, 0x20, 0x9a, 0xd7, 0x07, 0xa4,
        0x88, 0x1a, 0xff, 0xf0, 0x12, 0x61, 0x92, 0xc7, 0x9d, 0x83, 0x77, 0x49, 0x21, 0xcc, 0x5d,
        0xf3, 0xb9, 0x21, 0xc4, 0x3d, 0xae, 0xaa, 0x58, 0xb8, 0x34, 0x2b, 0x38, 0x3c, 0xda, 0xb2,
        0x88, 0xf0, 0xe4, 0xb9, 0x56, 0x14, 0x11, 0x15, 0x75, 0xba, 0xbb, 0x23, 0x7c, 0x67, 0xf7,
        0xd1, 0x97, 0x63, 0xc7, 0xb8, 0x56, 0xd3, 0x22, 0xb2, 0xba, 0xba, 0x1a, 0xc6, 0xb4, 0xea,
        0x0d, 0xad, 0xa2, 0x56, 0x29, 0xd5, 0xca, 0x0f, 0x4a, 0x4e, 0xee, 0x17, 0xb0, 0xb2, 0xf4,
        0xb1, 0x58, 0xba, 0xae, 0xa1, 0x58, 0x9c, 0x10, 0x07, 0xf7, 0x0e, 0xc7, 0x62, 0x42, 0xe0,
    ];

    pub(crate) const TEST_CRED_ID: [u8; 16] = [
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b,
    ];

    pub(crate) const TEST_CRED_PIN: [u8; 16] = [
        0x09, 0x90, 0xa8, 0x31, 0x06, 0x66, 0xc0, 0xe4, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0xe4,
        0x20,
    ];

    pub(crate) const TEST_SESSION_SEED: [u8; 48] = [
        0xe5, 0x1b, 0x8b, 0x4b, 0xa7, 0x94, 0xc7, 0xc8, 0xa2, 0x32, 0x84, 0xec, 0xad, 0x2b, 0x6a,
        0xc, 0x37, 0xe8, 0x6a, 0x63, 0x6a, 0x9f, 0x43, 0x20, 0x95, 0xe1, 0x24, 0xd0, 0x85, 0x12,
        0xe2, 0x12, 0x95, 0x14, 0xaa, 0x0f, 0x6b, 0x05, 0x40, 0x71, 0xbf, 0x63, 0xa5, 0x87, 0xa6,
        0x25, 0x70, 0x81,
    ];

    #[test]
    fn test_new() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        let vault_inner = vault.inner.read();

        assert_eq!(vault_inner.id, Uuid::from_bytes([0xb2; 16]));
        assert_eq!(vault_inner.tables.len(), 4);
        assert_eq!(
            vault_inner.user,
            UserCredentials {
                credentials: Credentials {
                    id: Uuid::nil(),
                    role: Role::User,
                    pin: [0; 16]
                },
                short_app_id: 0
            }
        );
        assert!(vault_inner.establish_cred_encryption_key_id.is_some());
        assert!(vault_inner.session_encryption_key_id.is_some());
    }

    #[test]
    fn test_key_num_to_table_index() {
        assert_eq!(KeyNumber(0x0000).table(), 0x00);
        assert_eq!(KeyNumber(0x0100).table(), 0x01);
        assert_eq!(KeyNumber(0x0200).table(), 0x02);
        assert_eq!(KeyNumber(0x0300).table(), 0x03);
        assert_eq!(KeyNumber(0x0400).table(), 0x04);
        assert_eq!(KeyNumber(0x0500).table(), 0x05);
        assert_eq!(KeyNumber(0x0600).table(), 0x06);
        assert_eq!(KeyNumber(0x0700).table(), 0x07);
        assert_eq!(KeyNumber(0x0800).table(), 0x08);
        assert_eq!(KeyNumber(0x0900).table(), 0x09);
        assert_eq!(KeyNumber(0x0a00).table(), 0x0a);
        assert_eq!(KeyNumber(0x0b00).table(), 0x0b);
        assert_eq!(KeyNumber(0x0c00).table(), 0x0c);
        assert_eq!(KeyNumber(0x0d00).table(), 0x0d);
        assert_eq!(KeyNumber(0x0e00).table(), 0x0e);
        assert_eq!(KeyNumber(0x0f00).table(), 0x0f);
        assert_eq!(KeyNumber(0x1000).table(), 0x10);
        assert_eq!(KeyNumber(0x1100).table(), 0x11);
        assert_eq!(KeyNumber(0x1200).table(), 0x12);
        assert_eq!(KeyNumber(0x1300).table(), 0x13);
        assert_eq!(KeyNumber(0x1400).table(), 0x14);
        assert_eq!(KeyNumber(0x1500).table(), 0x15);
    }

    #[test]
    fn test_key_num_to_entry_index() {
        assert_eq!(KeyNumber(0x0000).entry(), 0x00);
        assert_eq!(KeyNumber(0x0001).entry(), 0x01);
        assert_eq!(KeyNumber(0x0002).entry(), 0x02);
        assert_eq!(KeyNumber(0x0003).entry(), 0x03);
        assert_eq!(KeyNumber(0x0004).entry(), 0x04);
        assert_eq!(KeyNumber(0x0005).entry(), 0x05);
        assert_eq!(KeyNumber(0x0006).entry(), 0x06);
        assert_eq!(KeyNumber(0x0007).entry(), 0x07);
        assert_eq!(KeyNumber(0x0008).entry(), 0x08);
        assert_eq!(KeyNumber(0x0009).entry(), 0x09);
        assert_eq!(KeyNumber(0x000a).entry(), 0x0a);
        assert_eq!(KeyNumber(0x000b).entry(), 0x0b);
        assert_eq!(KeyNumber(0x000c).entry(), 0x0c);
        assert_eq!(KeyNumber(0x000d).entry(), 0x0d);
        assert_eq!(KeyNumber(0x000e).entry(), 0x0e);
        assert_eq!(KeyNumber(0x000f).entry(), 0x0f);
        assert_eq!(KeyNumber(0x0010).entry(), 0x10);
        assert_eq!(KeyNumber(0x0011).entry(), 0x11);
        assert_eq!(KeyNumber(0x0012).entry(), 0x12);
        assert_eq!(KeyNumber(0x0013).entry(), 0x13);
        assert_eq!(KeyNumber(0x0014).entry(), 0x14);
        assert_eq!(KeyNumber(0x0015).entry(), 0x15);
    }

    #[test]
    fn test_table_index_and_entry_index_to_key_num() {
        assert_eq!(KeyNumber::new(0x00, 0x00).0, 0x0000);
        assert_eq!(KeyNumber::new(0x00, 0x01).0, 0x0001);
        assert_eq!(KeyNumber::new(0x01, 0x02).0, 0x0102);
        assert_eq!(KeyNumber::new(0x01, 0x03).0, 0x0103);
        assert_eq!(KeyNumber::new(0x02, 0x04).0, 0x0204);
        assert_eq!(KeyNumber::new(0x02, 0x05).0, 0x0205);
        assert_eq!(KeyNumber::new(0x10, 0x10).0, 0x1010);
        assert_eq!(KeyNumber::new(0x10, 0x11).0, 0x1011);
        assert_eq!(KeyNumber::new(0x21, 0x12).0, 0x2112);
        assert_eq!(KeyNumber::new(0x21, 0x13).0, 0x2113);
        assert_eq!(KeyNumber::new(0x38, 0x14).0, 0x3814);
        assert_eq!(KeyNumber::new(0x38, 0x15).0, 0x3815);
    }

    #[test]
    fn test_add_key_user_id_is_default() {
        let key_tag = 0x5453;

        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        let result = vault.add_key(
            Uuid::nil(),
            Kind::Rsa2kPublic,
            Key::RsaPublic(rsa_public_key),
            EntryFlags::default(),
            key_tag,
        );
        assert!(result.is_ok());
    }

    fn hkdf_sha_384_derive(
        data: &[u8],
        info: Option<&[u8]>,
        out_len: usize,
    ) -> Result<Vec<u8>, ManticoreError> {
        let secret = SecretKey::from_bytes(data).expect("Failed to create secret key from bytes");
        secret.hkdf_derive(HashAlgorithm::Sha384, None, info, out_len)
    }

    pub(crate) fn helper_encrypt_credential(
        vault: &Vault,
        key_num: u16,
        id: [u8; 16],
        pin: [u8; 16],
    ) -> Result<(EncryptedCredential, Vec<u8>), ManticoreError> {
        let entry = vault.get_key_entry(key_num)?;

        if entry.kind() != Kind::Ecc384Private {
            Err(ManticoreError::InvalidArgument)?;
        }

        if let EccPrivate(key) = entry.key() {
            let nonce = vault.get_nonce();
            let pub_key_der = key.extract_pub_key_der()?;
            let device_credential_key =
                EccPublicKey::from_der(&pub_key_der, Some(Kind::Ecc384Public))?;

            let client_priv_key =
                EccPrivateKey::from_der(&TEST_ECC_384_PRIVATE_KEY, Some(Kind::Ecc384Private))?;

            // ECDH exchange
            let ecdh_bytes = client_priv_key.derive(&device_credential_key)?;

            // HKDF
            let derived_bytes = hkdf_sha_384_derive(&ecdh_bytes, Some(&nonce), 80)?;
            let mut aes_key = [0u8; 32];
            aes_key.copy_from_slice(&derived_bytes[..32]);
            let mut hmac_key = [0u8; 48];
            hmac_key.copy_from_slice(&derived_bytes[32..]);

            let mut encrypted_id = [0; 16];
            let mut encrypted_pin = [0; 16];
            let mut orig_iv = [0; 16];

            rand_bytes(&mut orig_iv)?;

            let aes_key = AesKey::from_bytes(&aes_key)?;

            let aes_result = aes_key.encrypt(&id, AesAlgo::Cbc, Some(&orig_iv))?;
            encrypted_id.copy_from_slice(&aes_result.cipher_text);
            let iv = aes_result.iv;

            let aes_result = aes_key.encrypt(&pin, AesAlgo::Cbc, iv.as_deref())?;
            encrypted_pin.copy_from_slice(&aes_result.cipher_text);

            let mut id_pin_iv_nonce = [0; 80];
            id_pin_iv_nonce[..16].copy_from_slice(&encrypted_id);
            id_pin_iv_nonce[16..32].copy_from_slice(&encrypted_pin);
            id_pin_iv_nonce[32..48].copy_from_slice(&orig_iv);
            id_pin_iv_nonce[48..].copy_from_slice(&nonce);

            let hmac_key = HmacKey::from_bytes(&hmac_key)?;
            let tag = hmac_key.hmac(&id_pin_iv_nonce, HashAlgorithm::Sha384)?;
            let tag_48: [u8; 48] = tag.try_into().map_err(|err| {
                tracing::error!("Failed to convert tag into 48 bytes: {:?}", err);
                ManticoreError::InternalError
            })?;
            Ok((
                EncryptedCredential {
                    id: encrypted_id,
                    pin: encrypted_pin,
                    iv: orig_iv,
                    nonce,
                    tag: tag_48,
                },
                TEST_ECC_384_PUBLIC_KEY.to_vec(),
            ))
        } else {
            Err(ManticoreError::InvalidArgument)
        }
    }

    pub(crate) fn helper_encrypt_session_credential(
        vault: &Vault,
        key_num: u16,
        id: [u8; 16],
        pin: [u8; 16],
        seed: [u8; 48],
    ) -> Result<(EncryptedSessionCredential, Vec<u8>), ManticoreError> {
        let entry = vault.get_key_entry(key_num)?;

        if entry.kind() != Kind::Ecc384Private {
            Err(ManticoreError::InvalidArgument)?;
        }

        if let EccPrivate(key) = entry.key() {
            let nonce = vault.get_nonce();
            let pub_key_der = key.extract_pub_key_der()?;
            let device_credential_key =
                EccPublicKey::from_der(&pub_key_der, Some(Kind::Ecc384Public))?;

            let client_priv_key =
                EccPrivateKey::from_der(&TEST_ECC_384_PRIVATE_KEY, Some(Kind::Ecc384Private))?;

            // ECDH exchange
            let ecdh_bytes = client_priv_key.derive(&device_credential_key)?;

            // HKDF
            let derived_bytes = hkdf_sha_384_derive(&ecdh_bytes, Some(&nonce), 80)?;
            let mut aes_key = [0u8; 32];
            aes_key.copy_from_slice(&derived_bytes[..32]);
            let mut hmac_key = [0u8; 48];
            hmac_key.copy_from_slice(&derived_bytes[32..]);

            let mut encrypted_id = [0; 16];
            let mut encrypted_pin = [0; 16];
            let mut encrypted_seed = [0; 48];
            let mut orig_iv = [0; 16];

            rand_bytes(&mut orig_iv)?;

            let aes_key = AesKey::from_bytes(&aes_key)?;

            let aes_result = aes_key.encrypt(&id, AesAlgo::Cbc, Some(&orig_iv))?;
            encrypted_id.copy_from_slice(&aes_result.cipher_text);
            let iv = aes_result.iv;

            let aes_result = aes_key.encrypt(&pin, AesAlgo::Cbc, iv.as_deref())?;
            encrypted_pin.copy_from_slice(&aes_result.cipher_text);
            let iv = aes_result.iv;

            let aes_result = aes_key.encrypt(&seed, AesAlgo::Cbc, iv.as_deref())?;
            encrypted_seed.copy_from_slice(&aes_result.cipher_text);

            let mut id_pin_seed_iv_nonce = [0; 128];
            id_pin_seed_iv_nonce[..16].copy_from_slice(&encrypted_id);
            id_pin_seed_iv_nonce[16..32].copy_from_slice(&encrypted_pin);
            id_pin_seed_iv_nonce[32..80].copy_from_slice(&encrypted_seed);
            id_pin_seed_iv_nonce[80..96].copy_from_slice(&orig_iv);
            id_pin_seed_iv_nonce[96..].copy_from_slice(&nonce);

            let hmac_key = HmacKey::from_bytes(&hmac_key)?;
            let tag = hmac_key.hmac(&id_pin_seed_iv_nonce, HashAlgorithm::Sha384)?;
            let tag_48: [u8; 48] = tag.try_into().map_err(|err| {
                tracing::error!("Failed to convert tag into 48 bytes: {:?}", err);
                ManticoreError::InternalError
            })?;
            Ok((
                EncryptedSessionCredential {
                    id: encrypted_id,
                    pin: encrypted_pin,
                    seed: encrypted_seed,
                    iv: orig_iv,
                    nonce,
                    tag: tag_48,
                },
                TEST_ECC_384_PUBLIC_KEY.to_vec(),
            ))
        } else {
            Err(ManticoreError::InvalidArgument)
        }
    }

    pub(crate) fn helper_establish_credential(vault: &Vault, id: [u8; 16], pin: [u8; 16]) {
        let key_num = vault
            .get_establish_cred_encryption_key_id()
            .expect("Failed to get_establish_cred_encryption_key_id()");
        let (encrypted_credential, client_pub_key) =
            helper_encrypt_credential(vault, key_num, id, pin)
                .expect("Failed to encrypt credential");
        vault
            .establish_credential(encrypted_credential, &client_pub_key)
            .expect("Failed to establish credential");
    }

    pub(crate) fn helper_open_session(
        vault: &Vault,
        id: [u8; 16],
        pin: [u8; 16],
        api_rev: ApiRev,
    ) -> Result<SessionResult, ManticoreError> {
        let key_num = vault
            .get_session_encryption_key_id()
            .expect("Failed to get_session_encryption_key_id()");
        let (encrypted_credential, client_pub_key) =
            helper_encrypt_session_credential(vault, key_num, id, pin, TEST_SESSION_SEED)
                .expect("Failed to encrypt session credential");

        // Use a hardcoded partition_mk
        let partition_mk = [42u8; 80];
        vault.open_session(
            encrypted_credential,
            &client_pub_key,
            api_rev,
            &partition_mk,
        )
    }

    pub(crate) fn helper_reopen_session(
        vault: &Vault,
        id: [u8; 16],
        pin: [u8; 16],
        api_rev: ApiRev,
        reopen_sess_id: u16,
        bmk: Option<&[u8]>,
    ) -> Result<SessionResult, ManticoreError> {
        let key_num = vault
            .get_session_encryption_key_id()
            .expect("Failed to get_session_encryption_key_id()");
        let (encrypted_credential, client_pub_key) =
            helper_encrypt_session_credential(vault, key_num, id, pin, TEST_SESSION_SEED)
                .expect("Failed to encrypt session credential");

        // Use a hardcoded partition_mk
        let partition_mk = [42u8; 80];
        vault.reopen_session(
            encrypted_credential,
            &client_pub_key,
            api_rev,
            reopen_sess_id,
            bmk,
            &partition_mk,
        )
    }

    #[test]
    fn add_key_basic() {
        let key_tag = 0;

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        for _ in 0..2 {
            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                EntryFlags::default(),
                key_tag,
            );
            assert!(result.is_ok());
        }

        let vault_inner = vault.inner.read();

        assert_eq!(vault_inner.tables.len(), 4);
        assert_eq!(
            vault_inner.user,
            UserCredentials {
                credentials: Credentials {
                    id: Uuid::from_bytes(TEST_CRED_ID),
                    role: Role::User,
                    pin: TEST_CRED_PIN
                },
                short_app_id: 0
            }
        );

        assert!(vault_inner.tables[1].remove(0).is_err());
        assert!(vault_inner.tables[1].remove(1).is_err());
        assert!(vault_inner.tables[2].remove(0).is_err());
        assert!(vault_inner.tables[2].remove(1).is_err());
        assert!(vault_inner.tables[3].remove(0).is_err());
        assert!(vault_inner.tables[3].remove(1).is_err());
        assert!(vault_inner.tables[0].remove(0).is_ok());
        assert!(vault_inner.tables[0].remove(1).is_ok());
    }

    #[test]
    fn add_key_app_not_found() {
        let key_tag = 0x5453;

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let result = vault.add_key(
            Uuid::from_bytes([0x04; 16]),
            Kind::Rsa2kPublic,
            Key::RsaPublic(rsa_public_key),
            EntryFlags::default(),
            key_tag,
        );
        assert_eq!(result, Err(ManticoreError::AppNotFound));

        let vault_inner = vault.inner.read();

        assert_eq!(vault_inner.tables.len(), 4);
        assert_eq!(
            vault_inner.user,
            UserCredentials {
                credentials: Credentials {
                    id: Uuid::from_bytes(TEST_CRED_ID),
                    role: Role::User,
                    pin: TEST_CRED_PIN
                },
                short_app_id: 0
            }
        );
    }

    #[test]
    fn add_key_table_max_bytes() {
        let key_tag = 0;

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        let (rsa_private_key, _rsa_public_key) = generate_rsa(4096).unwrap();
        let entry_kind = Kind::Rsa4kPrivate;
        let allowed_entry_count_per_table =
            min(MAX_TABLE_BYTES / entry_kind.size(), MAX_TABLE_KEY_COUNT) as u16;

        for _ in 0..allowed_entry_count_per_table {
            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                entry_kind,
                Key::RsaPrivate(rsa_private_key.clone()),
                EntryFlags::default(),
                key_tag,
            );
            assert!(result.is_ok());
        }

        for _ in 0..allowed_entry_count_per_table {
            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                entry_kind,
                Key::RsaPrivate(rsa_private_key.clone()),
                EntryFlags::default(),
                key_tag,
            );
            assert!(result.is_ok());
        }

        for _ in 0..allowed_entry_count_per_table {
            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                entry_kind,
                Key::RsaPrivate(rsa_private_key.clone()),
                EntryFlags::default(),
                key_tag,
            );
            assert!(result.is_ok());
        }

        for _ in 0..allowed_entry_count_per_table {
            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                entry_kind,
                Key::RsaPrivate(rsa_private_key.clone()),
                EntryFlags::default(),
                key_tag,
            );
            assert!(result.is_ok());
        }

        let result = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            entry_kind,
            Key::RsaPrivate(rsa_private_key.clone()),
            EntryFlags::default(),
            key_tag,
        );
        assert_eq!(result, Err(ManticoreError::NotEnoughSpace));

        let vault_inner = vault.inner.read();

        assert_eq!(vault_inner.tables.len(), 4);
        assert_eq!(
            vault_inner.user,
            UserCredentials {
                credentials: Credentials {
                    id: Uuid::from_bytes(TEST_CRED_ID),
                    role: Role::User,
                    pin: TEST_CRED_PIN
                },
                short_app_id: 0
            }
        );

        let result = vault_inner.tables[2].remove(3);
        assert!(result.is_ok());
        drop(vault_inner);

        let result = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            entry_kind,
            Key::RsaPrivate(rsa_private_key),
            EntryFlags::default(),
            key_tag,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn get_key_and_meta_data() {
        let key_tag = 0;

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        let (rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();

        let add_key_1 = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                EntryFlags::default(),
                key_tag,
            )
            .unwrap();
        let add_key_2 = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPrivate,
                Key::RsaPrivate(rsa_private_key.clone()),
                EntryFlags::default(),
                key_tag,
            )
            .unwrap();

        // Fetch keys and meta data.
        assert_eq!(
            vault.get_key_entry(add_key_1).unwrap().kind(),
            Kind::Rsa2kPublic
        );
        assert_eq!(
            vault.get_key_entry(add_key_1).unwrap().app_id(),
            Uuid::from_bytes(TEST_CRED_ID)
        );
        assert!(matches!(
            vault.get_key_entry(add_key_1).unwrap().key(),
            Key::RsaPublic(_)
        ));
        if let Key::RsaPublic(key) = vault.get_key_entry(add_key_1).unwrap().key() {
            assert_eq!(key.to_der().unwrap(), rsa_public_key.to_der().unwrap());
        }

        assert_eq!(
            vault.get_key_entry(add_key_2).unwrap().kind(),
            Kind::Rsa2kPrivate
        );
        assert_eq!(
            vault.get_key_entry(add_key_2).unwrap().app_id(),
            Uuid::from_bytes(TEST_CRED_ID)
        );
        assert!(matches!(
            vault.get_key_entry(add_key_2).unwrap().key(),
            Key::RsaPrivate(_)
        ));
        if let Key::RsaPrivate(key) = vault.get_key_entry(add_key_2).unwrap().key() {
            assert_eq!(key.to_der().unwrap(), rsa_private_key.to_der().unwrap());
        }
    }

    #[test]
    fn add_key_table_max_key_count() {
        let key_tag = 0;

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        let (ecc_private_key, _ecc_public_key) = generate_ecc(EccCurve::P256).unwrap();
        let entry_kind = Kind::Ecc256Private;
        let allowed_entry_count_per_table =
            min(MAX_TABLE_BYTES / entry_kind.size(), MAX_TABLE_KEY_COUNT) as u16;

        for _ in 0..allowed_entry_count_per_table - 1 {
            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                entry_kind,
                Key::EccPrivate(ecc_private_key.clone()),
                EntryFlags::default(),
                key_tag,
            );
            assert!(result.is_ok());
        }

        for _ in 0..allowed_entry_count_per_table {
            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                entry_kind,
                Key::EccPrivate(ecc_private_key.clone()),
                EntryFlags::default(),
                key_tag,
            );
            assert!(result.is_ok());
        }

        for _ in 0..allowed_entry_count_per_table {
            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                entry_kind,
                Key::EccPrivate(ecc_private_key.clone()),
                EntryFlags::default(),
                key_tag,
            );
            assert!(result.is_ok());
        }

        for _ in 0..allowed_entry_count_per_table {
            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                entry_kind,
                Key::EccPrivate(ecc_private_key.clone()),
                EntryFlags::default(),
                key_tag,
            );
            assert!(result.is_ok());
        }

        let result = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            entry_kind,
            Key::EccPrivate(ecc_private_key.clone()),
            EntryFlags::default(),
            key_tag,
        );
        assert_eq!(result, Err(ManticoreError::NotEnoughSpace));

        let vault_inner = vault.inner.read();

        assert_eq!(vault_inner.tables.len(), 4);
        assert_eq!(
            vault_inner.user,
            UserCredentials {
                credentials: Credentials {
                    id: Uuid::from_bytes(TEST_CRED_ID),
                    role: Role::User,
                    pin: TEST_CRED_PIN
                },
                short_app_id: 0
            }
        );

        let result = vault_inner.tables[2].remove(3);
        assert!(result.is_ok());
        drop(vault_inner);

        let result = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            entry_kind,
            Key::EccPrivate(ecc_private_key),
            EntryFlags::default(),
            key_tag,
        );
        assert_eq!(result, Ok(0x0203));
    }

    #[test]
    fn remove_key_invalid_table() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let result = vault.remove_key(0x6600);
        assert_eq!(result, Err(ManticoreError::InvalidKeyNumber));
    }

    #[test]
    fn remove_key_invalid_entry() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let result = vault.remove_key(0x0100);
        assert_eq!(result, Err(ManticoreError::InvalidKeyIndex));
    }

    #[test]
    fn remove_key_basic() {
        let key_tag = 0x5453;

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let key1 = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                EntryFlags::default(),
                key_tag,
            )
            .unwrap();
        let result2 = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            Kind::Rsa2kPublic,
            Key::RsaPublic(rsa_public_key.clone()),
            EntryFlags::default(),
            key_tag + 1,
        );
        assert!(result2.is_ok());

        let vault_inner = vault.inner.read();

        assert_eq!(vault_inner.tables.len(), 4);
        assert_eq!(
            vault_inner.user,
            UserCredentials {
                credentials: Credentials {
                    id: Uuid::from_bytes(TEST_CRED_ID),
                    role: Role::User,
                    pin: TEST_CRED_PIN
                },
                short_app_id: 0
            }
        );
        drop(vault_inner);

        let result = vault.remove_key(key1);
        assert!(result.is_ok());

        let result = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            Kind::Rsa2kPublic,
            Key::RsaPublic(rsa_public_key),
            EntryFlags::default(),
            key_tag,
        );
        assert_eq!(result, Ok(key1));
    }

    #[test]
    fn remove_key_middle() {
        let key_tag = 0;

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        let entry_kind = Kind::Rsa4kPrivate;
        let allowed_entry_count_per_table =
            min(MAX_TABLE_BYTES / entry_kind.size(), MAX_TABLE_KEY_COUNT) as u16;

        let (rsa_private_key, _rsa_public_key) = generate_rsa(4096).unwrap();
        for _ in 0..allowed_entry_count_per_table {
            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                entry_kind,
                Key::RsaPrivate(rsa_private_key.clone()),
                EntryFlags::default(),
                key_tag,
            );
            assert!(result.is_ok());
        }

        for _ in 0..allowed_entry_count_per_table {
            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                entry_kind,
                Key::RsaPrivate(rsa_private_key.clone()),
                EntryFlags::default(),
                key_tag,
            );
            assert!(result.is_ok());
        }

        for _ in 0..allowed_entry_count_per_table {
            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                entry_kind,
                Key::RsaPrivate(rsa_private_key.clone()),
                EntryFlags::default(),
                key_tag,
            );
            assert!(result.is_ok());
        }

        for _ in 0..allowed_entry_count_per_table {
            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                entry_kind,
                Key::RsaPrivate(rsa_private_key.clone()),
                EntryFlags::default(),
                key_tag,
            );
            assert!(result.is_ok());
        }

        let vault_inner = vault.inner.read();

        assert_eq!(vault_inner.tables.len(), 4);
        assert_eq!(
            vault_inner.user,
            UserCredentials {
                credentials: Credentials {
                    id: Uuid::from_bytes(TEST_CRED_ID),
                    role: Role::User,
                    pin: TEST_CRED_PIN
                },
                short_app_id: 0
            }
        );
        drop(vault_inner);

        let result = vault.remove_key(0x0203);
        assert_eq!(result, Ok(()));

        let result = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            entry_kind,
            Key::RsaPrivate(rsa_private_key),
            EntryFlags::default(),
            key_tag,
        );
        assert_eq!(result, Ok(0x0203));
    }

    #[test]
    fn close_session_basic() {
        let key_tag = 0x5453;

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        //cred-establish enc and session enc key IDs 0, 1, key 0 freed after use for cred-establish.
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap(); //reuse key ID 0

        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        // Add 2 persisent keys, key 2 and key 3
        for i in 0..2 {
            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                EntryFlags::default(),
                key_tag + i,
            );
            assert!(result.is_ok());
        }

        let mut flags = EntryFlags::default();
        flags.set_session_only(true);
        // Add 2 session_only keys, key IDs 4 and key 5.
        for i in 0..2 {
            let result = vault
                .add_key(
                    Uuid::from_bytes(TEST_CRED_ID),
                    Kind::Rsa2kPublic,
                    Key::RsaPublic(rsa_public_key.clone()),
                    flags,
                    session_result.session_id,
                )
                .unwrap();
            assert_eq!(result, i + 4);
        }

        let vault_inner = vault.inner.read();

        assert_eq!(vault_inner.tables.len(), 4);
        assert_eq!(
            vault_inner.user,
            UserCredentials {
                credentials: Credentials {
                    id: Uuid::from_bytes(TEST_CRED_ID),
                    role: Role::User,
                    pin: TEST_CRED_PIN
                },
                short_app_id: 0
            }
        );
        drop(vault_inner);

        //close session
        let result = vault.close_session(session_result.session_id);
        assert!(result.is_ok());

        // Verify session has been cleaned up from session table
        assert!(vault.get_session_entry(session_result.session_id).is_err());
    }

    #[test]
    fn close_session_with_key_in_use() {
        // Test the removal of session_only keys while the key is in use

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();

        let mut flags = EntryFlags::default();
        flags.set_session_only(true);
        // Add 3 session_only keys
        let key1 = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                flags,
                session_result.session_id,
            )
            .unwrap();
        for _ in 0..2 {
            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                flags,
                session_result.session_id,
            );
            assert!(result.is_ok());
        }

        // Hold a ref to Entry
        let entry = vault.get_key_entry(key1).unwrap();

        let result = vault.close_session(session_result.session_id);
        assert!(result.is_ok());

        // Check entry marked as disabled
        assert!(entry.disabled());
    }

    #[test]
    fn test_establish_credential() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        assert_eq!(
            vault.user(),
            UserCredentials {
                credentials: Credentials {
                    id: Uuid::from_bytes(TEST_CRED_ID),
                    role: Role::User,
                    pin: TEST_CRED_PIN
                },
                short_app_id: 0
            }
        );
    }

    #[test]
    fn test_reject_user_id_0() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");

        let id = [0; 16];
        let pin = TEST_CRED_PIN;
        let key_num = vault.get_establish_cred_encryption_key_id().unwrap();
        let (encrypted_credential, client_pub_key) =
            helper_encrypt_credential(&vault, key_num, id, pin).unwrap();
        let result = vault.establish_credential(encrypted_credential, &client_pub_key);
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_reject_user_pin_0() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");

        let id = TEST_CRED_ID;
        let pin = [0; 16];
        let key_num = vault.get_establish_cred_encryption_key_id().unwrap();
        let (encrypted_credential, client_pub_key) =
            helper_encrypt_credential(&vault, key_num, id, pin).unwrap();
        let result = vault.establish_credential(encrypted_credential, &client_pub_key);
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_establish_credential_tampered_id() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");

        let key_num = vault.get_establish_cred_encryption_key_id().unwrap();
        let (mut encrypted_credential, client_pub_key) =
            helper_encrypt_credential(&vault, key_num, TEST_CRED_ID, TEST_CRED_PIN).unwrap();
        encrypted_credential.id[4] = encrypted_credential.id[4].wrapping_add(0x1);
        let result = vault.establish_credential(encrypted_credential, &client_pub_key);
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_establish_credential_tampered_pin() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");

        let key_num = vault.get_establish_cred_encryption_key_id().unwrap();
        let (mut encrypted_credential, client_pub_key) =
            helper_encrypt_credential(&vault, key_num, TEST_CRED_ID, TEST_CRED_PIN).unwrap();
        encrypted_credential.pin[4] = encrypted_credential.pin[4].wrapping_add(0x1);
        let result = vault.establish_credential(encrypted_credential, &client_pub_key);
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_establish_credential_tampered_iv() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");

        let key_num = vault.get_establish_cred_encryption_key_id().unwrap();
        let (mut encrypted_credential, client_pub_key) =
            helper_encrypt_credential(&vault, key_num, TEST_CRED_ID, TEST_CRED_PIN).unwrap();
        encrypted_credential.iv[4] = encrypted_credential.iv[4].wrapping_add(0x1);
        let result = vault.establish_credential(encrypted_credential, &client_pub_key);
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_establish_credential_tampered_nonce() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");

        let key_num = vault.get_establish_cred_encryption_key_id().unwrap();
        let (mut encrypted_credential, client_pub_key) =
            helper_encrypt_credential(&vault, key_num, TEST_CRED_ID, TEST_CRED_PIN).unwrap();
        encrypted_credential.nonce[2] = encrypted_credential.nonce[2].wrapping_add(0x1);
        let result = vault.establish_credential(encrypted_credential, &client_pub_key);
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_establish_credential_tampered_tag() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");

        let key_num = vault.get_establish_cred_encryption_key_id().unwrap();
        let (mut encrypted_credential, client_pub_key) =
            helper_encrypt_credential(&vault, key_num, TEST_CRED_ID, TEST_CRED_PIN).unwrap();
        encrypted_credential.tag[4] = encrypted_credential.tag[4].wrapping_add(0x1);
        let result = vault.establish_credential(encrypted_credential, &client_pub_key);
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_establish_credential_multiple_times() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");

        let key_num = vault.get_establish_cred_encryption_key_id().unwrap();
        let (encrypted_credential, client_pub_key) =
            helper_encrypt_credential(&vault, key_num, TEST_CRED_ID, TEST_CRED_PIN).unwrap();
        let result = vault.establish_credential(encrypted_credential, &client_pub_key);
        assert!(result.is_ok());
        let result = vault.establish_credential(encrypted_credential, &client_pub_key);
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_open_session() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };
        let _ = helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
    }

    #[test]
    fn test_get_session_encryption_key_without_establish_credential() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        let result = vault.get_session_encryption_key_id();
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_open_session_tampered_id() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };
        let key_num = vault.get_session_encryption_key_id().unwrap();
        let (mut encrypted_credential, client_pub_key) = helper_encrypt_session_credential(
            &vault,
            key_num,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        )
        .unwrap();
        encrypted_credential.id[4] = encrypted_credential.id[4].wrapping_add(0x1);

        let mut partition_mk = [0u8; 80];
        rand_bytes(&mut partition_mk).unwrap();
        let result = vault.open_session(
            encrypted_credential,
            &client_pub_key,
            api_rev,
            &partition_mk,
        );
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_open_session_tampered_pin() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };
        let key_num = vault.get_session_encryption_key_id().unwrap();
        let (mut encrypted_credential, client_pub_key) = helper_encrypt_session_credential(
            &vault,
            key_num,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        )
        .unwrap();
        encrypted_credential.pin[4] = encrypted_credential.pin[4].wrapping_add(0x1);

        let mut partition_mk = [0u8; 80];
        rand_bytes(&mut partition_mk).unwrap();
        let result = vault.open_session(
            encrypted_credential,
            &client_pub_key,
            api_rev,
            &partition_mk,
        );
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_open_session_tampered_iv() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };
        let key_num = vault.get_session_encryption_key_id().unwrap();
        let (mut encrypted_credential, client_pub_key) = helper_encrypt_session_credential(
            &vault,
            key_num,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        )
        .unwrap();
        encrypted_credential.iv[4] = encrypted_credential.iv[4].wrapping_add(0x1);

        let mut partition_mk = [0u8; 80];
        rand_bytes(&mut partition_mk).unwrap();
        let result = vault.open_session(
            encrypted_credential,
            &client_pub_key,
            api_rev,
            &partition_mk,
        );
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_open_session_tampered_nonce() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };
        let key_num = vault.get_session_encryption_key_id().unwrap();
        let (mut encrypted_credential, client_pub_key) = helper_encrypt_session_credential(
            &vault,
            key_num,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        )
        .unwrap();
        encrypted_credential.nonce[2] = encrypted_credential.nonce[2].wrapping_add(0x1);

        let mut partition_mk = [0u8; 80];
        rand_bytes(&mut partition_mk).unwrap();
        let result = vault.open_session(
            encrypted_credential,
            &client_pub_key,
            api_rev,
            &partition_mk,
        );
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_open_session_tampered_tag() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };
        let key_num = vault.get_session_encryption_key_id().unwrap();
        let (mut encrypted_credential, client_pub_key) = helper_encrypt_session_credential(
            &vault,
            key_num,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        )
        .unwrap();
        encrypted_credential.tag[4] = encrypted_credential.tag[4].wrapping_add(0x1);

        let mut partition_mk = [0u8; 80];
        rand_bytes(&mut partition_mk).unwrap();
        let result = vault.open_session(
            encrypted_credential,
            &client_pub_key,
            api_rev,
            &partition_mk,
        );
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_open_session_tampered_seed() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };
        let key_num = vault.get_session_encryption_key_id().unwrap();
        let (mut encrypted_credential, client_pub_key) = helper_encrypt_session_credential(
            &vault,
            key_num,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        )
        .unwrap();
        encrypted_credential.seed[4] = encrypted_credential.seed[4].wrapping_add(0x1);

        let mut partition_mk = [0u8; 80];
        rand_bytes(&mut partition_mk).unwrap();
        let result = vault.open_session(
            encrypted_credential,
            &client_pub_key,
            api_rev,
            &partition_mk,
        );
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_add_remove_entry_in_use() {
        let key_tag = 0;

        let table_count = 4;
        let vault =
            Vault::new(Uuid::from_bytes([0xb2; 16]), table_count).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let flags = EntryFlags::new().with_generated(true);
        let kind = Kind::Rsa2kPublic;

        // Fill the vault so no space left
        for _ in 0..table_count {
            let max_keys = MAX_TABLE_BYTES / kind.size() - 1;
            for _ in 0..max_keys {
                let res = vault.add_key(
                    Uuid::from_bytes(TEST_CRED_ID),
                    kind,
                    Key::RsaPublic(rsa_public_key.clone()),
                    flags,
                    key_tag,
                );
                assert!(res.is_ok());
            }
        }

        let key1_num = 0x0101;
        let key2_num = 0x0202;

        // Hold reference to key1
        let entry = vault.get_key_entry(key1_num).unwrap();

        // Attempt to delete key1
        let res = vault.remove_key(key1_num);
        assert!(res.is_ok());

        // Delete key2
        let res = vault.remove_key(key2_num);
        assert!(res.is_ok());
        let res_after_remove = vault.get_key_entry(key2_num);
        assert!(res_after_remove.is_err());

        // Add and should get added at key2 slot.
        let res = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            kind,
            Key::RsaPublic(rsa_public_key.clone()),
            flags,
            key_tag,
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), key1_num);

        // Release reference to key1
        drop(entry);

        // Delete key1
        let res = vault.remove_key(key1_num);
        assert!(res.is_ok());
        let res_after_remove = vault.get_key_entry(key1_num);
        assert!(res_after_remove.is_err());

        // Add and should get added at key1 slot.
        let res = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            kind,
            Key::RsaPublic(rsa_public_key),
            flags,
            key_tag,
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), key1_num);
    }

    #[test]
    fn test_add_remove_entry_in_use_lazy_delete() {
        let key_tag = 0x5453;

        let table_count = 4;
        let vault =
            Vault::new(Uuid::from_bytes([0xb2; 16]), table_count).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let flags = EntryFlags::new().with_generated(true);
        let kind = Kind::Rsa2kPublic;

        // Fill the vault so no space left
        let mut cnt = 0;
        for _ in 0..table_count {
            let max_keys = MAX_TABLE_BYTES / kind.size() - 1;
            for _ in 0..max_keys {
                let res = vault.add_key(
                    Uuid::from_bytes(TEST_CRED_ID),
                    kind,
                    Key::RsaPublic(rsa_public_key.clone()),
                    flags,
                    key_tag + cnt,
                );
                assert!(res.is_ok());
                cnt += 1;
            }
        }

        let key1_num = 0x0101;
        let key2_num = 0x0203;

        // Hold reference to key1
        let entry = vault.get_key_entry(key1_num).unwrap();

        // Attempt to delete key1
        let res = vault.remove_key(key1_num);
        assert!(res.is_ok());

        // Delete key2
        let res = vault.remove_key(key2_num);
        assert!(res.is_ok());
        let res_after_remove = vault.get_key_entry(key2_num);
        assert!(res_after_remove.is_err());

        // Add and should get added at key2 slot.
        let res = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            kind,
            Key::RsaPublic(rsa_public_key.clone()),
            flags,
            key_tag - 1,
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), key1_num);

        // Release reference to key1
        drop(entry);

        // Sleep for LAZY_DELETE_TIMEOUT_IN_SECONDS seconds to allow lazy delete to kick in during add.
        thread::sleep(Duration::from_secs(KEY_LAZY_DELETE_TIMEOUT_IN_SECONDS));

        // Add and should get added at key1 slot.
        let res = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            kind,
            Key::RsaPublic(rsa_public_key),
            flags,
            key_tag - 2,
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), key2_num);
    }

    #[test]
    fn test_add_app_short_app_id() {
        let table_count = 4;
        let vault =
            Vault::new(Uuid::from_bytes([0xb2; 16]), table_count).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        assert_eq!(vault.user().short_app_id, 0);
    }

    #[test]
    fn test_get_key_num_by_tag() {
        let key_tag = 0x5453;

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        let result = vault.get_key_num_by_tag(Uuid::from_bytes(TEST_CRED_ID), key_tag);
        assert!(result.is_err(), "result {:?}", result);

        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let key1 = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                EntryFlags::default(),
                key_tag,
            )
            .unwrap();

        let result = vault.get_key_num_by_tag(Uuid::from_bytes(TEST_CRED_ID), key_tag);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), key1);
    }

    #[test]
    fn test_add_key_internal_session_only() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        let mut flags = EntryFlags::default();
        flags.set_session_only(true);
        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let result = vault.add_key(
            APP_ID_FOR_INTERNAL_KEYS,
            Kind::Rsa2kPublic,
            Key::RsaPublic(rsa_public_key.clone()),
            flags,
            0,
        );
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_add_key_duplicate_key_tag() {
        let key_tag = 0x5354;
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        let flags = EntryFlags::default();
        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let result = vault.add_key(
            APP_ID_FOR_INTERNAL_KEYS,
            Kind::Rsa2kPublic,
            Key::RsaPublic(rsa_public_key.clone()),
            flags,
            key_tag,
        );
        assert!(result.is_ok());
        let result = vault.add_key(
            APP_ID_FOR_INTERNAL_KEYS,
            Kind::Rsa2kPublic,
            Key::RsaPublic(rsa_public_key.clone()),
            flags,
            key_tag,
        );
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_get_key_entry_invalid_table_index() {
        let key_tag = 0x5354;
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        let flags = EntryFlags::default();
        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let result = vault.add_key(
            APP_ID_FOR_INTERNAL_KEYS,
            Kind::Rsa2kPublic,
            Key::RsaPublic(rsa_public_key.clone()),
            flags,
            key_tag,
        );
        assert!(result.is_ok());
        let result = vault.get_key_entry(0x8801);
        assert!(result.is_err(), "result {:?}", result);
    }
    #[test]
    fn test_virtual_session_id_reuse_after_cleanup() {
        // Test that virtual session IDs become available for reuse after cleanup

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };

        // Create first session
        let session_result1 =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

        // Verify session exists
        assert!(vault.get_session_entry(session_result1.session_id).is_ok());

        let result = vault.close_session(session_result1.session_id);
        assert!(result.is_ok());

        // Verify session is cleaned up
        assert!(vault.get_session_entry(session_result1.session_id).is_err());

        // Create a new session - should be able to reuse the same virtual session ID
        let session_result2 =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

        // The session ID should be reused (likely the same as session_id_1)
        assert_eq!(session_result1.session_id, session_result2.session_id);

        // Verify new session exists
        assert!(vault.get_session_entry(session_result2.session_id).is_ok());
    }

    #[test]
    fn test_multiple_sessions_independent_cleanup() {
        // Test multiple concurrent sessions and independent cleanup

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };

        // Create two sessions
        let session_result1 =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let session_result2 =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

        assert_ne!(session_result1.session_id, session_result2.session_id);

        // Verify both sessions exist
        assert!(vault.get_session_entry(session_result1.session_id).is_ok());
        assert!(vault.get_session_entry(session_result2.session_id).is_ok());

        // Add session-only keys to both sessions
        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let mut flags = EntryFlags::default();
        flags.set_session_only(true);

        let key_1 = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                flags,
                session_result1.session_id,
            )
            .unwrap();

        let key_2 = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                flags,
                session_result2.session_id,
            )
            .unwrap();

        assert_ne!(key_1, key_2);

        // Close only session 1
        let result = vault.close_session(session_result1.session_id);
        assert!(result.is_ok());

        // Verify session 1 is cleaned up but session 2 remains
        assert!(vault.get_session_entry(session_result1.session_id).is_err());
        assert!(vault.get_session_entry(session_result2.session_id).is_ok());

        // Close session 2
        let result = vault.close_session(session_result2.session_id);
        assert!(result.is_ok());

        // Verify both sessions are now cleaned up
        assert!(vault.get_session_entry(session_result1.session_id).is_err());
        assert!(vault.get_session_entry(session_result2.session_id).is_err());
    }

    #[test]
    fn test_close_nonexistent_session() {
        // Test calling close_session with invalid/nonexistent session ID

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        let nonexistent_session_id = 99;
        let result = vault.close_session(nonexistent_session_id);

        assert_eq!(result, Err(ManticoreError::SessionNotFound));
    }

    #[test]
    fn test_session_table_exhaustion_handling() {
        // Test what happens when all 8 session table slots are used

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };

        let mut session_ids = Vec::new();

        // Create sessions up to the limit (should be 8 based on session table design)
        // The actual limit might be lower due to vault session limits, so we'll test both
        for i in 0..10 {
            match helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev) {
                Ok(session_result) => {
                    session_ids.push(session_result.session_id);
                    tracing::debug!(
                        "Created session {}: virtual_id={}",
                        i,
                        session_result.session_id
                    );
                }
                Err(e) => {
                    tracing::debug!("Failed to create session {}: {:?}", i, e);
                    break;
                }
            }
        }

        assert_eq!(session_ids.len(), 8);
        tracing::debug!("Created {} sessions total", session_ids.len());

        // Clean up all sessions
        for session_id in session_ids {
            let result = vault.close_session(session_id);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_complete_session_lifecycle_with_session_table() {
        // Test: open_session -> add keys -> close_session -> verify cleanup

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };

        // 1. Open session
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

        // 2. Add both regular and session-only keys
        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();

        // Add regular key
        let regular_key = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                EntryFlags::default(),
                0x2000,
            )
            .unwrap();

        // Add session-only keys
        let mut flags = EntryFlags::default();
        flags.set_session_only(true);

        let session_key_1 = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                flags,
                session_result.session_id,
            )
            .unwrap();

        let session_key_2 = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                flags,
                session_result.session_id,
            )
            .unwrap();

        // Verify all keys exist
        assert!(vault.get_key_entry(regular_key).is_ok());
        assert!(vault.get_key_entry(session_key_1).is_ok());
        assert!(vault.get_key_entry(session_key_2).is_ok());

        // 3. Close session and remove session-only keys
        let result = vault.close_session(session_result.session_id);
        assert!(result.is_ok());

        // 4. Verify cleanup
        // Session table entry should be gone
        assert!(vault.get_session_entry(session_result.session_id).is_err());
        // Regular key should still exist
        assert!(vault.get_key_entry(regular_key).is_ok());

        // Session-only keys should be gone.
        assert!(vault.get_key_entry(session_key_1).is_err());
        assert!(vault.get_key_entry(session_key_2).is_err());
    }

    #[test]
    fn test_session_table_virtual_to_physical_mapping() {
        // Test that virtual session IDs properly map to physical session IDs

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };

        let mut sessions = Vec::new();

        // Create multiple sessions
        for _ in 0..3 {
            let session_result =
                helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

            // Get the physical ID
            let vault_inner = vault.inner.read();
            let session_table = &vault_inner.session_table;
            let physical_id = session_table
                .get_target_session(session_result.session_id)
                .unwrap();
            drop(vault_inner);

            sessions.push((session_result.session_id, physical_id));
        }

        // Verify mappings are consistent and unique
        for i in 0..sessions.len() {
            let (virtual_i, physical_i) = sessions[i];

            // Verify mapping is consistent
            let vault_inner = vault.inner.read();
            let session_table = &vault_inner.session_table;
            assert_eq!(
                session_table.get_target_session(virtual_i).unwrap(),
                physical_i
            );
            drop(vault_inner);

            // Verify virtual and physical IDs are unique across sessions
            for (virtual_j, physical_j) in sessions.iter().skip(i + 1) {
                assert_ne!(
                    virtual_i, *virtual_j,
                    "Virtual session IDs should be unique"
                );
                assert_ne!(
                    physical_i, *physical_j,
                    "Physical session IDs should be unique"
                );
            }
        }

        // Clean up sessions
        for (virtual_id, _) in sessions {
            let result = vault.close_session(virtual_id);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_session_table_backup_restore_integration() {
        // Test session table backup/restore with vault integration

        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };

        // Create sessions
        let session_result1 =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let session_result2 =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

        // Add session-only keys
        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let mut flags = EntryFlags::default();
        flags.set_session_only(true);

        let _key_1 = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                flags,
                session_result1.session_id,
            )
            .unwrap();

        let _key_2 = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                flags,
                session_result2.session_id,
            )
            .unwrap();

        // Backup session table state
        let vault_inner = vault.inner.read();
        let session_table = &vault_inner.session_table;
        let backup_mask = session_table.backup();
        drop(vault_inner);

        // Verify backup contains session information
        assert_ne!(backup_mask, 0); // Should have some sessions recorded

        // Simulate session table restoration (this would happen after live migration)
        let mut vault_inner = vault.inner.write();
        let session_table = &mut vault_inner.session_table;
        session_table.restore(backup_mask);
        assert!(session_table.needs_renegotiation(session_result1.session_id));
        assert!(session_table.needs_renegotiation(session_result2.session_id));
        drop(vault_inner);

        // After restore, sessions would need to be reestablished,
        // but the virtual ID allocation masks will be preserved.

        // This is tested more thoroughly in session_table.rs tests
        // Here we just verify that the vault integration works
        let result = vault.close_session(session_result1.session_id);
        assert!(result.is_ok());
        let result = vault.close_session(session_result2.session_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_close_already_closed_session() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };

        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let result = vault.close_session(session_result.session_id);
        assert!(result.is_ok());

        let result = vault.close_session(session_result.session_id);
        assert_eq!(result, Err(ManticoreError::SessionNotFound));
    }

    #[test]
    fn test_get_session_encryption_key_id_without_establish_credential() {
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        let result = vault.get_session_encryption_key_id();
        assert!(result.is_err(), "result {:?}", result);
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let result = vault.get_session_encryption_key_id();
        assert!(result.is_ok());
    }

    #[test]
    fn test_close_session_after_backup_restore_success() {
        // Test that closing a session succeeds after backup and restore operations by handling renegotiation requirement
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };

        // Create session
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

        // Verify session exists and is valid
        assert!(vault.get_session_entry(session_result.session_id).is_ok());

        // Perform backup operation
        let vault_inner = vault.inner.read();
        let session_table = &vault_inner.session_table;
        let backup_mask = session_table.backup();
        assert!(!session_table.needs_renegotiation(session_result.session_id));
        drop(vault_inner);

        // Verify backup captured the session
        assert_ne!(backup_mask, 0);

        // Perform restore operation
        let mut vault_inner = vault.inner.write();
        let session_table = &mut vault_inner.session_table;
        session_table.restore(backup_mask);
        // After restore, session should need renegotiation
        assert!(session_table.needs_renegotiation(session_result.session_id));
        assert_eq!(
            session_table.get_available_session_count(),
            (MAX_SESSIONS - 1) as u32
        );
        drop(vault_inner);

        // After backup/restore, the session needs renegotiation but can now be closed successfully
        let result = vault.close_session(session_result.session_id);
        assert!(
            result.is_ok(),
            "Expected session to be closeable after backup/restore even with renegotiation requirement: {:?}",
            result
        );

        // Verify session is properly cleaned up from session table
        assert!(vault.get_session_entry(session_result.session_id).is_err());
    }

    #[test]
    fn test_close_session_before_backup_restore_not_exist_after() {
        // Test that a session closed before backup/restore operations does not exist after
        let vault = Vault::new(Uuid::from_bytes([0xb2; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };

        // Create a session
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

        // Verify session exists
        assert!(vault.get_session_entry(session_result.session_id).is_ok());

        // Close the session before backup/restore
        let result = vault.close_session(session_result.session_id);
        assert!(result.is_ok());

        // Verify session is closed
        assert!(vault.get_session_entry(session_result.session_id).is_err());

        // Perform backup operation (should capture no sessions since the only session is closed)
        let vault_inner = vault.inner.read();
        let session_table = &vault_inner.session_table;
        let backup_mask = session_table.backup();
        assert!(
            backup_mask == 0,
            "Expected backup mask to be 0 since session was closed"
        );
        assert!(
            !session_table.needs_renegotiation(session_result.session_id),
            "Session should not need renegotiation since it was closed"
        );
        assert!(
            !session_table.valid(session_result.session_id),
            "Session should not exist in session table after being closed"
        );
        drop(vault_inner);

        // Since we closed the session, backup should be 0 (no sessions to backup)
        assert_eq!(backup_mask, 0);

        // Perform restore operation with empty mask
        let mut vault_inner = vault.inner.write();
        let session_table = &mut vault_inner.session_table;
        session_table.restore(backup_mask);
        assert!(!session_table.needs_renegotiation(session_result.session_id));
        assert!(
            !session_table.valid(session_result.session_id),
            "Session should not exist in session table after being closed"
        );
        assert_eq!(
            session_table.get_available_session_count(),
            MAX_SESSIONS as u32
        );
        drop(vault_inner);

        // Verify session still does not exist after backup/restore
        assert!(vault.get_session_entry(session_result.session_id).is_err());

        // Try to close the already-closed session (should fail)
        let result = vault.close_session(session_result.session_id);
        assert_eq!(result, Err(ManticoreError::SessionNotFound));
    }

    #[test]
    fn test_ecc_signing_session_isolation() {
        let vault = Vault::new(Uuid::from_bytes([0xb3; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };

        // Open session 1
        let session_result1 =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

        // Open session 2
        let session_result2 =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

        // Generate ECC key pairs
        let (ecc_private_key_1, _ecc_public_key_1) = generate_ecc(EccCurve::P256).unwrap();
        let (ecc_private_key_2, _ecc_public_key_2) = generate_ecc(EccCurve::P256).unwrap();

        // Add ECC signing key to session 1
        let mut flags = EntryFlags::default();
        flags.set_session_only(true);

        let key_1 = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Ecc256Private,
                Key::EccPrivate(ecc_private_key_1.clone()),
                flags,
                session_result1.session_id,
            )
            .unwrap();

        // Add ECC signing key to session 2
        let key_2 = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Ecc256Private,
                Key::EccPrivate(ecc_private_key_2.clone()),
                flags,
                session_result2.session_id,
            )
            .unwrap();

        // Test data to sign
        let blob_to_sign = b"test data to sign";

        // Test 1: Use key 1 with session 1 -> should succeed
        let entry_1 = vault.get_key_entry(key_1).unwrap();
        if let Key::EccPrivate(ref ecc_key) = entry_1.key() {
            let result = ecc_key.sign(blob_to_sign);
            assert!(
                result.is_ok(),
                "Signing with key 1 in session 1 should succeed"
            );
        } else {
            panic!("Expected ECC private key");
        }

        // Test 2: Use key 2 with session 2 -> should succeed
        let entry_2 = vault.get_key_entry(key_2).unwrap();
        if let Key::EccPrivate(ref ecc_key) = entry_2.key() {
            let result = ecc_key.sign(blob_to_sign);
            assert!(
                result.is_ok(),
                "Signing with key 2 in session 2 should succeed"
            );
        } else {
            panic!("Expected ECC private key");
        }

        // Test 3: Try to access key 2 after close session 2 -> should fail
        let result = vault.close_session(session_result2.session_id);
        assert!(result.is_ok(), "Closing session 2 should succeed");

        let entry_1 = vault.get_key_entry(key_1).unwrap();
        if let Key::EccPrivate(ref ecc_key) = entry_1.key() {
            let result = ecc_key.sign(blob_to_sign);
            assert!(
                result.is_ok(),
                "Signing with key 1 in session 1 should succeed after closing session 2"
            );
        } else {
            panic!("Expected ECC private key");
        }

        // Key 2 should no longer be accessible (was session-only)
        let result = vault.get_key_entry(key_2);
        assert!(
            result.is_err(),
            "Key 2 should be inaccessible after session 2 is closed"
        );

        let result = vault.close_session(session_result1.session_id);
        assert!(result.is_ok(), "Closing session 1 should succeed");

        // Key 1 should no longer be accessible (was session-only)
        let result = vault.get_key_entry(key_1);
        assert!(
            result.is_err(),
            "Key 1 should be inaccessible after session 1 is closed"
        );
    }

    #[test]
    fn test_get_target_session_id() {
        let vault = Vault::new(Uuid::from_bytes([0xb3; 16]), 4).expect("Failed to create Vault");
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let api_rev = ApiRev { major: 1, minor: 0 };

        // Open a session
        let session_result =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

        // Test 1: Get target session ID for valid virtual session ID -> should succeed
        let result = vault.get_target_session_id(session_result.session_id);
        assert!(
            result.is_ok(),
            "Getting target session ID for valid virtual session should succeed"
        );
        let _physical_session_id = result.unwrap();

        // Test 2: Get target session ID for invalid virtual session ID -> should fail
        let invalid_virtual_session_id = 999u16; // Invalid session ID
        let result = vault.get_target_session_id(invalid_virtual_session_id);
        assert!(
            result.is_err(),
            "Getting target session ID for invalid virtual session should fail"
        );
        assert_eq!(result.unwrap_err(), ManticoreError::SessionNotFound);

        // Test 3: Get target session ID after closing session -> should fail
        let result = vault.close_session(session_result.session_id);
        assert!(result.is_ok(), "Closing session should succeed");

        let result = vault.get_target_session_id(session_result.session_id);
        assert!(
            result.is_err(),
            "Getting target session ID for closed session should fail"
        );
        assert_eq!(result.unwrap_err(), ManticoreError::SessionNotFound);
    }

    // This test helps achieve 100% test coverage
    // as debug trait is mainly used for test purposes
    #[test]
    fn test_debug_trait_print() {
        let vault = Vault::new(Uuid::new_v4(), 4).expect("Failed to create Vault");

        let vault_weak = vault.as_weak();

        let _upgraded_vault = vault_weak.upgrade();
    }
}
