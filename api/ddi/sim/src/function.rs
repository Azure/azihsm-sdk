// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for Function. This is the root level data structure of the HSM.
//! It maintains state relevant at the virtual function level or operations which don't need a session.

use std::sync::Arc;
use std::sync::Weak;

use parking_lot::RwLock;
use tracing::instrument;
use uuid::Uuid;

use crate::errors::ManticoreError;
use crate::session::UserSession;
use crate::table::entry::key::Key;
use crate::table::entry::EntryFlags;
use crate::table::entry::Kind;
use crate::vault::Vault;
use crate::vault::APP_ID_FOR_INTERNAL_KEYS;
use crate::vault::DEFAULT_VAULT_ID;

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
            inner: Arc::new(RwLock::new(FunctionInner::new(table_count))),
        };

        let generate_attestation_err = instance.generate_attestation_key();
        let generate_unwrapping_err = instance.generate_unwrapping_key();

        // Note: earlier errors can mask later errors
        generate_attestation_err?;
        generate_unwrapping_err?;

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

    fn generate_unwrapping_key(&self) -> Result<(), ManticoreError> {
        self.inner.write().generate_unwrapping_key()
    }

    /// Reset the function to clean state.
    pub(crate) fn reset_function(&self) -> Result<(), ManticoreError> {
        self.inner.write().reset_function_state()
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
        self.get_user_session_api_rev(session_id, true)?;

        let vault = self.get_function_state().get_vault(DEFAULT_VAULT_ID)?;

        vault.remove_session_only_keys(session_id)?;
        vault.remove_key(session_id)
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
        let session_entry = vault.get_key_entry(session_id)?;

        let _api_rev = self
            .inner
            .read()
            .get_user_session_api_rev(session_id, allow_disabled)?;

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
}

#[derive(Debug)]
struct FunctionInner {
    state: FunctionState,
}

impl FunctionInner {
    fn new(table_count: usize) -> Self {
        Self {
            state: FunctionState::new(table_count),
        }
    }

    fn get_api_rev_range(&self) -> ApiRevRange {
        ApiRevRange {
            min: ApiRev { major: 1, minor: 0 },
            max: ApiRev { major: 1, minor: 0 },
        }
    }

    fn reset_function_state(&mut self) -> Result<(), ManticoreError> {
        tracing::debug!(table = self.state.tables_max(), "Resetting FunctionState");
        self.state = FunctionState::new(self.state.tables_max());
        let generate_attestation_err = self.generate_attestation_key();
        let generate_unwrapping_err = self.generate_unwrapping_key();

        // Note: earlier errors can mask later errors
        generate_attestation_err?;
        generate_unwrapping_err
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
            .with_allow_sign_verify(true)
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
            .with_allow_unwrap(true)
            .with_generated(true);

        let private_key_id = vault.add_key(
            APP_ID_FOR_INTERNAL_KEYS,
            Kind::Rsa2kPrivate,
            Key::RsaPrivate(rsa_private_key),
            key_flags,
            0, //sess_id_or_key_tag
        )?;

        // Save the key num on FunctionState
        self.state.set_unwrapping_key_num(private_key_id)?;

        Ok(())
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
    fn new(tables_max: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(FunctionStateInner::new(tables_max))),
        }
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
}

#[derive(Debug)]
struct FunctionStateInner {
    tables_max: usize,
    tables_used: usize,
    vaults: Vec<Vault>,
    // The key num of attestation key (only private key for now)
    // This key should be stored in vault DEFAULT_VAULT_ID
    attestation_key_num: Option<u16>,
    wrapping_key_num: Option<u16>,
}

impl Drop for FunctionStateInner {
    fn drop(&mut self) {
        tracing::trace!("Dropping FunctionStateInner");
    }
}

impl FunctionStateInner {
    fn new(table_count: usize) -> Self {
        let mut vaults = Vec::with_capacity(table_count);
        let default_vault = Vault::new(DEFAULT_VAULT_ID, table_count);
        vaults.push(default_vault);

        Self {
            tables_max: table_count,
            tables_used: table_count,
            vaults,
            attestation_key_num: None,
            wrapping_key_num: None,
        }
    }

    fn get_user_session_api_rev(
        &self,
        session_id: u16,
        allow_disabled: bool,
    ) -> Result<ApiRev, ManticoreError> {
        let vault = self.get_vault(DEFAULT_VAULT_ID)?;
        let entry = vault.get_key_entry_unchecked(session_id)?;

        if allow_disabled || !entry.disabled() {
            if let Key::Session(api_rev) = entry.key() {
                return Ok(api_rev);
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
            tracing::error!("Attestation Key can only be set once");
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
            None => Err(ManticoreError::KeyNotFound)?,
        }
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

        // Check unwrapping key
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
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

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
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

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
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

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
    fn test_reset_function() {
        let function = create_function(2);
        let api_rev = function.get_api_rev_range().max;

        let result = function.get_function_state().get_vault(DEFAULT_VAULT_ID);
        assert!(result.is_ok());
        let vault = result.unwrap();

        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let key1 = vault
            .add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                EntryFlags::default(),
                0,
            )
            .unwrap();

        assert_eq!(function.tables_max(), 2);
        let old_session = vault.get_key_entry(session_id).unwrap();
        assert_eq!(old_session.kind(), Kind::Session);
        assert!(vault.get_key_entry(key1).is_ok());

        let result = function.reset_function();
        assert!(result.is_ok());
        let result = function.get_function_state().get_vault(DEFAULT_VAULT_ID);
        assert!(result.is_ok());
        let vault = result.unwrap();

        assert_eq!(function.tables_max(), 2);

        let fetch_old_session = vault.get_key_entry(session_id);
        assert!(fetch_old_session.is_err() || fetch_old_session.unwrap().kind() != Kind::Session);
        assert!(vault.get_key_entry(key1).is_err());
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

    // This test helps achieve 100% test coverage
    #[test]
    fn test_ensure_code_coverage() {
        let function = create_function(2);

        println!("get_api_rev_range: {:?}", function.get_api_rev_range());

        let function_weak = function.as_weak();
        let function_weak_upgrade = function_weak.upgrade();
        println!("Function {:?}", function_weak_upgrade);

        let fs_weak = function.get_function_state().as_weak();
        println!("FunctionStateWeak {:?}", fs_weak);

        assert_eq!(function.inner.read().state.tables_available(), 0);

        let upgraded_fs = fs_weak.upgrade();
        println!("upgraded_fs {:?}", upgraded_fs);
    }
}
