// Copyright (C) Microsoft Corporation. All rights reserved.

//! Manage a [Function] and its vaults.

use std::sync::Arc;
use std::sync::Weak;

use bitfield_struct::bitfield;
use parking_lot::RwLock;
use tracing::instrument;
use uuid::Uuid;

use crate::attestation::*;
use crate::credentials::EncryptedPin;
use crate::crypto::aes::*;
use crate::crypto::ecc::*;
use crate::crypto::hmac::*;
use crate::crypto::rsa::*;
use crate::crypto::secret::*;
use crate::crypto::sha::*;
use crate::errors::ManticoreError;
// Make Function visible in scope for use in documentation links.
#[allow(unused)]
use crate::function::Function;
use crate::function::FunctionState;
use crate::function::FunctionStateWeak;
use crate::report::TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE;
use crate::table::entry::key::*;
use crate::table::entry::*;
use crate::vault::*;

/// The result of `AppSession::*_generate_key` operation.
///
/// * The first element of the tuple is the key number assigned to the generated private key.
/// - The second element is the [PKCS8](https://en.wikipedia.org/wiki/PKCS_8) representation of the generated public key.
pub type GenerateResponse = (u16, Vec<u8>);

/// Perform cryptographic operations for an app.
///
/// [AppSession] is a handle to a session used to perform cryptographic operations tied to an app on the vault.
///
/// Dropping an [AppSession] object does not close the session.
/// Calling the `close_session` method closes the session.
///
#[derive(Debug, Clone)]
pub struct UserSession {
    inner: Arc<RwLock<UserSessionInner>>,
}

impl UserSession {
    /// Create a new [AppSession] instance.
    ///
    /// # Arguments
    /// * `id`: The `u16` id of the session.
    /// * `vault_id`: The [Uuid] of the vault.
    /// * `kind`: The [SessionKind] of the session.
    /// * `state`: A weak reference ([FunctionStateWeak]) to the state of the function.
    /// * `vault`: A weak reference ([VaultWeak]) to the vault.
    ///
    /// # Returns
    /// * [AppSession] instance.
    ///
    #[instrument(name = "AppSession::new", skip(id, state, vault), fields(sess_id = id))]
    pub(crate) fn new(
        id: u16,
        session_entry: Entry,
        app_id: Uuid,
        short_app_id: u8,
        state: FunctionStateWeak,
        vault: VaultWeak,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(UserSessionInner::new(
                id,
                session_entry,
                app_id,
                short_app_id,
                state,
                vault,
            ))),
        }
    }

    /// Get the `u16` id of the session.
    pub(crate) fn id(&self) -> u16 {
        self.inner.read().id()
    }

    /// Get the short app id associated with this session.
    pub(crate) fn short_app_id(&self) -> u8 {
        self.inner.read().short_app_id()
    }

    fn with_inner(inner: Arc<RwLock<UserSessionInner>>) -> Self {
        Self { inner }
    }

    #[allow(unused)]
    fn as_weak(&self) -> AppSessionWeak {
        AppSessionWeak::new(Arc::downgrade(&self.inner))
    }

    /// Prepare to close the session managed by the [AppSession] instance.
    ///
    /// # Returns
    /// * `()`
    ///
    /// # Errors
    /// * [ManticoreError::SessionNotFound] if the session has been closed.
    /// * [ManticoreError::VaultNotFound] if the vault has been deleted.
    /// * [ManticoreError::FunctionNotFound] if the [Function] instance has been dropped.
    ///
    /// # Behavior
    /// * This is a helper method to be used in [Function]'s close session implementation.
    pub fn prepare_close_session(&self) -> Result<(), ManticoreError> {
        let mut locked_inner = self.inner.write();

        locked_inner.set_disabled();

        let strong_count = self.strong_count();

        // One reference is held in the FunctionState and one reference is the object that called this method.
        if strong_count > 2 {
            tracing::error!(error = ?ManticoreError::CannotCloseSessionInUse, strong_count, "Cannot close AppSession with strong_count > 2");
            Err(ManticoreError::CannotCloseSessionInUse)?
        }

        locked_inner.close_session_core()
    }

    /// Prepare to lazy close the session managed by the [AppSession] instance.
    ///
    /// # Returns
    /// * `()`
    ///
    /// # Errors
    /// * [ManticoreError::SessionNotFound] if the session has been closed.
    /// * [ManticoreError::VaultNotFound] if the vault has been deleted.
    /// * [ManticoreError::FunctionNotFound] if the [Function] instance has been dropped.
    ///
    /// # Behavior
    /// * This is a helper method to be used in [Function]'s lazy close session implementation.
    pub fn prepare_lazy_close_session(&self) -> Result<(), ManticoreError> {
        let mut locked_inner = self.inner.write();

        locked_inner.set_disabled();

        locked_inner.close_session_core()
    }

    /// Generate an attestation report for the given key num
    ///
    /// # Arguments
    /// * `key_num` - The `u16` number of the key.
    /// * `report_data` - The `128` byte report data to be included in the report.
    ///
    /// # Returns
    /// * `([u8; TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE], usize)` - The raw bytes of attestation report and the size of it.
    ///
    /// # Errors
    /// * [ManticoreError::InvalidPermissions] if key_num cannot be accessed.
    /// * [ManticoreError::InvalidKeyNumber] if key_num is invalid.
    /// * [ManticoreError::CborEncodeError] if CBOR encoding fails.
    /// * [ManticoreError::SessionNotFound] if current App Session not found.
    /// * [ManticoreError::KeyNotFound] if the attestation key is not set.
    /// * [ManticoreError::EccInvalidKeyType] if the attestation key is not expected ECC key type.
    #[instrument(skip(self, report_data), fields(sess_id = self.id()))]
    pub fn attest_key(
        &self,
        key_num: u16,
        report_data: &[u8; 128],
    ) -> Result<([u8; TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE], usize), ManticoreError> {
        self.inner.read().attest_key(key_num, report_data)
    }

    /// Get collateral
    #[instrument(skip_all, fields(sess_id = self.id()))]
    pub fn get_collateral(&self) -> Result<Vec<u8>, ManticoreError> {
        self.inner.read().get_collateral()
    }

    /// Change the PIN of the user.
    ///
    /// # Arguments
    /// * `new_pin` - The new encrypted user PIN to be set.
    /// * `pub_key` - The public key of the user.
    ///
    /// # Returns
    /// * `()` upon success.
    #[instrument(skip_all, fields(sess_id = self.id()))]
    pub fn change_pin(&self, new_pin: EncryptedPin, pub_key: &[u8]) -> Result<(), ManticoreError> {
        self.inner.read().change_pin(new_pin, pub_key)
    }

    /// Delete a key owned by the app.
    ///
    /// # Arguments
    /// `key_num` - The `u16` number of the key.
    ///
    /// # Returns
    /// * `()`
    ///
    /// # Errors
    /// * [ManticoreError::SessionNotFound] if the session has been closed.
    /// * [ManticoreError::VaultNotFound] if the vault has been deleted.
    /// * [ManticoreError::InvalidPermissions] if the key is not owned by the app.
    /// * [ManticoreError::InvalidKeyNumber] if the key number is invalid.
    #[instrument(skip(self), fields(sess_id = self.id()))]
    pub fn delete_key(&self, key_num: u16) -> Result<(), ManticoreError> {
        self.inner.read().delete_key(key_num)
    }

    #[instrument(skip(self), fields(sess_id = self.id()))]
    pub(crate) fn get_key_entry(&self, key_num: u16) -> Result<Entry, ManticoreError> {
        self.inner.read().get_key_entry(key_num)
    }

    #[instrument(skip(self), fields(sess_id = self.id()))]
    pub(crate) fn get_key_num_by_tag(&self, key_tag: u16) -> Result<u16, ManticoreError> {
        self.inner.read().get_key_num_by_tag(key_tag)
    }

    #[instrument(skip_all, fields(sess_id = self.id(), key_tag))]
    pub(crate) fn import_key(
        &self,
        key_buf: &[u8],
        key_class: KeyClass,
        flags: EntryFlags,
        key_tag: Option<u16>,
    ) -> Result<u16, ManticoreError> {
        self.inner
            .read()
            .import_key(key_buf, key_class, flags, key_tag)
    }

    /// Perform a RSA private key operation.
    ///
    /// # Arguments
    /// * `key_num`: The key number of the private key.
    /// * `data`: Input data.
    ///
    /// # Returns
    /// * [Vec\<u8\>] Output data.
    ///
    /// # Errors
    /// * [ManticoreError::SessionNotFound] if the session has been closed.
    /// * [ManticoreError::VaultNotFound] if the vault has been deleted.
    /// * [ManticoreError::InvalidPermissions] if the app does not have permissions to use the key.
    /// * [ManticoreError::RsaInvalidKeyType] if the key is not a private key.
    /// * [ManticoreError::RsaDecryptError] if the operation failed.
    ///
    #[instrument(skip_all, fields(sess_id = self.id(), key_num))]
    pub fn rsa_private(
        &self,
        key_num: u16,
        data: &[u8],
        op_type: RsaOpType,
    ) -> Result<Vec<u8>, ManticoreError> {
        self.inner.read().rsa_private(key_num, data, op_type)
    }

    /// Perform a RSA Decrypt operation.
    ///
    /// # Arguments
    /// * `key_num`: The key number of the private key.
    /// * `y`: Data to be decrypted.
    /// * `padding`: The padding scheme to be used.
    /// * `hash_algorithm`: The hash algorithm to be used.
    ///
    /// # Returns
    /// * [Vec\<u8\>] Decrypted data.
    ///
    /// # Errors
    /// * [ManticoreError::SessionNotFound] if the session has been closed.
    /// * [ManticoreError::VaultNotFound] if the vault has been deleted.
    /// * [ManticoreError::InvalidPermissions] if the app does not have permissions to use the key.
    /// * [ManticoreError::RsaInvalidKeyType] if the key is not a private key.
    /// * [ManticoreError::RsaEncryptError] if decryption failed.
    ///
    #[instrument(skip_all, fields(sess_id = self.id(), key_num))]
    pub fn rsa_decrypt(
        &self,
        key_num: u16,
        y: &[u8],
        padding: RsaCryptoPadding,
        hash_algorithm: Option<HashAlgorithm>,
    ) -> Result<Vec<u8>, ManticoreError> {
        self.inner
            .read()
            .rsa_decrypt(key_num, y, padding, hash_algorithm)
    }

    /// Generate an ECDSA key-pair.
    ///
    /// # Arguments
    /// * `curve` - The curve to be used for the key.
    /// * `flags` - The [EntryFlags] to be used for the key.
    /// * `key_tag` - The tag of the key.
    ///
    /// # Returns
    /// * [GenerateResponse] upon success.
    #[instrument(skip_all, fields(sess_id = self.id(), key_tag))]
    pub(crate) fn ecc_generate_key(
        &self,
        curve: EccCurve,
        flags: EntryFlags,
        key_tag: Option<u16>,
    ) -> Result<GenerateResponse, ManticoreError> {
        self.inner.read().ecc_generate_key(curve, flags, key_tag)
    }

    /// Perform a ECDSA Sign operation.
    ///
    /// # Arguments
    /// * `key_num`: The key number of the private key.
    /// * `digest`: Digest to be signed.
    ///
    /// # Returns
    /// * [Vec\<u8\>] Signature.
    #[instrument(skip(self, digest), fields(sess_id = self.id()))]
    pub(crate) fn ecc_sign(&self, key_num: u16, digest: &[u8]) -> Result<Vec<u8>, ManticoreError> {
        self.inner.read().ecc_sign(key_num, digest)
    }

    /// Perform an ECDH key exchange operation.
    ///
    /// # Arguments
    /// * `priv_key_num` - The key number of own private key.
    /// * `peer_pub_key_num` - The key number of peer's public key.
    /// * `output_key_type` - The type of output key.
    /// * `flags` - The [EntryFlags] for the generated key.
    /// * `key_tag`: The tag of the generated key.
    ///
    /// # Returns
    /// * [u16] The key number of the generated key.
    #[instrument(skip_all, fields(sess_id = self.id(), priv_key_num))]
    pub(crate) fn ecdh_key_exchange(
        &self,
        priv_key_num: u16,
        peer_pub_key_der: &[u8],
        output_key_type: Kind,
        flags: EntryFlags,
        key_tag: Option<u16>,
    ) -> Result<u16, ManticoreError> {
        self.inner.read().ecdh_key_exchange(
            priv_key_num,
            peer_pub_key_der,
            output_key_type,
            flags,
            key_tag,
        )
    }

    /// Perform HMAC key derivation operation
    ///
    /// # Arguments
    /// * `key_num` - The key number of own `Secret` [Kind] key.
    /// * `hash_algorithm` - Hash algorithm, e.g. SHA256
    /// * `salt` - optional salt value
    /// * `info` - optional context and application specific information
    /// * `target_key_kind` - The [Kind] for the generated key.
    /// * `target_key_flags` - The [EntryFlags] for the generated key.
    /// * `target_key_tag` - The tag of the generated key.
    ///
    /// # Returns
    /// * [u16] The key number of the generated key.
    #[instrument(skip_all, fields(sess_id = self.id(), key_num))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn hkdf_derive(
        &self,
        key_num: u16,
        hash_algorithm: HashAlgorithm,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        target_key_kind: Kind,
        target_key_flags: EntryFlags,
        target_key_tag: Option<u16>,
    ) -> Result<u16, ManticoreError> {
        self.inner.read().hkdf_derive(
            key_num,
            hash_algorithm,
            salt,
            info,
            target_key_kind,
            target_key_flags,
            target_key_tag,
        )
    }

    /// Perform key-based key derivation operation (Counter-mode, HMAC)
    ///
    /// # Arguments
    /// * `key_num` - The key number of own `Secret` [Kind] key.
    /// * `hash_algorithm` - Hash algorithm, e.g. SHA256
    /// * `label` - optional label value
    /// * `context` - optional context and application specific information
    /// * `target_key_kind` - The [Kind] for the generated key.
    /// * `target_key_flags` - The [EntryFlags] for the generated key.
    /// * `target_key_tag` - The tag of the generated key.
    ///
    /// # Returns
    /// * [u16] The key number of the generated key.
    #[instrument(skip_all, fields(sess_id = self.id(), key_num))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn kbkdf_counter_hmac_derive(
        &self,
        key_num: u16,
        hash_algorithm: HashAlgorithm,
        label: Option<&[u8]>,
        context: Option<&[u8]>,
        target_key_kind: Kind,
        target_key_flags: EntryFlags,
        target_key_tag: Option<u16>,
    ) -> Result<u16, ManticoreError> {
        self.inner.read().kbkdf_counter_hmac_derive(
            key_num,
            hash_algorithm,
            label,
            context,
            target_key_kind,
            target_key_flags,
            target_key_tag,
        )
    }

    /// Perform HMAC hash operation.
    /// The hash operation (Sha256,Sha384,Sha512) is based on key size.
    ///
    /// # Arguments
    /// * `key_num` - The key number of own `HmacSha` [Kind] key.
    /// * `digest` - Input data.
    ///
    /// # Returns
    /// * [Vec<u8>] Output tag; size is based on key size.
    pub(crate) fn hmac(&self, key_num: u16, digest: &[u8]) -> Result<Vec<u8>, ManticoreError> {
        self.inner.read().hmac(key_num, digest)
    }

    /// Generate AES key.
    ///
    /// # Arguments
    /// * `key_size`: The size of the key to be generated.
    /// * `flags`: The [EntryFlags] to be used for the key.
    /// * `key_tag`: The tag of the key.
    ///
    /// # Returns
    /// * [u16] The key number of the generated key.
    #[instrument(skip_all, fields(sess_id = self.id(), key_tag))]
    pub(crate) fn aes_generate_key(
        &self,
        key_size: AesKeySize,
        flags: EntryFlags,
        key_tag: Option<u16>,
    ) -> Result<u16, ManticoreError> {
        self.inner.read().aes_generate_key(key_size, flags, key_tag)
    }

    /// Perform AES Encrypt/ Decrypt operation.
    ///
    /// # Arguments
    /// * `key_num`: The key number of the key.
    /// * `mode`: The mode to be used.
    /// * `data`: Data to be encrypted.
    /// * `iv`: The initialization vector to be used.
    ///
    /// # Returns
    /// * [AesEncryptResult] upon success.
    #[instrument(skip_all, fields(sess_id = self.id(), key_num))]
    pub(crate) fn aes_encrypt_decrypt(
        &self,
        key_num: u16,
        mode: AesMode,
        data: &[u8],
        iv: &[u8],
    ) -> Result<AesEncryptDecryptResult, ManticoreError> {
        self.inner
            .read()
            .aes_encrypt_decrypt(key_num, mode, data, iv)
    }

    /// Execute AES GCM encryption decryption operation
    ///  (to be invoked for fast path)
    /// # Arguments
    /// * `key_num`: The key number of the key.
    /// * `mode`: The mode to be used (Encryption or decryption)
    /// * `iv`: The initialization vector to be used.
    /// * `aad`: The additional authenticated data to be used.
    /// * `tag`: The tag to be used.
    /// * `source_buffers`: source buffer
    /// * `destination_buffers` : destination buffer
    ///
    /// # Returns
    /// * [FPAesGcmEncryptDecryptResult] upon success.
    ///
    /// * `ManticoreError` upon failure

    #[instrument(skip_all, fields(sess_id = self.id(), key_num))]
    pub(crate) fn fp_aes_gcm_encrypt_decrypt(
        &self,
        key_num: u16,
        mode: AesMode,
        iv: &[u8],
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
        source_buffers: Vec<Vec<u8>>,
        destination_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesGcmEncryptDecryptResult, ManticoreError> {
        self.inner.read().fp_aes_gcm_encrypt_decrypt(
            key_num,
            mode,
            iv,
            aad,
            tag,
            source_buffers,
            destination_buffers,
        )
    }

    /// Execute AES XTS encryption decryption operation
    ///  (to be invoked for fast path)
    /// # Arguments
    /// * `mode`: The mode to be used (Encryption or decryption)
    /// * `key1`: First key
    /// * `key2`: Second key
    /// * `tweak`: The tweak value
    /// * `dul`:  Data unit length
    /// * `source_buffers`: source buffer
    /// * `destination_buffers` : destination buffer
    ///
    /// # Returns
    /// * [FPAesXtsEncryptDecryptResult] upon success.
    ///
    /// * `ManticoreError` upon failure

    #[instrument(skip_all, fields(sess_id = self.id(), key1, key2))]
    pub(crate) fn fp_aes_xts_encrypt_decrypt(
        &self,
        mode: AesMode,
        key1: u16,
        key2: u16,
        tweak: [u8; 16usize],
        dul: usize,
        source_buffers: Vec<Vec<u8>>,
        destination_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesXtsEncryptDecryptResult, ManticoreError> {
        self.inner.read().fp_aes_xts_encrypt_decrypt(
            mode,
            key1,
            key2,
            tweak,
            dul,
            source_buffers,
            destination_buffers,
        )
    }

    /// Returns the strong reference count of the AppSession.
    ///
    /// # Returns
    /// * Strong reference count of the AppSession.
    ///
    /// # Safety
    /// This method by itself is safe, but using it correctly requires extra care.
    /// Another thread can change the strong count at any time, including potentially
    /// between calling this method and acting on the result.
    fn strong_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }
}

/// Bitfield used to store the current status of the [AppSession].
#[bitfield(u8)]
pub(crate) struct AppSessionFlags {
    // Private flags internal to AppSession.
    /// Indicates whether the session has been closed.
    closed: bool,

    /// Tells if the AppSession was disabled or not
    disabled: bool,

    #[bits(6)]
    reserved: u8,
}

#[derive(Debug)]
struct UserSessionInner {
    id: u16,
    #[allow(unused)]
    session_entry: Entry, // We keep a reference to the Entry to prevent deletion if multiple session instances are open.
    app_id: Uuid,
    short_app_id: u8,
    state: FunctionStateWeak,
    vault: VaultWeak,
    flags: AppSessionFlags,
    launch_id: Uuid,
}

impl UserSessionInner {
    fn new(
        id: u16,
        session_entry: Entry,
        app_id: Uuid,
        short_app_id: u8,
        state: FunctionStateWeak,
        vault: VaultWeak,
    ) -> Self {
        Self {
            id,
            session_entry,
            app_id,
            short_app_id,
            state,
            vault,
            flags: AppSessionFlags::default(),
            launch_id: Uuid::from_u128(0), // Default launch ID is 0, which means no launch ID is set.
        }
    }

    fn id(&self) -> u16 {
        self.id
    }

    fn short_app_id(&self) -> u8 {
        self.short_app_id
    }

    fn get_vault(&self) -> Result<Vault, ManticoreError> {
        if self.flags.closed() {
            tracing::error!(error = ?ManticoreError::SessionNotFound, "AppSession already closed");
            Err(ManticoreError::SessionNotFound)?
        }
        self.vault.upgrade().ok_or(ManticoreError::VaultNotFound)
    }

    fn get_function_state(&self) -> Result<FunctionState, ManticoreError> {
        if self.flags.closed() {
            tracing::error!(error = ?ManticoreError::SessionNotFound, "AppSession already closed");
            Err(ManticoreError::SessionNotFound)?
        }
        self.state.upgrade().ok_or(ManticoreError::FunctionNotFound)
    }

    // Core operations involved with closing a session.
    // Handles everything other than removing the session itself from Function's state.
    fn close_session_core(&mut self) -> Result<(), ManticoreError> {
        tracing::debug!(sess_id = self.id(), "AppSessionInner::close_session_core");
        self.set_disabled();
        self.get_vault()?.remove_session_only_keys(self.id)?;
        self.flags.set_closed(true);
        Ok(())
    }

    fn attest_key(
        &self,
        key_num: u16,
        report_data: &[u8; 128],
    ) -> Result<([u8; TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE], usize), ManticoreError> {
        tracing::debug!(key_num, "Attesting key");
        let key_to_attest = self.get_key_entry(key_num)?;
        let key_flag = key_to_attest.flags().into();
        let app_uuid = *self.app_id.as_bytes();
        let launch_id = self.launch_id.as_bytes();

        // Encode the key to be attested
        let cose_key = match key_to_attest.key() {
            Key::RsaPrivate(key) => CoseKey::from_rsa_private(&key),
            Key::RsaPublic(key) => CoseKey::from_rsa_public(&key),
            Key::EccPrivate(key) => CoseKey::from_ecc_private(&key),
            Key::EccPublic(key) => CoseKey::from_ecc_public(&key),
            Key::Aes(_) => {
                tracing::error!(error = ?ManticoreError::InvalidKeyType, "Key to be attested cannot be an AES key");
                Err(ManticoreError::InvalidKeyType)
            }
            Key::Secret(_) => {
                tracing::error!(error = ?ManticoreError::InvalidKeyType, "Key to be attested cannot be a Secret key");
                Err(ManticoreError::InvalidKeyType)
            }
            Key::Hmac(_) => {
                tracing::error!(error = ?ManticoreError::InvalidKeyType, "Key to be attested cannot be an HMAC key");
                Err(ManticoreError::InvalidKeyType)
            }

            Key::Session(_) => Err(ManticoreError::InvalidKeyType)?,
        }?;
        let (encoded_key, encoded_key_len) = cose_key.encode()?;

        // Generate attestation report payload
        let mut attester = KeyAttester::new();
        attester.create_report_payload(
            &encoded_key,
            encoded_key_len,
            key_flag,
            app_uuid,
            report_data,
            launch_id,
        )?;

        // Retrieve Attestation Key to sign the report
        let function_state = self.get_function_state()?;
        let attestation_key_num = function_state.get_attestation_key_num()?;
        let attestation_key = self.get_key_entry(attestation_key_num)?;
        tracing::debug!(attestation_key_num, "Got attestation key");

        if !attestation_key.is_attestation_key() {
            // Implies attestation_key was initialized incorrectly
            tracing::error!(error = ?ManticoreError::InternalError, "Attestation key is not properly initialized! is_attestation_key flag should be true");
            Err(ManticoreError::AttestKeyInternalErr)?
        }

        if let Key::EccPrivate(key) = attestation_key.key() {
            let (signed_quote, signed_quote_len) = attester.sign(&key)?;
            Ok((signed_quote, signed_quote_len))
        } else {
            // Implies attestation_key was initialized incorrectly
            tracing::error!(error = ?ManticoreError::InternalError, "Attestation key should be an ECC key");
            Err(ManticoreError::AttestKeyInternalErr)?
        }
    }

    fn get_collateral(&self) -> Result<Vec<u8>, ManticoreError> {
        // Retrieve Attestation private Key to derive pub key from (TEST-only)
        // TODO: Return the AK cert and TEE report
        let function_state = self.get_function_state()?;
        let attestation_key_num = function_state.get_attestation_key_num()?;
        let attestation_key = self.get_key_entry(attestation_key_num)?;

        if let Key::EccPrivate(key) = attestation_key.key() {
            // TEST-ONLY: create a X509 certificate from the ecc private key for now.
            let collateral = key.create_pub_key_cert()?;
            Ok(collateral)
        } else {
            // Throw error if key type if not EccPrivateKey
            Err(ManticoreError::EccInvalidKeyType)?
        }
    }

    fn change_pin(
        &self,
        new_pin: EncryptedPin,
        client_pub_key: &[u8],
    ) -> Result<(), ManticoreError> {
        self.get_vault()?.change_pin(new_pin, client_pub_key)
    }

    fn delete_key(&self, key_num: u16) -> Result<(), ManticoreError> {
        tracing::debug!(key_num, "Deleting key");
        // Ensure that the AppSession has permissions to operate on the key.
        // Also we don't store the returned `Entry` as we would end up getting
        // a reference to it which would prevent us from removing it.
        {
            let entry = self.get_key_entry(key_num)?;

            // Cannot delete internal keys.
            if entry.app_id() == APP_ID_FOR_INTERNAL_KEYS {
                tracing::error!(error = ?ManticoreError::CannotDeleteInternalKeys, "Cannot delete internal keys");
                Err(ManticoreError::CannotDeleteInternalKeys)?
            }
        }

        // Remove the key from the vault.
        self.get_vault()?.remove_key(key_num)
    }

    fn import_key(
        &self,
        key_buf: &[u8],
        key_class: KeyClass,
        flags: EntryFlags,
        key_tag: Option<u16>,
    ) -> Result<u16, ManticoreError> {
        tracing::debug!(key_class = ?key_class, key_tag, "import_key");
        let vault = self.get_vault()?;

        let (key, kind) = match key_class {
            KeyClass::RsaPrivate => {
                let rsa_private_key = RsaPrivateKey::from_der(key_buf, None)?;
                let kind = rsa_private_key.size().into();

                (Key::RsaPrivate(rsa_private_key), kind)
            }

            KeyClass::RsaCrtPrivate => {
                let rsa_private_key = RsaPrivateKey::from_der(key_buf, None)?;
                let kind: Kind = rsa_private_key.size().into();

                (Key::RsaPrivate(rsa_private_key), kind.as_crt()?)
            }

            KeyClass::EccPrivate => {
                let ecc_private_key = EccPrivateKey::from_der(key_buf, None)?;
                let kind = ecc_private_key.size().into();

                (Key::EccPrivate(ecc_private_key), kind)
            }

            KeyClass::Aes => {
                let aes_key = AesKey::from_bytes(key_buf)?;
                let kind = aes_key.size().into();

                (Key::Aes(aes_key), kind)
            }

            KeyClass::AesBulk => {
                let aes_key = AesKey::from_bulk_bytes(key_buf)?;
                let kind = aes_key.size().into();

                (Key::Aes(aes_key), kind)
            }
        };

        if flags.session_only() && key_tag.is_some() {
            tracing::error!("Session_only keys cannot have a tag");
            Err(ManticoreError::InvalidArgument)?
        }

        if let Some(key_tag_value) = key_tag {
            if key_tag_value == 0 {
                tracing::error!("Key num cannot be 0");
                Err(ManticoreError::InvalidArgument)?
            }
        }

        let sess_id_or_key_tag = if flags.session_only() {
            self.id
        } else {
            key_tag.unwrap_or(0)
        };

        let key_num = vault.add_key(self.app_id, kind, key, flags, sess_id_or_key_tag)?;
        tracing::debug!(key_num, "Completed import_key successfully");
        Ok(key_num)
    }

    fn get_key_entry(&self, key_num: u16) -> Result<Entry, ManticoreError> {
        let vault = self.get_vault()?;

        // Fetch reference to the entry. It cannot get deleted while we are using it.
        let entry = vault.get_key_entry(key_num)?;
        // Bypass permission check for internal keys
        if entry.app_id() == APP_ID_FOR_INTERNAL_KEYS {
            tracing::trace!(key_num, "Return internal key without checking permissions");
            return Ok(entry);
        }

        // Ensure that the app has permissions.
        if self.app_id != entry.app_id() {
            tracing::error!(error = ?ManticoreError::InvalidPermissions, "Key does not belong to the app");
            Err(ManticoreError::InvalidPermissions)?
        }

        let sess_id = entry.sess_id();
        tracing::trace!(entry_sess_id = sess_id);

        if entry.flags().session_only() {
            // For session_only key, the session id must match.
            if Some(self.id) != sess_id {
                tracing::error!(error = ?ManticoreError::InvalidPermissions, "Session_only key cannot be accessed from another session");
                Err(ManticoreError::InvalidPermissions)?
            }
        }

        Ok(entry)
    }

    fn get_key_num_by_tag(&self, key_tag: u16) -> Result<u16, ManticoreError> {
        let vault = self.get_vault()?;

        // Fetch reference to the entry. It cannot get deleted while we are using it.
        let key_num = vault.get_key_num_by_tag(self.app_id, key_tag)?;

        Ok(key_num)
    }

    fn rsa_private(
        &self,
        key_num: u16,
        data: &[u8],
        op_type: RsaOpType,
    ) -> Result<Vec<u8>, ManticoreError> {
        // Ensure that the AppSession has permissions to operate on the key.
        let entry = self.get_key_entry(key_num)?;

        match op_type {
            RsaOpType::Decrypt => {
                if !entry.allow_encrypt_decrypt() {
                    tracing::error!(error = ?ManticoreError::InvalidPermissions, "Key does not allow RSA decrypt");
                    Err(ManticoreError::InvalidPermissions)?
                }
            }
            RsaOpType::Sign => {
                if !entry.allow_sign_verify() {
                    tracing::error!(error = ?ManticoreError::InvalidPermissions, "Key does not allow RSA sign");
                    Err(ManticoreError::InvalidPermissions)?
                }
            }
        }

        match (entry.key(), entry.kind()) {
            (
                Key::RsaPrivate(key),
                Kind::Rsa2kPrivate
                | Kind::Rsa3kPrivate
                | Kind::Rsa4kPrivate
                | Kind::Rsa2kPrivateCrt
                | Kind::Rsa3kPrivateCrt
                | Kind::Rsa4kPrivateCrt,
            ) => key.operate(data),
            _ => {
                tracing::error!(error = ?ManticoreError::RsaInvalidKeyType, key_num, "Key type is not RSA private");
                Err(ManticoreError::RsaInvalidKeyType)
            }
        }
    }

    fn rsa_decrypt(
        &self,
        key_num: u16,
        y: &[u8],
        padding: RsaCryptoPadding,
        hash_algorithm: Option<HashAlgorithm>,
    ) -> Result<Vec<u8>, ManticoreError> {
        // Ensure that the AppSession has permissions to operate on the key.
        let entry = self.get_key_entry(key_num)?;

        // Also allow an unwrapping key to perform RSA decryption
        if !entry.allow_encrypt_decrypt() && !entry.allow_unwrap() {
            tracing::error!(error = ?ManticoreError::InvalidPermissions, "Key does not allow RSA decrypt");
            Err(ManticoreError::InvalidPermissions)?
        }

        match (entry.key(), entry.kind()) {
            (
                Key::RsaPrivate(key),
                Kind::Rsa2kPrivate
                | Kind::Rsa3kPrivate
                | Kind::Rsa4kPrivate
                | Kind::Rsa2kPrivateCrt
                | Kind::Rsa3kPrivateCrt
                | Kind::Rsa4kPrivateCrt,
            ) => key.decrypt(y, padding, hash_algorithm),
            _ => {
                tracing::error!(error = ?ManticoreError::RsaInvalidKeyType, key_num, "Key type is not RSA private");
                Err(ManticoreError::RsaInvalidKeyType)
            }
        }
    }

    #[instrument(skip_all, fields(app_id = ?app_id, vault_id = ?vault.id()))]
    fn ecc_generate_and_store_key(
        vault: Vault,
        app_id: Uuid,
        curve: EccCurve,
        sess_id_or_key_tag: u16,
        flags: EntryFlags,
    ) -> Result<GenerateResponse, ManticoreError> {
        tracing::trace!(
            vault_id = ?vault.id(),
            ?app_id,
            ?curve,
            sess_id_or_key_tag,
            ?flags,
            "ecc_generate_and_store_key"
        );
        let kind_private = match curve {
            EccCurve::P256 => Kind::Ecc256Private,
            EccCurve::P384 => Kind::Ecc384Private,
            EccCurve::P521 => Kind::Ecc521Private,
        };

        let (ecc_private_key, ecc_public_key) = generate_ecc(curve)?;
        let ecc_public_key_der = ecc_public_key.to_der()?;

        // Mark the keys as generated.
        let mut entry_flags = flags;
        entry_flags.set_generated(true);

        let private_key_num = vault.add_key(
            app_id,
            kind_private,
            Key::EccPrivate(ecc_private_key),
            entry_flags,
            sess_id_or_key_tag,
        )?;
        tracing::debug!(private_key_num, "Done adding private key");

        Ok((private_key_num, ecc_public_key_der))
    }

    fn ecc_generate_key(
        &self,
        curve: EccCurve,
        flags: EntryFlags,
        key_tag: Option<u16>,
    ) -> Result<GenerateResponse, ManticoreError> {
        tracing::trace!(?curve, ?flags, key_tag, "ecc_generate_key");
        if flags.session_only() && key_tag.is_some() {
            tracing::error!(error = ?ManticoreError::InvalidArgument, "Session_only keys cannot have a tag");
            Err(ManticoreError::InvalidArgument)?
        }

        let sess_id_or_key_tag = if flags.session_only() {
            self.id
        } else {
            key_tag.unwrap_or(0)
        };

        Self::ecc_generate_and_store_key(
            self.get_vault()?,
            self.app_id,
            curve,
            sess_id_or_key_tag,
            flags,
        )
    }

    fn ecc_sign(&self, key_num: u16, digest: &[u8]) -> Result<Vec<u8>, ManticoreError> {
        // Ensure that the AppSession has permissions to operate on the key.
        let entry = self.get_key_entry(key_num)?;

        if !entry.allow_sign_verify() {
            tracing::error!(error = ?ManticoreError::InvalidPermissions, "Key does not allow sign/verify");
            Err(ManticoreError::InvalidPermissions)?
        }

        match (entry.key(), entry.kind()) {
            (
                Key::EccPrivate(key),
                Kind::Ecc256Private | Kind::Ecc384Private | Kind::Ecc521Private,
            ) => key.sign(digest),
            _ => {
                tracing::error!(error = ?ManticoreError::EccInvalidKeyType, key_num, "Key type is not ECC private");
                Err(ManticoreError::EccInvalidKeyType)
            }
        }
    }

    fn ecdh_key_exchange(
        &self,
        priv_key_num: u16,
        peer_pub_key_der: &[u8],
        output_key_type: Kind,
        flags: EntryFlags,
        key_tag: Option<u16>,
    ) -> Result<u16, ManticoreError> {
        if Some(0) == key_tag {
            tracing::error!(error = ?ManticoreError::InvalidArgument, "Key tag cannot be 0");
            Err(ManticoreError::InvalidArgument)?
        }

        if flags.session_only() && key_tag.is_some() {
            tracing::error!(error = ?ManticoreError::InvalidArgument, "Session_only keys cannot have a tag");
            Err(ManticoreError::InvalidArgument)?
        }

        let priv_entry: Entry = self.get_key_entry(priv_key_num)?;

        if !priv_entry.allow_derive() {
            Err(ManticoreError::InvalidPermissions)?
        }

        // We need to confirm that:
        // 1. priv_key_num is ECC Private, output_key_type is Secret
        // 2. All keys match bit size
        let expected_pub_key_type = match (priv_entry.kind(), output_key_type) {
            (Kind::Ecc256Private, Kind::Secret256) => Kind::Ecc256Public,
            (Kind::Ecc384Private, Kind::Secret384) => Kind::Ecc384Public,
            (Kind::Ecc521Private, Kind::Secret521) => Kind::Ecc521Public,
            _ => {
                tracing::error!(error = ?ManticoreError::EccInvalidKeyType, priv_key_type = ?priv_entry.kind(), output_key_type = ?output_key_type, "ECDH doesn't allow this set of key types");
                Err(ManticoreError::EccInvalidKeyType)?
            }
        };

        // Create ECC Public Key, validate if the size of the key is the same as the private key
        let peer_pub_key = EccPublicKey::from_der(peer_pub_key_der, Some(expected_pub_key_type))?;

        let sess_id_or_key_tag = if flags.session_only() {
            self.id
        } else {
            key_tag.unwrap_or(0)
        };

        let (key, key_kind) = match priv_entry.key() {
            Key::EccPrivate(priv_key) => {
                let derived_bytes = priv_key.derive(&peer_pub_key)?;

                let key_kind = match derived_bytes.len() {
                    32 => Kind::Secret256,
                    48 => Kind::Secret384,
                    66 => Kind::Secret521,
                    invalid_size => {
                        tracing::error!(error = ?ManticoreError::InternalError, invalid_size, "Unexpected size from ECDH output");
                        Err(ManticoreError::InternalError)?
                    }
                };
                (SecretKey::from_bytes(&derived_bytes)?, key_kind)
            }
            priv_key => {
                tracing::error!(error = ?ManticoreError::InternalError, priv_key = ?priv_key, "Unexpected entry types for ECDH input keys");
                Err(ManticoreError::InternalError)?
            }
        };

        let vault = self.get_vault()?;
        let key_num = vault.add_key(
            self.app_id,
            key_kind,
            Key::Secret(key),
            flags,
            sess_id_or_key_tag,
        )?;

        Ok(key_num)
    }

    #[allow(clippy::too_many_arguments)]
    fn hkdf_derive(
        &self,
        key_num: u16,
        hash_algorithm: HashAlgorithm,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        target_key_kind: Kind,
        target_key_flags: EntryFlags,
        target_key_tag: Option<u16>,
    ) -> Result<u16, ManticoreError> {
        let entry = self.get_key_entry(key_num)?;
        let vault = self.get_vault()?;

        if entry.kind() != Kind::Secret256
            && entry.kind() != Kind::Secret384
            && entry.kind() != Kind::Secret521
        {
            tracing::error!(error = ?ManticoreError::InvalidKeyType, key_type = ?entry.kind(), "Input key type is invalid");
            Err(ManticoreError::InvalidKeyType)?
        }

        if !entry.allow_derive() {
            tracing::error!(error = ?ManticoreError::InternalError, "Should not be possible for Secret Key to have non-derive permission");
            Err(ManticoreError::InternalError)?
        }

        if target_key_flags.session_only() && target_key_tag.is_some() {
            tracing::error!(error = ?ManticoreError::InvalidArgument, "Session_only keys cannot have a tag");
            Err(ManticoreError::InvalidArgument)?
        }

        if let Some(key_tag_value) = target_key_tag {
            if key_tag_value == 0 {
                tracing::error!(error = ?ManticoreError::InvalidArgument, "Key tag cannot be 0");
                Err(ManticoreError::InvalidArgument)?
            }
        }

        let sess_id_or_key_tag = if target_key_flags.session_only() {
            self.id
        } else {
            target_key_tag.unwrap_or(0)
        };

        let key = match entry.key() {
            Key::Secret(secret_key) => {
                let out_len = target_key_kind.size();
                let derived_bytes = secret_key.hkdf_derive(hash_algorithm, salt, info, out_len)?;
                match target_key_kind {
                    Kind::Aes128 | Kind::Aes192 | Kind::Aes256 => {
                        Key::Aes(AesKey::from_bytes(&derived_bytes)?)
                    }
                    Kind::AesBulk256 => Key::Aes(AesKey::from_bulk_bytes(&derived_bytes)?),
                    Kind::Secret256 | Kind::Secret384 | Kind::Secret521 => {
                        Key::Secret(SecretKey::from_bytes(&derived_bytes)?)
                    }
                    Kind::HmacSha256 | Kind::HmacSha384 | Kind::HmacSha512 => {
                        Key::Hmac(HmacKey::from_bytes(&derived_bytes)?)
                    }
                    unexpected_kind => {
                        tracing::error!(error = ?ManticoreError::InternalError, unexpected_kind = ?unexpected_kind, "Unexpected target kind for HKDF derive");
                        Err(ManticoreError::InternalError)?
                    }
                }
            }
            unexpected_entry => {
                tracing::error!(error = ?ManticoreError::InternalError, unexpected_entry = ?unexpected_entry, "Unexpected entry for HKDF derive");
                Err(ManticoreError::InternalError)?
            }
        };

        let key_num = vault.add_key(
            self.app_id,
            target_key_kind,
            key,
            target_key_flags,
            sess_id_or_key_tag,
        )?;

        Ok(key_num)
    }

    #[allow(clippy::too_many_arguments)]
    fn kbkdf_counter_hmac_derive(
        &self,
        key_num: u16,
        hash_algorithm: HashAlgorithm,
        label: Option<&[u8]>,
        context: Option<&[u8]>,
        target_key_kind: Kind,
        target_key_flags: EntryFlags,
        target_key_tag: Option<u16>,
    ) -> Result<u16, ManticoreError> {
        let entry = self.get_key_entry(key_num)?;
        let vault = self.get_vault()?;

        if entry.kind() != Kind::Secret256
            && entry.kind() != Kind::Secret384
            && entry.kind() != Kind::Secret521
        {
            tracing::error!(error = ?ManticoreError::InvalidKeyType, key_type = ?entry.kind(), "Input key type is not valid");
            Err(ManticoreError::InvalidKeyType)?
        }

        if !entry.allow_derive() {
            tracing::error!(error = ?ManticoreError::InternalError, "Should not be possible for Secret Key to have non-derive permission");
            Err(ManticoreError::InternalError)?
        }

        if target_key_flags.session_only() && target_key_tag.is_some() {
            tracing::error!(error = ?ManticoreError::InvalidArgument, "Session_only keys cannot have a tag");
            Err(ManticoreError::InvalidArgument)?
        }

        if let Some(key_tag_value) = target_key_tag {
            if key_tag_value == 0 {
                tracing::error!(error = ?ManticoreError::InvalidArgument, "Key tag cannot be 0");
                Err(ManticoreError::InvalidArgument)?
            }
        }

        let sess_id_or_key_tag = if target_key_flags.session_only() {
            self.id
        } else {
            target_key_tag.unwrap_or(0)
        };

        let key = match entry.key() {
            Key::Secret(secret_key) => {
                let out_len = target_key_kind.size();
                let derived_bytes = secret_key.kbkdf_counter_hmac_derive(
                    hash_algorithm,
                    label,
                    context,
                    true, /*use_seperator, default value*/
                    true, /*use_l, default value*/
                    out_len,
                )?;
                match target_key_kind {
                    Kind::Aes128 | Kind::Aes192 | Kind::Aes256 => {
                        Key::Aes(AesKey::from_bytes(&derived_bytes)?)
                    }
                    Kind::AesBulk256 => Key::Aes(AesKey::from_bulk_bytes(&derived_bytes)?),
                    Kind::Secret256 | Kind::Secret384 | Kind::Secret521 => {
                        Key::Secret(SecretKey::from_bytes(&derived_bytes)?)
                    }
                    Kind::HmacSha256 | Kind::HmacSha384 | Kind::HmacSha512 => {
                        Key::Hmac(HmacKey::from_bytes(&derived_bytes)?)
                    }
                    unexpected_kind => {
                        tracing::error!(error = ?ManticoreError::InternalError, unexpected_kind = ?unexpected_kind, "Unexpected target kind for KBKDF derive");
                        Err(ManticoreError::InternalError)?
                    }
                }
            }
            unexpected_entry => {
                tracing::error!(error = ?ManticoreError::InternalError, unexpected_entry = ?unexpected_entry, "Unexpected entry for KBKDF derive");
                Err(ManticoreError::InternalError)?
            }
        };

        let key_num = vault.add_key(
            self.app_id,
            target_key_kind,
            key,
            target_key_flags,
            sess_id_or_key_tag,
        )?;

        Ok(key_num)
    }

    #[instrument(skip_all, fields(key_num))]
    fn hmac(&self, key_num: u16, msg: &[u8]) -> Result<Vec<u8>, ManticoreError> {
        let entry = self.get_key_entry(key_num)?;

        if entry.kind() != Kind::HmacSha256
            && entry.kind() != Kind::HmacSha384
            && entry.kind() != Kind::HmacSha512
        {
            tracing::error!(error = ?ManticoreError::InvalidKeyType, key_type = ?entry.kind(), "Input key type is not valid");
            Err(ManticoreError::InvalidKeyType)?
        }

        if !entry.allow_sign_verify() {
            tracing::error!(error = ?ManticoreError::InternalError, "Should not be possible for Hmac key to have non-sign permission");
            Err(ManticoreError::InternalError)?
        }

        let hash_algorithm = match entry.kind() {
            Kind::HmacSha256 => HashAlgorithm::Sha256,
            Kind::HmacSha384 => HashAlgorithm::Sha384,
            Kind::HmacSha512 => HashAlgorithm::Sha512,
            unexpected_kind => {
                tracing::error!(error = ?ManticoreError::InternalError, unexpected_kind = ?unexpected_kind, "Unexpected kind for HMAC operation");
                Err(ManticoreError::InternalError)?
            }
        };

        match entry.key() {
            Key::Hmac(hmac_key) => hmac_key.hmac(msg, hash_algorithm),
            unexpected_entry => {
                tracing::error!(error = ?ManticoreError::InternalError, unexpected_entry = ?unexpected_entry, "Unexpected entry for KBKDF derive");
                Err(ManticoreError::InternalError)?
            }
        }
    }

    #[instrument(skip_all, fields(app_id = ?app_id, vault_id = ?vault.id()))]
    fn aes_generate_and_store_key(
        vault: Vault,
        app_id: Uuid,
        key_size: AesKeySize,
        sess_id_or_key_tag: u16,
        flags: EntryFlags,
    ) -> Result<u16, ManticoreError> {
        tracing::trace!(
            vault_id = ?vault.id(),
            app_id = ?app_id,
            key_size = ?key_size,
            sess_id_or_key_tag,
            flags = ?flags,
            "aes_generate_and_store_key"
        );
        let aes_key = generate_aes(key_size)?;

        // Mark the keys as generated.
        let mut entry_flags = flags;
        entry_flags.set_generated(true);

        let key_kind = match key_size {
            AesKeySize::Aes128 => Kind::Aes128,
            AesKeySize::Aes192 => Kind::Aes192,
            AesKeySize::Aes256 => Kind::Aes256,
            AesKeySize::AesBulk256 => Kind::AesBulk256,
        };

        let key_num = vault.add_key(
            app_id,
            key_kind,
            Key::Aes(aes_key),
            entry_flags,
            sess_id_or_key_tag,
        )?;
        tracing::debug!(key_num, "Done adding key");

        Ok(key_num)
    }

    fn aes_generate_key(
        &self,
        key_size: AesKeySize,
        flags: EntryFlags,
        key_tag: Option<u16>,
    ) -> Result<u16, ManticoreError> {
        tracing::trace!(key_size = ?key_size, flags = ?flags, key_tag, "aes_generate_key");
        if flags.session_only() && key_tag.is_some() {
            tracing::error!(error = ?ManticoreError::InvalidArgument, "Session_only keys cannot have a tag");
            Err(ManticoreError::InvalidArgument)?
        }

        let sess_id_or_key_tag = if flags.session_only() {
            self.id
        } else {
            key_tag.unwrap_or(0)
        };

        Self::aes_generate_and_store_key(
            self.get_vault()?,
            self.app_id,
            key_size,
            sess_id_or_key_tag,
            flags,
        )
    }

    fn aes_encrypt_decrypt(
        &self,
        key_num: u16,
        mode: AesMode,
        data: &[u8],
        iv: &[u8],
    ) -> Result<AesEncryptDecryptResult, ManticoreError> {
        // Ensure that the AppSession has permissions to operate on the key.
        let entry = self.get_key_entry(key_num)?;

        if !entry.allow_encrypt_decrypt() {
            tracing::error!(error = ?ManticoreError::InvalidPermissions, "Key does not allow AES encrypt/decrypt");
            Err(ManticoreError::InvalidPermissions)?
        }

        match (entry.key(), entry.kind()) {
            (Key::Aes(key), Kind::Aes128 | Kind::Aes192 | Kind::Aes256) => {
                if mode == AesMode::Encrypt {
                    let result = key.encrypt(data, AesAlgo::Cbc, Some(iv))?;

                    Ok(AesEncryptDecryptResult {
                        data: result.cipher_text,
                        iv: result.iv.unwrap_or([0; 16].to_vec()), // or is not possible due to previous conditions
                    })
                } else {
                    let result = key.decrypt(data, AesAlgo::Cbc, Some(iv))?;

                    Ok(AesEncryptDecryptResult {
                        data: result.plain_text,
                        iv: result.iv.unwrap_or([0; 16].to_vec()), // or is not possible due to previous conditions
                    })
                }
            }

            _ => {
                tracing::error!(error = ?ManticoreError::AesInvalidKeyType, key_num, "Key type is not AES");
                Err(ManticoreError::AesInvalidKeyType)
            }
        }
    }

    fn fp_aes_gcm_encrypt_decrypt(
        &self,
        key_num: u16,
        mode: AesMode,
        iv: &[u8],
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
        source_buffers: Vec<Vec<u8>>,
        destination_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesGcmEncryptDecryptResult, ManticoreError> {
        // Ensure that the AppSession has permissions to operate on the key.
        let entry = self.get_key_entry(key_num)?;

        if !entry.allow_encrypt_decrypt() {
            tracing::error!(error = ?ManticoreError::InvalidPermissions, "AES GCM: Key does not allow AES-GCM encrypt/decrypt");
            Err(ManticoreError::InvalidPermissions)?
        }

        if entry.kind() != Kind::AesBulk256 {
            tracing::error!(error = ?ManticoreError::AesInvalidKeyType, "AES GCM: Key type is not AES Bulk");
            Err(ManticoreError::AesInvalidKeyType)?
        }

        match (entry.key(), entry.kind()) {
            (Key::Aes(key), Kind::AesBulk256) => {
                if mode == AesMode::Encrypt {
                    let result = key.aes_gcm_encrypt_mb(
                        &source_buffers,
                        Some(iv),
                        aad,
                        destination_buffers,
                    )?;

                    Ok(result)
                } else {
                    let result = key.aes_gcm_decrypt_mb(
                        &source_buffers,
                        Some(iv),
                        aad,
                        tag,
                        destination_buffers,
                    )?;

                    Ok(result)
                }
            }

            _ => {
                tracing::error!(error = ?ManticoreError::AesInvalidKeyType, key_num, "AES GCM: Key type is not AES Bulk");
                Err(ManticoreError::AesInvalidKeyType)
            }
        }
    }

    fn fp_aes_xts_encrypt_decrypt(
        &self,
        mode: AesMode,
        key1: u16,
        key2: u16,
        tweak: [u8; 16usize],
        dul: usize,
        source_buffers: Vec<Vec<u8>>,
        destination_buffers: &mut [Vec<u8>],
    ) -> Result<FPAesXtsEncryptDecryptResult, ManticoreError> {
        // AES XTS takes 2 keys. Both must be Bulk256 and
        // must be configured for encryption and decryption
        let key1_entry = self.get_key_entry(key1)?;
        let key2_entry = self.get_key_entry(key2)?;

        // Perform error checking on both keys
        if !key1_entry.allow_encrypt_decrypt() {
            tracing::error!(error = ?ManticoreError::InvalidPermissions, "Key1 does not allow AES-GCM encrypt/decrypt");
            Err(ManticoreError::InvalidPermissions)?
        }

        if key1_entry.kind() != Kind::AesBulk256 {
            tracing::error!(error = ?ManticoreError::AesInvalidKeyType, "Key1 type is not AES Bulk");
            Err(ManticoreError::AesInvalidKeyType)?
        }

        if !key2_entry.allow_encrypt_decrypt() {
            tracing::error!(error = ?ManticoreError::InvalidPermissions, "Key2 does not allow AES-GCM encrypt/decrypt");
            Err(ManticoreError::InvalidPermissions)?
        }

        if key2_entry.kind() != Kind::AesBulk256 {
            tracing::error!(error = ?ManticoreError::AesInvalidKeyType, "Key2 type is not AES Bulk");
            Err(ManticoreError::AesInvalidKeyType)?
        }

        if key1_entry.session_only() != key2_entry.session_only() {
            tracing::error!(error = ? ManticoreError::AesInvalidKeyType, "Key1 Session_Only {:?} != Key 2 Session_Only {:?}",key1_entry.session_only(), key2_entry.session_only());
            Err(ManticoreError::AesInvalidKeyType)?
        }

        match (key1_entry.key(), key2_entry.key()) {
            (Key::Aes(key1), Key::Aes(key2)) => {
                if mode == AesMode::Encrypt {
                    let result = key1.aes_xts_encrypt_mb(
                        key2,
                        dul,
                        tweak,
                        &source_buffers,
                        destination_buffers,
                    )?;

                    Ok(result)
                } else {
                    let result = key1.aes_xts_decrypt_mb(
                        key2,
                        dul,
                        tweak,
                        &source_buffers,
                        destination_buffers,
                    )?;

                    Ok(result)
                }
            }
            _ => {
                tracing::error!(error = ?ManticoreError::AesInvalidKeyType, key1, key2, "AES XTS: Keys are not AES keys");
                Err(ManticoreError::AesInvalidKeyType)
            }
        }
    }

    fn set_disabled(&mut self) {
        self.flags.set_disabled(true);
    }
}

struct AppSessionWeak {
    weak: Weak<RwLock<UserSessionInner>>,
}

impl AppSessionWeak {
    #[allow(unused)]
    fn new(weak: Weak<RwLock<UserSessionInner>>) -> Self {
        Self { weak }
    }

    #[allow(unused)]
    fn upgrade(&self) -> Option<UserSession> {
        self.weak.upgrade().map(UserSession::with_inner)
    }
}

/// RSA Operation type, used for key permission checks.
pub enum RsaOpType {
    /// RSA Decrypt operation.
    Decrypt,

    /// RSA Sign operation.
    Sign,
}

#[cfg(test)]
mod tests {

    use std::thread;

    use test_with_tracing::test;

    use super::*;
    use crate::function::Function;
    use crate::vault::tests::*;
    use crate::vault::DEFAULT_VAULT_ID;

    pub(crate) const TEST_CRED_ID: [u8; 16] = [
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b,
    ];

    pub(crate) const TEST_CRED_PIN: [u8; 16] = [
        0x09, 0x90, 0xa8, 0x31, 0x06, 0x66, 0xc0, 0xe4, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0xe4,
        0x20,
    ];

    impl UserSession {
        /// Generate an [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) key-pair.
        ///
        /// This may use OpenSSL's [rsa_generate_key](https://www.openssl.org/docs/man1.1.1/man3/RSA_generate_key.html) under the hood.
        ///
        /// # Arguments
        /// * `bits` - The number of bits to be used for the key. Can be one of `[2048, 3072, 4096]`.
        /// * `session_only` - Whether the generated key is session only.
        /// * `flags` - The [EntryFlags] to be used for the key.
        /// * `key_tag` - The tag of the key.
        ///
        ///
        /// # Returns
        /// * [GenerateResponse] upon success.
        ///
        /// # Errors
        /// * [ManticoreError::SessionNotFound] if the session has been closed.
        /// * [ManticoreError::AppNotFound] if the app of the current session has been removed.
        /// * [ManticoreError::NotEnoughSpace] if there is not enough space to store generated keys.
        /// * [ManticoreError::VaultNotFound] if the vault has been deleted.
        /// * [ManticoreError::RsaInvalidKeyLength] if an invalid number of `bits` has been specified.
        /// * [ManticoreError::RsaGenerateError] if keys could not be generated.
        /// * [ManticoreError::RsaToDerError] if the public key could not serialized.
        ///
        /// # Behavior
        /// * The generated keys are stored in the vault as requested.
        /// * Keys marked as session_only can only be accessed by the [AppSession] that generated them. Such keys are deleted when the session is closed.
        /// * Keys marked not marked as session_only can be accessed by other [AppSession] sessions operating on the same app and vault.
        /// * The returned key numbers are used to refer to the keys in cryptographic operations.
        ///
        #[instrument(skip_all, fields(sess_id = self.id(), key_tag))]
        pub(crate) fn rsa_generate_key(
            &self,
            bits: u16,
            session_only: bool,
            flags: EntryFlags,
            key_tag: Option<u16>,
        ) -> Result<GenerateResponse, ManticoreError> {
            self.inner
                .read()
                .rsa_generate_key(bits, session_only, flags, key_tag)
        }
    }

    impl UserSessionInner {
        fn rsa_generate_key(
            &self,
            bits: u16,
            session_only: bool,
            flags: EntryFlags,
            key_tag: Option<u16>,
        ) -> Result<GenerateResponse, ManticoreError> {
            tracing::trace!(bits, key_tag, "rsa_generate_key");
            if session_only && key_tag.is_some() {
                tracing::error!(error = ?ManticoreError::InvalidArgument, "Session_only keys cannot have a tag");
                Err(ManticoreError::InvalidArgument)?
            }

            let sess_id_or_key_tag = if session_only {
                self.id
            } else {
                key_tag.unwrap_or(0)
            };

            Self::rsa_generate_and_store_key(
                self.get_vault()?,
                self.app_id,
                bits,
                session_only,
                sess_id_or_key_tag,
                flags,
            )
        }

        #[instrument(skip_all, fields(app_id = ?app_id, vault_id = ?vault.id()))]
        fn rsa_generate_and_store_key(
            vault: Vault,
            app_id: Uuid,
            bits: u16,
            session_only: bool,
            sess_id_or_key_tag: u16,
            flags: EntryFlags,
        ) -> Result<GenerateResponse, ManticoreError> {
            tracing::trace!(
                vault_id = ?vault.id(),
                ?app_id,
                bits,
                session_only,
                sess_id_or_key_tag,
                ?flags,
                "rsa_generate_and_store_key"
            );
            let kind_private = match bits {
                2048 => Kind::Rsa2kPrivate,
                3072 => Kind::Rsa3kPrivate,
                4096 => Kind::Rsa4kPrivate,
                _ => Err(ManticoreError::RsaInvalidKeyLength)?,
            };

            let (rsa_private_key, rsa_public_key) = generate_rsa(bits as u32)?;
            let rsa_public_key_der = rsa_public_key.to_der()?;

            // Mark the keys as generated.
            let mut entry_flags = flags;
            entry_flags.set_generated(true);

            if session_only {
                entry_flags.set_session_only(true);
            }
            tracing::debug!(entry_flags = ?entry_flags);

            let private_key_num = vault.add_key(
                app_id,
                kind_private,
                Key::RsaPrivate(rsa_private_key),
                entry_flags,
                sess_id_or_key_tag,
            )?;
            tracing::debug!(private_key_num, "Done adding private key");

            Ok((private_key_num, rsa_public_key_der))
        }
    }

    // Helper to perform RSA encrypt operation using OpenSSL.
    fn rsa_encrypt_local_openssl(
        pub_key: &[u8],
        x: &[u8],
        padding: RsaCryptoPadding,
        hash_algorithm: Option<HashAlgorithm>,
    ) -> Result<Vec<u8>, ManticoreError> {
        let pkey = RsaPublicKey::from_der(pub_key, None)?;
        pkey.encrypt(&x[..x.len()], padding, hash_algorithm)
    }

    fn create_function(table_count: usize) -> Function {
        let result = Function::new(table_count);
        assert!(result.is_ok());

        result.unwrap()
    }

    // Create Function, open an Vault Manager Session, and change its credentials
    fn common_setup(num_tables: usize) -> Function {
        let function = create_function(num_tables);
        let result = function.get_function_state().get_vault(DEFAULT_VAULT_ID);
        assert!(result.is_ok());
        let vault = result.unwrap();
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        function
    }

    #[test]
    fn app_session_flags_coverage() {
        // Call methods to ensure 100% coverage.
        let mut flags = AppSessionFlags::default();
        flags.set_reserved(0);
        assert_eq!(flags.reserved(), 0);
    }

    #[test]
    fn test_app_session_close_session() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        drop(app_session);

        // Close the session.
        assert!(function.close_user_session(session_id).is_ok());

        // Check that the session has been removed.
        assert!(vault.get_key_entry(session_id).is_err());
    }

    #[test]
    fn test_app_session_close_session_already_closed() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();
        drop(app_session);

        // Close the session.
        assert!(function.close_user_session(session_id).is_ok());

        // Check that the session has been removed.
        let same_app_session = function.get_user_session(session_id, true);
        assert!(same_app_session.is_err());
    }

    #[test]
    fn test_app_session_close_session_multiple_sessions() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id1, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session1 = function.get_user_session(session_id1, false).unwrap();

        let (session_id2, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session2 = function.get_user_session(session_id2, false).unwrap();

        drop(app_session1);

        // Close the first session.
        assert!(function.close_user_session(session_id1).is_ok());

        // Check that the session has been removed.
        assert!(function.get_user_session(session_id1, false).is_err());

        // The second session must exist.
        assert!(function.get_user_session(session_id2, false).is_ok());

        drop(app_session2);

        // Close the second session.
        assert!(function.close_user_session(session_id2).is_ok());

        // Check that the session has been removed.
        assert!(function.get_user_session(session_id2, false).is_err());
    }

    #[test]
    fn test_app_session_close_session_id_reused() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        drop(app_session);

        // Close the session and recreate another app session that has the same id.
        assert!(function.close_user_session(session_id).is_ok());

        // Open and close enough sessions so that the id is reused.
        let mut another_app_session_with_same_id = None;
        for _i in 0..3 {
            let (another_session_id, _) =
                helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();

            if another_session_id == session_id {
                another_app_session_with_same_id = Some(another_session_id);
                break;
            }
        }

        assert!(another_app_session_with_same_id.is_some());

        // Ensure that a session exists.
        // Check that session exists.
        assert!(function.get_user_session(session_id, true).is_ok());

        // It is possible to close the new session that has the same id.
        assert!(function.close_user_session(session_id).is_ok());

        // Check that the session has been removed.
        assert!(function.close_user_session(session_id).is_err());
    }

    #[test]
    fn test_app_session_close_persistent_session() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        // Create some app keys.
        let (key_num, _) = app_session
            .ecc_generate_key(EccCurve::P384, EntryFlags::new(), None)
            .expect("ecc_generate_key failed");

        // Check key_num exists
        let function_state = function.get_function_state();

        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();
        assert!(vault.get_key_entry(key_num).is_ok());

        let session_id = app_session.id();
        drop(app_session);

        // Close the session.
        assert!(function.close_user_session(session_id).is_ok());

        // Check key_num still exists.
        assert!(vault.get_key_entry(key_num).is_ok());
    }

    #[test]
    fn test_app_session_close_session_session_only_keys() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        // Create some session_only keys.
        let (key_num, _) = app_session
            .ecc_generate_key(
                EccCurve::P384,
                EntryFlags::new().with_session_only(true),
                None,
            )
            .expect("ecc_generate_key failed");

        // Check key_num exists
        let function_state = function.get_function_state();

        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();
        assert!(vault.get_key_entry(key_num).is_ok());

        drop(app_session);

        // Close the session.
        assert!(function.close_user_session(session_id).is_ok());

        // Check key_num is deleted.
        assert!(vault.get_key_entry(key_num).is_err());
    }

    #[test]
    fn test_app_session_close_session_with_key_in_use_session_only_keys() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        // Create some session_only keys.
        let (key_num, _) = app_session
            .ecc_generate_key(
                EccCurve::P384,
                EntryFlags::new().with_session_only(true),
                None,
            )
            .expect("ecc_generate_key failed");

        // Hold ref to Entry
        let function_state = function.get_function_state();

        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();
        let entry = vault.get_key_entry(key_num).unwrap();

        // Close App session should fail
        drop(app_session);

        // Close the session.
        let result = function.close_user_session(session_id);
        assert!(result.is_ok());

        // Should error because Entry is disabled
        assert_eq!(
            vault.get_key_entry(key_num).unwrap_err(),
            ManticoreError::InvalidKeyIndex
        );

        // Release Entry and close again
        drop(entry);

        let result = function.close_user_session(session_id);
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_open_close_app_session_persistent_in_use() {
        let function = common_setup(2);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        // Hold another reference to the session
        let app_session2 = app_session.clone();

        // Attempt to close the session.
        drop(app_session);

        // Close the session.
        assert!(function.close_user_session(session_id).is_ok());

        // Drop the second reference.
        drop(app_session2);

        // Now close the session.
        let result = function.close_user_session(session_id);
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_open_close_app_session_in_use_session_only_keys() {
        let function = common_setup(2);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        // Hold another reference to the session
        let app_session2 = app_session.clone();

        // Attempt to close the session.
        drop(app_session);

        assert!(function.close_user_session(session_id).is_ok());

        // Drop the second reference.
        drop(app_session2);

        // Now close the session.
        assert!(function.close_user_session(session_id).is_err());
    }

    #[test]
    fn test_persistent_app_session_rsa_generate_key() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        let der_lengths = [294, 422, 550];
        for (i, bits) in [2048, 3072, 4096].iter().enumerate() {
            let (private_key_num, public_key) = app_session
                .rsa_generate_key(*bits as u16, false, EntryFlags::new(), None)
                .expect("rsa_generate_key failed");
            assert_eq!(public_key.len(), der_lengths[i]);

            // Check the generated key has a App Session ID of None
            assert_eq!(
                vault.get_key_entry(private_key_num).unwrap().sess_id(),
                None
            );
        }
    }

    #[test]
    fn test_app_session_rsa_generate_key_session_only_keys() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        let der_lengths = [294, 422, 550];
        for (i, bits) in [2048, 3072, 4096].iter().enumerate() {
            let (private_key_num, public_key) = app_session
                .rsa_generate_key(*bits as u16, true, EntryFlags::new(), None)
                .expect("rsa_generate_key failed");
            assert_eq!(public_key.len(), der_lengths[i]);

            // Check the generated key has a App Session ID
            assert_eq!(
                vault.get_key_entry(private_key_num).unwrap().sess_id(),
                Some(app_session.id())
            );
        }
    }

    #[test]
    fn test_app_session_rsa_generate_key_errors() {
        let function = common_setup(1);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        // Generate key with invalid length.
        assert_eq!(
            app_session.rsa_generate_key(5, false, EntryFlags::new(), None),
            Err(ManticoreError::RsaInvalidKeyLength)
        );

        // Add and store 30 key to use all spaces
        let max_keys = 30;
        for _i in 0..max_keys {
            let result = app_session.rsa_generate_key(2048, false, EntryFlags::new(), None);
            assert!(result.is_ok());
        }

        // The next key won't have space
        assert_eq!(
            app_session.rsa_generate_key(2048, false, EntryFlags::new(), None),
            Err(ManticoreError::NotEnoughSpace)
        );

        // Remove one arbitrary key
        let key_id_to_remove = 21;
        assert_eq!(app_session.delete_key(key_id_to_remove), Ok(()));

        // Creating a new key, the key ID should be the one just deleted
        let (key_num, _) = app_session
            .rsa_generate_key(2048, false, EntryFlags::new(), None)
            .expect("rsa_generate_key shouldn't fail");
        assert_eq!(key_num, key_id_to_remove);
    }

    #[test]
    fn test_app_session_attest_key() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        let vault = function
            .get_function_state()
            .get_vault(DEFAULT_VAULT_ID)
            .expect("get vault failed");

        {
            let (ecc_private_key, _) = generate_ecc(EccCurve::P384).expect("generate_ecc failed");

            let entry_flags = EntryFlags::new().with_generated(true);

            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Ecc384Private,
                Key::EccPrivate(ecc_private_key),
                entry_flags,
                0,
            );
            assert!(result.is_ok());
            let key_num = result.unwrap();

            assert!(app_session.attest_key(key_num, &[0u8; 128]).is_ok());
        }

        {
            let (ecc_private_key, _) = generate_ecc(EccCurve::P384).expect("generate_ecc failed");

            let entry_flags = EntryFlags::new().with_generated(true);

            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Ecc384Private,
                Key::EccPrivate(ecc_private_key),
                entry_flags,
                0,
            );
            assert!(result.is_ok());
            let key_num = result.unwrap();

            assert!(app_session.attest_key(key_num, &[0u8; 128]).is_ok());
        }

        {
            let aes_key = AesKey::from_bytes(&[1u8; 16]).expect("import AES key failed");

            let entry_flags = EntryFlags::new().with_imported(true);

            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Aes128,
                Key::Aes(aes_key),
                entry_flags,
                0,
            );
            assert!(result.is_ok());
            let key_num = result.unwrap();

            assert_eq!(
                app_session.attest_key(key_num, &[0u8; 128]),
                Err(ManticoreError::InvalidKeyType)
            );
        }

        {
            let secret = SecretKey::from_bytes(&[1u8; 32]).expect("import secret failed");

            let entry_flags = EntryFlags::new().with_imported(true);

            let result = vault.add_key(
                Uuid::from_bytes(TEST_CRED_ID),
                Kind::Secret256,
                Key::Secret(secret),
                entry_flags,
                0,
            );
            assert!(result.is_ok());
            let key_num = result.unwrap();

            assert_eq!(
                app_session.attest_key(key_num, &[0u8; 128]),
                Err(ManticoreError::InvalidKeyType)
            );
        }
    }

    #[test]
    fn test_app_session_delete_key_basic() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        // Generate key
        let (private_key_num, _) = app_session
            .ecc_generate_key(EccCurve::P384, EntryFlags::new(), None)
            .expect("ecc_generate_key failed");
        assert!(app_session.delete_key(private_key_num).is_ok());
    }

    #[test]
    fn test_app_session_delete_key_app_keys() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Create 3 app sessions.
        // Admin session will try to delete keys added by client session.
        let (app_session_admin_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session_admin = function
            .get_user_session(app_session_admin_id, false)
            .unwrap();

        let (app_session_client_app_keys_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session_client_app_keys = function
            .get_user_session(app_session_client_app_keys_id, false)
            .unwrap();

        let (app_session_client_session_only_keys_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session_client_session_only_keys = function
            .get_user_session(app_session_client_session_only_keys_id, false)
            .unwrap();

        // Client adds some key.
        let (key_num_app_key, _) = app_session_client_app_keys
            .ecc_generate_key(EccCurve::P384, EntryFlags::new(), None)
            .expect("ecc_generate_key failed");
        let (key_num_session_only, _) = app_session_client_session_only_keys
            .ecc_generate_key(
                EccCurve::P384,
                EntryFlags::new().with_session_only(true),
                None,
            )
            .expect("ecc_generate_key failed");

        // Check key_num exists
        let function_state = function.get_function_state();

        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        {
            // We should be able to delete app key added by another session
            assert!(vault.get_key_entry(key_num_app_key).is_ok());
            assert!(app_session_admin.delete_key(key_num_app_key).is_ok());
            assert!(vault.get_key_entry(key_num_app_key).is_err());
        }

        {
            // We should fail to delete session_only key added by another session
            assert!(vault.get_key_entry(key_num_session_only).is_ok());
            assert!(app_session_admin.delete_key(key_num_session_only).is_err());
            assert!(vault.get_key_entry(key_num_session_only).is_ok());
        }
    }

    #[test]
    fn test_app_session_delete_key_session_only_keys() {
        // test session_only key is only able to be deleted from the same session.
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Create 2 app sessions.
        // Admin session will try to delete keys added by client session.
        let (app_session_admin_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session_admin = function
            .get_user_session(app_session_admin_id, false)
            .unwrap();

        let (app_session_client_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session_client = function
            .get_user_session(app_session_client_id, false)
            .unwrap();

        // Client adds some key.
        let (key_num, _) = app_session_client
            .ecc_generate_key(
                EccCurve::P384,
                EntryFlags::new().with_session_only(true),
                None,
            )
            .expect("ecc_generate_key failed");

        // Check key_num exists
        let function_state = function.get_function_state();

        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();
        assert!(vault.get_key_entry(key_num).is_ok());

        // Delete should fail
        assert!(app_session_admin.delete_key(key_num).is_err());

        // Key should exist
        assert!(vault.get_key_entry(key_num).is_ok());
    }

    #[test]
    fn test_delete_key_internal_keys() {
        // Test we cannot delete internal keys
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Create 2 app sessions, one for creating session_only keys, one for app keys.
        let (app_session_session_only_key_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session_session_only_key = function
            .get_user_session(app_session_session_only_key_id, false)
            .unwrap();

        let (app_session_app_keys_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session_app_keys = function
            .get_user_session(app_session_app_keys_id, false)
            .unwrap();

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Get the attestation key
        let attestation_key_num = function_state.get_attestation_key_num().unwrap();

        // Confirm we can't delete it.
        assert!(app_session_session_only_key
            .delete_key(attestation_key_num)
            .is_err());
        assert!(app_session_app_keys
            .delete_key(attestation_key_num)
            .is_err());

        // Key should exist
        assert!(vault.get_key_entry(attestation_key_num).is_ok());

        // Get the unwrapping key
        let unwrapping_key_num = function_state.get_unwrapping_key_num().unwrap();

        // Confirm we can't delete it.
        assert!(app_session_session_only_key
            .delete_key(unwrapping_key_num)
            .is_err());
        assert!(app_session_app_keys.delete_key(unwrapping_key_num).is_err());

        // Key should exist
        assert!(vault.get_key_entry(unwrapping_key_num).is_ok());
    }

    #[test]
    fn test_app_session_rsa_ops_basic() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        let bits = 2048;
        let flags = EntryFlags::new().with_allow_encrypt_decrypt(true);
        let (private_key_num, public_key) = app_session
            .rsa_generate_key(bits, false, flags, None)
            .expect("rsa_generate_key failed");
        let mut data = "Hello, World".as_bytes().to_vec();
        // Set length to be same as key length in bytes.
        let data_len = bits as usize / 8;
        data.resize(data_len, 5u8);

        // Encrypt data.
        let cipher_text = app_session
            .rsa_decrypt(private_key_num, &data, RsaCryptoPadding::None, None)
            .expect("rsa_private failed");
        assert_ne!(cipher_text, data);

        // Decrypt and make sure it matches original message.
        let plain_text =
            rsa_encrypt_local_openssl(&public_key, &cipher_text, RsaCryptoPadding::None, None)
                .expect("rsa_public failed");
        assert_eq!(plain_text, data);
    }

    #[test]
    fn test_app_session_rsa_ops_no_permission() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id1, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session1 = function.get_user_session(session_id1, false).unwrap();
        let (session_id2, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session2 = function.get_user_session(session_id2, false).unwrap();

        // Create a new session.
        let app_session = [app_session1, app_session2];

        // Generate credentials in first session.
        let bits = 2048;
        let flags = EntryFlags::new()
            .with_allow_encrypt_decrypt(true)
            .with_session_only(true);
        let (private_key_num, _) = app_session[0]
            .rsa_generate_key(bits, false, flags, None)
            .expect("rsa_generate_key failed");

        // Use key in second session.
        assert_eq!(
            app_session[1].rsa_decrypt(private_key_num, &[0; 256], RsaCryptoPadding::None, None),
            Err(ManticoreError::InvalidPermissions)
        );
    }

    #[test]
    fn test_app_session_rsa_ops_invalid_index() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        // Use invalid key index.
        assert_eq!(
            app_session.rsa_decrypt(100, &[0; 256], RsaCryptoPadding::None, None),
            Err(ManticoreError::InvalidKeyIndex)
        );
    }

    #[test]
    fn test_app_session_rsa_ops_mismatched_kind() {
        let key_tag = 0;
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        let vault = function
            .get_function_state()
            .get_vault(DEFAULT_VAULT_ID)
            .expect("get vault failed");

        // Generate keys, but use wrong kind to store them in the vault.
        // This scenario will be prevented by AppSession::rsa_generate_key,
        // but is coded here for code-coverage.
        let bits = 2048;
        let (rsa_private_key, rsa_public_key) =
            generate_rsa(bits as u32).expect("generate_rsa failed");

        let entry_flags = EntryFlags::new()
            .with_generated(true)
            .with_allow_encrypt_decrypt(true);

        let result = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            Kind::Rsa2kPublic,
            Key::RsaPrivate(rsa_private_key),
            entry_flags,
            key_tag,
        );
        assert!(result.is_ok());
        let key_num1 = result.unwrap();

        let result = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            Kind::Rsa2kPrivate,
            Key::RsaPublic(rsa_public_key),
            entry_flags,
            key_tag,
        );
        assert!(result.is_ok());
        let key_num2 = result.unwrap();

        // Check that no operations can be performed in the key.
        assert_eq!(
            app_session.rsa_decrypt(key_num1, &[0; 256], RsaCryptoPadding::None, None),
            Err(ManticoreError::RsaInvalidKeyType)
        );

        assert_eq!(
            app_session.rsa_decrypt(key_num2, &[0; 256], RsaCryptoPadding::None, None),
            Err(ManticoreError::RsaInvalidKeyType)
        );
    }

    #[test]
    fn test_app_session_rsa_ops_invalid_permissions() {
        let key_tag = 0;
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        let vault = function
            .get_function_state()
            .get_vault(DEFAULT_VAULT_ID)
            .expect("get vault failed");

        let bits = 2048;
        let (rsa_private_key, _) = generate_rsa(bits as u32).expect("generate_rsa failed");
        let result = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            Kind::Rsa2kPrivate,
            Key::RsaPrivate(rsa_private_key),
            EntryFlags::new(),
            key_tag,
        );
        assert!(result.is_ok());
        let key_num = result.unwrap();

        // Check that no operations can be performed in the key.
        assert_eq!(
            app_session.rsa_decrypt(key_num, &[0; 256], RsaCryptoPadding::None, None),
            Err(ManticoreError::InvalidPermissions)
        );
    }

    #[test]
    fn test_app_session_ecc_ops_invalid_permissions() {
        let key_tag = 0;
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        let vault = function
            .get_function_state()
            .get_vault(DEFAULT_VAULT_ID)
            .expect("get vault failed");

        let (ecc_private_key, _) = generate_ecc(EccCurve::P384).expect("generate_ecc failed");
        let result = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            Kind::Ecc384Private,
            Key::EccPrivate(ecc_private_key),
            EntryFlags::new(),
            key_tag,
        );
        assert!(result.is_ok());
        let key_num = result.unwrap();

        // Check that no operations can be performed in the key.
        assert_eq!(
            app_session.ecc_sign(key_num, &[]),
            Err(ManticoreError::InvalidPermissions)
        );
    }

    #[test]
    fn test_app_session_aes_ops_invalid_permissions() {
        let key_tag = 0;
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        let vault = function
            .get_function_state()
            .get_vault(DEFAULT_VAULT_ID)
            .expect("get vault failed");

        let aes_key = AesKey::from_bytes(&[1u8; 16]).expect("import AES key failed");

        let result = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            Kind::Aes128,
            Key::Aes(aes_key),
            EntryFlags::new(),
            key_tag,
        );
        assert!(result.is_ok());
        let key_num = result.unwrap();

        // Check that no operations can be performed in the key.
        assert_eq!(
            app_session.aes_encrypt_decrypt(key_num, AesMode::Encrypt, &[], &[]),
            Err(ManticoreError::InvalidPermissions)
        );
    }

    #[test]
    fn test_app_session_secret_ops_invalid_permissions() {
        let key_tag = 0;
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        let vault = function
            .get_function_state()
            .get_vault(DEFAULT_VAULT_ID)
            .expect("get vault failed");

        let secret1_raw = [1u8; 32];
        let secret2_raw = [2u8; 32];
        let secret1 = SecretKey::from_bytes(&secret1_raw).expect("import Secret failed");
        let result = vault.add_key(
            Uuid::from_bytes(TEST_CRED_ID),
            Kind::Secret256,
            Key::Secret(secret1),
            EntryFlags::new(),
            key_tag,
        );
        assert!(result.is_ok());
        let secret_num1 = result.unwrap();

        // Check that no operations can be performed in the key.
        assert_eq!(
            app_session.ecdh_key_exchange(
                secret_num1,
                &secret2_raw,
                Kind::Secret256,
                EntryFlags::new(),
                None
            ),
            Err(ManticoreError::InvalidPermissions)
        );

        assert_eq!(
            app_session.hkdf_derive(
                secret_num1,
                HashAlgorithm::Sha256,
                None,
                None,
                Kind::Secret256,
                EntryFlags::new(),
                None
            ),
            Err(ManticoreError::InternalError)
        );

        assert_eq!(
            app_session.kbkdf_counter_hmac_derive(
                secret_num1,
                HashAlgorithm::Sha256,
                None,
                None,
                Kind::Secret256,
                EntryFlags::new(),
                None
            ),
            Err(ManticoreError::InternalError)
        );
    }

    #[test]
    fn test_app_close_session_thread_stress() {
        fn app_close_session_stress_thread(_thread_id: u8, _app_id: u8, function: Function) {
            let api_rev = function.get_api_rev_range().max;
            let function_state = function.get_function_state();
            let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

            for _ in 0..1000 {
                // Open an app session.
                let result = helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev);
                if let Ok((session_id, _)) = result {
                    let session_id = {
                        let result = function.get_user_session(session_id, false);
                        assert!(result.is_ok());
                        session_id
                    };

                    // Close the session.
                    assert!(function.close_user_session(session_id).is_ok());
                }
            }
        }

        let thread_count = 7;

        let function = common_setup(4);

        let mut threads = Vec::new();
        for i in 0..thread_count {
            let thread_id = i;
            let thread_app_id = i / 2;
            let thread_function = function.clone();

            let thread = thread::spawn(move || {
                app_close_session_stress_thread(thread_id, thread_app_id, thread_function);
            });

            threads.push(thread);
        }

        for thread in threads {
            thread.join().unwrap();
        }
    }

    // This test helps achieve 100% test coverage
    #[test]
    fn test_ensure_coverage() {
        let function = common_setup(2);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        println!("app_session {:?}", app_session);
        let app_session_weak = app_session.as_weak();
        let app_session_weak_upgrade = app_session_weak.upgrade();
        println!("AppSessionWeak {:?}", app_session_weak_upgrade.unwrap());
    }

    #[test]
    fn test_app_session_import_key() {
        let function = common_setup(64);
        let api_rev = function.get_api_rev_range().max;

        let function_state = function.get_function_state();
        let vault = function_state.get_vault(DEFAULT_VAULT_ID).unwrap();

        // Open an app session.
        let (session_id, _) =
            helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev).unwrap();
        let app_session = function.get_user_session(session_id, false).unwrap();

        // import AES key
        let result = app_session.import_key(
            &[1u8; 16],
            KeyClass::Aes,
            EntryFlags::new().with_imported(true),
            None,
        );
        assert!(result.is_ok());

        // import RSA key
        let result = generate_rsa(2048);
        assert!(result.is_ok());
        let (rsa_private, _rsa_public) = result.unwrap();

        let result = rsa_private.to_der();
        assert!(result.is_ok());
        let rsa_private_der = result.unwrap();

        let result = app_session.import_key(
            &rsa_private_der,
            KeyClass::RsaPrivate,
            EntryFlags::new().with_imported(true),
            None,
        );
        assert!(result.is_ok());

        // TODO: enable after removing the dependency from rsa_unwrap tests.
        //let result = rsa_public.to_der();
        //assert!(result.is_ok());
        //let rsa_public_der = result.unwrap();

        //let result = app_session.import_key(
        //&rsa_public_der,
        //Kind::Rsa2kPublic,
        //EntryFlags::new().with_imported(true),
        //None,
        //);
        //assert_eq!(result, Err(ManticoreError::InvalidArgument));

        // import ECC key
        let result = generate_ecc(EccCurve::P384);
        assert!(result.is_ok());
        let (ecc_private, _ecc_public) = result.unwrap();

        let result = ecc_private.to_der();
        assert!(result.is_ok());
        let ecc_private_der = result.unwrap();

        let result = app_session.import_key(
            &ecc_private_der,
            KeyClass::EccPrivate,
            EntryFlags::new().with_imported(true),
            None,
        );
        assert!(result.is_ok());

        // TODO: enable after removing the dependency from ecc_sign_verify tests.
        //let result = ecc_public.to_der();
        //assert!(result.is_ok());
        //let ecc_public_der = result.unwrap();

        //let result = app_session.import_key(
        //&ecc_public_der,
        //Kind::Ecc384Public,
        //EntryFlags::new().with_imported(true),
        //None,
        //);
        //assert_eq!(result, Err(ManticoreError::InvalidArgument));
    }
}
