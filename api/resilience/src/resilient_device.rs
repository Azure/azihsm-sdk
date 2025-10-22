// Copyright (C) Microsoft Corporation. All rights reserved.

use std::collections::HashMap;
use std::fmt;
use std::process;
use std::sync::Arc;

use mcr_api::*;
use parking_lot::RwLock;
use tracing::instrument;
use uuid::Uuid;

use crate::memory_manager::MemoryManager;

// Hard-coded file path to store information on disk
// TODO 34728454: Need to store in path accessible to all process
#[allow(dead_code)]
pub(crate) const FILE_PATH: &str = "tmpfile";

// Hard-coded BK3 of 48 bytes for virtual device testing
#[allow(dead_code)]
pub const VIRTUAL_BK3: [u8; 48] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
];

// Fixed UUID for unwrapping key.
// caa103da-7c33-447a-9e6c-363eaf32168a
const UNWRAPPING_KEY_ID: KeyId = KeyId {
    uuid: Uuid::from_bytes([
        0xca, 0xa1, 0x03, 0xda, 0x7c, 0x33, 0x44, 0x7a, 0x9e, 0x6c, 0x36, 0x3e, 0xaf, 0x32, 0x16,
        0x8a,
    ]),
};

#[derive(Debug)]
pub(crate) struct ResilientDevice {
    inner: Arc<RwLock<ResilientDeviceInner>>,
}

impl ResilientDevice {
    pub(crate) fn open_device(device_path: &str) -> HsmResult<ResilientDevice> {
        let inner = ResilientDeviceInner::open_device(device_path)?;

        Ok(ResilientDevice {
            inner: Arc::new(RwLock::new(inner)),
        })
    }

    pub(crate) fn get_api_revision_range(&self) -> HsmApiRevisionRange {
        self.inner.read().get_api_revision_range()
    }

    pub(crate) fn get_device_info(&self) -> HsmDeviceInfo {
        self.inner.read().get_device_info()
    }

    pub(crate) fn open_session(
        &self,
        api_rev: HsmApiRevision,
        credentials: HsmAppCredentials,
    ) -> HsmResult<ResilientSession> {
        self.inner.write().open_session(api_rev, credentials)?;
        Ok(ResilientSession::new(self.inner.clone()))
    }
}

#[derive(Debug)]
pub(crate) struct ResilientSession {
    inner: Arc<RwLock<ResilientDeviceInner>>,
}

impl ResilientSession {
    /// Open Session
    fn new(device: Arc<RwLock<ResilientDeviceInner>>) -> Self {
        ResilientSession { inner: device }
    }

    /// Close Session
    /// Always takes write lock
    pub(crate) fn close_session(&self) -> HsmResult<()> {
        self.inner.write().close_session()
    }

    /// Create Key Operation
    /// Always takes write lock
    pub(crate) fn create_key_op(
        &self,
        key_name: Option<&[u8]>,
        fn_create_key_op: &dyn Fn(&HsmSession, Option<u16>) -> HsmResult<HsmKeyHandle>,
    ) -> HsmResult<ResilientKey> {
        if key_name.is_some() {
            Err(HsmError::NamedKeysNotSupported)?
        }

        let key_id = self.inner.write().run_create_key_op(fn_create_key_op)?;
        Ok(ResilientKey {
            key_id,
            inner: self.inner.clone(),
        })
    }

    /// Create Unwrapping Key Operation with caching
    /// Always takes write lock
    pub(crate) fn get_unwrapping_key(&self) -> HsmResult<ResilientKey> {
        let key_id = self.inner.write().run_get_unwrapping_key()?;
        Ok(ResilientKey {
            key_id,
            inner: self.inner.clone(),
        })
    }

    /// Create Key Operation that uses an existing key
    /// Always takes write lock
    pub(crate) fn create_key_key_op(
        &self,
        key: &ResilientKey,
        key_name: Option<&[u8]>,
        fn_create_key_op: &dyn Fn(
            &HsmSession,
            &HsmKeyHandle,
            Option<u16>,
        ) -> HsmResult<HsmKeyHandle>,
    ) -> HsmResult<ResilientKey> {
        if key_name.is_some() {
            Err(HsmError::NamedKeysNotSupported)?
        }

        let key_id = self
            .inner
            .write()
            .run_create_key_key_op(&key.key_id, fn_create_key_op)?;
        Ok(ResilientKey {
            key_id,
            inner: self.inner.clone(),
        })
    }

    /// Delete Key Operation
    /// Always takes write lock
    pub(crate) fn delete_key_op(&self, key: &ResilientKey) -> HsmResult<()> {
        self.inner.write().run_delete_key_op(&key.key_id)
    }

    /// Try Key Operation with read lock,
    /// then take write lock if necessary
    pub(crate) fn key_op<T>(
        &self,
        key: &ResilientKey,
        fn_key_op: &dyn Fn(&HsmSession, &HsmKeyHandle) -> HsmResult<T>,
    ) -> HsmResult<T> {
        let result = self.inner.read().try_key_op(&key.key_id, fn_key_op);

        if retry_on_in_session_op(&result) {
            // Try again, with write lock
            self.inner.write().run_key_op(&key.key_id, fn_key_op)
        } else {
            result
        }
    }

    /// Try Two Key Operation with read lock,
    /// then take write lock if necessary
    pub(crate) fn two_key_op<T>(
        &self,
        key1: &ResilientKey,
        key2: &ResilientKey,
        fn_key_op: &dyn Fn(&HsmSession, &HsmKeyHandle, &HsmKeyHandle) -> HsmResult<T>,
    ) -> HsmResult<T> {
        let result = self
            .inner
            .read()
            .try_two_key_op(&key1.key_id, &key2.key_id, fn_key_op);
        if retry_on_in_session_op(&result) {
            // Try again, with write lock
            self.inner
                .write()
                .run_two_key_op(&key1.key_id, &key2.key_id, fn_key_op)
        } else {
            result
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ResilientKey {
    key_id: KeyId,
    inner: Arc<RwLock<ResilientDeviceInner>>,
}

impl ResilientKey {
    // Get key property
    // This always takes a read lock
    pub(crate) fn get_key_property<T>(&self, fn_key_op: &dyn Fn(&HsmKeyHandle) -> T) -> T {
        self.inner.read().get_key_property(&self.key_id, fn_key_op)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct KeyId {
    // ID
    uuid: Uuid,
}

// Parameters to determine resiliency behavior
const MAX_RETRIES: u32 = 3;

// Returns true if the HsmResult could signify a resilience event
// during a device operation (e.g. open_session).
// Returns false if HsmResult is Ok(()), or an unexpected HsmError.
fn retry_on_open_session_op<T>(result: &HsmResult<T>) -> bool {
    // TODO: Update with correct error based on out-of-session error handling. TASK 34575020
    match result {
        Ok(_) => false,
        Err(err @ HsmError::CredentialsNotEstablished)
        | Err(err @ HsmError::NonceMismatch)
        | Err(err @ HsmError::PartitionNotProvisioned) => {
            tracing::info!(
                "Error {:?} on open_session operation indicates possible resiliency event occured. ProcessId={}",
                err,
                process::id()
            );
            true
        }
        _ => {
            tracing::debug!(
                "Error {:?} on open_session operation doesn't indicate resiliency event. Ignoring. ProcessId={}",
                result.as_ref().err(),
                process::id()
            );
            false
        }
    }
}

// Returns true if the HsmResult could signify a resilience event
// during an in-session operation (e.g. ecc_generate, or ecc_sign).
// Returns false if HsmResult is Ok(()), or an unexpected HsmError.
fn retry_on_in_session_op<T>(result: &HsmResult<T>) -> bool {
    match result {
        Ok(_) => false,
        // Errors that indicate possible resiliency event
        Err(err @ HsmError::SessionNeedsRenegotiation)
        | Err(err @ HsmError::AttestReportSignatureMismatch) => {
            tracing::info!(
                ?err,
                "Error on in-session operation indicates possible resiliency event occured. ProcessId={}",
                process::id()
            );
            true
        }
        // All other error
        Err(err) => {
            tracing::debug!(
                ?err,
                "Error on in-session operation doesn't indicate resiliency event. Ignoring. ProcessId={}",
                process::id()
            );
            false
        }
    }
}

struct CachedEstablishCredentials {
    credentials: HsmAppCredentials,
    api_rev: HsmApiRevision,
}

struct ResilientDeviceInner {
    device: HsmDevice,

    memory_manager: MemoryManager,

    credentials: Option<CachedEstablishCredentials>,
    session: Option<HsmSession>,
    session_keys: HashMap<KeyId, HsmKeyHandle>,
    unwrapping_key: Option<HsmKeyHandle>,
}

// We need to implement Debug manually to skip Credentials information.
// Unencrypted Credentials should not be included in tracing.
// Source: https://stackoverflow.com/questions/78870773/skip-struct-field-when-deriving-debug
impl fmt::Debug for ResilientDeviceInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        #[derive(Debug)]
        #[allow(unused)]
        struct ResilientDeviceInner<'a> {
            device: &'a HsmDevice,
            memory_manager: &'a MemoryManager,
            session: &'a Option<HsmSession>,
            session_keys: &'a HashMap<KeyId, HsmKeyHandle>,
            resilient_unwrapping_key: &'a Option<HsmKeyHandle>,
        }

        let Self {
            device,
            memory_manager,
            credentials: _,
            session,
            session_keys,
            unwrapping_key: resilient_unwrapping_key,
        } = self;

        fmt::Debug::fmt(
            &ResilientDeviceInner {
                device,
                memory_manager,
                session,
                session_keys,
                resilient_unwrapping_key,
            },
            f,
        )
    }
}

impl ResilientDeviceInner {
    fn open_device(device_path: &str) -> HsmResult<ResilientDeviceInner> {
        tracing::info!(
            "ResilientDeviceInner::open_device ProcessId={}",
            process::id()
        );

        let device = HsmDevice::open(device_path)?;

        Ok(ResilientDeviceInner {
            device,
            memory_manager: MemoryManager::new(FILE_PATH),
            credentials: None,
            session: None,
            session_keys: HashMap::new(),
            unwrapping_key: None,
        })
    }

    /// Generic retry helper that handles partition restore failures
    fn retry_with_restore<T, F>(
        &mut self,
        mut operation: F,
        retry_predicate: fn(&HsmResult<T>) -> bool,
    ) -> HsmResult<T>
    where
        F: FnMut(&mut Self) -> HsmResult<T>,
    {
        let mut op_result = operation(self);
        let mut iter = 0;

        while retry_predicate(&op_result) && iter < MAX_RETRIES {
            let restore_result = self.restore_partition();
            tracing::info!(
                "Restore_partition attempt#{}: result={:?}, ProcessId={}",
                iter,
                restore_result,
                process::id()
            );

            match restore_result {
                Err(HsmError::RestorePartitionFailed) => {
                    // Skip executing the operation, continue retry on partition restore failure
                }
                Err(err) => {
                    tracing::error!(
                        "restore_partition failed with err={:?}, iter={}. Giving up on recovering. ProcessId={}",
                        err,
                        iter,
                        process::id()
                    );
                    return Err(err);
                }
                Ok(()) => {
                    op_result = operation(self);
                }
            }
            iter += 1;
        }

        if let Err(err) = op_result.as_ref() {
            tracing::error!(
                "operation failed with err={:?}, iter={}. Giving up on recovering. ProcessId={}",
                err,
                iter,
                process::id()
            );
        }

        op_result
    }

    fn get_api_revision_range(&self) -> HsmApiRevisionRange {
        self.device.get_api_revision_range()
    }

    fn get_device_info(&self) -> HsmDeviceInfo {
        self.device.get_device_info()
    }

    /// Try to get sealed BK3 from device, then unseal with TPM to get masked BK3
    fn try_get_masked_bk3(&self, api_rev: HsmApiRevision) -> HsmResult<Vec<u8>> {
        let sealed_bk3 = self.device.get_sealed_bk3(api_rev);

        match sealed_bk3 {
            Err(HsmError::SealedBk3NotPresent) => {
                //TODO: for HW device: Need to get sealed BK3 from UEFI and unseal it with TPM
                // For now we just do init_bk3 and use same value for sealed and masked bk3
                tracing::info!("No sealed BK3 found on device, setting to test value virtual device. ProcessId={}", process::id());
                let masked_bk3 = self.device.init_bk3(api_rev, &VIRTUAL_BK3)?;
                self.device.set_sealed_bk3(api_rev, &masked_bk3)?;
                Ok(masked_bk3)
            }
            Err(e) => Err(e),
            Ok(sealed_bk3_value) => Ok(self.try_unseal_bk3(api_rev, sealed_bk3_value)?),
        }
    }

    /// Try to get masked BK3 from sealed BK3.
    fn try_unseal_bk3(&self, _api_rev: HsmApiRevision, sealed_bk3: Vec<u8>) -> HsmResult<Vec<u8>> {
        // TODO for HW device: Need to unseal BK3 with TPM to get masked BK3
        // For now we just use sealed_bk3 for testing.
        Ok(sealed_bk3)
    }

    fn try_establish_credential_no_lock(
        &mut self,
        api_rev: HsmApiRevision,
        credentials: HsmAppCredentials,
        write_locked_disk: &mut crate::memory_manager::FileLockGuard,
    ) -> HsmResult<()> {
        tracing::debug!(
            "try_establish_credential_no_lock: Trying to get BK3 from device. ProcessId={}",
            process::id()
        );

        let masked_bk3 = self.try_get_masked_bk3(api_rev)?;

        tracing::debug!(
            "try_establish_credential_no_lock: Getting masked unwrapping key and bmk from disk, then establishing credentials. ProcessId={}",
            process::id()
        );
        let masked_unwrapping_key = write_locked_disk.get_masked_unwrapping_key()?;
        let bmk = write_locked_disk.get_backup_masking_key()?;
        let new_bmk = self.device.establish_credential(
            api_rev,
            credentials,
            masked_bk3,
            bmk,
            masked_unwrapping_key,
        )?;
        write_locked_disk.set_backup_masking_key(&new_bmk)?;

        tracing::debug!(
            "try_establish_credential_no_lock: Saving credential information. ProcessId={}",
            process::id()
        );
        self.credentials = Some(CachedEstablishCredentials {
            credentials,
            api_rev,
        });
        Ok(())
    }

    fn try_open_session(
        &mut self,
        api_rev: HsmApiRevision,
        credentials: HsmAppCredentials,
    ) -> HsmResult<()> {
        // Get write lock to protect against synchronization issues with open session.
        let mut write_locked_disk = self.memory_manager.write_lock()?;

        let hsm_session_result = self.device.open_session(api_rev, credentials);

        // If open_session fails with CredentialsNotEstablished, try to establish credentials first
        let hsm_session = match hsm_session_result {
            Err(err @ HsmError::CredentialsNotEstablished)
            | Err(err @ HsmError::PartitionNotProvisioned) => {
                tracing::info!(
                    "try_open_session: Error {:?}, attempting to establish credentials from disk cache. ProcessId={}",
                    err,
                    process::id()
                );

                match self.try_establish_credential_no_lock(
                    api_rev,
                    credentials,
                    &mut write_locked_disk,
                ) {
                    Ok(()) => {
                        tracing::info!(
                            "try_open_session: Successfully established credentials from disk cache. ProcessId={}",
                            process::id()
                        );
                    }
                    Err(HsmError::KeyNotFound) => {
                        tracing::info!(
                            "try_open_session: Credentials already established (KeyNotFound), continuing with session open. ProcessId={}",
                            process::id()
                        );
                    }
                    Err(e) => return Err(e),
                }

                self.device.open_session(api_rev, credentials)?
            }
            Err(e) => return Err(e),
            Ok(session) => session,
        };

        tracing::debug!(
            "try_open_session: Saving session and credential information. ProcessId={}",
            process::id()
        );
        self.session = Some(hsm_session);
        self.credentials = Some(CachedEstablishCredentials {
            credentials,
            api_rev,
        });
        Ok(())
    }

    fn open_session(
        &mut self,
        api_rev: HsmApiRevision,
        credentials: HsmAppCredentials,
    ) -> HsmResult<()> {
        self.retry_with_restore(
            |device| device.try_open_session(api_rev, credentials),
            retry_on_open_session_op,
        )
    }

    fn try_close_session(&mut self) -> HsmResult<()> {
        let hsm_session = self.session.as_mut().ok_or(HsmError::SessionClosed)?;
        hsm_session.close_session()?;

        self.session = None;
        Ok(())
    }

    fn close_session(&mut self) -> HsmResult<()> {
        // Try running close_session on HsmSession.
        // Don't check error; even if live migration occured,
        // we don't expect an error for this function.
        self.try_close_session()
    }

    fn try_create_key_op(
        &mut self,
        fn_create_key_op: &dyn Fn(&HsmSession, Option<u16>) -> HsmResult<HsmKeyHandle>,
    ) -> HsmResult<KeyId> {
        let hsm_session = self.session.as_ref().ok_or(HsmError::SessionClosed)?;
        let hsm_key = fn_create_key_op(hsm_session, None)?;

        let key_uuid = KeyId {
            uuid: Uuid::new_v4(),
        };
        self.session_keys.insert(key_uuid.clone(), hsm_key);
        Ok(key_uuid)
    }

    fn run_create_key_op(
        &mut self,
        fn_create_key_op: &dyn Fn(&HsmSession, Option<u16>) -> HsmResult<HsmKeyHandle>,
    ) -> HsmResult<KeyId> {
        self.retry_with_restore(
            |device| device.try_create_key_op(fn_create_key_op),
            retry_on_in_session_op,
        )
    }

    fn try_get_unwrapping_key(&mut self) -> HsmResult<KeyId> {
        // Check if unwrapping key already exists in named cache
        if self.unwrapping_key.is_some() {
            return Ok(UNWRAPPING_KEY_ID);
        }

        // Note: restoring unwrapping key from disk is done in establish_credential,
        // And that is done automatically as part of restore_partition in case of live migration.
        let hsm_session = self.session.as_ref().ok_or(HsmError::SessionClosed)?;
        let hsm_key = hsm_session.get_unwrapping_key()?;

        // Cache the masked unwrapping key to disk for live migration resilience
        self.memory_manager
            .write_lock()?
            .set_masked_unwrapping_key(hsm_key.masked_key().ok_or(HsmError::InternalError)?)?;

        // Store the unwrapping key
        self.unwrapping_key = Some(hsm_key);
        Ok(UNWRAPPING_KEY_ID)
    }

    fn run_get_unwrapping_key(&mut self) -> HsmResult<KeyId> {
        self.retry_with_restore(
            |device| device.try_get_unwrapping_key(),
            retry_on_in_session_op,
        )
    }

    /// Helper function to get a key from either session_keys or the_unwrapping_key cache
    fn get_cached_key(&self, key_id: &KeyId) -> HsmResult<&HsmKeyHandle> {
        match self.session_keys.get(key_id) {
            Some(key) => Ok(key),
            None if *key_id == UNWRAPPING_KEY_ID => {
                self.unwrapping_key.as_ref().ok_or(HsmError::KeyNotFound)
            }
            None => Err(HsmError::KeyNotFound),
        }
    }

    fn try_create_key_key_op(
        &mut self,
        key_id: &KeyId,
        fn_key_op: &dyn Fn(&HsmSession, &HsmKeyHandle, Option<u16>) -> HsmResult<HsmKeyHandle>,
    ) -> HsmResult<KeyId> {
        let hsm_session = self.session.as_ref().ok_or(HsmError::SessionClosed)?;
        let hsm_key = self.get_cached_key(key_id)?;

        let new_hsm_key = fn_key_op(hsm_session, hsm_key, None)?;

        let key_uuid = KeyId {
            uuid: Uuid::new_v4(),
        };
        self.session_keys.insert(key_uuid.clone(), new_hsm_key);
        Ok(key_uuid)
    }

    fn run_create_key_key_op(
        &mut self,
        key_id: &KeyId,
        fn_key_op: &dyn Fn(&HsmSession, &HsmKeyHandle, Option<u16>) -> HsmResult<HsmKeyHandle>,
    ) -> HsmResult<KeyId> {
        self.retry_with_restore(
            |device| device.try_create_key_key_op(key_id, fn_key_op),
            retry_on_in_session_op,
        )
    }

    fn try_delete_key_op(&mut self, key_id: &KeyId) -> HsmResult<()> {
        let hsm_session = self.session.as_ref().ok_or(HsmError::SessionClosed)?;
        let hsm_key = self.get_cached_key(key_id)?;

        if *key_id != UNWRAPPING_KEY_ID {
            //only delete if not unwrapping key
            hsm_session.delete_key(hsm_key)?;

            // We just accessed the key on self.session_keys.
            // If remove fails, it's unexpected error.
            self.session_keys
                .remove(key_id)
                .ok_or(HsmError::UnknownError)?;
        }
        Ok(())
    }

    fn run_delete_key_op(&mut self, key_id: &KeyId) -> HsmResult<()> {
        // TODO: Maybe we can do an optimization where we don't
        // restore key just to delete it
        self.retry_with_restore(
            |device| device.try_delete_key_op(key_id),
            retry_on_in_session_op,
        )
    }

    fn try_key_op<T>(
        &self,
        key: &KeyId,
        fn_key_op: &dyn Fn(&HsmSession, &HsmKeyHandle) -> HsmResult<T>,
    ) -> HsmResult<T> {
        let hsm_session = self.session.as_ref().ok_or(HsmError::SessionClosed)?;
        let hsm_key = self.get_cached_key(key)?;
        fn_key_op(hsm_session, hsm_key)
    }

    fn run_key_op<T>(
        &mut self,
        key_id: &KeyId,
        fn_key_op: &dyn Fn(&HsmSession, &HsmKeyHandle) -> HsmResult<T>,
    ) -> HsmResult<T> {
        self.retry_with_restore(
            |device| device.try_key_op(key_id, fn_key_op),
            retry_on_in_session_op,
        )
    }

    fn try_two_key_op<T>(
        &self,
        key_id1: &KeyId,
        key_id2: &KeyId,
        fn_key_op: &dyn Fn(&HsmSession, &HsmKeyHandle, &HsmKeyHandle) -> HsmResult<T>,
    ) -> HsmResult<T> {
        // We only have one 2-key-op:aes_xts_encrypt_decrypt
        // Only check session_keys cache for now.
        let hsm_session = self.session.as_ref().ok_or(HsmError::SessionClosed)?;
        let hsm_key1 = self
            .session_keys
            .get(key_id1)
            .ok_or(HsmError::KeyNotFound)?;
        let hsm_key2 = self
            .session_keys
            .get(key_id2)
            .ok_or(HsmError::KeyNotFound)?;
        fn_key_op(hsm_session, hsm_key1, hsm_key2)
    }

    fn run_two_key_op<T>(
        &mut self,
        key_id1: &KeyId,
        key_id2: &KeyId,
        fn_key_op: &dyn Fn(&HsmSession, &HsmKeyHandle, &HsmKeyHandle) -> HsmResult<T>,
    ) -> HsmResult<T> {
        self.retry_with_restore(
            |device| device.try_two_key_op(key_id1, key_id2, fn_key_op),
            retry_on_in_session_op,
        )
    }

    fn get_key_property<T>(&self, key: &KeyId, fn_key_op: &dyn Fn(&HsmKeyHandle) -> T) -> T {
        let hsm_key = self.get_cached_key(key).expect("Key no longer exists");
        fn_key_op(hsm_key)

        // There is no run_get_key_property because key properties
        // are cached locally and are not expected to fail
    }

    /// Restore partition
    fn restore_partition(&mut self) -> HsmResult<()> {
        tracing::info!("Enter restore_partition. ProcessId={}", process::id());

        // Per resiliency-design.md:
        {
            // Get disk write lock to protect against synchronization
            // issues with establish credential and reopen session.
            let mut write_locked_disk = self.memory_manager.write_lock()?;

            // 1, 3, 4 : Reestablish credential, if credentials have been established, provision partition, unmask unwrapping key
            let Some(establish_credential_info) = self.credentials.as_ref() else {
                tracing::warn!(
                    "Restore_partition: We do not have cached credential info, skipping re-establishing credentials and session. ProcessId={}",
                    process::id()
                );

                return Ok(());
            };

            tracing::info!(
                "Restore_partition: We have cached credential info, re-establishing credentials. ProcessId={}",
                process::id()
            );
            let api_rev = establish_credential_info.api_rev;
            let creds = establish_credential_info.credentials;

            // Ignoring errors since establish credential can only be done once and may have happened before via another device handle.
            // TODO TASK 34575020: We should specifically check for error from credential already set.
            // If LM happens between GetEstablishCredEncryptionKey and EstablishCredential, we should catch that
            let _ = self.try_establish_credential_no_lock(api_rev, creds, &mut write_locked_disk).map_err(|err| (
                tracing::info!("Restore_partition: establish credential failed with {:?}, ignoring error. ProcessId={}", err, process::id())
            ));

            // 2 : Reopen session, if one has been opened
            let Some(session) = &self.session else {
                tracing::info!(
                "Restore_partition: We do not have session info, skipping re-establishing session. ProcessId={}",
                process::id()
                );

                return Ok(());
            };

            tracing::info!(
                "Restore_partition: We have session info, re-opening session. ProcessId={}",
                process::id()
            );

            let result = session.reopen(creds);
            if retry_on_open_session_op(&result) {
                // We may have had another LM event. Caller decides how to proceed.
                tracing::error!(
                    "Restore_partition: Detected resiliency event during restore_partition. ProcessId={}",
                    process::id()
                );
                return Err(HsmError::RestorePartitionFailed);
            }
            result?;
        }

        // 5 : unmask sessions keys stored in process memory
        let result = self.unmask_session_keys();
        // Throw RestorePartitionFailed if this step failed so we can retry
        if let Err(err) = result {
            tracing::error!(
                process_id = process::id(),
                ?err,
                "Restore_partition: unmask_session_keys failed",
            );
            return Err(HsmError::RestorePartitionFailed);
        }

        // Restoring successful, return Ok
        tracing::info!("Exit restore_partition. ProcessId={}", process::id());
        Ok(())
    }

    /// Restoring all session keys stored in memory after LM or similar events
    #[instrument(skip_all)]
    fn unmask_session_keys(&mut self) -> HsmResult<()> {
        let count = self.session_keys.len();
        tracing::debug!(
            ?count,
            "Start unmasking all session keys stored in process memory"
        );

        let hsm_session = self.session.as_mut().ok_or(HsmError::SessionClosed)?;

        let mut new_hash_map: HashMap<KeyId, HsmKeyHandle> = HashMap::new();

        // Iterate every key, make a copy, unmask it, store in new hash map
        for (i, key_handle) in self.session_keys.iter() {
            tracing::debug!(?i, "Unmasking session key");

            // Make a copy of key handle
            let mut copy_key_handle = key_handle.clone();

            let result = hsm_session.unmask_key_from_handle(&mut copy_key_handle);
            // Abort entire unmask operation if any key fails
            if let Err(err) = result {
                tracing::error!(?err, key_id = ?i, kind = ?key_handle.kind(), "Failed to unmask this session key");
                return Err(err);
            }

            new_hash_map.insert(i.clone(), copy_key_handle);
        }

        // Only replace original hash map if all keys were unmasked successfully
        self.session_keys = new_hash_map;

        tracing::debug!(?count, "Done unmask session keys");
        Ok(())
    }
}
