// Copyright (C) Microsoft Corporation. All rights reserved.

use std::sync::Arc;

use azihsm_ddi_types::DdiApiRev;
use parking_lot::RwLock;

use crate::crypto::Algo;
use crate::crypto::DecryptOp;
use crate::crypto::DeriveOp;
use crate::crypto::EncryptOp;
use crate::crypto::Key;
use crate::crypto::KeyDeleteOp;
use crate::crypto::KeyGenOp;
use crate::crypto::KeyId;
use crate::crypto::KeyUnwrapOp;
use crate::crypto::KeyWrapOp;
use crate::crypto::SignOp;
use crate::crypto::StreamingEncDecAlgo;
use crate::crypto::StreamingSignVerifyAlgo;
use crate::crypto::VerifyOp;
use crate::ddi;
use crate::types::key_props::AzihsmKeyPropId;
use crate::types::key_props::KeyPairPropsOps;
use crate::types::key_props::KeyPropValue;
use crate::types::key_props::KeyProps;
use crate::types::key_props::KeyPropsOps;
use crate::types::AlgoId;
use crate::AzihsmError;
use crate::PartitionInner;
use crate::AZIHSM_CLOSE_SESSION_FAILED;
use crate::AZIHSM_SESSION_ALREADY_CLOSED;

/// Size of the session seed in bytes
pub const SESSION_SEED_SIZE_BYTES: usize = 48;

/// HSM Session Types
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SessionType {
    /// A clear, unauthenticated, and unencrypted session.
    Clear = 1,

    /// An authenticated session, which may or may not be encrypted.
    Authenticated = 2,

    /// An authenticated and encrypted session.
    Encrypted = 3,
}

/// HSM API Version
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ApiRev {
    /// Major version number
    pub major: u32,

    /// Minor version number
    pub minor: u32,
}

impl From<ApiRev> for DdiApiRev {
    fn from(api_rev: ApiRev) -> Self {
        DdiApiRev {
            major: api_rev.major,
            minor: api_rev.minor,
        }
    }
}

/// HSM Application Credentials
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AppCreds {
    /// Application ID
    pub id: [u8; 16],

    /// Application Pin
    pub pin: [u8; 16],
}

/// Test credentials for use in unit tests. Keep these in sync with
/// TEST_CRED_ID & TEST_CRED_PIN in api/ddi/lib/tests/common.rs
#[cfg(test)]
pub const TEST_APP_CREDS: AppCreds = AppCreds {
    id: [
        0x70, 0xFC, 0xF7, 0x30, 0xB8, 0x76, 0x42, 0x38, 0xB8, 0x35, 0x80, 0x10, 0xCE, 0x8A, 0x3F,
        0x76,
    ],
    pin: [
        0xDB, 0x3D, 0xC7, 0x7F, 0xC2, 0x2E, 0x43, 0x00, 0x80, 0xD4, 0x1B, 0x31, 0xB6, 0xF0, 0x48,
        0x00,
    ],
};

/// HSM Session
pub struct Session {
    /// Partition reference that this session belongs to
    partition_inner: Arc<RwLock<PartitionInner>>,

    /// API Revision
    api_rev: ApiRev,

    /// Type of session
    session_type: SessionType,

    /// Application ID
    app_id: [u8; 16],

    /// Short Application ID
    short_app_id: u8,

    /// Session ID
    session_id: u16,

    /// Session state
    closed: bool,

    // Session seed
    seed: [u8; SESSION_SEED_SIZE_BYTES],
}

impl Session {
    pub(crate) fn new(
        partition: Arc<RwLock<PartitionInner>>,
        api_rev: ApiRev,
        session_type: SessionType,
        app_id: [u8; 16],
        short_app_id: u8,
        session_id: u16,
        seed: [u8; SESSION_SEED_SIZE_BYTES],
    ) -> Self {
        Self {
            partition_inner: partition,
            api_rev,
            session_type,
            app_id,
            short_app_id,
            session_id,
            closed: false,
            seed,
        }
    }

    /// Get the API revision of the session
    pub fn api_rev(&self) -> ApiRev {
        self.api_rev
    }

    /// Get the session type
    pub fn session_type(&self) -> SessionType {
        self.session_type
    }

    /// Get the application ID
    pub fn app_id(&self) -> [u8; 16] {
        self.app_id
    }

    /// Get the short application ID
    pub fn short_app_id(&self) -> u8 {
        self.short_app_id
    }

    /// Get the session ID
    pub fn session_id(&self) -> u16 {
        self.session_id
    }

    /// Check if the session is closed
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Get the session seed
    #[allow(dead_code)]
    pub(crate) fn seed(&self) -> &[u8; SESSION_SEED_SIZE_BYTES] {
        &self.seed
    }

    pub(crate) fn partition(&self) -> Arc<RwLock<PartitionInner>> {
        self.partition_inner.clone()
    }

    /// Generate a cryptographic key using this session.
    ///
    /// # Parameters
    /// * `key` - The key object to generate the key for.
    ///
    /// # Returns
    /// `Result<(), AzihsmError>` - Ok if the key was generated successfully,
    /// Err if the key generation failed.
    ///
    #[allow(private_bounds)]
    pub fn generate_key<K: Key + KeyGenOp>(&self, key: &mut K) -> Result<(), AzihsmError> {
        // Generate the key using the key's implementation
        key.generate_key(self)
    }

    /// Generate a cryptographic key pair using this session.
    ///
    /// # Parameters
    /// * `key` - The key object to generate the key pair for.
    ///
    /// # Returns
    /// `Result<(), AzihsmError>` - Ok if the key pair was generated successfully,
    /// Err if the key pair generation failed.
    ///
    #[allow(private_bounds)]
    pub fn generate_key_pair<K: Key + KeyGenOp>(&self, key: &mut K) -> Result<(), AzihsmError> {
        // Generate the key using the key's implementation
        key.generate_key_pair(self)
    }

    /// Unwrap a cryptographic key using this session.
    ///
    /// # Parameters
    /// * `key` - The key object to use for unwrapping (contains the unwrapping key).
    /// * `algo` - The algorithm specification for the unwrap operation.
    /// * `wrapped_blob` - The wrapped key data to unwrap.
    /// * `unwrapped_key_props` - Properties for the key that will be unwrapped.
    ///
    /// # Returns
    /// `Result<KeyId, AzihsmError>` - Ok with the KeyId of the unwrapped key if successful,
    /// Err if the key unwrapping failed.
    ///
    #[allow(private_bounds)]
    pub fn unwrap<A, K>(
        &self,
        key: &K,
        algo: &A,
        wrapped_blob: &[u8],
        unwrapped_key_props: &KeyProps,
    ) -> Result<KeyId, AzihsmError>
    where
        A: Algo,
        K: Key + KeyUnwrapOp<A>,
    {
        // Unwrap the key using the key's implementation
        key.unwrap(self, algo, wrapped_blob, unwrapped_key_props)
    }

    /// Get the maximum unwrap length for RSA OAEP unwrapping.
    ///
    /// # Parameters
    /// * `hash_algo_id` - The identifier of the hash algorithm to use
    /// * `key_size` - The size of the key in bytes
    /// # Returns
    /// `Result<usize, AzihsmError>` - Ok with the maximum unwrap length,
    /// Err if the operation failed.
    #[allow(private_bounds)]
    pub fn unwrap_max_len<A: Algo, K: Key + KeyUnwrapOp<A>>(
        &self,
        key: &K,
        hash_algo_id: AlgoId,
    ) -> Result<usize, AzihsmError> {
        // Get the maximum unwrap length using the session
        key.unwrap_max_len(hash_algo_id)
    }

    /// Wrap user data using the specified algorithm and key.
    ///
    /// This function performs a cryptographic wrapping operation using the specified
    /// algorithm and wrapping key. The wrapped data is written to the provided buffer.
    ///
    /// # Parameters
    /// * `key` - The key to use for wrapping.
    /// * `algo` - The algorithm specification to use for wrapping.
    /// * `user_data` - The user data to wrap.
    /// * `wrapped_data` - The buffer to store the wrapped data.
    ///
    /// # Returns
    /// `Result<usize, AzihsmError>` - Ok with bytes written if the wrapping was successful,
    /// Err if the wrapping failed.
    ///
    #[allow(private_bounds)]
    pub fn wrap<A, K>(
        &self,
        key: &K,
        algo: &A,
        user_data: &[u8],
        wrapped_data: &mut [u8],
    ) -> Result<usize, AzihsmError>
    where
        A: Algo,
        K: Key + KeyWrapOp<A>,
    {
        // Wrap the data using the key's implementation
        key.wrap(self, algo, user_data, wrapped_data)
    }

    /// Get the required buffer length for wrapping user data.
    ///
    /// # Parameters
    /// * `key` - The key to use for wrapping.
    /// * `algo` - The algorithm specification to use for wrapping.
    /// * `user_data_len` - The length of user data to wrap.
    ///
    /// # Returns
    /// `Result<usize, AzihsmError>` - Ok with required buffer length,
    /// Err if the operation failed.
    ///
    #[allow(private_bounds)]
    pub fn wrap_len<A, K>(
        &self,
        key: &K,
        algo: &A,
        user_data_len: usize,
    ) -> Result<usize, AzihsmError>
    where
        A: Algo,
        K: Key + KeyWrapOp<A>,
    {
        // Get the required buffer length using the key's implementation
        key.wrap_len(algo, user_data_len)
    }

    /// Delete a cryptographic key using this session.
    ///
    /// # Parameters
    /// * `key_id` - The identifier of the key to delete.
    ///
    /// # Returns
    /// `Result<(), AzihsmError>` - Ok if the key was deleted successfully,
    /// Err if the key deletion failed.
    ///
    #[allow(private_bounds)]
    pub fn delete_key<K: Key + KeyDeleteOp>(&self, key: &mut K) -> Result<(), AzihsmError> {
        // Delete the key using the key's implementation
        key.delete_key(self)
    }

    #[allow(private_bounds)]
    pub(crate) fn delete_pub_key<K: Key + KeyDeleteOp>(
        &self,
        key: &mut K,
    ) -> Result<(), AzihsmError> {
        // Delete the public key using the key's implementation
        key.delete_pub_key(self)
    }

    #[allow(private_bounds)]
    pub(crate) fn delete_priv_key<K: Key + KeyDeleteOp>(
        &self,
        key: &mut K,
    ) -> Result<(), AzihsmError> {
        // Delete the private key using the key's implementation
        key.delete_priv_key(self)
    }

    ///
    /// Get a property from a symmetric key.
    ///
    /// # Parameters
    /// * `key` - Reference to the symmetric key
    /// * `id` - The property ID to get
    ///
    /// # Returns
    /// `Result<KeyPropValue, AzihsmError>` - The property value if successful.
    #[allow(dead_code)]
    pub(crate) fn get_property<K>(
        &self,
        key: &K,
        id: AzihsmKeyPropId,
    ) -> Result<KeyPropValue, AzihsmError>
    where
        K: Key + KeyPropsOps,
    {
        key.get_property(id)
    }

    /// Get a property from an asymmetric key pair's public key.
    ///
    /// # Parameters
    /// * `key` - Reference to the key pair
    /// * `id` - The property ID to get
    ///
    /// # Returns
    /// `Result<KeyPropValue, AzihsmError>` - The property value if successful.
    pub(crate) fn get_pub_property<K>(
        &self,
        key: &K,
        id: AzihsmKeyPropId,
    ) -> Result<KeyPropValue, AzihsmError>
    where
        K: Key + KeyPairPropsOps,
    {
        key.get_pub_property(id)
    }

    /// Get a property from an asymmetric key pair's private key.
    ///
    /// # Parameters
    /// * `key` - Reference to the key pair
    /// * `id` - The property ID to get
    ///
    /// # Returns
    /// `Result<KeyPropValue, AzihsmError>` - The property value if successful.
    pub(crate) fn get_priv_property<K>(
        &self,
        key: &K,
        id: AzihsmKeyPropId,
    ) -> Result<KeyPropValue, AzihsmError>
    where
        K: Key + KeyPairPropsOps,
    {
        key.get_priv_property(id)
    }

    /// Set a property on a symmetric key.
    ///
    /// # Parameters
    /// * `key` - Reference to the symmetric key
    /// * `id` - The property ID to set
    /// * `value` - The property value to set
    ///
    /// # Returns
    /// `Result<(), AzihsmError>` - Ok if successful, Err if the operation failed.
    #[allow(dead_code)]
    pub(crate) fn set_property<K>(
        &self,
        key: &mut K,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError>
    where
        K: Key + KeyPropsOps,
    {
        key.set_property(id, value)
    }

    /// Set a property on an asymmetric key pair's public key.
    ///
    /// # Parameters
    /// * `key` - Reference to the key pair
    /// * `id` - The property ID to set
    /// * `value` - The property value to set
    ///
    /// # Returns
    /// `Result<(), AzihsmError>` - Ok if successful, Err if the operation failed.
    pub(crate) fn set_pub_property<K>(
        &self,
        key: &mut K,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError>
    where
        K: Key + KeyPairPropsOps,
    {
        key.set_pub_property(id, value)
    }

    /// Set a property on an asymmetric key pair's private key.
    ///
    /// # Parameters
    /// * `key` - Reference to the key pair
    /// * `id` - The property ID to set
    /// * `value` - The property value to set
    ///
    /// # Returns
    /// `Result<(), AzihsmError>` - Ok if successful, Err if the operation failed.
    pub(crate) fn set_priv_property<K>(
        &self,
        key: &mut K,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError>
    where
        K: Key + KeyPairPropsOps,
    {
        key.set_priv_property(id, value)
    }

    /// Encrypt data using the specified algorithm and key.
    ///
    /// # Parameters
    /// * `algo` - The algorithm to use for encryption.
    /// * `key` - The identifier of the key to use for encryption.
    /// * `pt` - The plaintext data to encrypt.
    /// * `ct` - The buffer to store the ciphertext data.
    ///
    /// # Returns
    /// `Result<usize, AzihsmError>` - Ok with bytes written if the encryption was successful,
    /// Err if the encryption failed.
    ///
    #[allow(private_bounds)]
    pub fn encrypt<K: Key, A: Algo + EncryptOp<K>>(
        &self,
        algo: &mut A,
        key: &K,
        pt: &[u8],
        ct: &mut [u8],
    ) -> Result<usize, AzihsmError> {
        algo.encrypt(self, key, pt, ct)
    }

    /// Decrypt data using the specified algorithm and key.
    ///
    /// # Parameters
    /// * `algo` - The algorithm to use for decryption.
    /// * `key` - The identifier of the key to use for decryption.
    /// * `ct` - The ciphertext data to decrypt.
    /// * `pt` - The buffer to store the plaintext data.
    ///
    /// # Returns
    /// `Result<usize, AzihsmError>` - Ok with bytes written if the decryption was successful,
    /// Err if the decryption failed.
    ///
    #[allow(private_bounds)]
    pub fn decrypt<K: Key, A: Algo + DecryptOp<K>>(
        &self,
        algo: &mut A,
        key: &K,
        ct: &[u8],
        pt: &mut [u8],
    ) -> Result<usize, AzihsmError> {
        algo.decrypt(self, key, ct, pt)
    }

    /// Sign data using the specified algorithm and key.
    ///
    /// This function performs a cryptographic signing operation using the specified
    /// algorithm and private key. The signature is written to the provided buffer.
    ///
    /// # Parameters
    /// * `algo` - The algorithm specification to use for signing.
    /// * `key` - The private key to use for signing.
    /// * `data` - The data to sign.
    /// * `signature` - The buffer to store the generated signature.
    ///
    /// # Returns
    /// `Result<(), AzihsmError>` - Ok if the signing was successful,
    /// Err if the signing failed.
    ///
    #[allow(private_bounds)]
    pub fn sign<A, K>(
        &self,
        algo: &A,
        key: &K,
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<(), AzihsmError>
    where
        A: Algo + SignOp<K>,
        K: Key,
    {
        algo.sign(self, key, data, signature)
    }

    /// Verify a signature using the specified algorithm and key.
    ///
    /// # Parameters
    /// * `algo` - The algorithm to use for verification.
    /// * `key` - The key to use for verification.
    /// * `data` - The original data that was signed.
    /// * `signature` - The signature to verify.
    ///
    /// # Returns
    /// `Result<(), AzihsmError>` - Ok if the signature is valid,
    /// Err if the signature is invalid or verification failed.
    ///
    #[allow(private_bounds)]
    pub fn verify<A, K>(
        &self,
        algo: &A,
        key: &K,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), AzihsmError>
    where
        A: Algo + VerifyOp<K>,
        K: Key,
    {
        algo.verify(self, key, data, signature)
    }

    /// Create a streaming encryption context
    ///
    /// # Parameters
    /// * `algo` - The algorithm to use for encryption
    /// * `key` - The key to use for encryption
    ///
    /// # Returns
    /// `Result<A::EncryptStream, AzihsmError>` - The streaming encryption context
    ///
    #[allow(private_bounds, private_interfaces)]
    pub fn encrypt_init<'a, A, K>(
        &'a self,
        algo: &A,
        key: &K,
    ) -> Result<A::EncryptStream, AzihsmError>
    where
        A: StreamingEncDecAlgo<'a, K>,
        K: Key,
    {
        algo.encrypt_init(self, key)
    }

    /// Create a streaming decryption context
    ///
    /// # Parameters
    /// * `algo` - The algorithm to use for decryption
    /// * `key` - The key to use for decryption
    ///
    /// # Returns
    /// `Result<A::DecryptStream, AzihsmError>` - The streaming decryption context
    ///
    #[allow(private_bounds, private_interfaces)]
    pub fn decrypt_init<'a, A, K>(
        &'a self,
        algo: &A,
        key: &K,
    ) -> Result<A::DecryptStream, AzihsmError>
    where
        A: StreamingEncDecAlgo<'a, K>,
        K: Key,
    {
        algo.decrypt_init(self, key)
    }

    /// Initialize a streaming sign operation.
    ///
    /// # Parameters
    /// * `algo` - The algorithm to use for signing.
    /// * `key` - The key to use for signing.
    ///
    /// # Returns
    /// A streaming sign context that can be updated with data and finalized to produce a signature.
    ///
    #[allow(private_bounds, private_interfaces)]
    pub fn sign_init<'a, A, K>(&'a self, algo: &A, key: &K) -> Result<A::SignStream, AzihsmError>
    where
        A: Algo + StreamingSignVerifyAlgo<'a, K>,
        K: Key,
    {
        algo.sign_init(self, key)
    }

    /// Initialize a streaming verify operation.
    ///
    /// # Parameters
    /// * `algo` - The algorithm to use for verification.
    /// * `key` - The key to use for verification.
    ///
    /// # Returns
    /// A streaming verify context that can be updated with data and finalized to verify a signature.
    ///
    #[allow(private_bounds, private_interfaces)]
    pub fn verify_init<'a, A, K>(
        &'a self,
        algo: &A,
        key: &K,
    ) -> Result<A::VerifyStream, AzihsmError>
    where
        A: Algo + StreamingSignVerifyAlgo<'a, K>,
        K: Key,
    {
        algo.verify_init(self, key)
    }

    /// Initialize a streaming digest operation.
    ///
    /// # Parameters
    /// * `algo` - The digest algorithm to use for streaming digest operations.
    ///
    /// # Returns
    /// `Result<A::DigestStream, AzihsmError>` - Ok with a digest stream context that can be updated with data and finalized to produce the digest,
    /// Err if the initialization failed.
    #[allow(private_bounds, private_interfaces)]
    pub fn digest_init<'a, A>(&'a self, algo: &A) -> Result<A::DigestStream, AzihsmError>
    where
        A: crate::crypto::StreamingDigestAlgo<'a>,
    {
        algo.digest_init(self)
    }

    /// Close the session
    ///
    /// # Returns
    /// `Result<(), AzihsmError>` - Ok if the session was closed successfully,
    /// Err if the session was already closed or if there was an error during the close operation
    ///
    pub fn close(&mut self) -> Result<(), AzihsmError> {
        let mut write_locked_partition = self.partition_inner.write();

        if self.closed {
            Err(AZIHSM_SESSION_ALREADY_CLOSED)?;
        }

        ddi::close_session(
            &write_locked_partition.partition,
            self.session_id,
            self.api_rev.into(),
        )
        .map_err(|_| AZIHSM_CLOSE_SESSION_FAILED)?;

        // Update the open session count on the partition.
        write_locked_partition.update_open_session_count(false);
        self.closed = true;

        Ok(())
    }

    /// Derive a new key from a base key using key derivation algorithms
    ///
    /// # Parameters
    /// * `algo` - The algorithm specification to use for key derivation
    /// * `base_key` - The base key to derive from
    /// * `derived_key_props` - Properties for the derived key that will be created
    ///
    /// # Returns
    /// `Result<KeyId, AzihsmError>` - Ok with the KeyId of the derived key if successful,
    /// Err if the key derivation failed
    ///
    pub(crate) fn key_derive<A, K>(
        &self,
        algo: &A,
        base_key: &K,
        derived_key_props: &KeyProps,
    ) -> Result<KeyId, AzihsmError>
    where
        A: Algo + DeriveOp<K>,
        K: Key,
    {
        algo.key_derive(self, base_key, derived_key_props)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Err(_error) = self.close() {
            // TODO: Add tracing for the error
        }
    }
}

/// Test helpers for creating sessions and partitions
#[cfg(test)]
pub mod test_helpers {
    use std::sync::Mutex;
    use std::sync::OnceLock;

    use super::*;
    use crate::partition_info_list;
    use crate::partition_open;
    use crate::ApiRev;
    use crate::Partition;
    use crate::SessionType;

    /// Shared test partition that's initialized once.
    static TEST_PARTITION: OnceLock<Mutex<Partition>> = OnceLock::new();

    /// Gets or creates the test partition, initializing it only once.
    fn get_test_partition() -> &'static Mutex<Partition> {
        TEST_PARTITION.get_or_init(|| {
            // Get the first available partition.
            let partition_list = partition_info_list();
            assert!(
                !partition_list.is_empty(),
                "No partitions available for testing"
            );

            let partition_info = &partition_list[0];
            let partition = partition_open(&partition_info.path).expect("Failed to open partition");

            // Initialize partition only once.
            partition
                .init(TEST_APP_CREDS)
                .expect("Failed to initialize partition");

            Mutex::new(partition)
        })
    }

    /// Creates a test session with the shared, initialized partition.
    pub fn create_test_session() -> (Partition, Session) {
        create_test_session_with_creds(TEST_APP_CREDS)
    }

    /// Creates a test session with custom credentials on the shared partition.
    pub fn create_test_session_with_creds(creds: AppCreds) -> (Partition, Session) {
        // Get the shared test partition (initialized only once)
        let partition_mutex = get_test_partition();
        let partition_guard = partition_mutex.lock().unwrap();

        // We need to create a new partition instance since we can't return a reference
        // from the mutex guard. For tests, we'll open the same partition again.
        let partition_list = partition_info_list();
        let partition_info = &partition_list[0];
        let partition = partition_open(&partition_info.path).expect("Failed to open partition");

        // Don't initialize again - the partition is already initialized.
        // Open a session directly.
        let api_rev = ApiRev { major: 1, minor: 0 };
        let session = partition
            .open_session(SessionType::Clear, api_rev, creds)
            .expect("Failed to open session");

        drop(partition_guard); // Release the lock
        (partition, session)
    }

    /// Creates a test partition (without session).
    pub fn create_test_partition() -> Partition {
        create_test_partition_with_creds(TEST_APP_CREDS)
    }

    /// Creates a test partition with custom credentials.
    pub fn create_test_partition_with_creds(_creds: AppCreds) -> Partition {
        // Ensure the shared partition is initialized
        let _partition_mutex = get_test_partition();

        // Return a new partition instance (already initialized)
        let partition_list = partition_info_list();
        let partition_info = &partition_list[0];
        partition_open(&partition_info.path).expect("Failed to open partition")
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::create_test_session;
    use super::*;

    #[test]
    fn test_session_open_and_close() {
        // Create test session using helper.
        let (_partition, mut session) = create_test_session();

        // Verify session properties.
        let api_rev = ApiRev { major: 1, minor: 0 };
        assert_eq!(session.api_rev(), api_rev);
        assert_eq!(session.session_type(), SessionType::Clear);
        assert_eq!(session.app_id(), TEST_APP_CREDS.id);
        assert!(!session.is_closed());

        // Close the session.
        session.close().expect("Failed to close session");

        // Verify session is closed.
        assert!(session.is_closed());

        // Attempting to close again should fail.
        let close_result = session.close();
        assert!(close_result.is_err());
        assert_eq!(close_result.unwrap_err(), AZIHSM_SESSION_ALREADY_CLOSED);
    }
}
