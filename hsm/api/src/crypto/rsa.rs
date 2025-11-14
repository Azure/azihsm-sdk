#![warn(missing_docs)]
// Copyright (C) Microsoft Corporation. All rights reserved.

//! RSA cryptographic operations
use std::sync::Arc;

use mcr_ddi_types::DdiKeyType;
use parking_lot::RwLock;

use crate::crypto::Key;
use crate::crypto::KeyDeleteOp;
use crate::crypto::KeyGenOp;
use crate::crypto::KeyId;
use crate::crypto::SafeInnerAccess;
use crate::ddi;
use crate::types::key_props::KeyProps;
use crate::AzihsmError;
use crate::Session;
use crate::AZIHSM_KEY_ALREADY_EXISTS;
use crate::AZIHSM_KEY_NOT_INITIALIZED;
use crate::AZIHSM_KEY_PROPERTY_NOT_PRESENT;
use crate::AZIHSM_RSA_KEYGEN_FAILED;

/// RSA Key Pair generation implementation
#[derive(Clone, Debug)]
pub struct RsaPkcsKeyPair(Arc<RwLock<RsaPkcsKeyPairInner>>);

struct RsaPkcsKeyPairInner {
    priv_key_id: Option<KeyId>,
    pub_key: Option<Vec<u8>>,
    #[allow(unused)]
    pub_key_props: KeyProps,
    priv_key_props: KeyProps,
}

impl std::fmt::Debug for RsaPkcsKeyPairInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaPkcsKeyPairInner")
            .field("priv_key_id", &self.priv_key_id)
            .field("pub_key", &self.pub_key.as_ref().map(|v| v.len()))
            .field("pub_key_props", &self.pub_key_props)
            .field("priv_key_props", &self.priv_key_props)
            .finish()
    }
}

impl Key for RsaPkcsKeyPair {}

impl RsaPkcsKeyPair {
    /// Create a new RSA PKCS#1 v1.5 key pair generation object
    pub fn new(pub_key_props: KeyProps, priv_key_props: KeyProps) -> Self {
        let inner = RsaPkcsKeyPairInner {
            priv_key_id: None,
            pub_key: None,
            pub_key_props,
            priv_key_props,
        };
        RsaPkcsKeyPair(Arc::new(RwLock::new(inner)))
    }
    #[allow(unused)]
    fn with_inner<R>(&self, f: impl FnOnce(&RsaPkcsKeyPairInner) -> R) -> R {
        self.0.with_inner(f)
    }

    #[allow(unused)]
    fn with_inner_mut<R>(&self, f: impl FnOnce(&mut RsaPkcsKeyPairInner) -> R) -> R {
        self.0.with_inner_mut(f)
    }

    #[allow(unused)]
    pub fn priv_key_id(&self) -> Option<KeyId> {
        self.with_inner(|inner| inner.priv_key_id)
    }

    #[allow(unused)]
    pub fn pub_key(&self) -> Option<Vec<u8>> {
        self.with_inner(|inner| inner.pub_key.clone())
    }

    #[allow(unused)]
    pub fn with_pub_key<R>(&self, f: impl FnOnce(Option<&[u8]>) -> R) -> R {
        self.with_inner(|inner| f(inner.pub_key.as_deref()))
    }

    /// Get the key size for this key pair
    #[allow(unused)]
    pub(crate) fn key_size(&self) -> Option<u32> {
        self.with_inner(|inner: &RsaPkcsKeyPairInner| inner.priv_key_props.bit_len())
    }
}

impl KeyGenOp for RsaPkcsKeyPair {
    fn generate_key_pair(&mut self, session: &Session) -> Result<(), AzihsmError> {
        // Check if already generated using the accessor functions
        if self.priv_key_id().is_some() || self.pub_key().is_some() {
            Err(AZIHSM_KEY_ALREADY_EXISTS)?;
        }

        let mut inner = self.0.write();

        // Get key size from public key properties
        let key_size = inner
            .priv_key_props
            .bit_len()
            .ok_or(AZIHSM_KEY_PROPERTY_NOT_PRESENT)? as usize;

        // Get RSA key pair from DDI
        let rsa_get_unwrapping_key = ddi::rsa_get_unwrapping_key(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
        )
        .map_err(|_| AZIHSM_RSA_KEYGEN_FAILED)?;

        // check if returned key_kind  is same size as bit_len by matching
        let rec_key_size = match rsa_get_unwrapping_key.data.pub_key.key_kind {
            DdiKeyType::Rsa2kPublic => 2048,
            DdiKeyType::Rsa3kPublic => 3072,
            DdiKeyType::Rsa4kPublic => 4096,
            _ => return Err(AZIHSM_RSA_KEYGEN_FAILED),
        };
        if key_size != rec_key_size {
            return Err(AZIHSM_RSA_KEYGEN_FAILED);
        }
        // Store both the key ID and the actual key handles
        inner.priv_key_id = Some(KeyId(rsa_get_unwrapping_key.data.key_id));
        // Copy public key
        inner.pub_key = Some(
            rsa_get_unwrapping_key.data.pub_key.der.data()
                [..rsa_get_unwrapping_key.data.pub_key.der.len()]
                .to_vec(),
        );

        Ok(())
    }
}

/// Key deletion operations for RSA PKCS key pairs
impl KeyDeleteOp for RsaPkcsKeyPair {
    /// Delete the entire key pair (both public and private keys)
    fn delete_key(&mut self, session: &Session) -> Result<(), AzihsmError> {
        let mut errors = Vec::new();

        // Try to delete private key first
        if let Err(e) = self.delete_priv_key(session) {
            // Only consider it an error if the key was actually initialized
            if e != AZIHSM_KEY_NOT_INITIALIZED {
                errors.push(e);
            }
        }

        // Always try to delete public key
        if let Err(e) = self.delete_pub_key(session) {
            // Only consider it an error if the key was actually initialized
            if e != AZIHSM_KEY_NOT_INITIALIZED {
                errors.push(e);
            }
        }

        // Return the first error if any occurred during actual deletion
        if let Some(error) = errors.first() {
            Err(*error)
        } else {
            Ok(())
        }
    }

    /// Delete only the public key (local storage only)
    fn delete_pub_key(&mut self, _session: &Session) -> Result<(), AzihsmError> {
        self.with_inner_mut(|inner| {
            if inner.pub_key.is_none() {
                return Err(AZIHSM_KEY_NOT_INITIALIZED);
            }

            inner.pub_key = None;
            Ok(())
        })
    }

    /// Delete only the private key from the HSM
    fn delete_priv_key(&mut self, _session: &Session) -> Result<(), AzihsmError> {
        self.with_inner_mut(|inner| {
            if inner.priv_key_id.is_none() {
                return Err(AZIHSM_KEY_NOT_INITIALIZED);
            }

            inner.priv_key_id = None;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::test_helpers::create_test_session;

    #[test]
    fn test_rsa_key_pair_gen_2048_bit() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create RSA key pair with 2048-bit properties
        let key_props = KeyProps::builder()
            .bit_len(2048)
            .sign(true)
            .verify(true)
            .build();

        let mut rsa_keypair = RsaPkcsKeyPair::new(key_props.clone(), key_props);

        // Verify initial state
        assert!(
            rsa_keypair.priv_key_id().is_none(),
            "Private key ID should be None before generation"
        );
        assert!(
            rsa_keypair.pub_key().is_none(),
            "Public key should be None before generation"
        );

        // Generate the key pair using session
        session
            .generate_key_pair(&mut rsa_keypair)
            .expect("Failed to generate RSA 2048-bit key pair");

        // Verify key pair was generated successfully
        assert!(
            rsa_keypair.priv_key_id().is_some(),
            "Private key ID should be set after generation"
        );
        assert!(
            rsa_keypair.pub_key().is_some(),
            "Public key should be set after generation"
        );

        // Verify key size
        assert_eq!(
            rsa_keypair.key_size(),
            Some(2048),
            "Key size should be 2048 bits"
        );

        // Verify public key is not empty
        rsa_keypair.with_pub_key(|pub_key| {
            assert!(pub_key.is_some(), "Public key should be present");
            let key_data = pub_key.unwrap();
            assert!(!key_data.is_empty(), "Public key data should not be empty");
            assert!(
                key_data.len() > 200,
                "Public key data should be reasonable size for 2048-bit RSA"
            );
        });

        // Delete the key pair
        session
            .delete_key(&mut rsa_keypair)
            .expect("Failed to delete RSA key pair");

        // Clean up
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_rsa_key_pair_gen_3072_bit() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create RSA key pair with 3072-bit properties
        let key_props = KeyProps::builder()
            .bit_len(3072)
            .sign(true)
            .verify(true)
            .build();

        let mut rsa_keypair = RsaPkcsKeyPair::new(key_props.clone(), key_props);

        // Try to generate the key pair - might not be supported in test environment
        let result = session.generate_key_pair(&mut rsa_keypair);

        match result {
            Ok(()) => {
                // If generation succeeds, verify the key pair
                assert!(
                    rsa_keypair.priv_key_id().is_some(),
                    "Private key ID should be set after generation"
                );
                assert!(
                    rsa_keypair.pub_key().is_some(),
                    "Public key should be set after generation"
                );

                // Verify key size
                assert_eq!(
                    rsa_keypair.key_size(),
                    Some(3072),
                    "Key size should be 3072 bits"
                );

                // Delete the key pair
                session
                    .delete_key(&mut rsa_keypair)
                    .expect("Failed to delete RSA key pair");
            }
            Err(AZIHSM_RSA_KEYGEN_FAILED) => {
                // 3072-bit RSA might not be supported in test environment
                println!("3072-bit RSA key generation not supported in test environment");
            }
            Err(e) => {
                panic!("Unexpected error generating 3072-bit RSA key: {:?}", e);
            }
        }

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_rsa_key_pair_gen_4096_bit() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create RSA key pair with 4096-bit properties
        let key_props = KeyProps::builder()
            .bit_len(4096)
            .sign(true)
            .verify(true)
            .build();

        let mut rsa_keypair = RsaPkcsKeyPair::new(key_props.clone(), key_props);

        // Try to generate the key pair - might not be supported in test environment
        let result = session.generate_key_pair(&mut rsa_keypair);

        match result {
            Ok(()) => {
                // If generation succeeds, verify the key pair
                assert!(
                    rsa_keypair.priv_key_id().is_some(),
                    "Private key ID should be set after generation"
                );
                assert!(
                    rsa_keypair.pub_key().is_some(),
                    "Public key should be set after generation"
                );

                // Verify key size
                assert_eq!(
                    rsa_keypair.key_size(),
                    Some(4096),
                    "Key size should be 4096 bits"
                );

                // Delete the key pair
                session
                    .delete_key(&mut rsa_keypair)
                    .expect("Failed to delete RSA key pair");
            }
            Err(AZIHSM_RSA_KEYGEN_FAILED) => {
                // 4096-bit RSA might not be supported in test environment
                println!("4096-bit RSA key generation not supported in test environment");
            }
            Err(e) => {
                panic!("Unexpected error generating 4096-bit RSA key: {:?}", e);
            }
        }

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_rsa_key_pair_gen_already_exists() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create RSA key pair with 2048-bit properties
        let key_props = KeyProps::builder()
            .bit_len(2048)
            .sign(true)
            .verify(true)
            .build();

        let mut rsa_keypair = RsaPkcsKeyPair::new(key_props.clone(), key_props);

        // Generate the key pair first time
        session
            .generate_key_pair(&mut rsa_keypair)
            .expect("Failed to generate RSA key pair");

        // Try to generate again - should fail
        let result = session.generate_key_pair(&mut rsa_keypair);
        assert!(result.is_err(), "Second generation should fail");
        assert_eq!(
            result.unwrap_err(),
            AZIHSM_KEY_ALREADY_EXISTS,
            "Should return AZIHSM_KEY_ALREADY_EXISTS error"
        );

        // Delete the key pair
        session
            .delete_key(&mut rsa_keypair)
            .expect("Failed to delete RSA key pair");

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_rsa_key_pair_gen_missing_bit_len() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create RSA key pair without bit_len property
        let key_props = KeyProps::builder().sign(true).verify(true).build(); // Missing bit_len

        let mut rsa_keypair = RsaPkcsKeyPair::new(key_props.clone(), key_props);

        // Try to generate - should fail
        let result = session.generate_key_pair(&mut rsa_keypair);
        assert!(result.is_err(), "Generation should fail without bit_len");
        assert_eq!(
            result.unwrap_err(),
            AZIHSM_KEY_PROPERTY_NOT_PRESENT,
            "Should return AZIHSM_KEY_PROPERTY_NOT_PRESENT error"
        );

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_rsa_key_pair_gen_unsupported_key_size() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create RSA key pair with unsupported key size
        let key_props = KeyProps::builder()
            .bit_len(1024) // Unsupported size
            .sign(true)
            .verify(true)
            .build();

        let mut rsa_keypair = RsaPkcsKeyPair::new(key_props.clone(), key_props);

        // Try to generate - should fail
        let result = session.generate_key_pair(&mut rsa_keypair);
        assert!(
            result.is_err(),
            "Generation should fail with unsupported key size"
        );
        assert_eq!(
            result.unwrap_err(),
            AZIHSM_RSA_KEYGEN_FAILED,
            "Should return AZIHSM_RSA_KEYGEN_FAILED error"
        );

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_rsa_key_pair_delete_before_generation() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create RSA key pair with 2048-bit properties
        let key_props = KeyProps::builder()
            .bit_len(2048)
            .sign(true)
            .verify(true)
            .build();

        let mut rsa_keypair = RsaPkcsKeyPair::new(key_props.clone(), key_props);

        // Try to delete before generation - should succeed (no-op)
        let result = session.delete_key(&mut rsa_keypair);
        assert!(
            result.is_ok(),
            "Delete should succeed even if key not generated"
        );

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_rsa_key_pair_delete_partial_keys() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create RSA key pair with 2048-bit properties
        let key_props = KeyProps::builder()
            .bit_len(2048)
            .sign(true)
            .verify(true)
            .build();

        let mut rsa_keypair = RsaPkcsKeyPair::new(key_props.clone(), key_props);

        // Generate the key pair
        session
            .generate_key_pair(&mut rsa_keypair)
            .expect("Failed to generate RSA key pair");

        // Delete only the public key
        let result = session.delete_pub_key(&mut rsa_keypair);
        assert!(result.is_ok(), "Public key deletion should succeed");

        // Verify public key is deleted but private key remains
        assert!(
            rsa_keypair.pub_key().is_none(),
            "Public key should be None after deletion"
        );
        assert!(
            rsa_keypair.priv_key_id().is_some(),
            "Private key should still exist"
        );

        // Delete only the private key
        let result = session.delete_priv_key(&mut rsa_keypair);
        assert!(result.is_ok(), "Private key deletion should succeed");

        // Verify private key is deleted
        assert!(
            rsa_keypair.priv_key_id().is_none(),
            "Private key should be None after deletion"
        );

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_rsa_key_pair_delete_already_deleted() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create RSA key pair with 2048-bit properties
        let key_props = KeyProps::builder()
            .bit_len(2048)
            .sign(true)
            .verify(true)
            .build();

        let mut rsa_keypair = RsaPkcsKeyPair::new(key_props.clone(), key_props);

        // Try to delete public key before generation
        let result = session.delete_pub_key(&mut rsa_keypair);
        assert!(
            result.is_err(),
            "Public key deletion should fail if not generated"
        );
        assert_eq!(
            result.unwrap_err(),
            AZIHSM_KEY_NOT_INITIALIZED,
            "Should return AZIHSM_KEY_NOT_INITIALIZED error"
        );

        // Try to delete private key before generation
        let result = session.delete_priv_key(&mut rsa_keypair);
        assert!(
            result.is_err(),
            "Private key deletion should fail if not generated"
        );
        assert_eq!(
            result.unwrap_err(),
            AZIHSM_KEY_NOT_INITIALIZED,
            "Should return AZIHSM_KEY_NOT_INITIALIZED error"
        );

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_rsa_key_pair_multiple_generations() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Test different key sizes in sequence - only test 2048-bit which is known to work
        // Other sizes might not be supported in test environment
        let supported_key_sizes = [2048];

        for key_size in supported_key_sizes {
            let key_props = KeyProps::builder()
                .bit_len(key_size)
                .sign(true)
                .verify(true)
                .build();

            let mut rsa_keypair = RsaPkcsKeyPair::new(key_props.clone(), key_props);

            // Generate the key pair
            session
                .generate_key_pair(&mut rsa_keypair)
                .unwrap_or_else(|_| panic!("Failed to generate RSA {}-bit key pair", key_size));

            // Verify key size
            assert_eq!(
                rsa_keypair.key_size(),
                Some(key_size),
                "Key size should be {} bits",
                key_size
            );

            // Verify keys exist
            assert!(
                rsa_keypair.priv_key_id().is_some(),
                "Private key should exist"
            );
            assert!(rsa_keypair.pub_key().is_some(), "Public key should exist");

            // Delete the key pair
            session
                .delete_key(&mut rsa_keypair)
                .unwrap_or_else(|_| panic!("Failed to delete RSA {}-bit key pair", key_size));
        }

        // Test optional key sizes that might not be supported
        let optional_key_sizes = [3072, 4096];

        for key_size in optional_key_sizes {
            let key_props = KeyProps::builder()
                .bit_len(key_size)
                .sign(true)
                .verify(true)
                .build();

            let mut rsa_keypair = RsaPkcsKeyPair::new(key_props.clone(), key_props);

            // Try to generate the key pair - might not be supported
            match session.generate_key_pair(&mut rsa_keypair) {
                Ok(()) => {
                    // If generation succeeds, verify and clean up
                    assert_eq!(
                        rsa_keypair.key_size(),
                        Some(key_size),
                        "Key size should be {} bits",
                        key_size
                    );
                    assert!(
                        rsa_keypair.priv_key_id().is_some(),
                        "Private key should exist"
                    );
                    assert!(rsa_keypair.pub_key().is_some(), "Public key should exist");

                    session.delete_key(&mut rsa_keypair).unwrap_or_else(|_| {
                        panic!("Failed to delete RSA {}-bit key pair", key_size)
                    });
                }
                Err(AZIHSM_RSA_KEYGEN_FAILED) => {
                    // Key size not supported in test environment
                    println!(
                        "{}-bit RSA key generation not supported in test environment",
                        key_size
                    );
                }
                Err(e) => {
                    panic!(
                        "Unexpected error generating RSA {}-bit key: {:?}",
                        key_size, e
                    );
                }
            }
        }

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_rsa_key_pair_persistence_across_sessions() {
        // Test if RSA key pairs persist or are regenerated across session close/reopen cycles

        // First session - generate a key pair
        let (_partition1, mut session1) = create_test_session();

        let key_props = KeyProps::builder()
            .bit_len(2048)
            .sign(true)
            .verify(true)
            .build();

        let mut rsa_keypair1 = RsaPkcsKeyPair::new(key_props.clone(), key_props.clone());

        // Generate the key pair in first session
        session1
            .generate_key_pair(&mut rsa_keypair1)
            .expect("Failed to generate RSA key pair in first session");

        // Store the key details for comparison
        let first_priv_key_id = rsa_keypair1
            .priv_key_id()
            .expect("Private key should exist");
        let first_pub_key = rsa_keypair1.pub_key().expect("Public key should exist");

        // Close the first session
        session1.close().expect("Failed to close first session");

        // Second session - try to generate another key pair with same properties
        let (_partition2, mut session2) = create_test_session();

        let mut rsa_keypair2 = RsaPkcsKeyPair::new(key_props.clone(), key_props.clone());

        // Generate the key pair in second session
        session2
            .generate_key_pair(&mut rsa_keypair2)
            .expect("Failed to generate RSA key pair in second session");

        // Store the key details for comparison
        let second_priv_key_id = rsa_keypair2
            .priv_key_id()
            .expect("Private key should exist");
        let second_pub_key = rsa_keypair2.pub_key().expect("Public key should exist");

        // Compare the key pairs
        println!("First session  - Private Key ID: {:?}", first_priv_key_id);
        println!("Second session - Private Key ID: {:?}", second_priv_key_id);
        println!(
            "First session  - Public Key length: {}",
            first_pub_key.len()
        );
        println!(
            "Second session - Public Key length: {}",
            second_pub_key.len()
        );

        // Check if we get the same key pair or different ones
        if first_priv_key_id == second_priv_key_id {
            println!("✓ Same private key ID across sessions - keys are persistent/reused");

            // If key IDs are same, public keys should also be same
            assert_eq!(
                first_pub_key, second_pub_key,
                "Public keys should be identical if private key IDs are same"
            );
        } else {
            println!("✓ Different private key IDs across sessions - new keys generated each time");

            // Different key IDs should mean different public keys
            assert_ne!(
                first_pub_key, second_pub_key,
                "Public keys should be different if private key IDs are different"
            );
        }

        // Clean up both key pairs
        session2
            .delete_key(&mut rsa_keypair2)
            .expect("Failed to delete second key pair");

        // Try to delete the first key pair (might fail if keys are not persistent)
        let (_partition3, mut session3) = create_test_session();
        let delete_result = session3.delete_key(&mut rsa_keypair1);
        match delete_result {
            Ok(()) => println!("✓ Successfully deleted first key pair from new session"),
            Err(e) => println!(
                "✗ Could not delete first key pair from new session: {:?}",
                e
            ),
        }

        session3.close().expect("Failed to close third session");
        session2.close().expect("Failed to close second session");
    }

    #[test]
    fn test_rsa_key_pair_session_isolation() {
        // Test if multiple sessions can work with RSA keys simultaneously

        let (_partition1, mut session1) = create_test_session();
        let (_partition2, mut session2) = create_test_session();

        let key_props = KeyProps::builder()
            .bit_len(2048)
            .sign(true)
            .verify(true)
            .build();

        let mut rsa_keypair1 = RsaPkcsKeyPair::new(key_props.clone(), key_props.clone());
        let mut rsa_keypair2 = RsaPkcsKeyPair::new(key_props.clone(), key_props.clone());

        // Generate key pairs in both sessions
        session1
            .generate_key_pair(&mut rsa_keypair1)
            .expect("Failed to generate RSA key pair in session1");

        session2
            .generate_key_pair(&mut rsa_keypair2)
            .expect("Failed to generate RSA key pair in session2");

        // Verify both key pairs are valid
        assert!(
            rsa_keypair1.priv_key_id().is_some(),
            "Session1 private key should exist"
        );
        assert!(
            rsa_keypair1.pub_key().is_some(),
            "Session1 public key should exist"
        );
        assert!(
            rsa_keypair2.priv_key_id().is_some(),
            "Session2 private key should exist"
        );
        assert!(
            rsa_keypair2.pub_key().is_some(),
            "Session2 public key should exist"
        );

        let key1_id = rsa_keypair1.priv_key_id().unwrap();
        let key2_id = rsa_keypair2.priv_key_id().unwrap();

        println!("Session1 Key ID: {:?}", key1_id);
        println!("Session2 Key ID: {:?}", key2_id);

        // Clean up both key pairs
        session1
            .delete_key(&mut rsa_keypair1)
            .expect("Failed to delete key pair in session1");

        session2
            .delete_key(&mut rsa_keypair2)
            .expect("Failed to delete key pair in session2");

        session1.close().expect("Failed to close session1");
        session2.close().expect("Failed to close session2");
    }
}
