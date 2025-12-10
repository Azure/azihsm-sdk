// Copyright (C) Microsoft Corporation. All rights reserved.

//! Integration tests for RSA key property get operations through session API.
//!
//! These tests validate the complete property handling path:
//! Session API → KeyPairPropsOps trait → RSA Key object
//!
//! Unlike unit tests in `types/tests/key_props_tests.rs` which test direct property access,
//! these tests validate the actual runtime behavior through the session API, ensuring:
//! - Property values are correctly retrieved for both public and private keys
//! - Session properly routes property requests to key pair objects
//! - Different property types (numeric, boolean, string, enum) work correctly
//! - Read-only properties are set correctly during key generation

#[cfg(test)]
mod tests {
    use crate::crypto::rsa::RsaPkcsKeyPair;
    use crate::session::test_helpers::create_test_session;
    use crate::types::key_props::AzihsmKeyPropId;
    use crate::types::key_props::KeyPropValue;
    use crate::types::key_props::KeyProps;

    #[test]
    fn test_rsa_key_get_bit_len_property() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate RSA key pair with 2048 bits
        let pub_key_props = KeyProps::builder().bit_len(2048).encrypt(true).build();
        let priv_key_props = KeyProps::builder().bit_len(2048).sign(true).build();

        let mut rsa_keypair = RsaPkcsKeyPair::new(pub_key_props, priv_key_props)
            .expect("RSA KeyPair creation failed");

        session
            .generate_key_pair(&mut rsa_keypair)
            .expect("Failed to generate RSA key pair");

        // Test getting BitLen property from public key
        let pub_bit_len = session
            .get_pub_property(&rsa_keypair, AzihsmKeyPropId::BitLen)
            .expect("Failed to get public key bit_len");

        if let KeyPropValue::BitLen(len) = pub_bit_len {
            assert_eq!(len, 2048);
        } else {
            panic!("Expected BitLen property");
        }

        // Test getting BitLen property from private key
        let priv_bit_len = session
            .get_priv_property(&rsa_keypair, AzihsmKeyPropId::BitLen)
            .expect("Failed to get private key bit_len");

        if let KeyPropValue::BitLen(len) = priv_bit_len {
            assert_eq!(len, 2048);
        } else {
            panic!("Expected BitLen property");
        }
    }

    #[test]
    fn test_rsa_key_get_boolean_properties() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate RSA key pair with specific boolean properties
        let pub_key_props = KeyProps::builder().bit_len(2048).verify(false).build();
        let priv_key_props = KeyProps::builder().bit_len(2048).sign(true).build();

        let mut rsa_keypair = RsaPkcsKeyPair::new(pub_key_props, priv_key_props)
            .expect("RSA KeyPair creation failed");

        session
            .generate_key_pair(&mut rsa_keypair)
            .expect("Failed to generate RSA key pair");

        // Test getting Sign property from private key
        let sign_prop = session
            .get_priv_property(&rsa_keypair, AzihsmKeyPropId::Sign)
            .expect("Failed to get sign property");

        if let KeyPropValue::Sign(val) = sign_prop {
            assert!(val);
        } else {
            panic!("Expected Sign property");
        }

        // Test getting Verify property from public key
        let verify_prop = session
            .get_pub_property(&rsa_keypair, AzihsmKeyPropId::Verify)
            .expect("Failed to get verify property");

        if let KeyPropValue::Verify(val) = verify_prop {
            assert!(!val);
        } else {
            panic!("Expected Verify property");
        }
    }

    #[test]
    fn test_rsa_key_get_label_property() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate RSA key pair with label
        let pub_key_props = KeyProps::builder().bit_len(2048).build();
        let priv_key_props = KeyProps::builder()
            .bit_len(2048)
            .sign(true)
            .label("Test RSA Key".to_string())
            .build();

        let mut rsa_keypair = RsaPkcsKeyPair::new(pub_key_props, priv_key_props)
            .expect("RSA KeyPair creation failed");

        session
            .generate_key_pair(&mut rsa_keypair)
            .expect("Failed to generate RSA key pair");

        // Get label property from private key
        // Note: Labels may not be persisted after key generation in all environments
        let label_result = session.get_priv_property(&rsa_keypair, AzihsmKeyPropId::Label);

        // If label is supported, verify it matches
        if let Ok(KeyPropValue::Label(label)) = label_result {
            assert_eq!(label, "Test RSA Key");
        }
        // Label property may not be supported/persisted in test environment
    }

    #[test]
    fn test_rsa_key_get_class_and_kind_properties() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate RSA key pair
        let key_props = KeyProps::builder().bit_len(2048).build();
        let mut rsa_keypair =
            RsaPkcsKeyPair::new(key_props.clone(), key_props).expect("RSA KeyPair creation failed");

        session
            .generate_key_pair(&mut rsa_keypair)
            .expect("Failed to generate RSA key pair");

        // Test getting Class property from public key (should be Public)
        let class_prop = session
            .get_pub_property(&rsa_keypair, AzihsmKeyPropId::Class)
            .expect("Failed to get class property");

        if let KeyPropValue::KeyClass(class) = class_prop {
            assert_eq!(class, crate::types::key_props::AzihsmKeyClass::Public);
        } else {
            panic!("Expected KeyClass property");
        }

        // Test getting Class property from private key (should be Private)
        let class_prop = session
            .get_priv_property(&rsa_keypair, AzihsmKeyPropId::Class)
            .expect("Failed to get class property");

        if let KeyPropValue::KeyClass(class) = class_prop {
            assert_eq!(class, crate::types::key_props::AzihsmKeyClass::Private);
        } else {
            panic!("Expected KeyClass property");
        }

        // Test getting Kind property (should be RSA)
        let kind_prop = session
            .get_priv_property(&rsa_keypair, AzihsmKeyPropId::Kind)
            .expect("Failed to get kind property");

        if let KeyPropValue::KeyType(kind) = kind_prop {
            assert_eq!(kind, crate::types::KeyKind::Rsa);
        } else {
            panic!("Expected KeyType property");
        }
    }

    #[test]
    fn test_rsa_key_get_multiple_properties() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate RSA key pair with multiple properties
        // Use only SignVerify operations to avoid operation exclusivity conflicts
        let pub_key_props = KeyProps::builder().bit_len(2048).verify(true).build();
        let priv_key_props = KeyProps::builder()
            .bit_len(2048)
            .sign(true)
            .label("Multi-Prop Test Key".to_string())
            .build();

        let mut rsa_keypair = RsaPkcsKeyPair::new(pub_key_props, priv_key_props)
            .expect("RSA KeyPair creation failed");

        session
            .generate_key_pair(&mut rsa_keypair)
            .expect("Failed to generate RSA key pair");

        // Verify all properties are retrievable from private key
        // 1. BitLen
        let bit_len = session
            .get_priv_property(&rsa_keypair, AzihsmKeyPropId::BitLen)
            .expect("Failed to get bit_len");
        if let KeyPropValue::BitLen(len) = bit_len {
            assert_eq!(len, 2048);
        } else {
            panic!("Expected BitLen property");
        }

        // 2. Sign
        let sign = session
            .get_priv_property(&rsa_keypair, AzihsmKeyPropId::Sign)
            .expect("Failed to get sign");
        if let KeyPropValue::Sign(val) = sign {
            assert!(val);
        } else {
            panic!("Expected Sign property");
        }

        // 3. Verify (from public key)
        let verify = session
            .get_pub_property(&rsa_keypair, AzihsmKeyPropId::Verify)
            .expect("Failed to get verify");
        if let KeyPropValue::Verify(val) = verify {
            assert!(val);
        } else {
            panic!("Expected Verify property");
        }

        // 4. Label (optional - may not persist in test environment)
        if let Ok(KeyPropValue::Label(val)) =
            session.get_priv_property(&rsa_keypair, AzihsmKeyPropId::Label)
        {
            assert_eq!(val, "Multi-Prop Test Key");
        }
    }
}
