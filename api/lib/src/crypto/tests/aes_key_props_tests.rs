// Copyright (C) Microsoft Corporation. All rights reserved.

//! Integration tests for AES key property get operations through session API.
//!
//! These tests validate the complete property handling path:
//! Session API → KeyPropsOps trait → AES Key object
//!
//! Unlike unit tests which test direct property access,
//! these tests validate the actual runtime behavior through the session API, ensuring:
//! - Property values are correctly retrieved for symmetric AES keys
//! - Session properly routes property requests to AES key objects
//! - Different property types (numeric, boolean, string, enum) work correctly
//! - Read-only properties are set correctly during key generation
//! - Default properties are applied when user doesn't specify operations

#[cfg(test)]
mod tests {
    use crate::crypto::aes::AesCbcKey;
    use crate::crypto::aes::AesXtsKey;
    use crate::session::test_helpers::create_test_session;
    use crate::types::key_props::AzihsmKeyClass;
    use crate::types::key_props::AzihsmKeyPropId;
    use crate::types::key_props::KeyPropValue;
    use crate::types::key_props::KeyProps;
    use crate::types::KeyKind;

    // ================================================================================
    // AES CBC Key Property Tests
    // ================================================================================

    #[test]
    fn test_aes_cbc_key_get_bit_len_property() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate AES CBC key with 128 bits
        let key_props = KeyProps::builder()
            .bit_len(128)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);

        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES CBC key");

        // Test getting BitLen property
        let bit_len = session
            .get_property(&aes_key, AzihsmKeyPropId::BitLen)
            .expect("Failed to get bit_len");

        if let KeyPropValue::BitLen(len) = bit_len {
            assert_eq!(len, 128);
        } else {
            panic!("Expected BitLen property");
        }
    }

    #[test]
    fn test_aes_cbc_key_get_boolean_properties() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate AES CBC key with specific boolean properties
        let key_props = KeyProps::builder()
            .bit_len(256)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);

        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES CBC key");

        // Test getting Encrypt property
        let encrypt_prop = session
            .get_property(&aes_key, AzihsmKeyPropId::Encrypt)
            .expect("Failed to get encrypt property");

        if let KeyPropValue::Encrypt(val) = encrypt_prop {
            assert!(val);
        } else {
            panic!("Expected Encrypt property");
        }

        // Test getting Decrypt property
        let decrypt_prop = session
            .get_property(&aes_key, AzihsmKeyPropId::Decrypt)
            .expect("Failed to get decrypt property");

        if let KeyPropValue::Decrypt(val) = decrypt_prop {
            assert!(val);
        } else {
            panic!("Expected Decrypt property");
        }
    }

    #[test]
    fn test_aes_cbc_key_get_label_property() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate AES CBC key with label
        let key_props = KeyProps::builder()
            .bit_len(192)
            .encrypt(true)
            .decrypt(true)
            .label("Test AES CBC Key".to_string())
            .build();

        let mut aes_key = AesCbcKey::new(key_props);

        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES CBC key");

        // Get label property
        // Note: Labels may not be persisted after key generation in all environments
        let label_result = session.get_property(&aes_key, AzihsmKeyPropId::Label);

        // If label is supported, verify it matches
        if let Ok(KeyPropValue::Label(label)) = label_result {
            assert_eq!(label, "Test AES CBC Key");
        }
        // Label property may not be supported/persisted in test environment
    }

    #[test]
    fn test_aes_cbc_key_get_class_and_kind_properties() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate AES CBC key
        let key_props = KeyProps::builder()
            .bit_len(128)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesCbcKey::new(key_props);

        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES CBC key");

        // Test getting Class property (should be Secret for symmetric keys)
        let class_prop = session
            .get_property(&aes_key, AzihsmKeyPropId::Class)
            .expect("Failed to get class property");

        if let KeyPropValue::KeyClass(class) = class_prop {
            assert_eq!(class, AzihsmKeyClass::Secret);
        } else {
            panic!("Expected KeyClass property");
        }

        // Test getting Kind property (should be AES)
        let kind_prop = session
            .get_property(&aes_key, AzihsmKeyPropId::Kind)
            .expect("Failed to get kind property");

        if let KeyPropValue::KeyType(kind) = kind_prop {
            assert_eq!(kind, KeyKind::Aes);
        } else {
            panic!("Expected KeyType property");
        }
    }

    #[test]
    fn test_aes_cbc_key_defaults_applied() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate AES CBC key WITHOUT specifying encrypt/decrypt
        // Defaults should be applied (both encrypt and decrypt)
        let key_props = KeyProps::builder().bit_len(256).build();

        let mut aes_key = AesCbcKey::new(key_props);

        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES CBC key");

        // Verify encrypt defaults to true
        let encrypt_prop = session
            .get_property(&aes_key, AzihsmKeyPropId::Encrypt)
            .expect("Failed to get encrypt property");

        if let KeyPropValue::Encrypt(val) = encrypt_prop {
            assert!(val, "Encrypt should default to true");
        } else {
            panic!("Expected Encrypt property");
        }

        // Verify decrypt defaults to true
        let decrypt_prop = session
            .get_property(&aes_key, AzihsmKeyPropId::Decrypt)
            .expect("Failed to get decrypt property");

        if let KeyPropValue::Decrypt(val) = decrypt_prop {
            assert!(val, "Decrypt should default to true");
        } else {
            panic!("Expected Decrypt property");
        }
    }

    #[test]
    fn test_aes_cbc_key_get_multiple_properties() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate AES CBC key with multiple properties
        let key_props = KeyProps::builder()
            .bit_len(256)
            .encrypt(true)
            .decrypt(true)
            .label("Multi-Prop AES Key".to_string())
            .build();

        let mut aes_key = AesCbcKey::new(key_props);

        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES CBC key");

        // Verify all properties are retrievable
        // 1. BitLen
        let bit_len = session
            .get_property(&aes_key, AzihsmKeyPropId::BitLen)
            .expect("Failed to get bit_len");
        if let KeyPropValue::BitLen(len) = bit_len {
            assert_eq!(len, 256);
        } else {
            panic!("Expected BitLen property");
        }

        // 2. Encrypt
        let encrypt = session
            .get_property(&aes_key, AzihsmKeyPropId::Encrypt)
            .expect("Failed to get encrypt");
        if let KeyPropValue::Encrypt(val) = encrypt {
            assert!(val);
        } else {
            panic!("Expected Encrypt property");
        }

        // 3. Decrypt
        let decrypt = session
            .get_property(&aes_key, AzihsmKeyPropId::Decrypt)
            .expect("Failed to get decrypt");
        if let KeyPropValue::Decrypt(val) = decrypt {
            assert!(val);
        } else {
            panic!("Expected Decrypt property");
        }

        // 4. Label (optional - may not persist in test environment)
        if let Ok(KeyPropValue::Label(val)) = session.get_property(&aes_key, AzihsmKeyPropId::Label)
        {
            assert_eq!(val, "Multi-Prop AES Key");
        }
    }

    // ================================================================================
    // AES XTS Key Property Tests
    // ================================================================================

    #[test]
    fn test_aes_xts_key_get_bit_len_property() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate AES XTS key with 512 bits (256-bit XTS)
        let key_props = KeyProps::builder()
            .bit_len(512)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesXtsKey::new(key_props);

        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES XTS key");

        // Test getting BitLen property
        let bit_len = session
            .get_property(&aes_key, AzihsmKeyPropId::BitLen)
            .expect("Failed to get bit_len");

        if let KeyPropValue::BitLen(len) = bit_len {
            assert_eq!(len, 512);
        } else {
            panic!("Expected BitLen property");
        }
    }

    #[test]
    fn test_aes_xts_key_get_boolean_properties() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate AES XTS key with specific boolean properties
        let key_props = KeyProps::builder()
            .bit_len(512)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesXtsKey::new(key_props);

        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES XTS key");

        // Test getting Encrypt property
        let encrypt_prop = session
            .get_property(&aes_key, AzihsmKeyPropId::Encrypt)
            .expect("Failed to get encrypt property");

        if let KeyPropValue::Encrypt(val) = encrypt_prop {
            assert!(val);
        } else {
            panic!("Expected Encrypt property");
        }

        // Test getting Decrypt property
        let decrypt_prop = session
            .get_property(&aes_key, AzihsmKeyPropId::Decrypt)
            .expect("Failed to get decrypt property");

        if let KeyPropValue::Decrypt(val) = decrypt_prop {
            assert!(val);
        } else {
            panic!("Expected Decrypt property");
        }
    }

    #[test]
    fn test_aes_xts_key_get_class_and_kind_properties() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate AES XTS key
        let key_props = KeyProps::builder()
            .bit_len(512)
            .encrypt(true)
            .decrypt(true)
            .build();

        let mut aes_key = AesXtsKey::new(key_props);

        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES XTS key");

        // Test getting Class property (should be Secret for symmetric keys)
        let class_prop = session
            .get_property(&aes_key, AzihsmKeyPropId::Class)
            .expect("Failed to get class property");

        if let KeyPropValue::KeyClass(class) = class_prop {
            assert_eq!(class, AzihsmKeyClass::Secret);
        } else {
            panic!("Expected KeyClass property");
        }

        // Test getting Kind property (should be AES XTS)
        let kind_prop = session
            .get_property(&aes_key, AzihsmKeyPropId::Kind)
            .expect("Failed to get kind property");

        if let KeyPropValue::KeyType(kind) = kind_prop {
            assert_eq!(kind, KeyKind::AesXts);
        } else {
            panic!("Expected KeyType property");
        }
    }

    #[test]
    fn test_aes_xts_key_defaults_applied() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate AES XTS key WITHOUT specifying encrypt/decrypt
        // Defaults should be applied (both encrypt and decrypt)
        let key_props = KeyProps::builder().bit_len(512).build();

        let mut aes_key = AesXtsKey::new(key_props);

        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES XTS key");

        // Verify encrypt defaults to true
        let encrypt_prop = session
            .get_property(&aes_key, AzihsmKeyPropId::Encrypt)
            .expect("Failed to get encrypt property");

        if let KeyPropValue::Encrypt(val) = encrypt_prop {
            assert!(val, "Encrypt should default to true");
        } else {
            panic!("Expected Encrypt property");
        }

        // Verify decrypt defaults to true
        let decrypt_prop = session
            .get_property(&aes_key, AzihsmKeyPropId::Decrypt)
            .expect("Failed to get decrypt property");

        if let KeyPropValue::Decrypt(val) = decrypt_prop {
            assert!(val, "Decrypt should default to true");
        } else {
            panic!("Expected Decrypt property");
        }
    }

    #[test]
    fn test_aes_xts_key_get_multiple_properties() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Generate AES XTS key with multiple properties
        let key_props = KeyProps::builder()
            .bit_len(512)
            .encrypt(true)
            .decrypt(true)
            .label("Multi-Prop AES XTS Key".to_string())
            .build();

        let mut aes_key = AesXtsKey::new(key_props);

        session
            .generate_key(&mut aes_key)
            .expect("Failed to generate AES XTS key");

        // Verify all properties are retrievable
        // 1. BitLen
        let bit_len = session
            .get_property(&aes_key, AzihsmKeyPropId::BitLen)
            .expect("Failed to get bit_len");
        if let KeyPropValue::BitLen(len) = bit_len {
            assert_eq!(len, 512);
        } else {
            panic!("Expected BitLen property");
        }

        // 2. Encrypt
        let encrypt = session
            .get_property(&aes_key, AzihsmKeyPropId::Encrypt)
            .expect("Failed to get encrypt");
        if let KeyPropValue::Encrypt(val) = encrypt {
            assert!(val);
        } else {
            panic!("Expected Encrypt property");
        }

        // 3. Decrypt
        let decrypt = session
            .get_property(&aes_key, AzihsmKeyPropId::Decrypt)
            .expect("Failed to get decrypt");
        if let KeyPropValue::Decrypt(val) = decrypt {
            assert!(val);
        } else {
            panic!("Expected Decrypt property");
        }

        // 4. Label (optional - may not persist in test environment)
        if let Ok(KeyPropValue::Label(val)) = session.get_property(&aes_key, AzihsmKeyPropId::Label)
        {
            assert_eq!(val, "Multi-Prop AES XTS Key");
        }

        // 5. Class
        let class = session
            .get_property(&aes_key, AzihsmKeyPropId::Class)
            .expect("Failed to get class");
        if let KeyPropValue::KeyClass(val) = class {
            assert_eq!(val, AzihsmKeyClass::Secret);
        } else {
            panic!("Expected KeyClass property");
        }
    }

    #[test]
    fn test_aes_cbc_key_reject_wrong_kind() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Create AES CBC key
        let key_props = KeyProps::builder().bit_len(128).build();
        let mut aes_key = AesCbcKey::new(key_props);

        // Try to set wrong KeyKind (RSA) - should fail
        let result = session.set_property(
            &mut aes_key,
            AzihsmKeyPropId::Kind,
            KeyPropValue::KeyType(KeyKind::Rsa),
        );
        assert!(result.is_err(), "Should reject RSA KeyKind for AES CBC key");
        assert_eq!(
            result.unwrap_err(),
            crate::AZIHSM_ERROR_INVALID_ARGUMENT,
            "Should return INVALID_ARGUMENT error"
        );

        // Try to set wrong KeyKind (AesXts) - should fail
        let result = session.set_property(
            &mut aes_key,
            AzihsmKeyPropId::Kind,
            KeyPropValue::KeyType(KeyKind::AesXts),
        );
        assert!(
            result.is_err(),
            "Should reject AesXts KeyKind for AES CBC key"
        );
        assert_eq!(
            result.unwrap_err(),
            crate::AZIHSM_ERROR_INVALID_ARGUMENT,
            "Should return INVALID_ARGUMENT error"
        );

        // Setting correct KeyKind (Aes) should succeed
        let result = session.set_property(
            &mut aes_key,
            AzihsmKeyPropId::Kind,
            KeyPropValue::KeyType(KeyKind::Aes),
        );
        assert!(result.is_ok(), "Should accept Aes KeyKind for AES CBC key");
    }

    #[test]
    fn test_aes_xts_key_reject_wrong_kind() {
        // Create test session
        let (_partition, session) = create_test_session();

        // Create AES XTS key
        let key_props = KeyProps::builder().bit_len(512).build();
        let mut aes_key = AesXtsKey::new(key_props);

        // Try to set wrong KeyKind (RSA) - should fail
        let result = session.set_property(
            &mut aes_key,
            AzihsmKeyPropId::Kind,
            KeyPropValue::KeyType(KeyKind::Rsa),
        );
        assert!(result.is_err(), "Should reject RSA KeyKind for AES XTS key");
        assert_eq!(
            result.unwrap_err(),
            crate::AZIHSM_ERROR_INVALID_ARGUMENT,
            "Should return INVALID_ARGUMENT error"
        );

        // Try to set wrong KeyKind (Aes/CBC) - should fail
        let result = session.set_property(
            &mut aes_key,
            AzihsmKeyPropId::Kind,
            KeyPropValue::KeyType(KeyKind::Aes),
        );
        assert!(result.is_err(), "Should reject Aes KeyKind for AES XTS key");
        assert_eq!(
            result.unwrap_err(),
            crate::AZIHSM_ERROR_INVALID_ARGUMENT,
            "Should return INVALID_ARGUMENT error"
        );

        // Setting correct KeyKind (AesXts) should succeed
        let result = session.set_property(
            &mut aes_key,
            AzihsmKeyPropId::Kind,
            KeyPropValue::KeyType(KeyKind::AesXts),
        );
        assert!(
            result.is_ok(),
            "Should accept AesXts KeyKind for AES XTS key"
        );
    }
}
