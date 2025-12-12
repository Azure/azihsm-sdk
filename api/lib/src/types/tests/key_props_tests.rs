// Copyright (C) Microsoft Corporation. All rights reserved.

use strum::EnumCount;

use crate::types::key_props::*;
use crate::*;

#[test]
fn test_key_props_new() {
    let props = KeyProps::new();

    // All properties should be None initially
    assert_eq!(props.class(), None);
    assert_eq!(props.kind(), None);
    assert_eq!(props.session(), None);
    assert_eq!(props.private(), None);
    assert_eq!(props.modifiable(), None);
    assert_eq!(props.copyable(), None);
    assert_eq!(props.destroyable(), None);
    assert_eq!(props.local(), None);
    assert_eq!(props.sensitive(), None);
    assert_eq!(props.always_sensitive(), None);
    assert_eq!(props.extractable(), None);
    assert_eq!(props.never_extractable(), None);
    assert_eq!(props.trusted(), None);
    assert_eq!(props.wrap_with_trusted(), None);
    assert_eq!(props.encrypt(), None);
    assert_eq!(props.decrypt(), None);
    assert_eq!(props.sign(), None);
    assert_eq!(props.verify(), None);
    assert_eq!(props.wrap(), None);
    assert_eq!(props.unwrap(), None);
    assert_eq!(props.derive(), None);
    assert_eq!(props.bit_len(), None);
    assert_eq!(props.label(), None);
}

#[test]
fn test_key_props_setters_and_getters() {
    let mut props = KeyProps::new();

    // Test class
    props.set_class(AzihsmKeyClass::Private);
    assert_eq!(props.class(), Some(AzihsmKeyClass::Private));

    // Test kind
    props.set_kind(KeyKind::Rsa);
    assert_eq!(props.kind(), Some(KeyKind::Rsa));

    // Test boolean properties
    props.set_session(true);
    assert_eq!(props.session(), Some(true));

    props.set_private(false);
    assert_eq!(props.private(), Some(false));

    props.set_modifiable(true);
    assert_eq!(props.modifiable(), Some(true));

    props.set_copyable(false);
    assert_eq!(props.copyable(), Some(false));

    props.set_destroyable(true);
    assert_eq!(props.destroyable(), Some(true));

    props.set_local(false);
    assert_eq!(props.local(), Some(false));

    props.set_sensitive(true);
    assert_eq!(props.sensitive(), Some(true));

    props.set_always_sensitive(false);
    assert_eq!(props.always_sensitive(), Some(false));

    props.set_extractable(true);
    assert_eq!(props.extractable(), Some(true));

    props.set_never_extractable(false);
    assert_eq!(props.never_extractable(), Some(false));

    props.set_trusted(true);
    assert_eq!(props.trusted(), Some(true));

    props.set_wrap_with_trusted(false);
    assert_eq!(props.wrap_with_trusted(), Some(false));

    props.set_encrypt(true);
    assert_eq!(props.encrypt(), Some(true));

    props.set_decrypt(false);
    assert_eq!(props.decrypt(), Some(false));

    props.set_sign(true);
    assert_eq!(props.sign(), Some(true));

    props.set_verify(false);
    assert_eq!(props.verify(), Some(false));

    props.set_wrap(true);
    assert_eq!(props.wrap(), Some(true));

    props.set_unwrap(false);
    assert_eq!(props.unwrap(), Some(false));

    props.set_derive(true);
    assert_eq!(props.derive(), Some(true));

    // Test numeric property
    props.set_bit_len(2048);
    assert_eq!(props.bit_len(), Some(2048));

    // Test string property
    props.set_label("Test Key".to_string());
    assert_eq!(props.label(), Some(&"Test Key".to_string()));
}

#[test]
fn test_key_class_enum() {
    assert_eq!(AzihsmKeyClass::Private as u32, 1);
    assert_eq!(AzihsmKeyClass::Public as u32, 2);
    assert_eq!(AzihsmKeyClass::Secret as u32, 3);
}

#[test]
fn test_key_kind_enum() {
    assert_eq!(KeyKind::Rsa as u32, 1);
    assert_eq!(KeyKind::Ec as u32, 2);
    assert_eq!(KeyKind::Aes as u32, 3);
    assert_eq!(KeyKind::AesXts as u32, 4);
    assert_eq!(KeyKind::Generic as u32, 5);
    assert_eq!(KeyKind::HmacSha1 as u32, 6);
    assert_eq!(KeyKind::HmacSha256 as u32, 7);
    assert_eq!(KeyKind::HmacSha384 as u32, 8);
    assert_eq!(KeyKind::HmacSha512 as u32, 9);
    assert_eq!(KeyKind::Masking as u32, 10);
}

#[test]
fn test_key_prop_id_enum() {
    assert_eq!(AzihsmKeyPropId::Class as u32, 1);
    assert_eq!(AzihsmKeyPropId::Kind as u32, 2);
    assert_eq!(AzihsmKeyPropId::Session as u32, 3);
    assert_eq!(AzihsmKeyPropId::Private as u32, 4);
    assert_eq!(AzihsmKeyPropId::Label as u32, 26);

    // Test enum count
    assert_eq!(AzihsmKeyPropId::COUNT, 26);
}

#[test]
fn test_from_repr_key_class() {
    assert_eq!(AzihsmKeyClass::from_repr(1), Some(AzihsmKeyClass::Private));
    assert_eq!(AzihsmKeyClass::from_repr(2), Some(AzihsmKeyClass::Public));
    assert_eq!(AzihsmKeyClass::from_repr(3), Some(AzihsmKeyClass::Secret));
    assert_eq!(AzihsmKeyClass::from_repr(999), None);
}

#[test]
fn test_from_repr_key_kind() {
    assert_eq!(KeyKind::from_repr(1), Some(KeyKind::Rsa));
    assert_eq!(KeyKind::from_repr(2), Some(KeyKind::Ec));
    assert_eq!(KeyKind::from_repr(3), Some(KeyKind::Aes));
    assert_eq!(KeyKind::from_repr(999), None);
}

#[test]
fn test_from_repr_key_prop_id() {
    assert_eq!(AzihsmKeyPropId::from_repr(1), Some(AzihsmKeyPropId::Class));
    assert_eq!(AzihsmKeyPropId::from_repr(2), Some(AzihsmKeyPropId::Kind));
    assert_eq!(AzihsmKeyPropId::from_repr(26), Some(AzihsmKeyPropId::Label));
    assert_eq!(AzihsmKeyPropId::from_repr(999), None);
}

#[test]
fn test_builder_pattern() {
    let props = KeyProps::builder()
        .bit_len(2048)
        .encrypt(true)
        .decrypt(true)
        .sign(true)
        .verify(false)
        .label("RSA Private Key".to_string())
        .build();

    // Only test settable properties via builder
    assert_eq!(props.bit_len(), Some(2048));
    assert_eq!(props.encrypt(), Some(true));
    assert_eq!(props.decrypt(), Some(true));
    assert_eq!(props.sign(), Some(true));
    assert_eq!(props.verify(), Some(false));
    assert_eq!(props.label(), Some(&"RSA Private Key".to_string()));

    // Non-settable properties should be None
    assert_eq!(props.class(), None);
    assert_eq!(props.kind(), None);
    assert_eq!(props.sensitive(), None);
    assert_eq!(props.extractable(), None);
}

#[test]
fn test_builder_chaining() {
    let builder = KeyProps::builder();
    let builder = builder.session(true);
    let builder = builder.bit_len(256);
    let props = builder.build();

    assert_eq!(props.session(), Some(true));
    assert_eq!(props.bit_len(), Some(256));

    // Non-settable properties should be None
    assert_eq!(props.class(), None);
    assert_eq!(props.kind(), None);
}

#[test]
fn test_settable_properties_only() {
    let props = KeyProps::builder()
        .session(false)
        .modifiable(true)
        .encrypt(true)
        .decrypt(true)
        .sign(false)
        .verify(true)
        .wrap(false)
        .unwrap(true)
        .derive(false)
        .bit_len(256)
        .label("AES-256 Key".to_string())
        .build();

    // Test only settable properties
    assert_eq!(props.session(), Some(false));
    assert_eq!(props.modifiable(), Some(true));
    assert_eq!(props.encrypt(), Some(true));
    assert_eq!(props.decrypt(), Some(true));
    assert_eq!(props.sign(), Some(false));
    assert_eq!(props.verify(), Some(true));
    assert_eq!(props.wrap(), Some(false));
    assert_eq!(props.unwrap(), Some(true));
    assert_eq!(props.derive(), Some(false));
    assert_eq!(props.bit_len(), Some(256));
    assert_eq!(props.label(), Some(&"AES-256 Key".to_string()));

    // Non-settable properties should be None
    assert_eq!(props.class(), None);
    assert_eq!(props.kind(), None);
    assert_eq!(props.private(), None);
    assert_eq!(props.copyable(), None);
    assert_eq!(props.destroyable(), None);
    assert_eq!(props.local(), None);
    assert_eq!(props.sensitive(), None);
    assert_eq!(props.always_sensitive(), None);
    assert_eq!(props.extractable(), None);
    assert_eq!(props.never_extractable(), None);
    assert_eq!(props.trusted(), None);
    assert_eq!(props.wrap_with_trusted(), None);
}

#[test]
fn test_direct_property_setting() {
    // Test direct property setting (used internally, not via builder)
    let mut props = KeyProps::new();

    // Set non-settable properties directly
    props.set_class(AzihsmKeyClass::Secret);
    props.set_kind(KeyKind::Aes);
    props.set_private(false);
    props.set_copyable(false);
    props.set_destroyable(true);
    props.set_local(true);
    props.set_sensitive(true);
    props.set_always_sensitive(true);
    props.set_extractable(false);
    props.set_never_extractable(true);
    props.set_trusted(false);
    props.set_wrap_with_trusted(false);

    // Set settable properties
    props.set_session(false);
    props.set_modifiable(false);
    props.set_encrypt(true);
    props.set_decrypt(true);
    props.set_bit_len(256);
    props.set_label("Test AES Key".to_string());

    // Verify all properties
    assert_eq!(props.class(), Some(AzihsmKeyClass::Secret));
    assert_eq!(props.kind(), Some(KeyKind::Aes));
    assert_eq!(props.private(), Some(false));
    assert_eq!(props.copyable(), Some(false));
    assert_eq!(props.destroyable(), Some(true));
    assert_eq!(props.local(), Some(true));
    assert_eq!(props.sensitive(), Some(true));
    assert_eq!(props.always_sensitive(), Some(true));
    assert_eq!(props.extractable(), Some(false));
    assert_eq!(props.never_extractable(), Some(true));
    assert_eq!(props.trusted(), Some(false));
    assert_eq!(props.wrap_with_trusted(), Some(false));
    assert_eq!(props.session(), Some(false));
    assert_eq!(props.modifiable(), Some(false));
    assert_eq!(props.encrypt(), Some(true));
    assert_eq!(props.decrypt(), Some(true));
    assert_eq!(props.bit_len(), Some(256));
    assert_eq!(props.label(), Some(&"Test AES Key".to_string()));
}

#[test]
fn test_bit_len_string_conversion() {
    let mut props = KeyProps::new();

    // Test various bit lengths
    props.set_bit_len(128);
    assert_eq!(props.bit_len(), Some(128));

    props.set_bit_len(256);
    assert_eq!(props.bit_len(), Some(256));

    props.set_bit_len(2048);
    assert_eq!(props.bit_len(), Some(2048));

    props.set_bit_len(4096);
    assert_eq!(props.bit_len(), Some(4096));
}

#[test]
fn test_empty_builder() {
    let props = KeyProps::builder().build();

    // Should be equivalent to KeyProps::new()
    assert_eq!(props.class(), None);
    assert_eq!(props.kind(), None);
    assert_eq!(props.bit_len(), None);
    assert_eq!(props.label(), None);
}

#[test]
fn test_partial_builder() {
    let props = KeyProps::builder().encrypt(true).bit_len(2048).build();

    assert_eq!(props.encrypt(), Some(true));
    assert_eq!(props.bit_len(), Some(2048));

    // Other properties should remain None
    assert_eq!(props.class(), None);
    assert_eq!(props.kind(), None);
    assert_eq!(props.decrypt(), None);
    assert_eq!(props.label(), None);
}

#[test]
fn test_key_prop_value_clone() {
    let value1 = KeyPropValue::Boolean(true);
    let value2 = value1.clone();
    assert_eq!(value1, value2);

    let value3 = KeyPropValue::KeyClass(AzihsmKeyClass::Private);
    let value4 = value3.clone();
    assert_eq!(value3, value4);

    let value5 = KeyPropValue::String("test".to_string());
    let value6 = value5.clone();
    assert_eq!(value5, value6);
}

#[test]
fn test_comprehensive_key_scenario() {
    // Test a comprehensive scenario with mixed settable/non-settable properties
    let mut props = KeyProps::new();

    // Set non-settable properties
    props.set_class(AzihsmKeyClass::Private);
    props.set_kind(KeyKind::Rsa);
    props.set_private(true);
    props.set_copyable(false);
    props.set_destroyable(true);
    props.set_local(true);
    props.set_sensitive(true);
    props.set_always_sensitive(true);
    props.set_extractable(false);
    props.set_never_extractable(true);
    props.set_trusted(true);
    props.set_wrap_with_trusted(true);

    // Set settable properties (user configurable)
    props.set_session(false);
    props.set_modifiable(false);
    props.set_encrypt(false); // Private key typically doesn't encrypt
    props.set_decrypt(true);
    props.set_sign(true);
    props.set_verify(false); // Private key typically doesn't verify
    props.set_wrap(false);
    props.set_unwrap(true);
    props.set_derive(false);
    props.set_bit_len(2048);
    props.set_label("Production RSA-2048 Private Key".to_string());

    // Verify all properties
    assert_eq!(props.class(), Some(AzihsmKeyClass::Private));
    assert_eq!(props.kind(), Some(KeyKind::Rsa));
    assert_eq!(props.bit_len(), Some(2048));
    assert_eq!(props.private(), Some(true));
    assert_eq!(props.sensitive(), Some(true));
    assert_eq!(props.always_sensitive(), Some(true));
    assert_eq!(props.extractable(), Some(false));
    assert_eq!(props.never_extractable(), Some(true));
    assert_eq!(props.local(), Some(true));
    assert_eq!(props.modifiable(), Some(false));
    assert_eq!(props.copyable(), Some(false));
    assert_eq!(props.destroyable(), Some(true));
    assert_eq!(props.trusted(), Some(true));
    assert_eq!(props.wrap_with_trusted(), Some(true));
    assert_eq!(props.encrypt(), Some(false));
    assert_eq!(props.decrypt(), Some(true));
    assert_eq!(props.sign(), Some(true));
    assert_eq!(props.verify(), Some(false));
    assert_eq!(props.wrap(), Some(false));
    assert_eq!(props.unwrap(), Some(true));
    assert_eq!(props.derive(), Some(false));
    assert_eq!(
        props.label(),
        Some(&"Production RSA-2048 Private Key".to_string())
    );
}

#[test]
fn test_immutable_properties() {
    let mut props = KeyProps::new();

    // First set of BitLen should succeed
    let result = props.set_property(AzihsmKeyPropId::BitLen, KeyPropValue::BitLen(2048));
    assert!(result.is_ok());

    // Verify the value was set
    let value = props.get_property(AzihsmKeyPropId::BitLen).unwrap();
    match value {
        KeyPropValue::BitLen(len) => assert_eq!(len, 2048),
        _ => panic!("Expected BitLen value"),
    }

    // Second set of BitLen should fail (property is now immutable)
    let result = props.set_property(AzihsmKeyPropId::BitLen, KeyPropValue::BitLen(4096));
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), AZIHSM_ILLEGAL_KEY_PROPERTY_OPERATION);

    // Verify the value was not changed
    let value = props.get_property(AzihsmKeyPropId::BitLen).unwrap();
    match value {
        KeyPropValue::BitLen(len) => assert_eq!(len, 2048), // Still 2048, not 4096
        _ => panic!("Expected BitLen value"),
    }

    // Test with other immutable properties
    // Note: Kind and Class are read-only properties that can only be set internally via set_kind/set_class
    // They are not user-settable, so we test them using internal setters
    props.set_kind(KeyKind::Rsa);
    // Verify Kind was set
    assert_eq!(props.kind(), Some(KeyKind::Rsa));
    // Attempting to set Kind again via internal setter will overwrite (no immutability check in internal setter)
    // But attempting to set via public API should fail
    assert!(props
        .set_property(AzihsmKeyPropId::Kind, KeyPropValue::KeyType(KeyKind::Aes))
        .is_err());

    props.set_class(AzihsmKeyClass::Private);
    // Verify Class was set
    assert_eq!(props.class(), Some(AzihsmKeyClass::Private));
    // Attempting to set via public API should fail
    assert!(props
        .set_property(
            AzihsmKeyPropId::Class,
            KeyPropValue::KeyClass(AzihsmKeyClass::Secret)
        )
        .is_err());

    // EcCurve is both settable AND immutable (user can set once during key creation)
    props
        .set_property(
            AzihsmKeyPropId::EcCurve,
            KeyPropValue::EcCurve(EcCurve::P256),
        )
        .unwrap();
    assert!(props
        .set_property(
            AzihsmKeyPropId::EcCurve,
            KeyPropValue::EcCurve(EcCurve::P384)
        )
        .is_err());

    // Verify mutable properties can still be changed
    props
        .set_property(AzihsmKeyPropId::Session, KeyPropValue::Boolean(true))
        .unwrap();
    props
        .set_property(AzihsmKeyPropId::Session, KeyPropValue::Boolean(false))
        .unwrap(); // Should succeed
    let value = props.get_property(AzihsmKeyPropId::Session).unwrap();
    match value {
        KeyPropValue::Boolean(val) => assert_eq!(val, false),
        _ => panic!("Expected Boolean value"),
    }
}
