// Copyright (C) Microsoft Corporation. All rights reserved.

//! Credentials module
//! This is used to store credentials for vault manager and applications.

use uuid::Uuid;

/// Role enumeration
/// Values are carefully chosen to prevent single or double bit flip to cause elevation of privilege.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub(crate) enum Role {
    User = 0xAA,
}

/// Credentials structure
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Credentials {
    /// App ID
    pub(crate) id: Uuid,

    /// App Role
    pub(crate) role: Role,

    /// App PIN
    pub(crate) pin: [u8; 16],
}

impl Credentials {
    pub(crate) fn new(id: Uuid, role: Role, pin: [u8; 16]) -> Self {
        Self { id, role, pin }
    }
}

/// User Credentials structure
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct UserCredentials {
    /// Credentials
    pub(crate) credentials: Credentials,

    /// Short App ID
    pub(crate) short_app_id: u8,
}

/// Encrypted Credential structure
#[derive(Debug, Copy, Clone)]
pub struct EncryptedCredential {
    /// ID
    pub(crate) id: [u8; 16],

    /// PIN
    pub(crate) pin: [u8; 16],

    /// IV
    pub(crate) iv: [u8; 16],

    /// Nonce
    pub(crate) nonce: [u8; 32],

    /// Tag
    pub(crate) tag: [u8; 48],
}

/// Encrypted Credential structure
#[derive(Debug, Copy, Clone)]
pub struct EncryptedSessionCredential {
    /// ID
    pub(crate) id: [u8; 16],

    /// PIN
    pub(crate) pin: [u8; 16],

    /// Seed
    pub(crate) seed: [u8; 48],

    /// IV
    pub(crate) iv: [u8; 16],

    /// Nonce
    pub(crate) nonce: [u8; 32],

    /// Tag
    pub(crate) tag: [u8; 48],
}

/// Encrypted Pin structure
#[derive(Debug, Copy, Clone)]
pub struct EncryptedPin {
    /// Encrypted PIN
    pub(crate) pin: [u8; 16],

    /// IV
    pub(crate) iv: [u8; 16],

    /// Nonce
    pub(crate) nonce: [u8; 32],

    /// Tag
    pub(crate) tag: [u8; 48],
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn check_default_vault_manager_credentials() {
        let mut vault_manager_id = [
            0xBC, 0x83, 0x2F, 0x56, 0x3C, 0xAB, 0x4E, 0xE4, 0x8A, 0xAD, 0x37, 0x15, 0x25, 0x07,
            0x9C, 0xDB,
        ];
        let mut vault_manager_pin = [
            0xC8, 0xF8, 0x9F, 0x21, 0xF9, 0x01, 0x42, 0x4A, 0xB9, 0xEB, 0xD2, 0xBC, 0x75, 0x1D,
            0x85, 0xB7,
        ];

        let credentials = Credentials::new(
            Uuid::from_bytes(vault_manager_id),
            Role::User,
            vault_manager_pin,
        );

        assert_eq!(credentials.id, Uuid::from_bytes(vault_manager_id));
        assert_eq!(credentials.pin, vault_manager_pin);
        assert_eq!(credentials.role, Role::User);

        vault_manager_id[15] -= 1;
        vault_manager_pin[15] -= 1;

        assert_ne!(credentials.id, Uuid::from_bytes(vault_manager_id));
        assert_ne!(credentials.pin, vault_manager_pin);
        assert_eq!(credentials.role, Role::User);

        assert!(credentials.id.ne(&Uuid::from_bytes(vault_manager_id)));
        assert!(credentials.pin.ne(&vault_manager_pin));
        assert!(credentials.role.eq(&Role::User));
    }

    // This test helps achieve 100% test coverage
    // as debug trait is mainly used for test purposes
    #[test]
    fn test_debug_trait_print() {}
}
