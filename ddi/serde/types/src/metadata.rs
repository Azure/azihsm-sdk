// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_derive::Ddi;

use super::*;

/// DDI Target Key Metadata Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq, Default)]
#[ddi(map)]
pub struct DdiTargetKeyMetadata {
    /// Key metadata blob
    #[ddi(id = 1)]
    pub(crate) blob: [u8; 16],
}

impl DdiTargetKeyMetadata {
    const BIT_FLAG_SESSION: usize = 0;
    const BIT_FLAG_MODIFIABLE: usize = 1;
    const BIT_FLAG_ENCRYPT: usize = 2;
    const BIT_FLAG_DECRYPT: usize = 3;
    const BIT_FLAG_SIGN: usize = 4;
    const BIT_FLAG_VERIFY: usize = 5;
    const BIT_FLAG_DERIVE: usize = 6;
    const BIT_FLAG_WRAP: usize = 7;
    const BIT_FLAG_UNWRAP: usize = 8;

    fn get_bit(&self, bit: usize) -> bool {
        let index = bit / u8::BITS as usize;
        let bit = bit % u8::BITS as usize;

        (self.blob[index] & (1 << bit)) != 0
    }

    fn set_bit(&mut self, bit: usize, value: bool) {
        let index = bit / u8::BITS as usize;
        let bit = bit % u8::BITS as usize;

        if value {
            self.blob[index] |= 1 << bit;
        } else {
            self.blob[index] &= !(1 << bit);
        }
    }

    /// Flag indicating if the key is a session key.
    pub fn session(&self) -> bool {
        self.get_bit(Self::BIT_FLAG_SESSION)
    }

    /// Flag indicating if the key is modifiable.
    pub fn modifiable(&self) -> bool {
        self.get_bit(Self::BIT_FLAG_MODIFIABLE)
    }

    /// Flag indicating if the key can be used for encryption.
    pub fn encrypt(&self) -> bool {
        self.get_bit(Self::BIT_FLAG_ENCRYPT)
    }

    /// Flag indicating if the key can be used for decryption.
    pub fn decrypt(&self) -> bool {
        self.get_bit(Self::BIT_FLAG_DECRYPT)
    }

    /// Flag indicating if the key can be used for signing.
    pub fn sign(&self) -> bool {
        self.get_bit(Self::BIT_FLAG_SIGN)
    }

    /// Flag indicating if the key can be used for verification.
    pub fn verify(&self) -> bool {
        self.get_bit(Self::BIT_FLAG_VERIFY)
    }

    /// Flag indicating if the key can be used for deriving other keys.
    pub fn derive(&self) -> bool {
        self.get_bit(Self::BIT_FLAG_DERIVE)
    }

    /// Flag indicating if the key can be used for wrapping.
    pub fn wrap(&self) -> bool {
        self.get_bit(Self::BIT_FLAG_WRAP)
    }

    /// Flag indicating if the key can be used for unwrapping.
    pub fn unwrap(&self) -> bool {
        self.get_bit(Self::BIT_FLAG_UNWRAP)
    }

    /// Set flag indicating if the key is a session key.
    pub fn set_session(&mut self, value: bool) {
        self.set_bit(Self::BIT_FLAG_SESSION, value);
    }

    /// Set flag indicating if the key is modifiable.
    pub fn set_modifiable(&mut self, value: bool) {
        self.set_bit(Self::BIT_FLAG_MODIFIABLE, value);
    }

    /// Set flag indicating if the key can be used for encryption.
    pub fn set_encrypt(&mut self, value: bool) {
        self.set_bit(Self::BIT_FLAG_ENCRYPT, value);
    }

    /// Set flag indicating if the key can be used for decryption.
    pub fn set_decrypt(&mut self, value: bool) {
        self.set_bit(Self::BIT_FLAG_DECRYPT, value);
    }

    /// Set flag indicating if the key can be used for signing.
    pub fn set_sign(&mut self, value: bool) {
        self.set_bit(Self::BIT_FLAG_SIGN, value);
    }

    /// Set flag indicating if the key can be used for verification.
    pub fn set_verify(&mut self, value: bool) {
        self.set_bit(Self::BIT_FLAG_VERIFY, value);
    }

    /// Set flag indicating if the key can be used for deriving other keys.
    pub fn set_derive(&mut self, value: bool) {
        self.set_bit(Self::BIT_FLAG_DERIVE, value);
    }

    /// Set flag indicating if the key can be used for wrapping.
    pub fn set_wrap(&mut self, value: bool) {
        self.set_bit(Self::BIT_FLAG_WRAP, value);
    }

    /// Set flag indicating if the key can be used for unwrapping.
    pub fn set_unwrap(&mut self, value: bool) {
        self.set_bit(Self::BIT_FLAG_UNWRAP, value);
    }

    /// Create a new `DdiTargetKeyMetadata` with specified session flag.
    pub fn with_session(mut self, value: bool) -> Self {
        self.set_session(value);
        self
    }

    /// Create a new `DdiTargetKeyMetadata` with specified modifiable flag.
    pub fn with_modifiable(mut self, value: bool) -> Self {
        self.set_modifiable(value);
        self
    }

    /// Create a new `DdiTargetKeyMetadata` with specified encryption flag.
    pub fn with_encrypt(mut self, value: bool) -> Self {
        self.set_encrypt(value);
        self
    }

    /// Create a new `DdiTargetKeyMetadata` with specified decryption flag.
    pub fn with_decrypt(mut self, value: bool) -> Self {
        self.set_decrypt(value);
        self
    }

    /// Create a new `DdiTargetKeyMetadata` with specified signing flag.
    pub fn with_sign(mut self, value: bool) -> Self {
        self.set_sign(value);
        self
    }

    /// Create a new `DdiTargetKeyMetadata` with specified verification flag.
    pub fn with_verify(mut self, value: bool) -> Self {
        self.set_verify(value);
        self
    }

    /// Create a new `DdiTargetKeyMetadata` with specified deriving flag.
    pub fn with_derive(mut self, value: bool) -> Self {
        self.set_derive(value);
        self
    }

    /// Create a new `DdiTargetKeyMetadata` with specified wrapping flag.
    pub fn with_wrap(mut self, value: bool) -> Self {
        self.set_wrap(value);
        self
    }

    /// Create a new `DdiTargetKeyMetadata` with specified unwrapping flag.
    pub fn with_unwrap(mut self, value: bool) -> Self {
        self.set_unwrap(value);
        self
    }
}

impl TryFrom<DdiTargetKeyMetadata> for DdiKeyUsage {
    type Error = DdiTypeError;

    fn try_from(value: DdiTargetKeyMetadata) -> Result<Self, Self::Error> {
        if value.encrypt()
            && value.decrypt()
            && !value.sign()
            && !value.verify()
            && !value.derive()
            && !value.wrap()
            && !value.unwrap()
        {
            Ok(DdiKeyUsage::EncryptDecrypt)
        } else if value.sign()
            && value.verify()
            && !value.encrypt()
            && !value.decrypt()
            && !value.derive()
            && !value.wrap()
            && !value.unwrap()
        {
            Ok(DdiKeyUsage::SignVerify)
        } else if value.unwrap()
            && !value.sign()
            && !value.verify()
            && !value.encrypt()
            && !value.decrypt()
            && !value.derive()
            && !value.wrap()
        {
            Ok(DdiKeyUsage::Unwrap)
        } else if value.derive()
            && !value.sign()
            && !value.verify()
            && !value.encrypt()
            && !value.decrypt()
            && !value.wrap()
            && !value.unwrap()
        {
            Ok(DdiKeyUsage::Derive)
        } else {
            Err(DdiTypeError::InvalidArgument)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_key_metadata() {
        let mut metadata = DdiTargetKeyMetadata::default();
        metadata.set_session(true);
        metadata.set_encrypt(true);
        metadata.set_sign(true);

        assert!(metadata.session());
        assert!(metadata.encrypt());
        assert!(metadata.sign());
        assert!(!metadata.decrypt());
    }

    #[test]
    fn test_target_key_metadata_with_flags() {
        let metadata = DdiTargetKeyMetadata::default()
            .with_session(true)
            .with_encrypt(true)
            .with_sign(true);

        assert!(metadata.session());
        assert!(metadata.encrypt());
        assert!(metadata.sign());
        assert!(!metadata.decrypt());
    }
}
