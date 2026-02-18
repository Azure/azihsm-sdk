// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key-related trait definitions.
//!
//! This module defines traits for cryptographic key operations, including key generation
//! and key management. These traits provide the foundation for algorithm-specific
//! implementations.

use std::error::Error;

use super::*;

/// Marker trait for cryptographic keys.
///
/// This trait is implemented by types representing cryptographic keys.
/// It serves as a base trait that all key types must implement.
pub trait HsmKey: Clone {}

/// Marker trait for secret keys.
///
/// This trait is implemented by types representing secret cryptographic keys.
pub trait HsmSecretKey: HsmKey {}

/// Marker trait for private keys.
///
/// This trait is implemented by types representing private cryptographic keys.
pub trait HsmPrivateKey: HsmKey {
    type PublicKey: HsmPublicKey;

    /// Returns a reference to the corresponding public key.
    fn public_key(&self) -> Self::PublicKey;
}

/// Marker trait for public keys.
///
/// This trait is implemented by types representing public cryptographic keys.
pub trait HsmPublicKey: HsmKey {}

/// Marker trait for symmetric encryption keys.
///
/// This trait is implemented by types representing encryption keys.
pub trait HsmEncryptionKey: HsmKey {}

/// Marker trait for decryption keys.
///
/// This trait is implemented by types representing decryption keys.
pub trait HsmDecryptionKey: HsmKey {}

/// Marker trait for signing keys.
///
/// This trait is implemented by types representing signing keys.
pub trait HsmSigningKey: HsmKey {}

/// Marker trait for verification keys.
///
/// This trait is implemented by types representing verification keys.
pub trait HsmVerificationKey: HsmKey {}

/// Marker trait for wrapping keys.
///
/// This trait is implemented by types representing wrapping keys.
pub trait HsmWrappingKey: HsmKey {}

/// Marker trait for unwrapping keys.
///
/// This trait is implemented by types representing unwrapping keys.
pub trait HsmUnwrappingKey: HsmKey {}

/// Marker trait for derivation keys.
///
/// This trait is implemented by types representing derivation keys.
pub trait HsmDerivationKey: HsmKey {}

#[allow(private_bounds)]
#[allow(private_interfaces)]
pub trait HsmKeyCommonProps: HsmKeyPropsProvider {
    /// Returns the key class.
    fn class(&self) -> HsmKeyClass {
        self.with_props(|p| p.class())
    }

    /// Returns the key kind.
    fn kind(&self) -> HsmKeyKind {
        self.with_props(|p| p.kind())
    }

    /// Returns the key label.
    fn label(&self) -> Vec<u8> {
        self.with_props(|p| p.label().to_vec())
    }

    /// Returns the key bit length.
    fn bits(&self) -> u32 {
        self.with_props(|p| p.bits())
    }

    /// Returns the key size in bytes.
    fn size(&self) -> usize {
        self.bits().div_ceil(8) as usize
    }

    /// Returns the ECC curve if applicable.
    fn ecc_curve(&self) -> Option<HsmEccCurve> {
        self.with_props(|p| p.ecc_curve())
    }

    /// Returns the masked key.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer to write the masked key into. If `None`, only the
    ///   required size is returned.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer, or the required size if `output`
    /// is `None`.
    fn masked_key(&self, output: Option<&mut [u8]>) -> HsmResult<usize> {
        self.with_props(|p| {
            let Some(masked_key) = p.masked_key() else {
                return Err(HsmError::PropertyNotPresent);
            };
            let expected_len = masked_key.len();
            if let Some(buf) = output {
                if buf.len() != expected_len {
                    return Err(HsmError::BufferTooSmall);
                }
                buf[..expected_len].copy_from_slice(masked_key);
            }
            Ok(expected_len)
        })
    }

    /// Returns the masked key as a vector.
    fn masked_key_vec(&self) -> HsmResult<Vec<u8>> {
        let len = self.masked_key(None)?;
        let mut buf = vec![0u8; len];
        self.masked_key(Some(&mut buf))?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Returns the public key DER.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer to write the public key DER into. If `None`, only the
    ///   required size is returned.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer, or the required size if `output`
    /// is `None`.
    fn pub_key_der(&self, output: Option<&mut [u8]>) -> HsmResult<usize> {
        self.with_props(|p| {
            let Some(pub_key_der) = p.pub_key_der() else {
                return Err(HsmError::PropertyNotPresent);
            };
            let expected_len = pub_key_der.len();
            if let Some(buf) = output {
                if buf.len() != expected_len {
                    return Err(HsmError::BufferTooSmall);
                }
                buf[..expected_len].copy_from_slice(pub_key_der);
            }
            Ok(expected_len)
        })
    }

    /// Returns the public key DER as a vector.
    fn pub_key_der_vec(&self) -> HsmResult<Vec<u8>> {
        let len = self.pub_key_der(None)?;
        let mut buf = vec![0u8; len];
        self.pub_key_der(Some(&mut buf))?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Returns whether the key is a session key.
    fn is_session(&self) -> bool {
        self.with_props(|p| p.is_session())
    }

    /// Returns whether the key is a local key.
    fn is_local(&self) -> bool {
        self.with_props(|p| p.is_local())
    }

    /// Returns whether the key is sensitive.
    fn is_sensitive(&self) -> bool {
        self.with_props(|p| p.is_sensitive())
    }

    /// Returns whether the key is extractable.
    fn is_extractable(&self) -> bool {
        self.with_props(|p| p.is_extractable())
    }

    /// Returns whether the key can be used for encryption.
    fn can_encrypt(&self) -> bool {
        self.with_props(|p| p.can_encrypt())
    }

    /// Returns whether the key can be used for decryption.
    fn can_decrypt(&self) -> bool {
        self.with_props(|p| p.can_decrypt())
    }

    /// Returns whether the key can be used for signing.
    fn can_sign(&self) -> bool {
        self.with_props(|p| p.can_sign())
    }

    /// Returns whether the key can be used for verification.
    fn can_verify(&self) -> bool {
        self.with_props(|p| p.can_verify())
    }

    /// Returns whether the key can be used for wrapping.
    fn can_wrap(&self) -> bool {
        self.with_props(|p| p.can_wrap())
    }

    /// Returns whether the key can be used for unwrapping.
    fn can_unwrap(&self) -> bool {
        self.with_props(|p| p.can_unwrap())
    }

    /// Returns whether the key can be used for key derivation.
    fn can_derive(&self) -> bool {
        self.with_props(|p| p.can_derive())
    }
}

pub(crate) trait HsmKeyPropsProvider {
    fn with_props<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&HsmKeyProps) -> R;
}

/// Key generation operation trait.
///
/// Defines the interface for generating new cryptographic keys. Implementations
/// of this trait provide algorithm-specific key generation logic.
pub trait HsmKeyGenOp {
    /// The type of key generated by this operation.
    type Key: HsmKey;

    /// The session type required for key generation.
    type Session: Session;

    /// The error type returned by this operation.
    type Error: Error;

    /// Generates a new cryptographic key.
    ///
    /// Creates a new key with the specified properties within the context
    /// of the provided session.
    ///
    /// # Arguments
    ///
    /// * `session` - The session context in which to generate the key
    /// * `props` - Key properties specifying the desired key attributes
    ///
    /// # Returns
    ///
    /// Returns the newly generated key on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key properties are invalid or unsupported
    /// - The session is invalid or expired
    /// - The underlying cryptographic operation fails
    fn generate_key(
        &mut self,
        session: &Self::Session,
        props: HsmKeyProps,
    ) -> Result<Self::Key, Self::Error>;
}

/// key Deriver operation trait.
pub trait HsmKeyDeriveOp {
    /// Session type required for key derivation.
    type Session: Session;

    /// The type of base key used by this operation.
    type BaseKey: HsmDerivationKey;

    /// The type of derived key produced by this operation.
    type DerivedKey: HsmKey;

    /// The error type returned by this operation.
    type Error: Error;

    /// Derives a new key from an existing base key.
    ///
    /// Creates a new derived key based on the provided base key and
    /// derivation properties within the context of the provided session.
    ///
    /// # Arguments
    ///
    /// * `session` - The session context in which to derive the key
    /// * `props` - Key properties specifying the desired attributes of the derived key
    ///
    /// # Returns
    ///
    /// Returns the newly derived key on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The base key is invalid or incompatible for derivation    
    /// - The derivation properties are invalid or unsupported
    /// - The session is invalid or expired
    /// - The underlying cryptographic operation fails
    fn derive_key(
        &mut self,
        session: &Self::Session,
        base_key: &Self::BaseKey,
        props: HsmKeyProps,
    ) -> Result<Self::DerivedKey, Self::Error>;
}

/// Key pair generation operation trait.
///
/// Defines the interface for generating asymmetric cryptographic key pairs.
/// Implementations of this trait provide algorithm-specific key pair generation
/// logic for asymmetric algorithms like RSA and EC.
pub trait HsmKeyPairGenOp {
    /// The type of private key generated by this operation.
    type PrivateKey: HsmPrivateKey;

    /// The session type required for key pair generation.
    type Session: Session;

    /// The error type returned by this operation.
    type Error: Error;

    /// Generates a new asymmetric key pair.
    ///
    /// Creates a new public/private key pair with the specified properties
    /// within the context of the provided session.
    ///
    /// # Arguments
    ///
    /// * `session` - The session context in which to generate the key pair
    /// * `priv_key_props` - Key properties for the private key
    /// * `pub_key_props` - Key properties for the public key
    ///
    /// # Returns
    ///
    /// Returns a tuple containing both the private key and public key on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key properties are invalid or unsupported
    /// - The session is invalid or expired
    /// - The underlying cryptographic operation fails
    /// - The public and private key properties are incompatible
    fn generate_key_pair(
        &mut self,
        session: &Self::Session,
        priv_key_props: HsmKeyProps,
        pub_key_props: HsmKeyProps,
    ) -> Result<
        (
            Self::PrivateKey,
            <Self::PrivateKey as HsmPrivateKey>::PublicKey,
        ),
        Self::Error,
    >;
}

/// Key unwrapping operation trait.
pub trait HsmKeyUnwrapOp {
    type UnwrappingKey: HsmUnwrappingKey;
    type Key: HsmSecretKey;
    type Error: Error;

    /// Unwraps (decrypts) a wrapped key using this key.
    ///
    /// # Arguments
    ///
    /// * `session` - The session context in which to perform the unwrapping operation
    /// * `unwrapping_key` - The key used to unwrap the wrapped key
    /// * `wrapped_key` - The wrapped key data to be unwrapped
    /// * `key_props` - Key properties to apply to the unwrapped key
    ///
    /// # Returns
    ///
    /// Returns the unwrapped key on success.
    fn unwrap_key(
        &mut self,
        unwrapping_key: &Self::UnwrappingKey,
        wrapped_key: &[u8],
        key_props: HsmKeyProps,
    ) -> Result<Self::Key, Self::Error>;
}

pub trait HsmKeyPairUnwrapOp {
    type UnwrappingKey: HsmUnwrappingKey;
    type PrivateKey: HsmPrivateKey;
    type Error: Error;

    /// Unwraps (decrypts) a wrapped key pair using this key.
    ///
    /// # Arguments
    ///
    /// * `session` - The session context in which to perform the unwrapping operation
    /// * `unwrapping_key` - The key used to unwrap the wrapped key pair
    /// * `wrapped_priv_key` - The wrapped private key data to be unwrapped
    /// * `wrapped_pub_key` - The wrapped public key data to be unwrapped
    /// * `priv_key_props` - Key properties to apply to the unwrapped private key
    /// * `pub_key_props` - Key properties to apply to the unwrapped public key
    ///
    /// # Returns
    ///
    /// Returns a tuple containing the unwrapped private key and public key on success.
    fn unwrap_key_pair(
        &mut self,
        unwrapping_key: &Self::UnwrappingKey,
        wrapped_key: &[u8],
        priv_key_props: HsmKeyProps,
        pub_key_props: HsmKeyProps,
    ) -> Result<
        (
            Self::PrivateKey,
            <Self::PrivateKey as HsmPrivateKey>::PublicKey,
        ),
        Self::Error,
    >;
}

/// Key unmasking operation trait.
pub trait HsmKeyUnmaskOp {
    type Session: Session;
    type Key: HsmSecretKey;
    type Error: Error;

    /// Unmasks a masked key.
    ///
    /// # Arguments
    ///
    /// * `session` - The session context in which to perform the unmasking operation
    /// * `masked_key` - The masked key data to be unmasked
    ///
    /// # Returns
    ///
    /// Returns the unmasked key on success.
    fn unmask_key(
        &mut self,
        session: &Self::Session,
        masked_key: &[u8],
    ) -> Result<Self::Key, Self::Error>;
}

/// Key pair unmasking operation trait.
pub trait HsmKeyPairUnmaskOp {
    type Session: Session;
    type PrivateKey: HsmPrivateKey;
    type Error: Error;

    /// Unmasks a masked key pair.
    ///
    /// # Arguments
    ///
    /// * `session` - The session context in which to perform the unmasking operation
    /// * `masked_key` - The masked key pair data to be unmasked
    ///
    /// # Returns
    ///
    /// Returns a tuple containing the unmasked private key and public key on success.
    fn unmask_key_pair(
        &mut self,
        session: &Self::Session,
        masked_key: &[u8],
    ) -> Result<
        (
            Self::PrivateKey,
            <Self::PrivateKey as HsmPrivateKey>::PublicKey,
        ),
        Self::Error,
    >;
}

/// Key deletion operation trait.
///
/// Defines the interface for securely deleting cryptographic keys. Implementations
/// of this trait provide algorithm-specific key deletion logic, ensuring proper
/// cleanup of key material from the HSM.
pub trait HsmKeyDeleteOp {
    /// The error type returned by this operation.
    ///
    /// This associated type represents errors that may occur during key deletion.
    /// It must implement the standard [`Error`] trait.
    type Error: Error;

    /// Deletes the cryptographic key.
    ///
    /// Securely removes the key and its associated material from the HSM.
    /// This method consumes the key, ensuring it cannot be used after deletion.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The key was successfully deleted
    /// * `Err(Self::Error)` - An error occurred during deletion
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid or already deleted
    /// - The underlying HSM operation fails
    /// - Insufficient permissions to delete the key
    fn delete_key(self) -> Result<(), Self::Error>;
}

/// Key report generation operation trait.
pub trait HsmKeyReportOp {
    type Error: Error;

    /// Generates a key report for the specified key.
    ///
    /// # Arguments
    ///
    /// * `report_data` - Custom data to include in the key report.
    /// * `report` - Optional output buffer to write the key report into.
    ///   If `None`, the method will return the required buffer size.
    ///
    /// # Returns
    ///
    /// Returns the size of the key report on success.
    fn generate_key_report(
        &self,
        report_data: &[u8],
        report: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error>;
}
