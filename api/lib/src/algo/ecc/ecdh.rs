// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECDH (Elliptic Curve Diffie-Hellman) key derivation implementation.
//! This module provides ECDH key agreement operations using platform-specific
//! cryptographic primitives. ECDH is a key agreement protocol that allows two
//! parties to establish a shared secret over an insecure channel using elliptic curve
//! cryptography.
//!

use azihsm_crypto as crypto;
use azihsm_crypto::ImportableKey;

use super::*;

/// EcdhAlgo struct that wraps platform-specific implementations.
pub struct EcdhAlgo {
    /// The peer's public key in DER format
    peer_der: Vec<u8>,
}

impl EcdhAlgo {
    /// Creates a new ECDH operation with a peer's public key.
    ///
    /// This constructor initializes an ECDH key agreement operation that will
    /// use the provided peer public key to derive a shared secret when combined
    /// with a local private key.
    ///
    /// # Arguments
    ///
    /// * `peer_key` - Reference to the peer's ECC public key in DER format
    ///
    /// # Returns
    ///
    /// An instance of `EcdhAlgo`.
    pub fn new(peer_key: &[u8]) -> Self {
        Self {
            peer_der: peer_key.to_vec(),
        }
    }
}

impl HsmKeyDeriveOp for EcdhAlgo {
    /// Session type for this operation.
    type Session = HsmSession;

    /// The type of base key used by this operation.
    type BaseKey = HsmEccPrivateKey;

    /// The type of derived key produced by this operation.
    type DerivedKey = HsmGenericSecretKey;

    /// The error type returned by this operation.
    type Error = HsmError;

    /// Derives a shared secret using ECDH.
    ///
    /// This performs an ECDH key agreement between the provided `base_key` (local ECC private
    /// key handle) and the peer public key provided to [`EcdhAlgo::new`]. The derived secret is
    /// returned as an HSM-managed generic secret key.
    ///
    /// # Arguments
    ///
    /// * `session` - Active session used to associate the returned key.
    /// * `base_key` - Local ECC private key used for the ECDH operation.
    /// * `props` - Properties for the derived key (usage flags, lifetime, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The peer public key DER is invalid.
    /// - The base key does not expose an ECC curve, or the curve does not match the peer key.
    /// - The underlying DDI ECDH operation fails.
    fn derive_key(
        &mut self,
        session: &Self::Session,
        base_key: &Self::BaseKey,
        props: HsmKeyProps,
    ) -> Result<Self::DerivedKey, Self::Error> {
        // Make sure base key can be used for derivation
        if !base_key.can_derive() {
            Err(HsmError::InvalidKey)?;
        }

        // Parse the peer public key from DER so we can validate curve compatibility before
        // dispatching the operation to the DDI layer.
        let peer_pub_key =
            crypto::EccPublicKey::from_bytes(&self.peer_der).map_hsm_err(HsmError::InvalidKey)?;

        // Ensure the peer key curve matches the base private key curve.
        let Some(curve) = base_key.ecc_curve() else {
            return Err(HsmError::InvalidKey);
        };

        // check if shared secret size matches curve size
        if crypto::EccCurve::from(curve) != peer_pub_key.curve()
            || curve.key_size_bits() != props.bits() as usize
        {
            return Err(HsmError::InvalidArgument);
        }

        //check if props are valid for shared secret
        HsmGenericSecretKey::validate_props(&props)?;

        // Perform the ECDH derive operation via DDI.
        let (handle, props) = ddi::ecdh_derive(base_key, &self.peer_der, props)?;
        // update derived key properties based on base key properties if needed

        Ok(HsmGenericSecretKey::new(session.clone(), props, handle))
    }
}
