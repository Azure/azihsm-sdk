// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate store types and traits.
//!
//! Defines the [`CertificateStore`] trait for retrieving certificate chains
//! associated with partition/slot pairs.

use super::*;

/// Metadata about a certificate chain for a partition slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertChainInfo {
    /// Number of certificates in the chain.
    pub count: u8,

    /// SHA-256 thumbprint of the leaf certificate.
    pub thumbprint: [u8; 32],
}

/// Certificate store interface.
///
/// Provides methods for retrieving certificate chains for partitions.
pub trait HsmCertStore {
    /// Returns the certificate chain information for the given partition and slot.
    ///
    /// # Parameters
    ///
    /// - `part_id` — Partition index.
    /// - `slot_id` — Slot index.
    ///
    /// # Returns
    ///
    /// A [`CertChainInfo`] containing the chain length and leaf thumbprint.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if the partition or slot index is invalid.
    async fn get_cert_chain_info(
        &self,
        part_id: HsmPartId,
        slot_id: u8,
    ) -> HsmResult<CertChainInfo>;

    /// Reads a certificate from the chain into the provided buffer.
    ///
    /// # Parameters
    ///
    /// - `part_id` — Partition identifier.
    /// - `slot_id` — Slot index.
    /// - `idx` — Zero-based index of the certificate within the chain.
    /// - `cert` — When `Some`, output buffer to receive the certificate bytes.
    ///   When `None`, only the certificate length is returned (size query).
    ///
    /// # Returns
    ///
    /// The number of bytes that were (or would be) written to `cert`.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if the partition index, slot index, or certificate
    /// index is invalid, or if `cert` is `Some` but too small for the
    /// certificate being read.
    async fn get_cert(
        &self,
        part_id: HsmPartId,
        slot_id: u8,
        idx: u8,
        cert: Option<&mut [u8]>,
    ) -> HsmResult<usize>;
}
