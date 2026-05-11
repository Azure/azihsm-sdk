// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate store types and traits.
//!
//! Defines the [`HsmCertStore`] trait used by DDI handlers
//! (`get_cert_chain_info`, `get_certificate`) to read per-partition
//! certificate chains.  Each partition can hold multiple chains
//! addressed by a `slot_id` (e.g. slot 0 = identity chain, slot 1 =
//! attestation chain — exact slot mapping is platform-defined).
//!
//! ## Storage model
//!
//! A *chain* is an ordered list of DER-encoded X.509 certificates,
//! conventionally arranged leaf-first.  The store reports two pieces
//! of metadata per chain via [`CertChainInfo`]:
//!
//! - the chain length (`count`), and
//! - the SHA-256 thumbprint of the leaf certificate.
//!
//! Individual certificates are streamed one at a time through
//! [`HsmCertStore::get_cert`] using the standard query/copy pattern.
//!
//! ## Addressing
//!
//! Every method takes both an [`HsmIo`] handle and an explicit
//! [`HsmPartId`].  Unlike most PAL traits, the partition is *not*
//! resolved from `io.pid()` here: the cert store is read by core
//! partition-management paths that need to inspect *another*
//! partition's chains (for example, returning the host's own
//! identity-cert metadata in a query that arrived on partition 0).
//! The [`HsmIo`] handle is still passed for per-IO scope (allocator,
//! logging, throttling).

use super::*;

/// Metadata for a single certificate chain.
///
/// Returned by [`HsmCertStore::get_cert_chain_info`].  The
/// thumbprint lets the host detect chain rotation without
/// downloading every certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertChainInfo {
    /// Number of certificates in the chain.
    ///
    /// Indices passed to [`HsmCertStore::get_cert`] must satisfy
    /// `idx < count`.
    pub count: u8,

    /// SHA-256 thumbprint of the leaf certificate (DER bytes).
    ///
    /// Computed once at chain-load time and cached; reading it does
    /// not invoke the SHA accelerator.
    pub thumbprint: [u8; 32],
}

/// Per-partition certificate store interface.
///
/// Both methods are `async` so PAL implementations can stream
/// certificate bytes from non-volatile storage (flash, eMMC) without
/// blocking the core's IO loop.  Implementations backed by RAM may
/// resolve immediately; callers should still treat the await as
/// potentially yielding.
pub trait HsmCertStore {
    /// Returns metadata for the certificate chain at
    /// `(part_id, slot_id)`.
    ///
    /// Cheap query that lets the host decide whether to fetch
    /// individual certificates; performs no buffer allocation.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `part_id` — partition whose chain is being queried (not
    ///   necessarily `io.pid()`).
    /// - `slot_id` — chain slot within the partition.  Valid range
    ///   is platform-defined; the standard PAL currently treats this
    ///   as advisory.
    ///
    /// # Returns
    ///
    /// - `Ok(info)` — populated [`CertChainInfo`].
    /// - `Err(HsmError::InvalidArg)` — `part_id` or `slot_id` is out
    ///   of range, or the partition has no chain installed at this
    ///   slot.
    /// - `Err(HsmError)` — propagated from the underlying storage
    ///   driver.
    async fn get_cert_chain_info(
        &self,
        io: &impl HsmIo,
        part_id: HsmPartId,
        slot_id: u8,
    ) -> HsmResult<CertChainInfo>;

    /// Reads one certificate from a chain, optionally copying its
    /// bytes into a caller-supplied buffer.
    ///
    /// Follows the standard query/copy pattern used elsewhere in the
    /// PAL: pass `cert = None` to obtain the certificate's size
    /// without copying, then call again with `cert = Some(buf)` to
    /// perform the copy.  Both calls return the same canonical
    /// length.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `part_id` — partition whose chain is being read.
    /// - `slot_id` — chain slot within the partition.
    /// - `idx` — zero-based certificate index; must satisfy
    ///   `idx < CertChainInfo::count` for the same `(part_id,
    ///   slot_id)`.  By convention `idx == 0` is the leaf and the
    ///   last index is the root.
    /// - `cert` — `None` to query the size, or `Some(buf)` to copy
    ///   the DER-encoded certificate into `buf[..size]`.  `buf.len()`
    ///   must be ≥ size.
    ///
    /// # Returns
    ///
    /// - `Ok(size)` — number of bytes that were (or would be)
    ///   written.
    /// - `Err(HsmError::InvalidArg)` — `part_id`, `slot_id`, or
    ///   `idx` is out of range, or `cert = Some(buf)` and
    ///   `buf.len() < size`.
    /// - `Err(HsmError)` — propagated from the underlying storage
    ///   driver.
    async fn get_cert(
        &self,
        io: &impl HsmIo,
        part_id: HsmPartId,
        slot_id: u8,
        idx: u8,
        cert: Option<&mut [u8]>,
    ) -> HsmResult<usize>;
}
