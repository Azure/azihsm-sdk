// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Evidence descriptors for TBOR out-of-band certificate/report chains.
//!
//! Several TBOR commands carry their bulk evidence — DER certificate
//! chains and COSE_Sign1 attestation reports — **out of band** as SGL
//! Data Blocks, and reference each item from the TBOR message with a
//! small `(index, length)` descriptor.  This module defines the packed,
//! `Unaligned` descriptor POD types shared by those schemas.
//!
//! Each descriptor is a `#[repr(C)]` POD whose `u8` `index` and
//! little-endian [`U16`](crate::tbor_int::U16) `length` keep it
//! alignment-1 (`Unaligned`), so a `&[T]` typed slice is borrowed
//! zero-copy from the data section at any offset with no alignment
//! padding.

use azihsm_fw_ddi_tbor_api::tbor;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::Unaligned;

use crate::tbor_int::U16;

/// Size of a single [`CertDescriptor`] on the wire (`index(1) ‖
/// length(2)`, little-endian).
pub const CERT_DESCRIPTOR_LEN: usize = 3;

/// Maximum number of certificates a PTA chain descriptor list may carry.
pub const MAX_CERTS: usize = 2;

/// Maximum on-the-wire length of a `cert_descriptors` field
/// (`MAX_CERTS × CERT_DESCRIPTOR_LEN`).
pub const CERT_DESCRIPTORS_MAX_LEN: usize = MAX_CERTS * CERT_DESCRIPTOR_LEN;

/// One PTA-chain certificate descriptor: the OOB SGL-descriptor `index`
/// and byte `length` of a DER certificate carried out of band.
///
/// `#[repr(C)]` POD (size [`CERT_DESCRIPTOR_LEN`] = 3 B, alignment 1).
/// `index` is a `u8` and `length` a little-endian
/// [`U16`](crate::tbor_int::U16).  The type is therefore `Unaligned`, so
/// the zero-copy `&[CertDescriptor]` cast is sound at any data-section
/// offset (no alignment padding is inserted for the descriptor slice).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned,
)]
#[repr(C)]
pub struct CertDescriptor {
    /// Index of the DER certificate's SGL Data Block descriptor in the
    /// OOB descriptor page.
    pub index: u8,

    /// Byte length of the DER certificate.
    pub length: U16,
}

/// Size of a single [`ReportDescriptor`] on the wire (`index(1) ‖
/// length(2)`, little-endian).
pub const REPORT_DESCRIPTOR_LEN: usize = 3;

/// Maximum number of reports a descriptor list may carry.
pub const MAX_REPORTS: usize = 2;

/// Maximum on-the-wire length of a `report_descriptors` field
/// (`MAX_REPORTS × REPORT_DESCRIPTOR_LEN`).
pub const REPORT_DESCRIPTORS_MAX_LEN: usize = MAX_REPORTS * REPORT_DESCRIPTOR_LEN;

/// One attestation-report descriptor: the OOB SGL-descriptor `index`
/// and byte `length` of a COSE_Sign1 report carried out of band.
///
/// `#[repr(C)]` POD (size [`REPORT_DESCRIPTOR_LEN`] = 3 B, alignment 1).
/// Like [`CertDescriptor`], `index` is a `u8` and `length` a
/// little-endian [`U16`](crate::tbor_int::U16), so the type is
/// `Unaligned` and the zero-copy `&[ReportDescriptor]` cast is sound at
/// any offset.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned,
)]
#[repr(C)]
pub struct ReportDescriptor {
    /// Index of the report's SGL Data Block descriptor in the OOB
    /// descriptor page.
    pub index: u8,

    /// Byte length of the report.
    pub length: U16,
}

/// Maximum certificates per chain on the wire. A wire-size bound (DMA
/// budget), **not** a structural limit — raise it as cert-chain depth
/// requires; the descriptor list is a variable-length typed slice.
pub const EVIDENCE_CHAIN_MAX_CERTS: usize = 8;

/// Maximum on-the-wire length of one cert-chain descriptor list
/// (`EVIDENCE_CHAIN_MAX_CERTS × CERT_DESCRIPTOR_LEN`).
pub const EVIDENCE_CHAIN_MAX_LEN: usize = EVIDENCE_CHAIN_MAX_CERTS * CERT_DESCRIPTOR_LEN;
// Pin the `Evidence` group's `#[tbor(... = N)]` byte literals to their
// descriptor-size constants (the derive requires integer literals):
// `max_len = 24` on the cert-chain lists and `len = 3` on `evidence`.
const _: () = assert!(EVIDENCE_CHAIN_MAX_LEN == 24);
const _: () = assert!(REPORT_DESCRIPTOR_LEN == 3);

/// Out-of-band evidence as a reusable TBOR **field group**: the three
/// certificate-chain descriptor lists plus the attestation-report
/// descriptor list.  `#[tbor(include)]` it into a command to splice these
/// four TOC entries into the message.
///
/// The bulk bytes (the DER chains and the COSE_Sign1 report) travel **out
/// of band** as SGL Data Blocks; this group carries only the
/// `(index, length)` descriptors referencing them.  Each list is a
/// variable-length typed slice (`&[CertDescriptor]` /
/// `&[ReportDescriptor]`) — there is no fixed per-chain cap, only the
/// wire-size [`EVIDENCE_CHAIN_MAX_LEN`] bound (24 B = 8 descriptors).
#[tbor(fields)]
pub struct Evidence<'a> {
    /// Manufacturer certificate-chain descriptors.
    #[tbor(buffer, max_len = 24)]
    pub mfgr_cert_chain: &'a [CertDescriptor],

    /// Owner certificate-chain descriptors.
    #[tbor(buffer, max_len = 24)]
    pub owner_cert_chain: &'a [CertDescriptor],

    /// Partition-owner certificate-chain descriptors.
    #[tbor(buffer, max_len = 24)]
    pub part_owner_cert_chain: &'a [CertDescriptor],

    /// Attestation-report (COSE_Sign1) descriptor.  A single zero-copy
    /// [`ReportDescriptor`] reference; its 3-byte image is pinned on the
    /// wire.
    #[tbor(buffer, len = 3)]
    pub evidence: &'a ReportDescriptor,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_descriptor_layout_is_packed_3_bytes() {
        const _: () = assert!(core::mem::size_of::<CertDescriptor>() == CERT_DESCRIPTOR_LEN);
        const _: () = assert!(core::mem::align_of::<CertDescriptor>() == 1);
        assert_eq!(CERT_DESCRIPTORS_MAX_LEN, MAX_CERTS * CERT_DESCRIPTOR_LEN);
    }

    #[test]
    fn cert_descriptor_round_trips_bytes() {
        let d = CertDescriptor {
            index: 0x12,
            length: U16::new(0x0567),
        };
        // Little-endian on the wire (index byte then length).
        assert_eq!(IntoBytes::as_bytes(&d), &[0x12, 0x67, 0x05]);
    }

    #[test]
    fn report_descriptor_layout_is_packed_3_bytes() {
        const _: () = assert!(core::mem::size_of::<ReportDescriptor>() == REPORT_DESCRIPTOR_LEN);
        const _: () = assert!(core::mem::align_of::<ReportDescriptor>() == 1);
        assert_eq!(
            REPORT_DESCRIPTORS_MAX_LEN,
            MAX_REPORTS * REPORT_DESCRIPTOR_LEN
        );
    }

    #[test]
    fn report_descriptor_round_trips_bytes() {
        let d = ReportDescriptor {
            index: 0x12,
            length: U16::new(0x0567),
        };
        // Little-endian on the wire (index byte then length).
        assert_eq!(IntoBytes::as_bytes(&d), &[0x12, 0x67, 0x05]);
    }
}
