// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side evidence descriptors for TBOR out-of-band chains.
//!
//! Several Security-Domain TBOR commands carry their bulk attestation
//! evidence — DER certificate chains and COSE_Sign1 attestation reports —
//! **out of band** as SGL Data Blocks, and reference each item from the
//! TBOR message with a small `(index, length)` descriptor.
//!
//! The firmware schema groups these four descriptor TOC entries
//! (`mfgr_cert_chain` / `owner_cert_chain` / `part_owner_cert_chain` /
//! `evidence`) into a reusable `Evidence` field group
//! (`azihsm_fw_ddi_tbor_types::evidence`).  The host derive does not
//! support field groups, so each host command wrapper spells these four
//! TOC entries out explicitly using [`CertDescriptor`](crate::CertDescriptor)
//! (the cert-chain lists) and [`ReportDescriptor`] (the report).

use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::Unaligned;

use crate::tbor_int::U16;

/// Size of a single [`ReportDescriptor`] on the wire (`index(1) ‖
/// length(2)`, little-endian).
pub const REPORT_DESCRIPTOR_LEN: usize = 3;

/// Maximum number of certificate descriptors a single chain list may
/// carry on the wire.  A wire-size bound (DMA), not a structural
/// limit; mirrors `azihsm_fw_ddi_tbor_types::evidence::EVIDENCE_CHAIN_MAX_CERTS`.
pub const EVIDENCE_CHAIN_MAX_CERTS: usize = 8;

/// One attestation-report descriptor: the OOB SGL-descriptor `index` and
/// byte `length` of a COSE_Sign1 report carried out of band.
///
/// Host-side mirror of
/// `azihsm_fw_ddi_tbor_types::evidence::ReportDescriptor`.  `#[repr(C)]`
/// POD (size [`REPORT_DESCRIPTOR_LEN`] = 3 B, alignment 1); `index` is a
/// `u8` and `length` a little-endian [`U16`](crate::tbor_int::U16) on the
/// wire, keeping the type `Unaligned`.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    FromBytes,
    IntoBytes,
    Immutable,
    KnownLayout,
    Unaligned,
)]
#[repr(C)]
pub struct ReportDescriptor {
    /// Index of the report's SGL Data Block descriptor in the OOB
    /// descriptor page.
    pub index: u8,

    /// Byte length of the report.
    pub length: U16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_descriptor_layout_is_packed_3_bytes() {
        const _: () = assert!(core::mem::size_of::<ReportDescriptor>() == REPORT_DESCRIPTOR_LEN);
        const _: () = assert!(core::mem::align_of::<ReportDescriptor>() == 1);
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
