// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side evidence descriptors for TBOR side-band buffers.
//!
//! Several Security-Domain TBOR commands carry their bulk attestation
//! evidence — DER certificate chains and COSE_Sign1 attestation reports —
//! **out of band** in a side-band data buffer, and reference each item
//! from the TBOR message with a small `(offset, length)` descriptor.
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

/// Size of a single [`ReportDescriptor`] on the wire (`offset(2) ‖
/// length(2)`, little-endian).
pub const REPORT_DESCRIPTOR_LEN: usize = 4;

/// Maximum number of certificate descriptors a single chain list may
/// carry on the wire.  A wire-size bound (DMA), not a structural
/// limit; mirrors `azihsm_fw_ddi_tbor_types::evidence::EVIDENCE_CHAIN_MAX_CERTS`.
pub const EVIDENCE_CHAIN_MAX_CERTS: usize = 8;

/// One attestation-report descriptor: the byte `offset` and `length` of a
/// COSE_Sign1 report within the side-band data buffer.
///
/// Host-side mirror of
/// `azihsm_fw_ddi_tbor_types::evidence::ReportDescriptor`.  `#[repr(C)]`
/// POD (size [`REPORT_DESCRIPTOR_LEN`] = 4 B, alignment 1); the
/// [`U16`](crate::tbor_int::U16) fields are little-endian on the wire and
/// keep the type `Unaligned`.
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
    /// Byte offset of the report in the side-band buffer.
    pub offset: U16,

    /// Byte length of the report.
    pub length: U16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_descriptor_layout_is_packed_4_bytes() {
        const _: () = assert!(core::mem::size_of::<ReportDescriptor>() == REPORT_DESCRIPTOR_LEN);
        const _: () = assert!(core::mem::align_of::<ReportDescriptor>() == 1);
    }

    #[test]
    fn report_descriptor_round_trips_bytes() {
        let d = ReportDescriptor {
            offset: U16::new(0x1234),
            length: U16::new(0x0567),
        };
        // Little-endian on the wire (offset then length).
        assert_eq!(IntoBytes::as_bytes(&d), &[0x34, 0x12, 0x67, 0x05]);
    }
}
