// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `PartFinal` (FinalizePart) command.
//!
//! `PartFinal` is a CO-session command that finalizes a partition after
//! `PartInit` by installing the POTA-endorsed PTA certificate chain and
//! deriving the partition's local masking keys.  It re-supplies the
//! unified `PartPolicy` (for `POTAPubKey` recovery), the PTA cert-chain
//! descriptor list (pointing into the side-band data buffer), and an
//! optional prior `local_mk` backup to restore; it returns the current
//! `local_mk` backup.  See `azihsm_fw_ddi_tbor_types::part_final` for the
//! full wire schema.

use alloc::vec::Vec;

use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::Unaligned;

use crate::policy::PartPolicy;
use crate::tbor;
use crate::tbor_int::U16;

/// TBOR opcode for `PartFinal`.
pub const TBOR_OP_PART_FINAL: u8 = 0x08;

/// Size of a single [`CertDescriptor`] on the wire (`offset(2) ‖
/// length(2)`, little-endian).
pub const CERT_DESCRIPTOR_LEN: usize = 4;

/// Maximum number of certificates the PTA chain descriptor list may
/// carry.
pub const MAX_CERTS: usize = 2;

/// Maximum on-the-wire length of the `cert_descriptors` field.
pub const CERT_DESCRIPTORS_MAX_LEN: usize = MAX_CERTS * CERT_DESCRIPTOR_LEN;

/// Maximum on-the-wire length of a `local_mk` backup envelope.
pub const LOCAL_MK_BACKUP_MAX_LEN: usize = 1024;

/// One PTA-chain certificate descriptor: the byte `offset` and `length`
/// of a DER certificate within the side-band data buffer.
///
/// Host-side mirror of
/// `azihsm_fw_ddi_tbor_types::evidence::CertDescriptor`.  `#[repr(C)]`
/// POD (size [`CERT_DESCRIPTOR_LEN`] = 4 B, alignment 1); the
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
pub struct CertDescriptor {
    /// Byte offset of the DER certificate in the side-band buffer.
    pub offset: U16,

    /// Byte length of the DER certificate.
    pub length: U16,
}

/// Host-facing TBOR `PartFinal` request.
///
/// Field sizes are pinned to the FW schema; passing a slice of the wrong
/// length produces a host-side encode error before the request reaches
/// the device.
#[tbor(opcode = TBOR_OP_PART_FINAL, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborPartFinalReq {
    /// CO session id this request is bound to.  Cross-checked against
    /// the SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Caller-asserted unified [`PartPolicy`], re-supplied from
    /// `PartInit` for `POTAPubKey` recovery.  Encoded as its 484-byte
    /// little-endian image.
    pub part_policy: PartPolicy,

    /// PTA certificate chain descriptors `(offset, length)` pointing into
    /// the side-band buffer.  Encoded as the packed little-endian byte
    /// image of the elements; carries 1..=[`MAX_CERTS`] entries.
    #[tbor(min_len = 1, max_len = 8)]
    pub cert_descriptors: Vec<CertDescriptor>,

    /// Optional previously-generated `local_mk` backup to restore.
    /// Empty on first instantiation.
    #[tbor(max_len = 1024)]
    pub prev_local_mk_backup: Vec<u8>,
}

/// Host-facing TBOR `PartFinal` response.
///
/// The byte field is an owned `Vec<u8>` so callers don't have to carry
/// max-sized padding buffers around.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborPartFinalResp {
    /// Current `local_mk` backup envelope (`CurrPartLocalKMKBackup`).
    #[tbor(max_len = 1024)]
    pub local_mk_backup: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn cert_descriptor_layout_matches_wire() {
        assert_eq!(core::mem::size_of::<CertDescriptor>(), CERT_DESCRIPTOR_LEN);
        assert_eq!(core::mem::align_of::<CertDescriptor>(), 1);
        assert_eq!(CERT_DESCRIPTORS_MAX_LEN, MAX_CERTS * CERT_DESCRIPTOR_LEN);
    }

    #[test]
    fn request_encodes_typed_cert_descriptors_le() {
        let req = TborPartFinalReq {
            session_id: 7,
            part_policy: PartPolicy::zeroed(),
            cert_descriptors: alloc::vec![
                CertDescriptor {
                    offset: U16::new(0x1234),
                    length: U16::new(0x0567),
                },
                CertDescriptor {
                    offset: U16::new(16),
                    length: U16::new(32),
                },
            ],
            prev_local_mk_backup: Vec::new(),
        };

        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The packed little-endian descriptor image must appear verbatim
        // somewhere in the encoded frame's data section.
        let needle = [0x34, 0x12, 0x67, 0x05, 0x10, 0x00, 0x20, 0x00];
        assert!(
            frame.windows(needle.len()).any(|w| w == needle),
            "encoded frame must carry the packed LE cert descriptors",
        );
    }

    #[test]
    fn request_emits_no_padding_entry_for_typed_slice() {
        use azihsm_ddi_tbor_types::codec::RequestView;
        use azihsm_ddi_tbor_types::codec::TocEntry;

        let req = TborPartFinalReq {
            session_id: 7,
            part_policy: PartPolicy::zeroed(),
            cert_descriptors: alloc::vec![CertDescriptor {
                offset: U16::new(16),
                length: U16::new(32),
            }],
            prev_local_mk_backup: Vec::new(),
        };

        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");
        let view = RequestView::parse(frame).expect("parse");

        // `CertDescriptor` is `Unaligned`, so the typed `cert_descriptors`
        // slice needs no alignment padding: session_id, part_policy,
        // cert_descriptors, prev_local_mk_backup = 4 entries. The firmware
        // derive produces the same layout (no padding entry), so the FW
        // decodes this request 1:1.
        assert_eq!(
            view.toc_count(),
            4,
            "typed slice must not emit a padding entry"
        );
        assert!(matches!(view.toc_entry(0), TocEntry::SessionId(7)));
        assert!(matches!(view.toc_entry(2), TocEntry::Buffer(_)));
        assert!(matches!(view.toc_entry(3), TocEntry::Buffer(_)));
    }
}
