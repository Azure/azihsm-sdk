// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `PartInit` command.
//!
//! `PartInit` is a CO-session command that derives the partition's
//! deterministic PTA keypair, persists the caller-asserted
//! `PartPolicy` + POTA thumbprint into partition state, and returns
//! the PTA CSR + COSE_Sign1 PTA key-attestation report.  See
//! [`azihsm_fw_ddi_tbor_types::part_init`] for the full wire schema.

use alloc::vec::Vec;

pub use azihsm_fw_ddi_tbor_types::build_part_init_mach_seed_aad;
pub use azihsm_fw_ddi_tbor_types::MACH_SEED_ENVELOPE_MAX_LEN;
pub use azihsm_fw_ddi_tbor_types::MACH_SEED_LEN;
pub use azihsm_fw_ddi_tbor_types::PART_INIT_MACH_SEED_AAD_LABEL;
pub use azihsm_fw_ddi_tbor_types::PART_INIT_MACH_SEED_AAD_LEN;
pub use azihsm_fw_ddi_tbor_types::PART_POLICY_LEN;
pub use azihsm_fw_ddi_tbor_types::POTA_THUMBPRINT_LEN;
pub use azihsm_fw_ddi_tbor_types::PTA_CSR_MAX_LEN;
pub use azihsm_fw_ddi_tbor_types::PTA_REPORT_MAX_LEN;
pub use azihsm_fw_ddi_tbor_types::TBOR_OP_PART_INIT;

use crate::tbor;

/// Host-facing TBOR `PartInit` request.
///
/// Field sizes are pinned to the FW schema; passing a slice of the
/// wrong length produces a host-side encode error before the request
/// reaches the device.
#[tbor(session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborPartInitReq {
    /// CO session id this request is bound to.  Cross-checked
    /// against the SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// AEAD-GCM envelope wrapping the 32-byte `mach_seed` plaintext
    /// under the active session's `param_key`.  Construct with
    /// [`build_part_init_mach_seed_aad`] as the AAD.
    #[tbor(max_len = 160)]
    pub mach_seed_envelope: Vec<u8>,

    /// Caller-asserted [`PartPolicy`] bytes.
    ///
    /// [`PartPolicy`]: azihsm_fw_ddi_tbor_types::policy::PartPolicy
    pub part_policy: [u8; PART_POLICY_LEN],

    /// SHA-384 thumbprint of the POTA certificate the partition is
    /// being provisioned under.
    pub pota_thumbprint: [u8; POTA_THUMBPRINT_LEN],
}

impl Default for TborPartInitReq {
    fn default() -> Self {
        Self {
            session_id: 0,
            mach_seed_envelope: Vec::new(),
            part_policy: [0u8; PART_POLICY_LEN],
            pota_thumbprint: [0u8; POTA_THUMBPRINT_LEN],
        }
    }
}

/// Host-facing TBOR `PartInit` response.
///
/// Both byte fields are owned `Vec<u8>` so callers don't have to
/// carry max-sized padding buffers around.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborPartInitResp {
    /// DER-encoded PKCS#10 CertificationRequest for the PTA pubkey.
    #[tbor(max_len = 512)]
    pub pta_csr: Vec<u8>,

    /// COSE_Sign1 PTA key-attestation report signed by the PID.
    #[tbor(max_len = 1024)]
    pub pta_report: Vec<u8>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use azihsm_fw_ddi_tbor_types::TborPartInitReq as ReqSchema;

    use super::*;
    use crate::TborOpReq;

    #[test]
    fn opcode_matches_schema() {
        assert_eq!(<TborPartInitReq as TborOpReq>::OPCODE, TBOR_OP_PART_INIT);
    }

    #[test]
    fn encode_decode_round_trip() {
        let mach_seed_envelope: Vec<u8> = (0u8..100).collect();
        let mut part_policy = [0u8; PART_POLICY_LEN];
        for (i, b) in part_policy.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut pota_thumbprint = [0u8; POTA_THUMBPRINT_LEN];
        for (i, b) in pota_thumbprint.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3);
        }
        let req = TborPartInitReq {
            session_id: 0x0042,
            mach_seed_envelope: mach_seed_envelope.clone(),
            part_policy,
            pota_thumbprint,
        };
        let mut buf = [0u8; 512];
        let wire = req.encode_request(&mut buf).expect("encode");
        let view = ReqSchema::decode(wire).expect("schema decode");
        assert_eq!(u16::from(view.session_id()), 0x0042);
        assert_eq!(view.mach_seed_envelope(), mach_seed_envelope.as_slice());
        assert_eq!(view.part_policy(), &part_policy);
        assert_eq!(view.pota_thumbprint(), &pota_thumbprint);
    }
}
