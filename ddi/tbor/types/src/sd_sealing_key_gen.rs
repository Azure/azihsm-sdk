// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdSealingKeyGen` command.
//!
//! `SdSealingKeyGen` is an **in-session** Crypto-Officer command that
//! generates a new security-domain sealing key (ECC-P384) and returns
//! the **masked** private key plus its public key.  The private key is
//! not stored on the device; the caller holds the masked blob and
//! re-imports it (unmask-on-use) when the key is later needed.
//!
//! The request carries the requested key `scope` (lifecycle / visibility
//! domain) as its 1-byte discriminant.  The firmware-side schema
//! (`azihsm_fw_ddi_tbor_types::sd_sealing_key_gen`) types it as the
//! `KeyScope` open-enum (mirror of the PAL `HsmKeyScope`); this host
//! crate is firewalled from the firmware PAL types, so it carries the
//! same byte as a raw `u8`.  The private key is masked under the masking
//! key associated with the scope.

use crate::tbor;

/// TBOR opcode for `SdSealingKeyGen`.
pub const TBOR_OP_SD_SEALING_KEY_GEN: u8 = 0x09;

/// Wire length of the returned sealing public key: a raw P-384 point
/// (`x ‖ y`, 48 + 48 bytes).
pub const SD_SEALING_PUB_KEY_LEN: usize = 96;

/// Wire length of the masked sealing private key: an AEAD-GCM-256
/// masked-key envelope (`header(8) ‖ iv(12) ‖ aad(96) ‖ pt(48) ‖
/// tag(16)`) over the 48-byte raw P-384 private scalar.
pub const MASKED_SEALING_KEY_LEN: usize = 8 + 12 + 96 + 48 + 16;

/// Host-facing TBOR `SdSealingKeyGen` request.
#[tbor(opcode = TBOR_OP_SD_SEALING_KEY_GEN, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborSdSealingKeyGenReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Requested key scope (lifecycle / visibility domain) as the 1-byte
    /// `KeyScope` discriminant (mirror of the firmware `HsmKeyScope`).
    pub scope: u8,
}

/// Host-facing TBOR `SdSealingKeyGen` response.
#[tbor(response)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TborSdSealingKeyGenResp {
    /// The new sealing key's ECC-P384 private half, masked
    /// (AEAD-GCM-256) under the requested scope's masking key.  Always
    /// exactly [`MASKED_SEALING_KEY_LEN`] (180 B); not stored on-device.
    pub masked_key: [u8; MASKED_SEALING_KEY_LEN],

    /// Raw P-384 public key (`x ‖ y` affine coordinates, 96 bytes,
    /// little-endian per coordinate) of the new sealing key.  Not a SEC1
    /// point encoding (no `0x04` prefix).
    pub pub_key: [u8; SD_SEALING_PUB_KEY_LEN],
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_session_and_scope() {
        let req = TborSdSealingKeyGenReq {
            session_id: 9,
            // KeyScope::SecurityDomain discriminant (0b100).
            scope: 0b100,
        };

        let mut buf = [0u8; 256];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The 1-byte scope discriminant must appear in the encoded frame.
        assert!(
            frame.contains(&0b100),
            "encoded frame must carry the scope discriminant",
        );
    }
}
