// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdSealingKeyGen` command.
//!
//! `SdSealingKeyGen` is an **in-session** command that generates a new
//! security-domain sealing key in the partition's vault and returns its
//! key handle.
//!
//! The request carries the requested key `scope` (lifecycle / visibility
//! domain) as its 1-byte discriminant.  The firmware-side schema
//! (`azihsm_fw_ddi_tbor_types::sd_sealing_key_gen`) types it as the
//! `KeyScope` open-enum (mirror of the PAL `HsmKeyScope`); this host
//! crate is firewalled from the firmware PAL types, so it carries the
//! same byte as a raw `u8`.

use crate::tbor;

/// TBOR opcode for `SdSealingKeyGen`.
pub const TBOR_OP_SD_SEALING_KEY_GEN: u8 = 0x09;

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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborSdSealingKeyGenResp {
    /// Vault id (`HsmKeyId`) of the newly generated sealing key. Carried
    /// as a `KeyId` (inline 16-bit, TOC entry type 1); represented here
    /// as the raw `u16`.
    #[tbor(key_id)]
    pub key_handle: u16,
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
