// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security-domain sealing-key generation over the TBOR transport at
//! the DDI layer.
//!
//! This module hosts the host-side dispatch for the in-session
//! `SdSealingKeyGen` command, mirroring the firmware handler:
//!
//! * **`SdSealingKeyGen`** (opcode `0x09`) — generate a new
//!   security-domain sealing key in the partition vault and return its
//!   key handle.
//!
//! It runs **inside an already-open session** established by
//! [`super::session_ex::open_session_ex`]: the request carries the
//! active session id, which the firmware dispatcher cross-checks
//! against the SQE-carried session id. Unlike `PartInit`, no host-side
//! crypto is required — the request only conveys the active session id
//! and the requested key `scope`, and the response yields the vault id
//! of the freshly generated key.
//!
//! The wire schema lives in [`azihsm_ddi_tbor_types`]. The `scope`
//! byte is the 1-byte `KeyScope` discriminant (host mirror of the
//! firmware `HsmKeyScope`); this host crate is firewalled from the
//! firmware PAL types, so it is carried as a raw `u8`.

use azihsm_ddi_tbor_types::*;

use super::*;

/// Issue `SdSealingKeyGen` (opcode `0x09`) on the active session.
///
/// Ships the active session id and the requested key `scope`, and
/// returns the [`HsmKeyHandle`] for the newly generated security-domain
/// sealing key. The firmware allocates the key in the partition vault
/// and returns its vault id, packed into a key handle with no bulk-key
/// component.
///
/// # Arguments
///
/// * `session` - The active security-domain (V2) session.
/// * `scope` - Requested key scope (lifecycle / visibility domain) as
///   the 1-byte `KeyScope` discriminant (mirror of the firmware
///   `HsmKeyScope`).
///
/// # Errors
///
/// Returns [`HsmError::InvalidSession`] on a non-security-domain (V1)
/// session, and surfaces DDI/device failures from the round-trip.
pub(crate) fn sd_sealing_key_gen(session: &HsmSession, scope: u8) -> HsmResult<HsmKeyHandle> {
    let req = TborSdSealingKeyGenReq {
        session_id: session.ex_session_id()?,
        scope,
    };

    let mut cookie = None;
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(&req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    Ok(to_key_handle(resp.key_handle, None))
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    /// The request must carry the active session id and the requested
    /// scope discriminant into the encoded TBOR frame so the firmware
    /// dispatcher can cross-check the session and honour the scope.
    #[test]
    fn request_encodes_session_and_scope() {
        let req = TborSdSealingKeyGenReq {
            session_id: 9,
            // KeyScope::SecurityDomain discriminant (0b100).
            scope: 0b100,
        };

        let mut buf = [0u8; 256];
        let frame = req.encode_request(&mut buf).expect("encode");

        assert!(
            frame.contains(&0b100),
            "encoded frame must carry the scope discriminant",
        );
    }

    /// A vault id returned by the firmware is packed into a key handle
    /// with no bulk-key component (`0xFFFF` in the high 16 bits).
    #[test]
    fn key_handle_packs_vault_id_without_bulk() {
        let handle = to_key_handle(0x1234, None);
        assert_eq!(get_key_id(handle), 0x1234);
        assert_eq!(get_bulk_key_id(handle), None);
    }
}
