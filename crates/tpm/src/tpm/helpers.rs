// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt;
use std::io;

use crate::tpm::types::TpmCommandCode;
use crate::tpm::types::TpmMarshal;
use crate::tpm::types::TPM_RS_PW;
use crate::tpm::types::TPM_ST_NO_SESSIONS;
use crate::tpm::types::TPM_ST_SESSIONS;

/// Structured TPM error carrying the raw response code (rc), decoded description,
/// and optional originating command code.
#[derive(Debug)]
pub struct TpmError {
    pub rc: u32,
    pub decoded: String,
    pub command: Option<TpmCommandCode>,
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(cmd) = &self.command {
            write!(
                f,
                "TPM error 0x{:08x} (command={:?}/0x{:08x}): {}",
                self.rc, cmd, *cmd as u32, self.decoded
            )
        } else {
            write!(f, "TPM error 0x{:08x}: {}", self.rc, self.decoded)
        }
    }
}

impl std::error::Error for TpmError {}

pub fn build_header_no_sessions(code: TpmCommandCode, out: &mut Vec<u8>) {
    out.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&(code as u32).to_be_bytes());
}

pub fn finalize_size(out: &mut [u8]) {
    let len = out.len() as u32;
    out[2..6].copy_from_slice(&len.to_be_bytes());
}

pub fn build_header_sessions(code: TpmCommandCode, out: &mut Vec<u8>) {
    out.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&(code as u32).to_be_bytes());
}

/// Build a TPM command without sessions given the code, handles and parameter payload marshaler closure.
pub fn build_command_no_sessions<F>(
    code: TpmCommandCode,
    handles: &[u32],
    mut marshal_params: F,
) -> Vec<u8>
where
    F: FnMut(&mut Vec<u8>),
{
    let mut buf = Vec::new();
    build_header_no_sessions(code, &mut buf);
    for h in handles {
        h.marshal(&mut buf);
    }
    marshal_params(&mut buf);
    finalize_size(&mut buf);
    buf
}

/// Build a TPM command with one or more password sessions (TPM_RS_PW) – one per entry in `session_auths`.
/// Each slice in `session_auths` is the authValue (may be empty) for the corresponding authorized handle.
/// The number of password sessions should match the number of authorized handles for the command,
/// but this function does not enforce semantic correctness beyond encoding.
pub fn build_command_pw_sessions<F>(
    code: TpmCommandCode,
    handles: &[u32],
    session_auths: &[&[u8]],
    mut marshal_params: F,
) -> Vec<u8>
where
    F: FnMut(&mut Vec<u8>),
{
    let mut buf = Vec::new();
    build_header_sessions(code, &mut buf);
    // Handle area
    for h in handles {
        h.marshal(&mut buf);
    }
    // Authorization area size is sum of session structures (excluding the u32 authorizationSize itself)
    // Each PW session structure = 4 (handle) + 2 (nonceSize=0) + 1 (attrs) + 2 (authSize) + auth.len()
    let mut auth_area_size: u32 = 0;
    for auth in session_auths {
        auth_area_size = auth_area_size
            .checked_add(4 + 2 + 1 + 2 + auth.len() as u32)
            .expect("auth area size overflow");
    }
    buf.extend_from_slice(&auth_area_size.to_be_bytes());
    for auth in session_auths {
        // sessionHandle = TPM_RS_PW
        buf.extend_from_slice(&TPM_RS_PW.to_be_bytes());
        // nonceSize = 0
        buf.extend_from_slice(&0u16.to_be_bytes());
        // sessionAttributes = 0
        buf.push(0u8);
        // authSize
        buf.extend_from_slice(&(auth.len() as u16).to_be_bytes());
        // auth bytes
        if !auth.is_empty() {
            buf.extend_from_slice(auth);
        }
    }
    // Parameters
    marshal_params(&mut buf);
    finalize_size(&mut buf);
    buf
}

/// Session entry for `build_command_custom_sessions` allowing arbitrary session handles (e.g. policy sessions)
pub struct SessionEntry<'a> {
    pub handle: u32,
    pub auth: &'a [u8], // authValue or HMAC (empty for policy session with no auth)
    pub attrs: u8,      // sessionAttributes bitfield
}

/// Build a TPM command with arbitrary pre-existing session handles (e.g., policy session) plus optional auth bytes.
/// Caller is responsible for ensuring the session handles are valid and bound to the required policy or auth state.
pub fn build_command_custom_sessions<F>(
    code: TpmCommandCode,
    handles: &[u32],
    sessions: &[SessionEntry<'_>],
    mut marshal_params: F,
) -> Vec<u8>
where
    F: FnMut(&mut Vec<u8>),
{
    let mut buf = Vec::new();
    build_header_sessions(code, &mut buf);
    for h in handles {
        h.marshal(&mut buf);
    }
    // Compute auth area size (sum of session structs excluding the u32 size field itself)
    let mut auth_area_size: u32 = 0;
    for s in sessions {
        auth_area_size = auth_area_size
            .checked_add(4 + 2 + 1 + 2 + s.auth.len() as u32)
            .expect("auth area overflow");
    }
    buf.extend_from_slice(&auth_area_size.to_be_bytes());
    for s in sessions {
        buf.extend_from_slice(&s.handle.to_be_bytes()); // sessionHandle
        buf.extend_from_slice(&0u16.to_be_bytes()); // nonceSize=0
        buf.push(s.attrs); // sessionAttributes
        buf.extend_from_slice(&(s.auth.len() as u16).to_be_bytes());
        if !s.auth.is_empty() {
            buf.extend_from_slice(s.auth);
        }
    }
    marshal_params(&mut buf);
    finalize_size(&mut buf);
    buf
}

/// Parse a TPM response code, associating it with a specific command.
pub(crate) fn parse_tpm_rc_with_cmd(resp: &[u8], command: TpmCommandCode) -> io::Result<()> {
    if resp.len() < 10 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "TPM response too short",
        ));
    }
    // Basic length check first so we don't decode nonsense
    let declared = u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]) as usize;
    if declared != resp.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "response length mismatch (declared {declared} actual {})",
                resp.len()
            ),
        ));
    }
    let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
    if rc != 0 {
        let decoded = decode_tpm_rc(rc);
        return Err(io::Error::other(TpmError {
            rc,
            decoded,
            command: Some(command),
        }));
    }
    Ok(())
}

/// Decode a TPM2 response code into a human-readable classification. Based on
/// TPM 2.0 Part 2 spec (response code structure). This is intentionally
/// partial; unknown codes are still surfaced with structural hints.
fn decode_tpm_rc(rc: u32) -> String {
    // Quick special cases
    if rc == 0 {
        return "SUCCESS".to_string();
    }

    // Format bit (bit 7)
    let is_format1 = (rc & 0x80) != 0; // TPM_RC_FMT1
                                       // Parameter / session / handle indicator bits
    let is_session = (rc & 0x800) != 0; // TPM_RC_S (bit 11)
    let is_handle = (rc & 0x100) != 0; // TPM_RC_H (bit 8)
                                       // If format1 and neither session nor handle bits set => parameter code
    let is_parameter = is_format1 && !is_session && !is_handle;
    let index = if is_format1 {
        ((rc >> 8) & 0x7) as u8
    } else {
        0
    };
    let base = (rc & 0x3F) as u16; // lower 6 bits for FMT1, also useful subset for FMT0 mapping

    // Vendor or warning codes (bit 10 for warnings in spec, we just surface)
    let is_warning = (rc & 0x900) == 0x900; // simplistic detection (bit 11 clear? / combine) – best-effort

    // Known Format 1 base codes (partial set) mapping
    let fmt1_name = match base {
        0x01 => "ASYMMETRIC",
        0x02 => "ATTRIBUTES",
        0x03 => "HASH",
        0x04 => "VALUE",
        0x05 => "HIERARCHY",
        0x07 => "KEY_SIZE",
        0x08 => "MGF",
        0x09 => "MODE",
        0x0A => "TYPE",
        0x0B => "HANDLE",
        0x0C => "KDF",
        0x0D => "RANGE",
        0x0E => "AUTH_FAIL",
        0x0F => "NONCE",
        0x10 => "PP",
        0x12 => "SCHEME",
        0x15 => "SIZE",
        0x16 => "SYMMETRIC",
        0x17 => "CURVE",
        0x18 => "KEY",
        _ => "UNKNOWN_FMT1_BASE",
    };

    // Selected Format 0 codes (subset focusing on NV + common)
    let fmt0_name = match rc & 0x7F {
        // mask to low 7 bits when format0
        0x01 => "INITIALIZE",
        0x03 => "SEQUENCE",
        0x09 => "HMAC",
        0x0B => "DISABLED",
        0x12 => "COMMAND_SIZE",
        0x14 => "COMMAND_CODE",
        0x15 => "AUTH_SIZE",
        0x16 => "AUTH_CONTEXT",
        0x20 => "NV_RANGE",
        0x22 => "NV_SIZE",
        0x24 => "NV_LOCKED",
        0x25 => "NV_AUTHORIZATION",
        0x26 => "NV_UNINITIALIZED",
        0x28 => "NV_SPACE",
        0x2C => "NV_DEFINED",
        _ => "UNKNOWN_FMT0_BASE",
    };

    if is_format1 {
        let target = if is_parameter {
            "PARAM"
        } else if is_handle {
            "HANDLE"
        } else if is_session {
            "SESSION"
        } else {
            "BASE"
        };
        return format!(
            "FMT1 base={fmt1_name}({base:#04x}) target={target} index={index} warning={is_warning}"
        );
    }
    // Format 0
    format!("FMT0 base={fmt0_name}({:#04x})", rc & 0x7F)
}

pub fn hex_fmt(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
