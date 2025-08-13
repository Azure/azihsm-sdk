// Copyright (c) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! Definitions for mcr session enumerations
//!
use crate::DdiOp;

/// Enumeration for different types of opcodes
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SessionControlKind {
    /// This kind of opcode means that there is no
    /// session id associated with this opcode
    NoSession,

    /// This kind of opcode indicates that a session
    /// is being opened
    Open,

    /// Kind used to indicate opcodes for closing a
    /// session
    Close,

    /// Kind used to indicate opcodes that are part of
    /// a session
    InSession,
}

/// from trait to convert SessionControlKind to
/// u8
impl From<SessionControlKind> for u8 {
    fn from(kind: SessionControlKind) -> u8 {
        match kind {
            SessionControlKind::NoSession => 0,
            SessionControlKind::Open => 1,
            SessionControlKind::Close => 2,
            SessionControlKind::InSession => 3,
        }
    }
}

/// Trait to convert DdiOps to SessionControlKind
impl From<DdiOp> for SessionControlKind {
    fn from(e: DdiOp) -> Self {
        match e {
            DdiOp::GetApiRev
            | DdiOp::GetDeviceInfo
            | DdiOp::GetCertChainInfo
            | DdiOp::GetCertificate
            | DdiOp::GetEstablishCredEncryptionKey
            | DdiOp::EstablishCredential
            | DdiOp::GetSessionEncryptionKey => SessionControlKind::NoSession,

            DdiOp::OpenSession => SessionControlKind::Open,

            DdiOp::CloseSession | DdiOp::ResetFunction => SessionControlKind::Close,

            _ => SessionControlKind::InSession,
        }
    }
}

/// Trait to convert u8 to SessionControlKind
impl From<u8> for SessionControlKind {
    fn from(value: u8) -> Self {
        match value {
            0 => SessionControlKind::NoSession,
            1 => SessionControlKind::Open,
            2 => SessionControlKind::Close,
            3 => SessionControlKind::InSession,
            _ => SessionControlKind::NoSession,
        }
    }
}

/**
Session information structure used to
map information from a command submission
to the dispatcher
opcode is an Option to support legacy
applications
*/
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Copy, Debug, PartialEq, Clone)]
pub struct SessionInfoRequest {
    /// Session handling parameter
    /// Indicates the type of opcode
    /// legacy applications (ones which do
    /// not encode session information) use
    /// NoSession opcode
    pub session_control_kind: SessionControlKind,

    /// session id (optional)
    /// Depending on the presence of the opcode field
    /// and the value of the opcode field, this field
    /// is valid
    /// Legacy applications will have this set to None
    pub session_id: Option<u16>,
}

impl Default for SessionInfoRequest {
    fn default() -> Self {
        SessionInfoRequest {
            session_control_kind: SessionControlKind::NoSession,
            session_id: None,
        }
    }
}

/// Structure used to return information about
/// the completion of a command.
///
#[derive(Copy, Debug, PartialEq, Clone)]
pub struct SessionInfoResponse {
    /// # of bytes being returned as part of completion
    pub response_length: u16,

    /// opcode that is returned in the completion
    /// (response).
    pub session_control_kind: SessionControlKind,

    /// session_id
    /// Depending on the opcode in the completion
    /// this field may or may not be valid
    pub session_id: Option<u16>,

    /// short_app_id
    /// Depending on the opcode in the completion
    /// this field may or may not be valid
    pub short_app_id: Option<u8>,
}

impl Default for SessionInfoResponse {
    fn default() -> Self {
        SessionInfoResponse {
            response_length: 0,
            session_control_kind: SessionControlKind::NoSession,
            session_id: None,
            short_app_id: None,
        }
    }
}
