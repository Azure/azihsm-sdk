// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side TBOR request/response types and the [`TborOpReq`] /
//! [`TborResp`] traits.
//!
//! This crate sits above [`azihsm_ddi_tbor_codec`] and provides:
//!
//! - [`TborOpReq`] — implemented by host-side request value types.
//!   Carries the TBOR opcode, the matching response type, and an
//!   `encode_request` method that drives the codec encoder.
//! - [`TborResp`] — implemented by owned response value types. Provides
//!   `decode_response` returning an owned struct (not a borrowing
//!   `View<'a>`), which lets [`exec_op_tbor`] return decoded responses
//!   without lifetime gymnastics around the IO scratch buffer.
//!
//! Concrete request/response pairs are added as DDI commands are
//! migrated from MBOR to TBOR; the first pair is [`TborGetApiRevReq`] /
//! [`TborGetApiRevResp`].
//!
//! [`exec_op_tbor`]: ../../azihsm_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

#![no_std]

extern crate alloc;
extern crate self as azihsm_ddi_tbor_types;

pub use azihsm_ddi_tbor_codec as codec;
pub use azihsm_ddi_tbor_derive::*;

/// Session-control kind carried in the SQE `session_flags.ctrl` byte
/// for a TBOR request.  The four variants encode as `u8` 0-3.
///
/// Defined locally in this crate (rather than re-using the MBOR
/// equivalent) so the host TBOR surface has no transport-layer
/// dependency on MBOR types.  The on-the-wire `u8` encoding matches
/// the MBOR enum, so both transports populate the same SQE field
/// with the same byte values.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SessionControlKind {
    /// Sessionless request (e.g. bootstrap commands).
    NoSession,
    /// Request that opens a new session.
    Open,
    /// Request that closes the bound session.
    Close,
    /// Request that operates within an already-open session.
    InSession,
}

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

mod change_psk;
mod close_session;
mod get_api_rev;
mod open_session_finish;
mod open_session_init;
mod part_info;
mod part_init;
mod status;
pub use change_psk::*;
pub use close_session::*;
pub use get_api_rev::*;
pub use open_session_finish::*;
pub use open_session_init::*;
pub use part_info::*;
pub use part_init::*;
pub use status::*;

/// Trait implemented by host-side TBOR request value types.
///
/// Implementors carry per-call data as struct fields. The trait
/// provides the wire opcode, the matching response type, optional
/// session id, and an `encode_request` method that serializes the
/// request into a caller-supplied buffer using the TBOR codec.
pub trait TborOpReq: Sized {
    /// TBOR opcode (single byte) carried in the request header.
    const OPCODE: u8;

    /// Owned, decoded response type.
    type OpResp: TborResp;

    /// Session identifier for this request, if any. The default
    /// `None` matches the current bootstrap commands which are all
    /// sessionless.
    fn get_session_id(&self) -> Option<u16> {
        None
    }

    /// SQE session-control kind for this request.  Mirrors the MBOR
    /// pattern (`From<DdiOp> for SessionControlKind`): each request
    /// type declares its own kind so the transport layer doesn't
    /// need a central opcode→ctrl table.  Default is `NoSession`
    /// to match the sessionless bootstrap commands.
    fn session_ctrl(&self) -> SessionControlKind {
        SessionControlKind::NoSession
    }

    /// Encode this request into `buf` and return the encoded message
    /// slice. The slice borrows from `buf` for the duration of the call.
    fn encode_request<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8], codec::EncodeError>;
}

/// Trait implemented by owned TBOR response value types.
///
/// Decoded via [`decode_response`](Self::decode_response), which parses
/// and validates the wire buffer via the codec [`codec::ResponseView`]
/// and copies all field values out into the owned struct.
pub trait TborResp: Sized {
    /// Decode an owned response value from the wire buffer.
    fn decode_response(buf: &[u8]) -> Result<Self, codec::DecodeError>;
}
