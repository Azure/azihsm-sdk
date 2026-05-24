// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side TBOR request/response types and the [`TborOpReq`] trait.
//!
//! This crate currently holds only the trait skeleton. Concrete
//! request/response types will be added as DDI commands are migrated
//! from MBOR (see `ddi/mbor/types`) to TBOR; the first migration target
//! is `GetApiRev`.

#![no_std]

// Re-exports kept intentionally narrow until concrete types land.
pub use azihsm_ddi_tbor_codec as codec;
pub use azihsm_ddi_tbor_derive::*;

/// Trait all TBOR-encoded DDI request structures must implement.
///
/// Mirrors [`azihsm_ddi_mbor_types::DdiOpReq`] but with TBOR codec
/// bounds. The first concrete implementation will be the TBOR
/// `GetApiRev` request once that command is migrated; until then this
/// trait is only used as a generic bound on
/// [`azihsm_ddi_interface::DdiDev::exec_op_tbor`].
pub trait TborOpReq: codec::TborRequest + Sized {
    /// Response type — the TBOR `RequestEncoder`-emitted struct's
    /// matching `TborResponse` decoder.
    type OpResp: codec::TborResponse;

    /// Opcode carried by this request (mirrors
    /// [`codec::TborRequest::OPCODE`], surfaced as a method so it can
    /// be queried through a `&self`).
    fn get_opcode(&self) -> u8;

    /// Session identifier carried by this request, if any.
    fn get_session_id(&self) -> Option<u16>;
}
