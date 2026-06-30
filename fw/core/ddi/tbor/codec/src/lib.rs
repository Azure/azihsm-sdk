// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tabular Binary Object Representation (TBOR) — core wire format library.
//!
//! `azihsm_fw_ddi_tbor` provides zero-copy decoders (`RequestView`, `ResponseView`)
//! and fluent encoders (`RequestEncoder`, `ResponseEncoder`) for the TBOR
//! binary protocol. It is `#![no_std]` with no heap allocation.
//!
//! # Usage
//!
//! ```rust,ignore
//! use azihsm_fw_ddi_tbor::{RequestView, RequestEncoder, TocEntry};
//!
//! // Decode
//! let view = RequestView::parse(wire_bytes).unwrap();
//! for entry in view.toc_iter() {
//!     match entry {
//!         TocEntry::SessionId(id) => { /* ... */ }
//!         TocEntry::Buffer(data)  => { /* zero-copy &[u8] */ }
//!         _ => {}
//!     }
//! }
//!
//! // Encode
//! let mut buf = [0u8; 256];
//! let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
//!     .session_id(43).unwrap()
//!     .buffer(b"Hello").unwrap()
//!     .finish().unwrap();
//! ```

#![no_std]

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;

/// Zero-copy decoders for request and response messages.
pub mod decode;
/// Fluent encoders for request and response messages.
pub mod encode;
/// Error types returned by encoding and decoding operations.
/// Human-readable display helpers (hex dump, hex preview).
pub mod fmt;
/// TOC (Table of Contents) entry types and wire-level helpers.
pub mod toc;

// Re-exports for convenience.
pub use decode::RequestView;
pub use decode::ResponseView;
pub use encode::RequestEncoder;
pub use encode::ResponseEncoder;
pub use toc::TocEntry;
pub use toc::TocType;
pub use toc::MAX_DATA_SIZE;
pub use toc::MAX_TOC_ENTRIES;
pub use toc::PROTOCOL_VERSION;
pub use toc::REQ_HEADER_LEN;
pub use toc::RESP_HEADER_LEN;

/// Trait implemented by all `#[tbor(opcode = N)]` request types.
///
/// Provides the opcode constant and typed decode for dispatch:
/// ```rust,ignore
/// match raw.opcode() {
///     EncryptReq::OPCODE => handle(EncryptReq::decode(wire)?),
///     DecryptReq::OPCODE => handle(DecryptReq::decode(wire)?),
///     _ => { /* unknown */ }
/// }
/// ```
pub trait TborRequest {
    /// The opcode identifying this request type on the wire.
    const OPCODE: u8;

    /// The zero-copy view type returned by [`decode`](Self::decode).
    type View<'a>;

    /// Decode and validate a wire buffer into a typed view.
    ///
    /// Returns `Err` if the buffer is malformed, the opcode doesn't match,
    /// or the TOC structure doesn't match the schema.
    fn decode(buf: &DmaBuf) -> Result<Self::View<'_>, HsmError>;
}

/// Trait implemented by all `#[tbor(response)]` response types.
///
/// Provides typed decode for response messages.
pub trait TborResponse {
    /// The zero-copy view type returned by [`decode`](Self::decode).
    type View<'a>;

    /// Decode and validate a wire buffer into a typed view.
    fn decode(buf: &DmaBuf) -> Result<Self::View<'_>, HsmError>;
}
