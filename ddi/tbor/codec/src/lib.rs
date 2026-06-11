// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tabular Binary Object Representation (TBOR) — host-side wire codec.
//!
//! Provides zero-copy decoding ([`RequestView`], [`ResponseView`]) and
//! fluent encoding ([`RequestEncoder`], [`ResponseEncoder`]) of TBOR
//! messages over plain `&[u8]` / `&mut [u8]` buffers with no `DmaBuf`
//! branding, so host-side code does not have to depend on any firmware
//! crate. The firmware codec ([`azihsm_fw_ddi_tbor`]) speaks the same
//! wire format but is maintained independently.
//!
//! # Usage
//!
//! ```rust,ignore
//! use azihsm_ddi_tbor_codec::{RequestView, RequestEncoder, TocEntry};
//!
//! // Decode
//! let view = RequestView::parse(wire_bytes)?;
//! for entry in view.toc_iter() {
//!     if let TocEntry::Buffer(data) = entry {
//!         // zero-copy &[u8]
//!     }
//! }
//!
//! // Encode
//! let mut buf = [0u8; 256];
//! let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
//!     .session_id(43)?
//!     .buffer(b"Hello")?
//!     .finish()?;
//! ```
//!
//! [`azihsm_fw_ddi_tbor`]: ../azihsm_fw_ddi_tbor/index.html

#![no_std]

pub mod encode;
pub mod error;
pub mod fmt;
pub mod header;
pub mod toc;
pub mod view;

mod validate;

// ── Public re-exports ──────────────────────────────────────────────────

pub use encode::Encoder;
pub use encode::RequestEncoder;
pub use encode::ResponseEncoder;
pub use error::DecodeError;
pub use error::EncodeError;
pub use header::Header;
pub use header::Request;
pub use header::Response;
pub use toc::TocEntry;
pub use toc::TocType;
pub use toc::MAX_DATA_SIZE;
pub use toc::MAX_TOC_ENTRIES;
pub use toc::PROTOCOL_VERSION;
pub use view::RequestView;
pub use view::ResponseView;
pub use view::View;

// Request/response header lengths, computed from the `Header` impls so
// they cannot drift from the on-the-wire layout.
/// Request header size in bytes.
pub const REQ_HEADER_LEN: usize = <Request as Header>::LEN;
/// Response header size in bytes.
pub const RESP_HEADER_LEN: usize = <Response as Header>::LEN;
