// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments)]

//! Self-contained AEAD envelopes, sealed and opened in place on a
//! single DMA-resident buffer.
//!
//! # Scope (v1)
//!
//! AES-256-GCM only. The wire format reserves an `alg` byte so
//! future algorithms (other GCM key sizes, AES-CBC + HMAC,
//! ChaCha20-Poly1305, etc.) can be added without a format break.
//!
//! # Wire format
//!
//! ```text
//! ┌────────┬─────┬─────┬─────────────┬─────┬─────────────────┬─────────┬─────┐
//! │ "AEAD" │ alg │ rsv │ aad_len_be  │ IV  │       AAD       │  DATA   │ TAG │
//! └────────┴─────┴─────┴─────────────┴─────┴─────────────────┴─────────┴─────┘
//!    4B     1B    1B       2B         12B   0 or 32·k bytes  pt_len    16B
//! ```
//!
//! | Field        | Size       | Notes                                                |
//! |--------------|------------|------------------------------------------------------|
//! | `magic`      | 4 B        | [`FORMAT_TAG`] (`b"AEAD"`) — format + version 1.     |
//! | `alg`        | 1 B        | [`AeadAlg`] discriminant (`0x03` = AES-256-GCM).     |
//! | `rsv`        | 1 B        | Reserved; MUST be `0`. Future versions may use.      |
//! | `aad_len_be` | 2 B        | u16 big-endian. Must be `0` or a multiple of `32`.   |
//! | `iv`         | 12 B       | 96-bit GCM nonce.                                    |
//! | `aad`        | `aad_len`  | Application-supplied associated data.                |
//! | `data`       | `pt_len`   | Ciphertext after [`seal`], plaintext after [`open`]. |
//! | `tag`        | 16 B       | Standard NIST GCM tag.                               |
//!
//! Total framing overhead for AES-256-GCM: **36 bytes**
//! (`HEADER_LEN` + IV + TAG = 8 + 12 + 16).
//!
//! # AAD-length invariant
//!
//! `aad_len` MUST be `0` or a multiple of `32`. This collapses the
//! ocelot BCP `[padded_AAD | text]` hardware DMA layout to the
//! wire-natural `[AAD | DATA]` contiguity — there are no padding
//! bytes anywhere, so the same buffer serves wire, in-memory, and
//! hardware-DMA roles simultaneously.
//!
//! The constraint is enforced at [`seal`] (rejected with
//! [`AeadError::InvalidAadLength`]) and at [`open`] (rejected with
//! [`AeadError::InvalidAadLength`] when parsing).
//!
//! # Interop
//!
//! The PAL produces standard NIST AES-GCM tags (the ocelot BCP
//! tag-correction step ensures this), so a non-firmware consumer
//! can open an envelope with one ordinary AES-256-GCM call. See
//! the crate-level README / design notes for a Python example.
//!
//! # Nonce management
//!
//! Callers are responsible for nonce generation. Use 96 random bits
//! per envelope from a CSPRNG, or a counter that never repeats
//! under a given key. Rekey before approximately `2^32` envelopes
//! per key.
//!
//! # Security properties
//!
//! * No panics on any input.
//! * No `unsafe` (`#![forbid(unsafe_code)]`).
//! * Tag comparison is constant-time (inherited from the PAL).
//! * No logging of keys, IVs, or plaintext.
//! * Magic, `alg`, and `aad_len` are bound into the GCM auth tag
//!   via the AAD parameter (they live at the front of the
//!   contiguous `[header | iv | aad | data]` region and any
//!   single-bit flip is caught at [`open`]).
//!
//! # Out of scope (v1)
//!
//! AES-128/192-GCM, AES-CBC + HMAC, AES-GCM-SIV, ChaCha20-Poly1305,
//! streaming/chunked seal/open, key commitment.

mod alg;
mod envelope;
mod error;
mod format;
mod gcm;
mod ops;

pub use ops::open;
pub use ops::seal;
pub use ops::AeadAlg;
pub use ops::AeadEnvelope;
pub use ops::AeadError;
pub use ops::FORMAT_TAG;
pub use ops::HEADER_LEN;
pub use ops::MAX_AAD_LEN;
