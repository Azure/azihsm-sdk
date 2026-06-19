// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side AEAD envelopes — bit-identical wire format to the fw
//! [`aead-envelope`] crate, slice-based API.
//!
//! # Scope (v1)
//!
//! AES-256-GCM only. The wire format reserves an `alg` byte so
//! future algorithms can be added without a format break.
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
//! `aad_len` MUST be `0` or a multiple of `32`. The constraint
//! comes from the fw side's hardware DMA layout; mirroring it here
//! guarantees envelopes produced by either side share an identical
//! wire layout.
//!
//! # Interop
//!
//! The fw crate's PAL produces standard NIST AES-GCM tags, so an
//! envelope sealed on the HSM can be opened by this crate with a
//! single [`open`] call, and vice versa.
//!
//! [`aead-envelope`]: ../../../../fw/core/crypto/aead-envelope

mod alg;
mod envelope;
mod format;
mod gcm;
mod ops;

#[cfg(test)]
mod tests;

pub use ops::AeadAlg;
pub use ops::AeadEnvelope;
pub use ops::FORMAT_TAG;
pub use ops::HEADER_LEN;
pub use ops::MAX_AAD_LEN;
pub use ops::inspect;
pub use ops::open;
pub use ops::seal;
