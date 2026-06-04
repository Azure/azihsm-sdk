// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! v1 masked-key format: AES-CBC-256 + HMAC-SHA-384 (encrypt-then-MAC).
//!
//! Host-visible wire format used by `init_bk3`, `establish_credential`,
//! live migration, and the simulator.  The byte layout is pinned by
//! the cross-domain `MaskedKey` contract; do not change it.
//!
//! See [crate-level docs](crate) for the full envelope layout.

mod decode;
mod encode;
mod format;

pub use decode::unmask;
pub use decode::UnmaskLayout;
pub use encode::mask;
pub use format::MASKING_KEY_AES_CBC_256_HMAC_384_LEN;
