// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hybrid Public Key Encryption (HPKE — RFC 9180), single-shot API.
//!
//! Sync port of `fw/core/crypto/hpke` for host use. Supports all four
//! HPKE modes (Base / PSK / Auth / AuthPSK) across six ciphersuites
//! built from three KEMs and two AEAD primitives — three of those
//! suites are RFC 9180 standard combinations and three substitute
//! AES-256-CBC + HMAC for AES-GCM under a private-use AEAD identifier
//! (`0xFFFF`).
//!
//! # Public surface
//!
//! Four operations, each with a `_vec` convenience sibling:
//!
//! | Operation       | Buffer form | Owned-output form     |
//! |-----------------|-------------|-----------------------|
//! | [`seal`]        | slice       | [`seal_vec`]          |
//! | [`open`]        | slice       | [`open_vec`]          |
//! | [`send_export`] | slice       | [`send_export_vec`]   |
//! | [`receive_export`] | slice    | [`receive_export_vec`] |
//!
//! Mode is selected via a config-struct constructor — for example
//! [`HpkeSealConfig::base`] / `psk` / `auth` / `auth_psk` — mirroring
//! the established [`crate::AesGcmAlgo::for_encrypt`] pattern.
//!
//! See [`suite`] for ciphersuite constants and wire-format conventions
//! (host uses SEC1 uncompressed public keys and raw scalar private keys).

mod aead;
mod kdf;
mod kem;
mod ops;
mod schedule;
mod suite;

pub use ops::HpkeExportSent;
pub use ops::HpkeOpenConfig;
pub use ops::HpkeReceiveExportConfig;
pub use ops::HpkeSealConfig;
pub use ops::HpkeSealed;
pub use ops::HpkeSendExportConfig;
pub use ops::PskParams;
pub use ops::open;
pub use ops::open_vec;
pub use ops::receive_export;
pub use ops::receive_export_vec;
pub use ops::seal;
pub use ops::seal_vec;
pub use ops::send_export;
pub use ops::send_export_vec;
pub use suite::HpkeSuite;

#[cfg(test)]
mod tests;
