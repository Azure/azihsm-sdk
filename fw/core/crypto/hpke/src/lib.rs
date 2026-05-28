// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![allow(clippy::too_many_arguments)]

//! Hybrid Public Key Encryption (HPKE — RFC 9180), single-shot API.
//!
//! Supports all four HPKE modes (Base / PSK / Auth / AuthPSK) across
//! six ciphersuites built from three KEMs and two AEAD primitives:
//!
//! | KEM          | KDF          | AEAD                    |
//! |--------------|--------------|-------------------------|
//! | DHKEM(P-256) | HKDF-SHA-256 | AES-256-GCM             |
//! | DHKEM(P-256) | HKDF-SHA-256 | AES-256-CBC-HMAC-SHA-256 |
//! | DHKEM(P-384) | HKDF-SHA-384 | AES-256-GCM             |
//! | DHKEM(P-384) | HKDF-SHA-384 | AES-256-CBC-HMAC-SHA-384 |
//! | DHKEM(P-521) | HKDF-SHA-512 | AES-256-GCM             |
//! | DHKEM(P-521) | HKDF-SHA-512 | AES-256-CBC-HMAC-SHA-512 |
//!
//! See [`HpkeSuite`] for the full enum and per-suite size constants.
//!
//! ## API surface
//!
//! Each HPKE mode exposes a `seal_*` and `open_*` pair that takes a
//! caller-owned [`SealRequest`] / [`OpenRequest`]:
//!
//! | Mode    | Seal              | Open              |
//! |---------|-------------------|-------------------|
//! | Base    | [`seal_base`]     | [`open_base`]     |
//! | PSK     | [`seal_psk`]      | [`open_psk`]      |
//! | Auth    | [`seal_auth`]     | [`open_auth`]     |
//! | AuthPSK | [`seal_auth_psk`] | [`open_auth_psk`] |
//!
//! Two Base-mode export helpers are also exported:
//! [`send_export_base`] (sender side, runs Encap) and
//! [`receive_export_base`] (receiver side, runs Decap).
//!
//! ## Scoped-allocation contract
//!
//! Every entry point takes an [`azihsm_fw_hsm_pal_traits::HsmScopedAlloc`]
//! and allocates its intermediate buffers from that alloc. Internal
//! helpers request only the slices they need, and the PAL frees them
//! automatically when the outer alloc returns.
//!
//! ## Internal modules
//!
//! * `aead` — AES-GCM / AES-CBC-HMAC seal & open dispatch.
//! * `kdf` — RFC 9180 §4 LabeledExtract / LabeledExpand.
//! * `kem` — DHKEM Encap / Decap and their Auth variants.
//! * `ops` — public seal / open / export entry points.
//! * `schedule` — RFC 9180 §5.1 key schedule.
//! * `suite` — [`HpkeSuite`] enum and per-suite constants.
//! * `error` — placeholder; HPKE currently surfaces
//!   [`azihsm_fw_hsm_pal_traits::HsmError`] directly.

mod aead;
mod error;
mod helpers;
mod kdf;
mod kem;
mod ops;
mod schedule;
mod suite;

pub use ops::open_auth;
pub use ops::open_auth_psk;
pub use ops::open_base;
pub use ops::open_psk;
pub use ops::receive_export_base;
pub use ops::seal_auth;
pub use ops::seal_auth_psk;
pub use ops::seal_base;
pub use ops::seal_psk;
pub use ops::send_export_base;
pub use ops::AuthParams;
pub use ops::OpenRequest;
pub use ops::PskParams;
pub use ops::SealRequest;
pub use suite::HpkeSuite;
