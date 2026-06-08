// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared test infrastructure for the TBOR integration suite.
//!
//! - [`ctx`]           per-test fixture + canonical error-shape assertions
//! - [`session_guard`] RAII guard that closes a live session on drop
//! - [`fixture`]       backend bring-up and canonical PSK constants
//! - [`assertions`]    reusable error-shape predicates
//! - [`session`]       session-establishment + per-command crypto helpers
//! - [`api_rev`]       `GetApiRev` request helper
//!
//! Anything declared `pub` here is reachable from `crate::harness::…`
//! inside the test binary. Nothing in this directory is part of the
//! `azihsm_ddi_tbor_types` public API.
//!
//! # Backend feature regimes
//!
//! The test binary supports three build modes; each disables a
//! different subset of tests via `#![cfg(...)]` so failures show up
//! as "no test compiled" instead of as silent passes:
//!
//! * `--features emu` (the canonical configuration; runs the full
//!   suite). All in-session command tests are gated
//!   `#![cfg(feature = "emu")]` because they require the FW handler
//!   actually present in the std/emu PAL build.
//! * `--features mock` (transport-contract probes only).
//!   `commands::get_api_rev::unsupported_on_mock` exercises that the
//!   mock backend rejects TBOR opcodes at the transport layer; it
//!   is gated `#[cfg(feature = "mock")]`.
//! * No backend feature. The pure host-side codec tests (everything
//!   in `commands::fw_error_decode` and `commands::unexpected_toc_type`)
//!   compile and run because they do not touch the harness; this
//!   module is gated `#![cfg(any(feature = "emu", feature = "mock"))]`
//!   so the harness itself disappears in this mode.
//!
//! Backend-specific [`TestCtx`] methods (`erase`, `cert_chain_info`,
//! `get_certificate`) carry per-method `#[cfg(feature = "emu")]` and
//! are unavailable under `--features mock`.

#![cfg(any(feature = "emu", feature = "mock"))]

pub mod api_rev;
pub mod assertions;
pub mod ctx;
pub mod fixture;
pub mod session;
pub mod session_guard;

// Re-export commonly-used schema items so test code doesn't have to
// import them from `azihsm_ddi_tbor_types` directly when driving
// negative-path tests through raw `TborOpenSession*Req` /
// `TborChangePskReq` requests.
// Flat re-exports so test files write `use crate::harness::open_session`
// instead of `crate::harness::session::open_session`.
pub use api_rev::helper_get_api_rev_tbor;
pub use azihsm_ddi_tbor_types::build_psk_change_aad;
pub use azihsm_ddi_tbor_types::TborChangePskReq;
pub use azihsm_ddi_tbor_types::PSK_CHANGE_AAD_LEN;
pub use azihsm_ddi_tbor_types::PSK_CHANGE_ENVELOPE_MAX_LEN;
pub use ctx::TestCtx;
pub use fixture::open_dev;
pub use session::build_mac_fin;
pub use session::build_part_init_mach_seed_aad;
pub use session::change_psk;
pub use session::close_session;
pub use session::encrypt_mach_seed_envelope;
pub use session::encrypt_psk_envelope;
pub use session::open_session;
pub use session::open_session_finish;
pub use session::open_session_finish_with_mac;
pub use session::open_session_init;
pub use session::open_session_init_with_options;
pub use session::part_init;
pub use session::OpenSessionInitOptions;
pub use session::PendingHandshake;
pub use session::SessionHandshake;
pub use session_guard::SessionGuard;
