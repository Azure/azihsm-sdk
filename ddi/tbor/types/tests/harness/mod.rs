// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared test infrastructure for the TBOR integration suite.
//!
//! - [`ctx`]           per-test fixture + canonical error-shape assertions
//! - [`session_guard`] RAII guard that closes a live session on drop
//! - [`fixture`]       backend bring-up and canonical PSK constants
//! - [`assertions`]    reusable error-shape predicates
//! - [`session`]       session-establishment + per-command crypto helpers
//! - [`api_rev`]       `ApiRev` request helper
//!
//! Anything declared `pub` here is reachable from `crate::harness::…`
//! inside the test binary. Nothing in this directory is part of the
//! `azihsm_ddi_tbor_types` public API.
//!
//! # Backend feature regimes
//!
//! The test binary supports three active build modes:
//!
//! * `--features emu` — the canonical configuration; runs the full
//!   suite against the in-process std-PAL firmware.
//! * `--features sock` — drives the same TBOR round-trips against
//!   firmware behind a socket server.
//! * **No backend feature** — targets the native OS backend (`nix` on
//!   Linux / `win` on Windows) so the hw-eligible tests in
//!   [`crate::commands`] run against real silicon. Destructive
//!   emu-only tests remain gated `#[cfg(feature = "emu")]` at the
//!   test-item level.
//!
//! `--features mock` is compilable but disables both this harness
//! and the `commands` tree at the crate root
//! (`tests/azihsm_ddi_tbor_tests.rs`) — mock rejects TBOR at the
//! transport layer, so command-level integration tests are
//! meaningless there.

pub mod api_rev;
pub mod assertions;
pub mod ctx;
pub mod fixture;
pub mod session;
pub mod session_guard;
#[cfg(feature = "emu")]
pub mod x509_fixture;

// Re-export commonly-used schema items so test code doesn't have to
// import them from `azihsm_ddi_tbor_types` directly when driving
// negative-path tests through raw `TborSessionOpen*Req` /
// `TborPskChangeReq` requests.
// Flat re-exports so test files write `use crate::harness::open_session`
// instead of `crate::harness::session::open_session`.
pub use api_rev::helper_api_rev_tbor;
pub use azihsm_ddi_tbor_types::build_psk_change_aad;
pub use azihsm_ddi_tbor_types::TborPskChangeReq;
pub use azihsm_ddi_tbor_types::PSK_CHANGE_AAD_LEN;
pub use azihsm_ddi_tbor_types::PSK_CHANGE_ENVELOPE_MAX_LEN;
pub use ctx::TestCtx;
pub use fixture::open_dev;
pub use session::build_mac_fin;
pub use session::build_part_init_mach_seed_aad;
pub use session::encrypt_mach_seed_envelope;
pub use session::encrypt_psk_envelope;
pub use session::open_session_on_dev;
pub use session::part_init;
pub use session::psk_change;
pub use session::session_close_on_dev;
pub use session::session_open_finish_on_dev;
pub use session::session_open_finish_with_mac;
pub use session::session_open_init_on_dev;
pub use session::session_open_init_with_options;
pub use session::PendingHandshake;
pub use session::SessionHandshake;
pub use session::SessionOpenInitOptions;
pub use session_guard::SessionGuard;
