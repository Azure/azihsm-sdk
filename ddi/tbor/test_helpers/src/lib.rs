// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test helpers for TBOR DDI commands.
//!
//! Mirrors [`azihsm_ddi_mbor_test_helpers`] for the TBOR codec. Each
//! module wraps a TBOR command in a small `helper_*` function that
//! constructs the request, invokes `exec_op_tbor`, and returns the
//! typed response.

mod api_rev;
mod fixtures;
pub mod session;

pub use api_rev::*;
// Re-export commonly-used schema items so test code doesn't have to
// import them from `azihsm_ddi_tbor_types` directly when driving
// negative-path tests through raw `TborOpenSession*Req` /
// `TborChangePskReq` requests.
pub use azihsm_ddi_tbor_types::build_psk_change_aad;
pub use azihsm_ddi_tbor_types::TborChangePskReq;
pub use azihsm_ddi_tbor_types::PSK_CHANGE_AAD_LEN;
pub use azihsm_ddi_tbor_types::PSK_CHANGE_ENVELOPE_MAX_LEN;
pub use fixtures::*;
pub use session::build_mac_fin;
pub use session::change_psk;
pub use session::close_session;
pub use session::encrypt_psk_envelope;
pub use session::open_session;
pub use session::open_session_finish;
pub use session::open_session_finish_with_mac;
pub use session::open_session_init;
pub use session::open_session_init_with_options;
pub use session::OpenSessionInitOptions;
pub use session::PendingHandshake;
pub use session::SessionHandshake;
