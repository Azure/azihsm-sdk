// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared test fixtures for TBOR DDI helpers and integration tests.
//!
//! Centralises canonical constants (well-known default PSKs) so
//! per-command helper modules and per-command integration tests
//! don't drift on the values they pass to the FW handshake.

pub use azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CO;
pub use azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CU;
pub use azihsm_fw_hsm_pal_traits::PSK_LEN;
pub use azihsm_fw_hsm_pal_traits::SESSION_SEED_LEN;
