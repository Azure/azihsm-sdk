// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration test binary for `azihsm_ddi_tbor_types`.
//!
//! Backend selection is feature-gated. Run with `--features emu` for the
//! happy-path round-trip tests, or `--features mock` for the negative
//! `UnsupportedEncoding` test.

pub mod integration;
