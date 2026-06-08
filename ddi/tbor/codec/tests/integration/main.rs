// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for `azihsm_ddi_tbor_codec`.
//!
//! Single test binary, split into topical modules for readability.
//! Cargo compiles `tests/<name>/main.rs` as one binary along with all
//! sibling files declared via `mod`.

// `unwrap_err()` is the natural way to assert error variants in tests.
#![allow(clippy::unwrap_used)]

mod common;
mod decode_errors;
mod display;
mod encode_errors;
mod error_display;
mod forward_compat;
mod header_ctors;
mod round_trip;
