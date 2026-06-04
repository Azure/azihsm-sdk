// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for TBOR command integration tests.
//!
//! Per-command test files compose the helpers in this module so
//! backend setup, error-shape assertions, and HsmError-discriminant
//! matching live in exactly one place.
//!
//! Both submodules are gated on at least one backend feature being
//! enabled, matching the per-command test files. Without that gate,
//! the helpers become dead code that trips `-D warnings`.

#![cfg(any(feature = "emu", feature = "mock"))]

pub mod assertions;
pub mod fixture;
