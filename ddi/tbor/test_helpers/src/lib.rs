// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test helpers for TBOR DDI commands.
//!
//! Mirrors [`azihsm_ddi_mbor_test_helpers`] for the TBOR codec. Each
//! module wraps a TBOR command in a small `helper_*` function that
//! constructs the request, invokes `exec_op_tbor`, and returns the
//! typed response.

mod api_rev;

pub use api_rev::*;
