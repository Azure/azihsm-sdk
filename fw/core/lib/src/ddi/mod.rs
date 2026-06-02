// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI command dispatch — split per wire codec.
//!
//! - [`mbor`] hosts the original MBOR-encoded DDI command handlers
//!   reached via the `OP_MBOR` SQE opcode.
//! - [`tbor`] hosts the TBOR-encoded DDI command handlers reached via
//!   the `OP_TBOR` SQE opcode.
//!
//! Both sub-modules expose a `dispatch` entry point invoked from
//! [`crate::Hsm::handle_mbor_op`] / [`crate::Hsm::handle_tbor_op`] and
//! a per-codec error encoder used when post-decode failures need to be
//! surfaced as a typed response body rather than a CQE status code.

pub(crate) mod mbor;
pub(crate) mod tbor;

// Re-expose crate-root symbols (HsmPal, HsmIo, HsmError, …) to the
// child modules' `use super::*;` imports.
use super::*;
