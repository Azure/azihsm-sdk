// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Re-export of `harness/assertions.rs` for hardware tests.
//!
//! The `harness` module tree is `#[cfg]`'d off in the hardware build,
//! so we pull the file in directly via `#[path]` and re-export its
//! public surface. This keeps hw and emu tests using the same
//! `assert_fw_rejects` predicate so a wire-contract change touches
//! one file.

#[path = "../harness/assertions.rs"]
mod _inner;
pub use _inner::*;
