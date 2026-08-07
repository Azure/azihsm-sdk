// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM core — generic application logic over a platform abstraction layer.
//!
//! This crate is a pure async library with no executor dependency.
//! The concrete PAL type and Embassy task wiring are provided by the
//! platform crate (e.g. `fw/plat/std/lib`).

#![cfg_attr(not(feature = "std"), no_std)]

mod ddi;
mod error;
mod hsm;
mod io;
mod op;
pub mod part_state;
mod session;

use azihsm_fw_hsm_core_tracing::*;
use azihsm_fw_hsm_pal_traits::*;
pub(crate) use error::*;
pub use hsm::Hsm;
pub(crate) use op::*;

/// Compares two byte slices in constant time with respect to their
/// contents.
///
/// Rust's `==` on `[u8]` lowers to `memcmp`, which returns as soon as
/// it finds a differing byte.  Against a secret (a PSK, a MAC tag, a
/// freshly-decrypted key) that early-out is a timing oracle.  This
/// helper always walks the whole slice and folds the XOR of every byte
/// pair into one accumulator, so its runtime depends only on the input
/// *length* — which is public.  A length mismatch short-circuits for
/// the same reason.
///
/// Use it wherever either side is secret; plain `==` remains correct
/// (and preferable) for public values.
#[must_use]
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod ct_eq_tests {
    use super::ct_eq;

    #[test]
    fn equal_slices_match() {
        assert!(ct_eq(b"abcdef", b"abcdef"));
        assert!(ct_eq(&[], &[]));
    }

    #[test]
    fn differing_slices_do_not_match() {
        assert!(!ct_eq(b"abcdef", b"abcdeg"));
        assert!(!ct_eq(b"abcdef", b"zbcdef"));
    }

    #[test]
    fn length_mismatch_does_not_match() {
        assert!(!ct_eq(b"abcdef", b"abcde"));
        assert!(!ct_eq(b"", b"a"));
    }
}
