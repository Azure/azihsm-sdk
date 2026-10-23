// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pairwise consistency tests (PCTs) for the Uno firmware.
//!
//! FIPS 140-3 requires a PCT when the module generates an asymmetric key pair,
//! and when it accepts a key pair from outside the module. The Uno PAL runs
//! every PCT with this crate. [`ecc_pct`] and [`rsa_pct`] run the PCT that the
//! caller selects: a sign/verify round trip for signing keys, a two-way ECDH
//! agreement with a fixed test key pair for key-agreement keys, and an
//! encrypt/decrypt round trip for RSA decryption keys.
//!
//! The PCT functions report an inconsistent key pair as `Ok(false)` and a
//! failed operation as `Err`. The caller decides what each outcome means: an
//! import is rejected, while a generated key sends the module to its error
//! state. The crate calls only PAL trait operations, and it builds its ECDH
//! test key in the Uno PAL's vault format.

#![cfg_attr(not(test), no_std)]

mod ecc;
mod rsa;
mod vectors;

#[cfg(test)]
mod tests;

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
pub use ecc::ecc_pct;
pub use rsa::rsa_pct;

/// Compares two byte strings without stopping at the first difference, so
/// the time it takes doesn't depend on where they differ. Use it for secret
/// data, such as key material. Strings of different lengths are unequal.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    core::hint::black_box(diff) == 0
}

/// Allocates PCT scratch.
///
/// A PAL's scoped allocator can inline its bounds checks into every caller.
/// The PCTs allocate through these out-of-line wrappers instead, so that code
/// appears once.
#[inline(never)]
fn scratch<A: HsmScopedAlloc>(alloc: &A, len: usize) -> HsmResult<&mut DmaBuf> {
    alloc.dma_alloc(len)
}

/// Allocates zeroed PCT scratch; see [`scratch`].
#[inline(never)]
fn scratch_zeroed<A: HsmScopedAlloc>(alloc: &A, len: usize) -> HsmResult<&mut DmaBuf> {
    alloc.dma_alloc_zeroed(len)
}
