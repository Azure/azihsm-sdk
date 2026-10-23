// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-algorithm crypto trait implementations for the Uno PAL.
//!
//! Each submodule implements one of the platform-agnostic crypto traits
//! defined in [`azihsm_fw_hsm_pal_traits`] against the on-chip Uno
//! hardware accelerators:
//!
//! | Submodule | Trait                | Hardware backend |
//! |-----------|----------------------|------------------|
//! | [`aes`]   | [`HsmAes`] (AES half) | AES core        |
//! | [`kw`]    | [`HsmAes`] (KW/KWP)  | AES core        |
//! | [`hash`]  | [`HsmHash`]           | SHA core        |
//! | [`hmac`]  | [`HsmHmac`]           | SHA core        |
//! | [`kdf`]   | [`HsmKdf`]            | SHA core + HMAC |
//! | [`rng`]   | [`HsmRng`]            | RNG driver      |
//! | [`ecc`]   | [`HsmEcc`]            | PKA             |
//! | [`rsa`]   | [`HsmRsa`]            | PKA             |
//!
//! [`HsmCrypto`] is the marker supertrait that requires the full set;
//! the empty `impl` below ties everything together so the HSM core can
//! treat [`UnoHsmPal`] as a complete crypto provider.
//!
//! The [`ecc_det`] submodule is a companion to [`ecc`]: it holds the
//! deterministic ECDSA-P384 sign path (RFC 6979) as inherent methods on
//! [`UnoHsmPal`] rather than a distinct trait impl, kept separate so the
//! base [`HsmEcc`] adapter stays focused on the standard curve ops.
//!
//! [`HsmAes`]: azihsm_fw_hsm_pal_traits::HsmAes
//! [`HsmHash`]: azihsm_fw_hsm_pal_traits::HsmHash
//! [`HsmHmac`]: azihsm_fw_hsm_pal_traits::HsmHmac
//! [`HsmKdf`]: azihsm_fw_hsm_pal_traits::HsmKdf
//! [`HsmRng`]: azihsm_fw_hsm_pal_traits::HsmRng
//! [`HsmEcc`]: azihsm_fw_hsm_pal_traits::HsmEcc
//! [`HsmRsa`]: azihsm_fw_hsm_pal_traits::HsmRsa

mod aes;
mod ecc;
mod ecc_det;
mod gcm;
mod hash;
mod hmac;
mod kdf;
mod kw;
mod rng;
mod rsa;

use azihsm_fw_hsm_pal_traits::HsmCrypto;

use crate::UnoHsmPal;

impl HsmCrypto for UnoHsmPal {}

/// Copies `src` into `dst[..src.len()]` in reverse byte order.
///
/// The crypto drivers cross two endian conventions constantly: PKA operands
/// and the vault layout are little-endian, while DER/SEC1 integers and the
/// RFC 6979 DRBG work big-endian. Converting between them is always "copy
/// these bytes backwards", so the loop lives here once instead of being
/// rewritten per call site.
///
/// `src` and `dst` must not overlap; use `copy_within` plus an in-place
/// `reverse` when they can. Bytes of `dst` beyond `src.len()` are left
/// untouched, so a caller needing a fixed-width zero-padded field must clear
/// them itself.
///
/// # Panics
///
/// Debug builds assert that `dst` is at least as long as `src`; a shorter
/// `dst` silently truncates, which is a caller bug.
#[inline]
pub(crate) fn reverse_copy(dst: &mut [u8], src: &[u8]) {
    debug_assert!(dst.len() >= src.len());
    for (d, s) in dst.iter_mut().zip(src.iter().rev()) {
        *d = *s;
    }
}
