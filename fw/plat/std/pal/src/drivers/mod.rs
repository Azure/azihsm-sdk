// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crypto driver modules for the standard (host-native) PAL.
//!
//! Each driver owns a [`WorkerPool`](crate::workers::WorkerPool) clone
//! and exposes `async` methods that dispatch blocking `azihsm_crypto`
//! operations onto a background thread pool.  The PAL trait
//! implementations in the parent module are thin wrappers that
//! map PAL-level enums to `azihsm_crypto` types, delegate to the
//! appropriate driver, and convert handles back to raw byte slices.
//!
//! ## Drivers
//!
//! | Module      | Trait                | Operations |
//! |-------------|----------------------|------------|
//! | [`aes`]     | [`HsmAes`]           | AES-CBC / AES-ECB keygen, encrypt, decrypt |
//! | [`ecc`]     | [`HsmEcc`]           | ECDSA sign / verify, ECDH derive, keygen |
//! | [`hash`]    | [`HsmHash`]          | SHA-1 / SHA-256 / SHA-384 / SHA-512 digest |
//! | [`hmac`]    | [`HsmHmac`]          | HMAC sign / verify with all SHA variants |
//! | [`kdf`]     | [`HsmKdf`]           | HKDF (RFC 5869) and KBKDF (NIST SP 800-108) |
//! | [`rsa`]     | [`HsmRsa`]           | RSA keygen, modular exponentiation |
//! | [`session`] | [`HsmSessionManager`]| Per-partition session allocation via bitmask |
//! | [`vault`]   | [`HsmVault`]         | Per-partition key storage with firmware capacity emulation |
//!
//! ## Non-crypto drivers
//!
//! | Module   | Description |
//! |----------|-------------|
//! | [`gdma`] | Guest DMA controller — buffer copies (no host DMA in simulator) |
//! | [`iic`]  | Input I/O controller — SQE ring management |
//! | [`oic`]  | Output I/O controller — CQE ring management |
//!
//! [`HsmAes`]: azihsm_fw_hsm_pal_traits::HsmAes
//! [`HsmEcc`]: azihsm_fw_hsm_pal_traits::HsmEcc
//! [`HsmHash`]: azihsm_fw_hsm_pal_traits::HsmHash
//! [`HsmHmac`]: azihsm_fw_hsm_pal_traits::HsmHmac
//! [`HsmKdf`]: azihsm_fw_hsm_pal_traits::HsmKdf
//! [`HsmRsa`]: azihsm_fw_hsm_pal_traits::HsmRsa
//! [`HsmSessionManager`]: azihsm_fw_hsm_pal_traits::HsmSessionManager
//! [`HsmVault`]: azihsm_fw_hsm_pal_traits::HsmVault

pub mod aes;
pub mod ecc;
pub mod gdma;
pub mod hash;
pub mod hmac;
pub mod iic;
pub mod kdf;
pub mod oic;
pub mod rsa;
pub mod session;
pub mod vault;

/// Reverse-copy `src` into `dst[..src.len()]`.
///
/// Centralizes the big-endian↔little-endian byte reversal shared by the
/// crypto drivers: their wire convention is little-endian (what real PKA
/// hardware emits natively), while the OpenSSL backend produces
/// big-endian components.  The reversal is symmetric, so the same helper
/// serves both directions.  Trailing pad bytes in `dst` beyond
/// `src.len()` (e.g. the 2-byte pad after a 66-byte P-521 coordinate
/// inside a 68-byte word) are left untouched — callers that need them
/// zeroed should pre-`fill(0)` the full `dst` slot.
pub(crate) fn reverse_copy(dst: &mut [u8], src: &[u8]) {
    let len = src.len();
    debug_assert!(dst.len() >= len);
    for (d, s) in dst[..len].iter_mut().zip(src.iter().rev()) {
        *d = *s;
    }
}
