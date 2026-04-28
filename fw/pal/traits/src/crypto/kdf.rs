// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key Derivation Function (KDF) traits for the HSM PAL.
//!
//! Defines [`HkdfMode`] and the [`HsmKdf`] trait that PAL implementations
//! use to expose HKDF (RFC 5869) and KBKDF (NIST SP 800-108) key
//! derivation operations.
//!
//! On Cortex-M7 hardware these would delegate to the HMAC engine in
//! streaming mode. On the standard (host-native) PAL they use OpenSSL's
//! HKDF and KBKDF implementations.
//!
//! ## Key representation
//!
//! All key parameters are plain `&[u8]` byte slices containing the raw
//! key material. Each PAL implementation is responsible for parsing
//! them into whatever internal representation it needs.
//!
//! ## Output buffer convention
//!
//! Both methods write derived key material into a caller-provided
//! `&mut [u8]` buffer. The buffer length determines the number of
//! bytes derived (OKM length).

use super::*;

/// HKDF operation mode (RFC 5869).
///
/// HKDF is a two-stage KDF built on HMAC:
/// 1. **Extract** — condenses input key material (IKM) + salt into a
///    fixed-length pseudorandom key (PRK).
/// 2. **Expand** — derives output key material (OKM) from the PRK +
///    info context.
///
/// Most callers use [`ExtractAndExpand`](HkdfMode::ExtractAndExpand) for
/// the full operation. Separate modes are available for protocols that
/// split the two phases (e.g., TLS 1.3).
pub enum HkdfMode {
    /// Extract only — produce PRK from IKM + salt.
    Extract,

    /// Expand only — derive OKM from an existing PRK + info.
    /// The `key` parameter is treated as the PRK.
    Expand,

    /// Full HKDF — extract then expand in one call.
    ExtractAndExpand,
}

/// Asynchronous Key Derivation Function trait.
///
/// PAL implementations provide this to the core for deriving
/// cryptographic key material from existing keys using standardized
/// KDF algorithms. The async signatures allow hardware-backed
/// implementations to yield while the HMAC engine processes data.
pub trait HsmKdf {
    /// Derive key material using HKDF (RFC 5869).
    ///
    /// # Parameters
    /// - `key` — Input key material (IKM) for Extract mode, or the
    ///   pseudorandom key (PRK) for Expand mode.
    /// - `algo` — The underlying hash algorithm for HMAC
    ///   (e.g., SHA-256, SHA-384).
    /// - `mode` — Which HKDF phase(s) to perform.
    /// - `salt` — Optional salt value. Pass an empty slice `&[]` to use
    ///   the default salt (a string of zero bytes of hash length).
    /// - `info` — Context and application-specific info. Pass `&[]` if
    ///   not needed.
    /// - `output` — Buffer for the derived output key material (OKM).
    ///   The buffer length determines how many bytes are derived.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the HKDF operation fails (e.g.,
    /// unsupported algorithm, output length exceeds 255 * hash length).
    async fn hkdf(
        &self,
        key: &[u8],
        algo: HsmHashAlgo,
        mode: HkdfMode,
        salt: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()>;

    /// Derive key material using KBKDF in Counter Mode with HMAC
    /// (NIST SP 800-108).
    ///
    /// Uses HMAC as the PRF with an incrementing counter. The derived
    /// output is computed as:
    /// `K(i) = HMAC(key, i ‖ label ‖ 0x00 ‖ context ‖ L)` for each
    /// block `i`, where `L` is the requested output length in bits.
    ///
    /// # Parameters
    /// - `key` — The key-derivation key (KDK).
    /// - `algo` — The HMAC hash algorithm (e.g., SHA-384).
    /// - `label` — A string identifying the purpose of the derived key.
    ///   Pass `&[]` if not needed.
    /// - `context` — Context information binding the derived key to a
    ///   specific use. Pass `&[]` if not needed.
    /// - `output` — Buffer for the derived key material. The buffer
    ///   length determines how many bytes are derived.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the KBKDF operation fails (e.g.,
    /// unsupported algorithm, HMAC computation error).
    async fn kbkdf(
        &self,
        key: &[u8],
        algo: HsmHashAlgo,
        label: &[u8],
        context: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()>;
}
