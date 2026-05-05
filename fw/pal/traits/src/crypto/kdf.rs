// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key Derivation Function (KDF) and Mask Generation traits for the HSM PAL.
//!
//! Defines [`HsmKdfState`] and the [`HsmKdf`] trait that PAL implementations
//! use to expose HKDF (RFC 5869), SP 800-108 Counter Mode KDF, and
//! hash-based concatenation KDFs (MGF1, X9.63 KDF, SP 800-56A one-step KDF).
//!
//! On Cortex-M7 hardware the concatenation KDFs use the SHA engine in
//! exclusive synchronous mode for efficiency. HKDF and KBKDF delegate to
//! the HMAC engine. On the standard (host-native) PAL they use OpenSSL.
//!
//! ## Key representation
//!
//! All key parameters are plain `&[u8]` byte slices containing the raw
//! key material. Each PAL implementation is responsible for parsing
//! them into whatever internal representation it needs.
//!
//! ## Output buffer convention
//!
//! All methods write derived key material into a caller-provided
//! `&mut [u8]` buffer. The buffer length determines the number of
//! bytes derived (OKM length).
//!
//! ## Concatenation KDF family
//!
//! MGF1, X9.63 KDF, and SP 800-56A one-step KDF are all variations of
//! the same pattern: hash a counter with input keying material to
//! produce arbitrary-length output. They differ only in the order of
//! fields within each hash input:
//!
//! | Algorithm | Hash input |
//! |---|---|
//! | MGF1 (RFC 8017 §B.2.1) | `seed \|\| counter` |
//! | X9.63 KDF (SEC 1 §3.6.1) | `Z \|\| counter \|\| SharedInfo` |
//! | SP 800-56A one-step | `counter \|\| Z \|\| OtherInfo` |
//!
//! All three accept a caller-owned state buffer sized by
//! [`HsmHashAlgo::mgf1_state_len`] (or the corresponding KDF variant).
//!
//! ## HKDF (RFC 5869)
//!
//! HKDF is split into two methods matching the two-phase design:
//!
//! - [`hkdf_extract`](HsmKdf::hkdf_extract) — condenses IKM + salt into a
//!   fixed-length PRK.
//! - [`hkdf_expand`](HsmKdf::hkdf_expand) — derives arbitrary-length OKM
//!   from a PRK + info context.
//!
//! This split supports protocols (e.g., TLS 1.3) that perform one extract
//! followed by multiple expands with different info values. Both methods
//! accept an [`HsmKdfState`] of at least [`HsmHashAlgo::hmac_state_len`]
//! bytes as working space.

use super::*;

/// Caller-owned working buffer for KDF operations.
///
/// A zero-cost newtype over `&mut [u8]` that provides type safety —
/// prevents accidentally passing an unrelated buffer where a KDF
/// state is expected. Unlike [`HsmHashState`], this carries no
/// algorithm tag; the algorithm is passed separately to each KDF
/// method.
///
/// Size requirements depend on the KDF:
/// - HKDF / SP 800-108: [`HsmHashAlgo::hmac_state_len`] bytes.
/// - MGF1: [`HsmHashAlgo::mgf1_state_len`] bytes.
/// - X9.63 / SP 800-56A: [`HsmHashAlgo::concat_kdf_state_len`] bytes.
#[repr(transparent)]
#[derive(Debug)]
pub struct HsmKdfState<'a>(&'a mut [u8]);

impl<'a> HsmKdfState<'a> {
    /// Wrap a caller-owned byte slice as KDF working state.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self(buf)
    }

    /// Returns the buffer length.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume the wrapper and return the underlying mutable buffer.
    pub fn into_buf(self) -> &'a mut [u8] {
        self.0
    }
}

/// Asynchronous Key Derivation Function trait.
///
/// PAL implementations provide this to the core for deriving
/// cryptographic key material from existing keys using standardized
/// KDF algorithms. The async signatures allow hardware-backed
/// implementations to yield while the hash/HMAC engine processes data.
pub trait HsmKdf {
    /// HKDF-Extract (RFC 5869 §2.2) — condense IKM + salt into a PRK.
    ///
    /// `PRK = HMAC-Hash(salt, IKM)`
    ///
    /// # Parameters
    ///
    /// - `algo` — the underlying hash algorithm (e.g. SHA-256).
    /// - `salt` — optional salt value. Pass `&[]` to use the default
    ///   salt (a string of zero bytes of hash length).
    /// - `ikm` — input keying material.
    /// - `prk` — output buffer for the pseudorandom key. Must be at
    ///   least [`HsmHashAlgo::digest_len`] bytes.
    /// - `state` — caller-owned working buffer. Must wrap at least
    ///   [`HsmHashAlgo::hmac_state_len`] bytes.
    ///
    /// # Returns
    ///
    /// The `state` buffer, returned for reuse in subsequent calls
    /// (e.g. [`hkdf_expand`](Self::hkdf_expand)).
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if `prk` is too short, `state` is too
    /// small, or the HMAC operation fails.
    async fn hkdf_extract<'a>(
        &self,
        algo: HsmHashAlgo,
        salt: &[u8],
        ikm: &[u8],
        prk: &mut [u8],
        state: HsmKdfState<'a>,
    ) -> HsmResult<HsmKdfState<'a>>;

    /// HKDF-Expand (RFC 5869 §2.3) — derive OKM from a PRK.
    ///
    /// ```text
    /// T(0) = empty
    /// T(i) = HMAC-Hash(PRK, T(i-1) || info || i)  for i = 1..N
    /// OKM  = first L bytes of T(1) || T(2) || …
    /// ```
    ///
    /// # Parameters
    ///
    /// - `algo` — the underlying hash algorithm.
    /// - `prk` — pseudorandom key from [`hkdf_extract`](Self::hkdf_extract).
    /// - `info` — context and application-specific info. Pass `&[]` if
    ///   not needed.
    /// - `output` — buffer for the derived output key material (OKM).
    ///   Length must not exceed `255 * digest_len`.
    /// - `state` — caller-owned working buffer. Must wrap at least
    ///   [`HsmHashAlgo::hmac_state_len`] bytes.
    ///
    /// # Returns
    ///
    /// The `state` buffer, returned for reuse in subsequent expand calls.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if `output` exceeds the RFC limit, `state`
    /// is too small, or the HMAC operation fails.
    async fn hkdf_expand<'a>(
        &self,
        algo: HsmHashAlgo,
        prk: &[u8],
        info: &[u8],
        output: &mut [u8],
        state: HsmKdfState<'a>,
    ) -> HsmResult<HsmKdfState<'a>>;

    /// Derive key material using SP 800-108 KDF in Counter Mode with HMAC.
    ///
    /// Uses HMAC as the PRF with an incrementing counter. The derived
    /// output is computed as:
    /// `K(i) = HMAC(key, i ‖ label ‖ 0x00 ‖ context ‖ L)` for each
    /// block `i`, where `L` is the requested output length in bits.
    ///
    /// # Parameters
    ///
    /// - `algo` — the HMAC hash algorithm (e.g. SHA-384).
    /// - `key` — the key-derivation key (KDK).
    /// - `label` — a string identifying the purpose of the derived key.
    ///   Pass `&[]` if not needed.
    /// - `context` — context information binding the derived key to a
    ///   specific use. Pass `&[]` if not needed.
    /// - `output` — buffer for the derived key material. The buffer
    ///   length determines how many bytes are derived.
    /// - `state` — caller-owned working buffer. Must wrap at least
    ///   [`HsmHashAlgo::hmac_state_len`] bytes.
    ///
    /// # Returns
    ///
    /// The `state` buffer, returned for reuse.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if the KDF operation fails (e.g.,
    /// unsupported algorithm, HMAC computation error).
    async fn sp800_108_kdf<'a>(
        &self,
        algo: HsmHashAlgo,
        key: &[u8],
        label: &[u8],
        context: &[u8],
        output: &mut [u8],
        state: HsmKdfState<'a>,
    ) -> HsmResult<HsmKdfState<'a>>;

    /// Compute MGF1 per [RFC 8017 §B.2.1](https://www.rfc-editor.org/rfc/rfc8017#appendix-B.2.1).
    ///
    /// Expands `seed` into `mask.len()` bytes of mask material using
    /// the specified hash algorithm:
    /// `T(C) = Hash(seed || I2OSP(C, 4))` for `C = 0, 1, …`.
    ///
    /// # Parameters
    ///
    /// - `algo` — hash algorithm (e.g. SHA-256).
    /// - `seed` — the MGF1 seed input.
    /// - `mask` — output buffer; filled with `mask.len()` bytes of mask
    ///   material.
    /// - `state` — caller-owned working buffer. Must be at least
    ///   [`HsmHashAlgo::mgf1_state_len`]`(seed.len())` bytes.
    ///   Layout: `[hash(digest_len) | input(seed_len + 4)]`.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if `state` is too small or the underlying
    /// hash operation fails.
    async fn mgf1(
        &self,
        algo: HsmHashAlgo,
        seed: &[u8],
        mask: &mut [u8],
        state: &mut [u8],
    ) -> HsmResult<()>;

    /// MGF1 with in-place XOR (RFC 8017 §B.2.1).
    ///
    /// Like [`mgf1`](Self::mgf1) but instead of overwriting `mask`, each
    /// generated mask byte is **XOR'd** into the existing content of
    /// `mask`. This is the primitive needed by OAEP and PSS padding.
    ///
    /// # Parameters
    ///
    /// - `algo` — hash algorithm.
    /// - `seed` — the MGF1 seed input.
    /// - `mask` — buffer to XOR the generated mask into (in-place).
    /// - `state` — caller-owned working buffer. Must be at least
    ///   [`HsmHashAlgo::mgf1_state_len`]`(seed.len())` bytes.
    async fn mgf1_xor(
        &self,
        algo: HsmHashAlgo,
        seed: &[u8],
        mask: &mut [u8],
        state: &mut [u8],
    ) -> HsmResult<()>;

    /// Derive key material using X9.63 KDF (SEC 1 §3.6.1).
    ///
    /// Expands shared secret `z` into `key.len()` bytes of key material:
    /// `T(C) = Hash(Z || I2OSP(C, 4) || SharedInfo)` for `C = 1, 2, …`.
    ///
    /// # Parameters
    ///
    /// - `algo` — hash algorithm (e.g. SHA-256).
    /// - `z` — the shared secret (e.g. ECDH output).
    /// - `shared_info` — optional shared info. Pass `&[]` to omit.
    /// - `key` — output buffer; filled with `key.len()` bytes of derived
    ///   key material.
    /// - `state` — caller-owned working buffer. Must be at least
    ///   [`HsmHashAlgo::concat_kdf_state_len`]`(z.len(), shared_info.len())`
    ///   bytes. Layout: `[hash(digest_len) | input(z_len + 4 + info_len)]`.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if `state` is too small or the underlying
    /// hash operation fails.
    async fn x963_kdf(
        &self,
        algo: HsmHashAlgo,
        z: &[u8],
        shared_info: &[u8],
        key: &mut [u8],
        state: &mut [u8],
    ) -> HsmResult<()>;

    /// Derive key material using SP 800-56A one-step Concatenation KDF.
    ///
    /// Expands shared secret `z` into `key.len()` bytes of key material:
    /// `T(C) = Hash(I2OSP(C, 4) || Z || OtherInfo)` for `C = 1, 2, …`.
    ///
    /// # Parameters
    ///
    /// - `algo` — hash algorithm (e.g. SHA-256).
    /// - `z` — the shared secret (e.g. ECDH output).
    /// - `other_info` — context information. Pass `&[]` to omit.
    /// - `key` — output buffer; filled with `key.len()` bytes of derived
    ///   key material.
    /// - `state` — caller-owned working buffer. Must be at least
    ///   [`HsmHashAlgo::concat_kdf_state_len`]`(z.len(), other_info.len())`
    ///   bytes. Layout: `[hash(digest_len) | input(4 + z_len + info_len)]`.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if `state` is too small or the underlying
    /// hash operation fails.
    async fn sp800_56a_kdf(
        &self,
        algo: HsmHashAlgo,
        z: &[u8],
        other_info: &[u8],
        key: &mut [u8],
        state: &mut [u8],
    ) -> HsmResult<()>;
}
