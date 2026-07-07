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
//! All three allocate their internal working state from an
//! [`HsmScopedAlloc`] sized by [`HsmHashAlgo::mgf1_state_len`] (or the
//! corresponding KDF variant).
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
//! followed by multiple expands with different info values. The HMAC-backed
//! methods allocate their internal working state from an [`HsmScopedAlloc`].

use super::*;

/// Buffer-backed working state for PAL-internal KDF helpers.
///
/// A zero-cost newtype over `&mut [u8]` that provides type safety when
/// a PAL needs to manage concatenation-KDF scratch space explicitly.
/// Public [`HsmKdf`] methods allocate their working state from an
/// [`HsmScopedAlloc`], but this wrapper remains available for buffer-
/// backed helper code.
///
/// Size requirements depend on the KDF:
/// - MGF1: [`HsmHashAlgo::mgf1_state_len`] bytes.
/// - X9.63 / SP 800-56A: [`HsmHashAlgo::concat_kdf_state_len`] bytes.
#[repr(transparent)]
#[derive(Debug)]
pub struct HsmKdfState<'a>(&'a mut [u8]);

impl<'a> HsmKdfState<'a> {
    /// Wrap a caller-owned byte slice as buffer-backed KDF state.
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
    /// HKDF-Extract (RFC 5869 §2.2): condense `ikm` and `salt` into
    /// a fixed-length pseudorandom key.
    ///
    /// `PRK = HMAC-Hash(salt, IKM)`
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — underlying hash algorithm (e.g. SHA-256).
    /// - `salt` — optional salt; `None` selects the RFC 5869 default
    ///   (a string of zero bytes of `algo.digest_len()`).
    /// - `ikm` — input keying material.
    /// - `prk` — output PRK; must be at least `algo.digest_len()`
    ///   bytes.  Only the leading `digest_len` bytes are written.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `prk[..digest_len]` populated.
    /// - `Err(HsmError::InvalidArg)` — `prk` shorter than
    ///   `algo.digest_len()`.
    /// - `Err(HsmError::NotEnoughSpace)` — internal scoped allocation too
    ///   small for the HMAC state.
    /// - `Err(HsmError)` — SHA / HMAC driver failure.
    async fn hkdf_extract(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        salt: Option<&DmaBuf>,
        ikm: &DmaBuf,
        prk: &mut DmaBuf,
    ) -> HsmResult<()>;

    /// HKDF-Expand (RFC 5869 §2.3): derive arbitrary-length output
    /// key material from a PRK.
    ///
    /// ```text
    /// T(0) = empty
    /// T(i) = HMAC-Hash(PRK, T(i-1) || info || i)  for i = 1..N
    /// OKM  = first L bytes of T(1) || T(2) || …
    /// ```
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — underlying hash algorithm.
    /// - `prk` — PRK from
    ///   [`hkdf_extract`](Self::hkdf_extract).
    /// - `info` — context / application info; `None` to omit.
    /// - `output` — OKM destination; `output.len()` must satisfy
    ///   `output.len() <= 255 * algo.digest_len()`.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `output` filled with `output.len()` bytes of OKM.
    /// - `Err(HsmError::InvalidArg)` — `output` exceeds the RFC 5869
    ///   length cap.
    /// - `Err(HsmError::NotEnoughSpace)` — internal scoped allocation too
    ///   small.
    /// - `Err(HsmError)` — SHA / HMAC driver failure.
    async fn hkdf_expand(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        prk: &DmaBuf,
        info: Option<&DmaBuf>,
        output: &mut DmaBuf,
    ) -> HsmResult<()>;

    /// SP 800-108 Counter Mode KDF with HMAC PRF.
    ///
    /// `K(i) = HMAC(key, i ‖ label ‖ 0x00 ‖ context ‖ L)` for each
    /// block `i`, with `L` the requested output length in bits.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — HMAC underlying hash (e.g. SHA-384).
    /// - `key` — key-derivation key (KDK).
    /// - `label` — purpose string; `None` to omit.
    /// - `context` — binding context; `None` to omit.
    /// - `output` — derived-key destination; `output.len()` bytes
    ///   are produced.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `output` filled.
    /// - `Err(HsmError::InvalidArg)` — `output` exceeds the
    ///   `2^32 - 1` block-counter limit.
    /// - `Err(HsmError::NotEnoughSpace)` — internal scoped allocation too small.
    /// - `Err(HsmError)` — SHA / HMAC driver failure.
    async fn sp800_108_kdf(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        key: &DmaBuf,
        label: Option<&DmaBuf>,
        context: Option<&DmaBuf>,
        output: &mut DmaBuf,
    ) -> HsmResult<()>;

    /// MGF1 mask generation per
    /// [RFC 8017 §B.2.1](https://www.rfc-editor.org/rfc/rfc8017#appendix-B.2.1).
    ///
    /// Expands `seed` into `mask.len()` mask bytes:
    /// `T(C) = Hash(seed || I2OSP(C, 4))` for `C = 0, 1, …`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — hash algorithm.
    /// - `seed` — MGF1 seed.
    /// - `mask` — mask destination; `mask.len()` bytes are written.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `mask` overwritten with mask material.
    /// - `Err(HsmError::NotEnoughSpace)` — internal scoped allocation too small.
    /// - `Err(HsmError)` — SHA driver failure.
    async fn mgf1(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        seed: &DmaBuf,
        mask: &mut DmaBuf,
    ) -> HsmResult<()>;

    /// MGF1 with in-place XOR.
    ///
    /// Identical to [`mgf1`](Self::mgf1), but each generated mask
    /// byte is XOR'd into the existing content of `mask` rather than
    /// overwriting it.  This is the primitive used by OAEP unmasking
    /// and PSS encoding/verification.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — hash algorithm.
    /// - `seed` — MGF1 seed.
    /// - `mask` — in-place buffer; XOR'd with `mask.len()` bytes of
    ///   mask material.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success.
    /// - `Err(HsmError::NotEnoughSpace)` — internal scoped allocation too small.
    /// - `Err(HsmError)` — SHA driver failure.
    async fn mgf1_xor(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        seed: &DmaBuf,
        mask: &mut DmaBuf,
    ) -> HsmResult<()>;

    /// X9.63 KDF (SEC 1 §3.6.1) — the KDF used by ECIES variants
    /// and CMS ECDH key wrap.
    ///
    /// `T(C) = Hash(Z || I2OSP(C, 4) || SharedInfo)` for `C = 1, 2,
    /// …`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — hash algorithm.
    /// - `z` — shared secret (typically an ECDH x-coordinate).
    /// - `shared_info` — SharedInfo octet string; `&[]` to omit.
    /// - `key` — derived-key destination; `key.len()` bytes are
    ///   written.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `key` filled.
    /// - `Err(HsmError::NotEnoughSpace)` — internal scoped allocation too small.
    /// - `Err(HsmError)` — SHA driver failure.
    async fn x963_kdf(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        z: &DmaBuf,
        shared_info: &DmaBuf,
        key: &mut DmaBuf,
    ) -> HsmResult<()>;

    /// SP 800-56A r3 §5.8.2.1 one-step concatenation KDF.
    ///
    /// `T(C) = Hash(I2OSP(C, 4) || Z || OtherInfo)` for `C = 1, 2,
    /// …`.  Differs from X9.63 only in field ordering (counter
    /// first).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — hash algorithm.
    /// - `z` — shared secret.
    /// - `other_info` — OtherInfo octet string; `&[]` to omit.
    /// - `key` — derived-key destination; `key.len()` bytes are
    ///   written.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `key` filled.
    /// - `Err(HsmError::NotEnoughSpace)` — internal scoped allocation too small.
    /// - `Err(HsmError)` — SHA driver failure.
    async fn sp800_56a_kdf(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        z: &DmaBuf,
        other_info: &DmaBuf,
        key: &mut DmaBuf,
    ) -> HsmResult<()>;
}
