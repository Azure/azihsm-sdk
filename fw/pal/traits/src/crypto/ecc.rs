// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Elliptic Curve Cryptography (ECC) trait for the HSM PAL.
//!
//! Defines [`EccCurve`] and the [`HsmEcc`] trait that PAL implementations
//! use to expose ECC key generation, raw EC sign/verify, and ECDSA
//! sign/verify operations.
//!
//! **Status**: The trait is defined but not yet included in the
//! [`HsmCrypto`] supertrait bound — no PAL implements it yet. It will
//! be wired in when the `EccSign`, `EccGenerateKeyPair`, and
//! `EcdhKeyExchange` DDI handlers are implemented in `fw/core`.
//!
//! ## Output buffer convention
//!
//! All methods that produce output take mandatory `&mut` parameters.
//! The caller is responsible for providing buffers of the correct size.
//! Use [`EccCurve::priv_key_len`], [`EccCurve::pub_key_len`],
//! [`EccCurve::sig_len`], and [`EccCurve::secret_len`] to determine
//! the required sizes.
//!
//! ## Raw EC vs ECDSA
//!
//! - **`ecc_sign` / `ecc_verify`** — Raw EC operations on a pre-computed
//!   hash digest. The caller is responsible for hashing the message first.
//! - **`ecdsa_sign` / `ecdsa_verify`** — Full ECDSA with algorithm
//!   selection. The implementation hashes internally using `hash_algo`.

use super::*;

/// Supported NIST elliptic curves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmEccCurve {
    /// NIST P-256 (secp256r1) — 32-byte key components.
    P256,

    /// NIST P-384 (secp384r1) — 48-byte key components.
    P384,

    /// NIST P-521 (secp521r1) — 66-byte key components.
    P521,
}

impl HsmEccCurve {
    /// Return the size in bytes of the private key for this curve.
    pub fn priv_key_len(&self) -> usize {
        match self {
            HsmEccCurve::P256 => 32,
            HsmEccCurve::P384 => 48,
            HsmEccCurve::P521 => 66,
        }
    }

    /// Return the public key size in bytes (X + Y coordinates).
    ///
    /// Public keys are represented as the concatenation of the X and Y
    /// coordinates, each of which is `priv_key_len()` bytes.
    pub fn pub_key_len(&self) -> usize {
        self.priv_key_len() * 2
    }

    /// Return the ECDSA signature size in bytes (R + S values).
    ///
    /// ECDSA signatures are represented as the concatenation of the R and S
    /// values, each of which is `priv_key_len()` bytes.
    pub fn sig_len(&self) -> usize {
        self.priv_key_len() * 2
    }

    /// Return the wire-format coordinate / signature-component byte
    /// length per curve.
    ///
    /// The PAL exposes `priv_key_len()` (66 for P-521), but the wire
    /// format pads P-521 coordinates and ECDSA signature components
    /// to 68 bytes so each one lands on a 4-byte (32-bit) PKA word
    /// boundary.  P-256 / P-384 are already word-aligned and need no
    /// padding.
    pub fn wire_coord_len(&self) -> usize {
        match self {
            HsmEccCurve::P521 => 68,
            _ => self.priv_key_len(),
        }
    }

    /// Return the wire-format public-key byte length (two padded
    /// coordinates).  See [`HsmEccCurve::wire_coord_len`].
    pub fn wire_pub_key_len(&self) -> usize {
        self.wire_coord_len() * 2
    }

    /// Return the wire-format ECDSA signature byte length (two padded
    /// components — `r || s`).  See [`HsmEccCurve::wire_coord_len`].
    pub fn wire_sig_len(&self) -> usize {
        self.wire_coord_len() * 2
    }

    /// Return the ECDH shared secret size in bytes.
    ///
    /// The shared secret derived from ECDH is the same length as the private
    /// key for the selected curve.
    pub fn secret_len(&self) -> usize {
        self.priv_key_len()
    }

    /// Maximum PKCS#8 DER size for a private key on this curve.
    ///
    /// The std PAL encodes private keys as PKCS#8 DER (variable
    /// length); callers use this as the upper bound returned by
    /// [`ecc_gen_keypair`](HsmEcc::ecc_gen_keypair) in query mode.
    /// Real-HW PALs that work in raw scalars instead report
    /// [`priv_key_len`](Self::priv_key_len) — always ≤ this max.
    pub fn priv_key_der_max(&self) -> usize {
        match self {
            HsmEccCurve::P256 => 138,
            HsmEccCurve::P384 => 185,
            HsmEccCurve::P521 => 241,
        }
    }
}

/// ECC Pairwise Consistency Test (PCT) mode for key generation.
///
/// FIPS 140-3 requires a PCT after key generation to verify the key
/// pair is functional.  The variant selects which operation is used
/// for verification, or skips the test entirely.
pub enum HsmEccPct {
    /// No PCT — skip the consistency test.
    None,

    /// Sign / verify round-trip with the freshly generated key pair.
    SignVerify,

    /// ECDH key-agreement self-test against a known public-key
    /// counterpart.
    KeyAgreement,
}

/// Asynchronous ECC operations.
///
/// PAL implementations provide this to core for ECC key generation,
/// signing, verification, and ECDH.  The `async` signatures let
/// hardware-backed implementations yield while the PKA engine runs.
///
/// Key parameters are byte slices in raw `priv || pub_x || pub_y`
/// format — not DER — sized per [`HsmEccCurve::priv_key_len`] /
/// [`HsmEccCurve::pub_key_len`].
pub trait HsmEcc {
    /// Generates an ECC key pair on the chosen curve, optionally
    /// writing the keys into caller-provided buffers.
    ///
    /// Uses the canonical query-alloc-use workflow:
    ///
    /// 1. **Query** — call with `out = None`.  No key generation
    ///    happens; the method returns `(priv_max, pub_max)` upper
    ///    bounds the caller must allocate.  `pub_max` is always the
    ///    deterministic `HsmEccCurve::wire_pub_key_len(curve)`;
    ///    `priv_max` depends on the PAL's encoding — real-HW PALs
    ///    return the raw-scalar size `HsmEccCurve::priv_key_len`
    ///    (32 / 48 / 66 bytes), while the std PAL uses PKCS#8 DER
    ///    and returns `HsmEccCurve::priv_key_der_max`.
    /// 2. **Alloc** — caller allocates two DMA buffers of those
    ///    sizes.
    /// 3. **Use** — call with `out = Some((priv_out, pub_out))`.
    ///    The method generates a fresh keypair (using `alloc` for
    ///    any internal contiguous PKA scratch), writes the PAL-format
    ///    private key into `priv_out[..priv_actual]` and the
    ///    wire-format LE public key into `pub_out[..pub_actual]`,
    ///    and returns the actual lengths.  Both are guaranteed to
    ///    be `≤` the upper bounds reported by the matching query
    ///    call (real-HW PALs always return the same value in both
    ///    modes; std-PAL DER may be shorter than the max).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `alloc` — scoped allocator used by the implementation for
    ///   any internal scratch (e.g. the contiguous `priv || pub`
    ///   buffer real PKA hardware emits before the bytes are split
    ///   into the caller's two output slots).  Unused in query
    ///   mode.
    /// - `curve` — NIST curve selector.
    /// - `out` — `None` to query buffer sizes; `Some((priv_out,
    ///   pub_out))` to actually generate.  Each output buffer must
    ///   be at least as large as the corresponding length returned
    ///   by an earlier query call.
    /// - `pct` — pairwise consistency test selector.
    ///
    /// # Returns
    ///
    /// - `Ok((priv_len, pub_len))` — in query mode, the upper-bound
    ///   sizes the caller must allocate; in use mode, the actual
    ///   bytes written into `priv_out` / `pub_out` (always `≤` the
    ///   query bounds).
    /// - `Err(HsmError::InvalidArg)` — `out` is `Some` and one of
    ///   the buffers is shorter than the required length.
    /// - `Err(HsmError)` — PKA / RNG / PCT / DMA failure.
    async fn ecc_gen_keypair(
        &self,
        io: &impl HsmIo,
        alloc: &impl HsmScopedAlloc,
        curve: HsmEccCurve,
        out: Option<(&mut DmaBuf, &mut DmaBuf)>,
        pct: HsmEccPct,
    ) -> HsmResult<(usize, usize)>;

    /// Raw EC sign over a pre-computed message digest.
    ///
    /// The caller is responsible for hashing the message; this method
    /// performs no hashing itself.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `curve` — NIST curve the private key is on.
    /// - `priv_key` — signing key (PAL-format byte blob — std uses
    ///   PKCS#8 DER; real-HW PALs use the raw scalar).
    /// - `hash` — message digest to sign, in **little-endian** byte
    ///   order to match the wire-native format produced by real PKA
    ///   hardware.  Must contain exactly the digest's native length
    ///   (e.g. 32 bytes for SHA-256, 64 bytes for SHA-512); ECDSA
    ///   truncates internally if longer than the curve's order.
    ///   Implementations that delegate to a big-endian-native
    ///   primitive (e.g. OpenSSL) must reverse the bytes internally.
    /// - `signature` — output buffer.  On return, holds `r || s`
    ///   with **each component in little-endian** byte order — the
    ///   wire-native format produced by real PKA hardware.  P-521
    ///   components occupy 68 bytes each (66 real + 2-byte trailing
    ///   zero pad) for 32-bit word alignment.  Required length is
    ///   `HsmEccCurve::wire_sig_len(curve)`: 64 for P-256, 96 for
    ///   P-384, 136 for P-521.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `signature[..wire_sig_len]` populated in LE.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError)` — PKA / RNG failure.
    async fn ecc_sign(
        &self,
        io: &impl HsmIo,
        curve: HsmEccCurve,
        priv_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &mut DmaBuf,
    ) -> HsmResult<()>;

    /// Raw EC verify of `signature` against a pre-computed message
    /// digest.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `curve` — NIST curve the public key is on; determines the
    ///   expected signature length.
    /// - `pub_key` — verification key; uncompressed `x || y`,
    ///   exactly `curve.wire_pub_key_len()` bytes.  **Each coordinate
    ///   is in little-endian byte order** with P-521 coordinates
    ///   padded to 68 bytes (66 real + 2-byte trailing zero pad) for
    ///   32-bit word alignment — matches the on-wire DDI
    ///   representation and real PKA hardware.  Implementations that
    ///   delegate to a big-endian-native primitive (e.g. OpenSSL)
    ///   must strip the per-coordinate padding and reverse each
    ///   coordinate internally.
    /// - `hash` — message digest that was signed.  Raw digest bytes;
    ///   no endianness conversion is applied.
    /// - `signature` — signature to verify; must be exactly
    ///   `curve.wire_sig_len()` bytes (`r || s`).  **Each component
    ///   is in little-endian byte order** with P-521 components
    ///   padded to 68 bytes — matches the on-wire DDI representation
    ///   and real PKA hardware.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — signature is valid.
    /// - `Ok(false)` — signature is invalid (not an error).
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch or
    ///   malformed public key.
    /// - `Err(HsmError)` — propagated from the PKA driver.
    async fn ecc_verify(
        &self,
        io: &impl HsmIo,
        curve: HsmEccCurve,
        pub_key: &DmaBuf,
        hash: &DmaBuf,
        signature: &DmaBuf,
    ) -> HsmResult<bool>;

    /// ECDH key agreement: derives a shared secret from a local
    /// private key and a remote public key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `curve` — NIST curve both keys are on.
    /// - `priv_key` — local private key (PAL-format byte blob — std
    ///   uses PKCS#8 DER; real-HW PALs use the raw scalar).
    /// - `pub_key` — remote uncompressed point; must be exactly
    ///   `curve.wire_pub_key_len()` bytes (`x || y`).  **Each
    ///   coordinate is in little-endian byte order** with P-521
    ///   coordinates padded to 68 bytes (66 real + 2-byte trailing
    ///   zero pad) for 32-bit word alignment — matches the on-wire
    ///   DDI representation and real PKA hardware.  Implementations
    ///   that delegate to a big-endian-native primitive (e.g.
    ///   OpenSSL) must strip the per-coordinate padding and reverse
    ///   each coordinate internally.
    /// - `secret` — output buffer; must be at least
    ///   `curve.secret_len()` bytes.  On success, holds the
    ///   x-coordinate of the shared point.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `secret[..secret_len]` populated.
    /// - `Err(HsmError::InvalidArg)` — buffer mismatch or invalid
    ///   public-key point.
    /// - `Err(HsmError)` — PKA driver failure.
    async fn ecdh_derive(
        &self,
        io: &impl HsmIo,
        curve: HsmEccCurve,
        priv_key: &DmaBuf,
        pub_key: &DmaBuf,
        secret: &mut DmaBuf,
    ) -> HsmResult<()>;
}
