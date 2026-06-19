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
    /// Return the **raw cryptographic** scalar / coordinate length in
    /// bytes for this curve (i.e. `ceil(bit_size / 8)`).
    ///
    /// This is the natural mathematical size of a single field element
    /// (private scalar, X coordinate, Y coordinate, or ECDSA `r`/`s`
    /// component) before any hardware alignment padding is applied.
    ///
    /// | Curve  | Raw |
    /// |--------|-----|
    /// | P-256  | 32  |
    /// | P-384  | 48  |
    /// | P-521  | 66  |
    ///
    /// **This is _not_ the on-wire/HSM serialized size.**  Use
    /// [`HsmEccCurve::wire_coord_len`] /
    /// [`HsmEccCurve::wire_priv_key_len`] /
    /// [`HsmEccCurve::wire_pub_key_len`] /
    /// [`HsmEccCurve::wire_sig_len`] to size buffers exchanged with
    /// the driver, the PAL, or any HSM-format consumer.
    pub fn priv_key_len(&self) -> usize {
        match self {
            HsmEccCurve::P256 => 32,
            HsmEccCurve::P384 => 48,
            HsmEccCurve::P521 => 66,
        }
    }

    /// Return the **raw cryptographic** public-key length in bytes
    /// (`X || Y`, each [`HsmEccCurve::priv_key_len`] bytes).
    ///
    /// **This is _not_ the on-wire/HSM size.**  See
    /// [`HsmEccCurve::wire_pub_key_len`].
    pub fn pub_key_len(&self) -> usize {
        self.priv_key_len() * 2
    }

    /// Return the **wire-format / HSM-serialized** private-key length
    /// in bytes — the size of an HSM-format private scalar buffer.
    ///
    /// Alias of [`HsmEccCurve::wire_coord_len`] kept for caller-site
    /// clarity (private keys are a single padded scalar; this name
    /// makes intent explicit at allocation sites).  Matches
    /// `azihsm_crypto`'s `ExportableHsmKey::hsm_bytes_len` /
    /// `to_hsm_bytes` output for an ECC private key.
    ///
    /// Per-curve sizes (P-256 → 32, P-384 → 48, P-521 → 68).
    pub fn wire_priv_key_len(&self) -> usize {
        self.wire_coord_len()
    }

    /// Raw cryptographic signature length.  See
    /// [`HsmEccCurve::wire_sig_len`] for the HSM/wire-format size.
    pub fn sig_len(&self) -> usize {
        self.priv_key_len() * 2
    }

    /// Return the **wire-format / HSM-serialized** coordinate or
    /// signature-component length in bytes.
    ///
    /// The HSM serializes every scalar / coordinate / signature
    /// component padded up to a 4-byte (32-bit) PKA word boundary so
    /// that DMA transfers from the PKA engine are word-aligned.
    /// P-256 and P-384 are already word-aligned, so their wire size
    /// equals [`HsmEccCurve::priv_key_len`].  P-521's 66-byte raw
    /// component is zero-padded to 68 bytes on the wire.
    ///
    /// | Curve  | Raw | Wire |
    /// |--------|-----|------|
    /// | P-256  | 32  | 32   |
    /// | P-384  | 48  | 48   |
    /// | P-521  | 66  | 68   |
    ///
    /// This is the single source of truth for sizing any buffer that
    /// crosses the PAL boundary — private-key scratch, public-key
    /// scratch, signature scratch — and matches
    /// `azihsm_crypto`'s `ExportableHsmKey::hsm_bytes_len` /
    /// `to_hsm_bytes` output.
    pub fn wire_coord_len(&self) -> usize {
        match self {
            HsmEccCurve::P521 => 68,
            _ => self.priv_key_len(),
        }
    }

    /// Return the OKM byte length required for FIPS 186-5 §A.2.1
    /// extra-random-bits deterministic key generation.
    pub fn a2_1_okm_len(&self) -> usize {
        self.wire_coord_len() + 8
    }

    /// Return the wire-format public-key byte length (two padded
    /// coordinates: `X || Y`).  See [`HsmEccCurve::wire_coord_len`].
    pub fn wire_pub_key_len(&self) -> usize {
        self.wire_coord_len() * 2
    }

    /// Return the wire-format ECDSA signature byte length (two padded
    /// components: `r || s`).  See [`HsmEccCurve::wire_coord_len`].
    pub fn wire_sig_len(&self) -> usize {
        self.wire_coord_len() * 2
    }

    /// Return the ECDH shared-secret length in bytes (raw X
    /// coordinate, no padding — this matches the cryptographic
    /// definition, not the HSM wire format).
    pub fn secret_len(&self) -> usize {
        self.priv_key_len()
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
    ///    happens; the method returns `(priv_len, pub_len)` byte
    ///    counts the caller must allocate.  Both are deterministic
    ///    per-curve: `priv_len = HsmEccCurve::wire_coord_len(curve)`
    ///    (raw HSM scalar — 32 / 48 / 68 bytes) and
    ///    `pub_len = HsmEccCurve::wire_pub_key_len(curve)`.
    /// 2. **Alloc** — caller allocates two DMA buffers of those
    ///    sizes.
    /// 3. **Use** — call with `out = Some((priv_out, pub_out))`.
    ///    The method generates a fresh keypair (using `alloc` for
    ///    any internal contiguous PKA scratch), writes the raw
    ///    HSM-format private scalar into `priv_out[..priv_len]` and
    ///    the wire-format LE public key into `pub_out[..pub_len]`,
    ///    and returns the same lengths reported by the query call.
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

    /// Derive an ECC keypair deterministically from `okm` (output
    /// keying material from a KDF), per FIPS 186-5 §A.2.1 / SP
    /// 800-133r2 §6.2.3. `okm.len()` must be
    /// `curve.wire_coord_len() + 8` bytes.
    async fn ecc_gen_keypair_from_okm(
        &self,
        io: &impl HsmIo,
        alloc: &impl HsmScopedAlloc,
        curve: HsmEccCurve,
        okm: &DmaBuf,
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
    /// - `priv_key` — signing key in raw HSM-format scalar bytes
    ///   (32 / 48 / 68 bytes for P-256 / P-384 / P-521).
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
    /// - `priv_key` — local private key in raw HSM-format scalar bytes
    ///   (32 / 48 / 68 bytes for P-256 / P-384 / P-521).
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
