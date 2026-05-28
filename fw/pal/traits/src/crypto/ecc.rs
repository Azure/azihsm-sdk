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

    /// Return the ECDH shared secret size in bytes.
    ///
    /// The shared secret derived from ECDH is the same length as the private
    /// key for the selected curve.
    pub fn secret_len(&self) -> usize {
        self.priv_key_len()
    }

    /// Maximum PKCS#8 DER size for a private key on this curve.
    ///
    /// Callers use this to allocate buffers for
    /// [`ecc_gen_keypair`](HsmEcc::ecc_gen_keypair).
    ///
    /// TODO: Remove this
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
    /// Generates an ECC key pair on the chosen curve and writes
    /// `priv_key || pub_key` contiguously into `key_out`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `curve` — NIST curve selector.
    /// - `key_out` — output buffer; must be at least
    ///   `curve.priv_key_len() + curve.pub_key_len()` bytes.  On
    ///   success, `key_out[..nsk]` holds the private scalar and
    ///   `key_out[nsk..nsk+npk]` holds the uncompressed public point
    ///   (`x || y`).
    /// - `pct` — pairwise consistency test selector.
    ///
    /// # Returns
    ///
    /// - `Ok((priv_key, pub_key))` — borrowed views into `key_out`.
    /// - `Err(HsmError::InvalidArg)` — `key_out` too small.
    /// - `Err(HsmError)` — PKA / RNG / PCT failure.
    async fn ecc_gen_keypair<'a>(
        &self,
        io: &impl HsmIo,
        curve: HsmEccCurve,
        key_out: &'a mut DmaBuf,
        pct: HsmEccPct,
    ) -> HsmResult<(&'a DmaBuf, &'a DmaBuf)>;

    /// Raw EC sign over a pre-computed message digest.
    ///
    /// The caller is responsible for hashing the message; this method
    /// performs no hashing itself.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `curve` — NIST curve the private key is on.
    /// - `priv_key` — signing key; must be exactly
    ///   `curve.priv_key_len()` bytes.
    /// - `hash` — message digest to sign.  Truncated or zero-padded
    ///   internally if shorter/longer than the curve's order.
    /// - `signature` — output buffer; must be at least
    ///   `curve.sig_len()` bytes (`r || s`).
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `signature[..sig_len]` populated.
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
    ///   `curve.pub_key_len()` bytes.  **Each coordinate is in
    ///   little-endian byte order** — matches the on-wire DDI
    ///   representation and real PKA hardware.  Implementations that
    ///   delegate to a big-endian-native primitive (e.g. OpenSSL) must
    ///   reverse each coordinate internally.
    /// - `hash` — message digest that was signed.  Raw digest bytes;
    ///   no endianness conversion is applied.
    /// - `signature` — signature to verify; must be exactly
    ///   `curve.sig_len()` bytes (`r || s`).  **Each component is in
    ///   little-endian byte order** — matches the on-wire DDI
    ///   representation and real PKA hardware.
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
    /// - `priv_key` — local private scalar; must be exactly
    ///   `curve.priv_key_len()` bytes.
    /// - `pub_key` — remote uncompressed point; must be exactly
    ///   `curve.pub_key_len()` bytes (`x || y`).  **Each coordinate
    ///   is in little-endian byte order** — matches the on-wire DDI
    ///   representation and real PKA hardware.  Implementations that
    ///   delegate to a big-endian-native primitive (e.g. OpenSSL) must
    ///   reverse each coordinate internally.
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
