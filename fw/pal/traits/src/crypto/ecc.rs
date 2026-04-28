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
}

/// ECC Pairwise Consistency Test (PCT) type used to indicate which
/// operation should be exercised in a self-test: none, signing, or key
/// agreement.
pub enum HsmEccPct {
    None,
    SignVerify,
    KeyAgreement,
}

/// Asynchronous ECC operations trait.
///
/// PAL implementations provide this to the core for ECC key generation,
/// signing, and verification. The async signatures allow hardware-backed
/// implementations to yield while the PKA engine processes operations.
///
/// All key parameters are plain `&[u8]` byte slices containing
/// DER-encoded key material (PKCS#8 for private keys, SPKI for public
/// keys). Each PAL implementation is responsible for parsing them into
/// whatever internal representation it needs.
pub trait HsmEcc {
    /// Generate an ECC key pair on the specified curve.
    ///
    /// # Parameters
    /// - `curve` — The NIST curve to use for key generation.
    /// - `priv_key` — Output for the generated private key.
    /// - `pub_key` — Output for the generated public key.
    /// - `pct` — Indicates which ECC Pairwise Consistency Test (PCT)
    ///   operation should be exercised during self-test: none, signing,
    ///   or key agreement.
    ///
    /// # Errors
    /// Returns [`HsmError`] if key generation fails (e.g., PKA engine
    /// error, RNG failure).
    async fn ecc_gen_keypair(
        &self,
        curve: HsmEccCurve,
        priv_key: &mut [u8],
        pub_key: &mut [u8],
        pct: HsmEccPct,
    ) -> HsmResult<()>;

    /// Raw EC sign over a pre-computed hash digest.
    ///
    /// # Parameters
    /// - `priv_key` — The signing key.
    /// - `hash` — Pre-computed hash digest to sign.
    /// - `signature` — Output buffer for the signature. Must be at least
    ///   [`HsmEccCurve::sig_len`] bytes.
    ///
    /// # Errors
    /// Returns [`HsmError`] if signing fails or the buffer is too small.
    async fn ecc_sign(
        &self,
        curve: HsmEccCurve,
        priv_key: &[u8],
        hash: &[u8],
        signature: &mut [u8],
    ) -> HsmResult<()>;

    /// Raw EC verify a signature over a pre-computed hash digest.
    ///
    /// # Parameters
    /// - `pub_key` — The verification key.
    /// - `curve` — The NIST curve that the key was generated on (P-256,
    ///   P-384, or P-521). Used to determine the expected signature length.
    /// - `hash` — Pre-computed hash digest that was signed.
    /// - `signature` — The signature to verify.
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise.
    async fn ecc_verify(
        &self,
        curve: HsmEccCurve,
        pub_key: &[u8],
        hash: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool>;

    /// Perform ECDH key agreement to derive a shared secret.
    ///
    /// # Parameters
    /// - `priv_key` — The local private key.
    /// - `pub_key` — The remote party's public key.
    /// - `secret` — Output for the derived shared secret.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the key agreement operation fails (e.g., PKA
    /// engine error, invalid public key point).
    async fn ecdh_derive(
        &self,
        curve: HsmEccCurve,
        priv_key: &[u8],
        pub_key: &[u8],
        secret: &mut [u8],
    ) -> HsmResult<()>;
}
