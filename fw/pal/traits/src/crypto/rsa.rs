// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA cryptographic operations trait for the HSM PAL.
//!
//! Defines [`HsmRsaPct`] and the [`HsmRsa`] trait that PAL implementations
//! use to expose RSA key generation and modular exponentiation.
//!
//! On Cortex-M7 hardware this would delegate to the PKA (Public Key
//! Accelerator) engine. On the standard (host-native) PAL it would use
//! OpenSSL's RSA primitives.
//!
//! ## Key representation
//!
//! All key parameters are plain `&[u8]` byte slices containing the raw
//! key material. Each PAL implementation is responsible for parsing
//! them into whatever internal representation it needs.
//!
//! ## Modular exponentiation
//!
//! RSA signing and decryption are expressed as private-key modular
//! exponentiation (`mod_exp_priv`), while encryption and verification
//! use public-key modular exponentiation (`mod_exp_pub`). This matches
//! the hardware PKA register model where the engine performs a single
//! `base^exp mod n` operation regardless of the higher-level use case.
//!
//! ## Output buffer convention
//!
//! All methods take mandatory `&mut [u8]` output buffers. The caller is
//! responsible for providing buffers of the correct size (key size in
//! bytes for RSA operations).

use super::*;

// ── RSA key size ───────────────────────────────────────────────────

/// RSA key type: modulus size, public/private, and CRT format.
///
/// Each variant encodes three properties:
/// - **Modulus size** — 2048, 3072, or 4096 bits.
/// - **Key role** — public (`Pub`) or private (`Priv`/`CrtPriv`).
/// - **Private key format** — standard (`Priv`) or Chinese Remainder
///   Theorem (`CrtPriv`). CRT is irrelevant for public keys.
///
/// Use [`pub_variant`](Self::pub_variant) to obtain the corresponding
/// public key variant from any private variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmRsaKey {
    /// RSA-2048 public key.
    Rsa2048Pub,

    /// RSA-2048 non-CRT private key.
    Rsa2048Priv,

    /// RSA-2048 CRT private key.
    Rsa2048CrtPriv,

    /// RSA-3072 public key.
    Rsa3072Pub,

    /// RSA-3072 non-CRT private key.
    Rsa3072Priv,

    /// RSA-3072 CRT private key.
    Rsa3072CrtPriv,

    /// RSA-4096 public key.
    Rsa4096Pub,

    /// RSA-4096 non-CRT private key.
    Rsa4096Priv,

    /// RSA-4096 CRT private key.
    Rsa4096CrtPriv,
}

impl HsmRsaKey {
    /// Modulus size in bytes (`k`).
    pub const fn modulus_len(&self) -> usize {
        match self {
            Self::Rsa2048Pub | Self::Rsa2048Priv | Self::Rsa2048CrtPriv => 256,
            Self::Rsa3072Pub | Self::Rsa3072Priv | Self::Rsa3072CrtPriv => 384,
            Self::Rsa4096Pub | Self::Rsa4096Priv | Self::Rsa4096CrtPriv => 512,
        }
    }

    /// Whether this is a public key variant.
    pub const fn is_public(&self) -> bool {
        matches!(self, Self::Rsa2048Pub | Self::Rsa3072Pub | Self::Rsa4096Pub)
    }

    /// Whether this is a private key variant (CRT or non-CRT).
    pub const fn is_private(&self) -> bool {
        !self.is_public()
    }

    /// Whether this variant uses CRT (Chinese Remainder Theorem) format.
    pub const fn is_crt(&self) -> bool {
        matches!(
            self,
            Self::Rsa2048CrtPriv | Self::Rsa3072CrtPriv | Self::Rsa4096CrtPriv
        )
    }

    /// Return the corresponding public key variant.
    ///
    /// Maps any private variant to the public variant of the same
    /// modulus size. Public variants map to themselves.
    pub const fn pub_variant(&self) -> Self {
        match self {
            Self::Rsa2048Pub | Self::Rsa2048Priv | Self::Rsa2048CrtPriv => Self::Rsa2048Pub,
            Self::Rsa3072Pub | Self::Rsa3072Priv | Self::Rsa3072CrtPriv => Self::Rsa3072Pub,
            Self::Rsa4096Pub | Self::Rsa4096Priv | Self::Rsa4096CrtPriv => Self::Rsa4096Pub,
        }
    }

    /// Maximum plaintext length for PKCS#1 v1.5 encryption: `k - 11`.
    pub const fn max_pkcs1_message(&self) -> usize {
        self.modulus_len() - 11
    }

    /// Maximum plaintext length for OAEP encryption: `k - 2*hLen - 2`.
    pub const fn max_oaep_message(&self, algo: HsmHashAlgo) -> usize {
        self.modulus_len() - 2 * algo.digest_len() - 2
    }

    /// Minimum work buffer size for PKCS#1 v1.5 operations.
    pub const fn pkcs1_work_len(&self) -> usize {
        self.modulus_len()
    }

    /// Minimum work buffer size for OAEP operations.
    pub const fn oaep_work_len(&self, algo: HsmHashAlgo) -> usize {
        let k = self.modulus_len();
        let h_len = algo.digest_len();
        let db_len = k - h_len - 1;
        k + algo.mgf1_state_len(db_len)
    }

    /// Minimum work buffer size for PSS operations.
    pub const fn pss_work_len(&self, algo: HsmHashAlgo) -> usize {
        let k = self.modulus_len();
        let h_len = algo.digest_len();
        k + algo.hash_state_len() + algo.mgf1_state_len(h_len)
    }
}

/// Pairwise Consistency Test (PCT) mode for RSA key generation.
///
/// FIPS 140-3 requires a PCT after key generation to verify the key
/// pair is functional. The test mode determines which operation is
/// used for verification.
pub enum HsmRsaPct {
    /// No PCT — skip the consistency test.
    None,

    /// Sign-verify PCT: sign a test message with the private key and
    /// verify it with the public key.
    SignVerify,

    /// Encrypt-decrypt PCT: encrypt test data with the public key and
    /// verify the private key recovers the original.
    EncryptDecrypt,
}

/// Asynchronous RSA operations trait.
///
/// PAL implementations provide this to the core for RSA key generation
/// and modular exponentiation. The async signatures allow hardware-backed
/// implementations to yield while the PKA engine processes operations.
pub trait HsmRsa {
    /// Generate an RSA key pair.
    ///
    /// # Parameters
    /// - `key_size` — RSA modulus size in bits (2048, 3072, or 4096).
    /// - `priv_key` — Output buffer for the serialized private key.
    /// - `pub_key` — Output buffer for the serialized public key.
    /// - `pct` — Pairwise Consistency Test mode. When not [`HsmRsaPct::None`],
    ///   a sign/verify or encrypt/decrypt round-trip is performed to
    ///   validate the generated key pair (FIPS 140-3 requirement).
    ///
    /// # Errors
    /// Returns [`HsmError`] if key generation fails, or if the PCT
    /// verification fails.
    async fn ras_gen_keypair(
        &self,
        key_size: HsmRsaKey,
        priv_key: &mut [u8],
        pub_key: &mut [u8],
        pct: HsmRsaPct,
    ) -> Result<(), HsmError>;

    /// Private-key modular exponentiation: `x = y^d mod n`.
    ///
    /// Used for RSA decryption and signing.
    ///
    /// # Parameters
    /// - `key` — The RSA private key.
    /// - `y` — Input data (ciphertext for decryption, message hash for
    ///   signing). Must be exactly the key size in bytes.
    /// - `x` — Output buffer for the result. Must be exactly the key
    ///   size in bytes.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the exponentiation fails (e.g., PKA
    /// engine error, invalid key).
    async fn mod_exp_priv(
        &self,
        key_size: HsmRsaKey,
        key: &[u8],
        y: &[u8],
        x: &mut [u8],
    ) -> Result<(), HsmError>;

    /// Public-key modular exponentiation: `y = x^e mod n`.
    ///
    /// Used for RSA encryption and signature verification.
    ///
    /// # Parameters
    /// - `key` — The RSA public key.
    /// - `x` — Input data (plaintext for encryption, signature for
    ///   verification). Must be exactly the key size in bytes.
    /// - `y` — Output buffer for the result. Must be exactly the key
    ///   size in bytes.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the exponentiation fails (e.g., PKA
    /// engine error, invalid key).
    async fn mod_exp_pub(
        &self,
        key_size: HsmRsaKey,
        key: &[u8],
        x: &[u8],
        y: &mut [u8],
    ) -> Result<(), HsmError>;

    /// PKCS#1 v1.5 encrypt (EME-PKCS1-v1_5).
    ///
    /// Pads `message` with random non-zero bytes per RFC 8017 §7.2.1, then
    /// encrypts with the public key.
    ///
    /// # Parameters
    ///
    /// - `pub_key` — RSA public key.
    /// - `message` — plaintext. Must satisfy `message.len() <= k - 11`.
    /// - `output` — ciphertext output buffer. Must be at least `rsa_pkcs1_work_len(k)` bytes.
    /// - `work` — scratch buffer. Must be at least `rsa_pkcs1_work_len(k)` bytes.
    async fn rsa_pkcs1_encrypt(
        &self,
        key_size: HsmRsaKey,
        pub_key: &[u8],
        message: &[u8],
        output: &mut [u8],
        work: &mut [u8],
    ) -> HsmResult<()>;

    /// PKCS#1 v1.5 decrypt (EME-PKCS1-v1_5).
    ///
    /// Decrypts `ciphertext` with the private key and removes padding.
    ///
    /// # Parameters
    ///
    /// - `priv_key` — RSA private key.
    /// - `ciphertext` — encrypted data. Must be exactly `k` bytes.
    /// - `output` — plaintext output buffer. Must be at least `k - 11` bytes.
    /// - `work` — scratch buffer. Must be at least `rsa_pkcs1_work_len(k)` bytes.
    ///
    /// # Returns
    ///
    /// The length of the recovered plaintext.
    async fn rsa_pkcs1_decrypt(
        &self,
        key_size: HsmRsaKey,
        priv_key: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
        work: &mut [u8],
    ) -> HsmResult<usize>;

    /// PKCS#1 v1.5 sign (EMSA-PKCS1-v1_5, pre-hashed).
    ///
    /// Builds DigestInfo from `message_hash`, pads, and signs.
    ///
    /// # Parameters
    ///
    /// - `algo` — hash algorithm for DigestInfo OID.
    /// - `priv_key` — RSA private key.
    /// - `message_hash` — pre-computed message digest (`algo.digest_len()`
    ///   bytes).
    /// - `signature` — output buffer. Must be at least `rsa_pkcs1_work_len(k)` bytes.
    /// - `work` — scratch buffer. Must be at least
    ///   `rsa_pkcs1_work_len(k)` bytes.
    async fn rsa_pkcs1_sign(
        &self,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &[u8],
        message_hash: &[u8],
        signature: &mut [u8],
        work: &mut [u8],
    ) -> HsmResult<()>;

    /// PKCS#1 v1.5 verify (EMSA-PKCS1-v1_5, pre-hashed).
    ///
    /// Verifies `signature` against `message_hash` using the public key.
    ///
    /// # Parameters
    ///
    /// - `algo` — hash algorithm for DigestInfo OID.
    /// - `pub_key` — RSA public key.
    /// - `message_hash` — pre-computed message digest.
    /// - `signature` — signature to verify.
    /// - `work` — scratch buffer. Must be at least
    ///   `rsa_pkcs1_work_len(k)` bytes.
    async fn rsa_pkcs1_verify(
        &self,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        pub_key: &[u8],
        message_hash: &[u8],
        signature: &[u8],
        work: &mut [u8],
    ) -> HsmResult<bool>;

    /// OAEP encrypt (EME-OAEP).
    ///
    /// Pads `message` with OAEP per RFC 8017 §7.1.1 and encrypts.
    ///
    /// # Parameters
    ///
    /// - `algo` — hash algorithm for OAEP (label hash + MGF1).
    /// - `pub_key` — RSA public key.
    /// - `message` — plaintext. Must satisfy `message.len() <= k - 2*hLen - 2`.
    /// - `label` — optional label (pass `&[]` for default empty label).
    /// - `output` — ciphertext output buffer. Must be at least `rsa_pkcs1_work_len(k)` bytes.
    /// - `work` — scratch buffer. Must be at least
    ///   `k + mgf1_state_len(k - hLen - 1)` bytes.
    async fn rsa_oaep_encrypt(
        &self,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        pub_key: &[u8],
        message: &[u8],
        label: &[u8],
        output: &mut [u8],
        work: &mut [u8],
    ) -> HsmResult<()>;

    /// OAEP decrypt (EME-OAEP).
    ///
    /// Decrypts `ciphertext` with OAEP unpadding per RFC 8017 §7.1.2.
    ///
    /// # Parameters
    ///
    /// - `algo` — hash algorithm for OAEP.
    /// - `priv_key` — RSA private key.
    /// - `ciphertext` — encrypted data. Must be exactly `k` bytes.
    /// - `label` — optional label (must match encryption label).
    /// - `output` — plaintext output buffer. Must be at least
    ///   `k - 2*hLen - 2` bytes (max recoverable plaintext).
    /// - `work` — scratch buffer. Must be at least
    ///   `rsa_oaep_work_len(algo, k)` bytes.
    ///
    /// # Returns
    ///
    /// The length of the recovered plaintext.
    async fn rsa_oaep_decrypt(
        &self,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &[u8],
        ciphertext: &[u8],
        label: &[u8],
        output: &mut [u8],
        work: &mut [u8],
    ) -> HsmResult<usize>;

    /// PSS sign (EMSA-PSS, pre-hashed).
    ///
    /// Pads `message_hash` with PSS per RFC 8017 §9.1.1 and signs.
    ///
    /// # Parameters
    ///
    /// - `algo` — hash algorithm for PSS (H and MGF1).
    /// - `priv_key` — RSA private key.
    /// - `message_hash` — pre-computed message digest (`hLen` bytes).
    /// - `salt_len` — PSS salt length in bytes.
    /// - `signature` — output buffer. Must be at least `rsa_pkcs1_work_len(k)` bytes.
    /// - `work` — scratch buffer. Must be at least
    ///   `k + hash_state_len + mgf1_state_len(hLen)` bytes.
    async fn rsa_pss_sign(
        &self,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &[u8],
        message_hash: &[u8],
        salt_len: usize,
        signature: &mut [u8],
        work: &mut [u8],
    ) -> HsmResult<()>;

    /// PSS verify (EMSA-PSS, pre-hashed).
    ///
    /// Verifies `signature` against `message_hash` using PSS per RFC 8017 §9.1.2.
    ///
    /// # Parameters
    ///
    /// - `algo` — hash algorithm for PSS.
    /// - `pub_key` — RSA public key.
    /// - `message_hash` — pre-computed message digest (`hLen` bytes).
    /// - `salt_len` — PSS salt length in bytes.
    /// - `signature` — signature to verify.
    /// - `work` — scratch buffer. Must be at least
    ///   `k + hash_state_len + mgf1_state_len(hLen)` bytes.
    async fn rsa_pss_verify(
        &self,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        pub_key: &[u8],
        message_hash: &[u8],
        salt_len: usize,
        signature: &[u8],
        work: &mut [u8],
    ) -> HsmResult<bool>;
}
