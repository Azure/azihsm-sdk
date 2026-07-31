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

use super::HsmScopedAlloc;
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
        k + algo.mgf1_state_len(h_len)
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
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector (2048 / 3072 / 4096).
    /// - `priv_key` — destination for the serialized private key;
    ///   length depends on `key_size` and CRT vs non-CRT layout.
    /// - `pub_key` — destination for the serialized public key;
    ///   length is `key_size.modulus_len()` plus the encoded
    ///   exponent.
    /// - `pct` — Pairwise Consistency Test selector.  When not
    ///   [`HsmRsaPct::None`], a sign / verify or encrypt / decrypt
    ///   round-trip is performed (FIPS 140-3 requirement).
    ///
    /// # Returns
    ///
    /// - `Ok(())` — both buffers populated.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError)` — PKA / RNG failure or PCT failed (the key
    ///   pair is rejected).
    async fn rsa_gen_keypair(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        priv_key: &mut DmaBuf,
        pub_key: &mut DmaBuf,
        pct: HsmRsaPct,
    ) -> Result<(), HsmError>;

    /// Private-key modular exponentiation: `x = y^d mod n`.
    ///
    /// Used by RSA decryption and signing primitives.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `key` — RSA private key in PAL-defined serialization
    ///   matching `key_size.is_crt()`.
    /// - `y` — input integer; must be exactly
    ///   `key_size.modulus_len()` bytes, in wire **little-endian** byte
    ///   order.  The PAL flips to its primitive's native order (e.g. the
    ///   std/OpenSSL PAL reverses to big-endian).
    /// - `x` — output integer; must be exactly
    ///   `key_size.modulus_len()` bytes, written in wire **little-endian**
    ///   byte order.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `x` populated.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError)` — PKA driver failure.
    async fn mod_exp_priv(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        key: &DmaBuf,
        y: &DmaBuf,
        x: &mut DmaBuf,
    ) -> Result<(), HsmError>;

    /// Public-key modular exponentiation: `y = x^e mod n`.
    ///
    /// Used by RSA encryption and signature-verification primitives.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `key` — RSA public key.
    /// - `x` — input integer; must be exactly
    ///   `key_size.modulus_len()` bytes, in wire **little-endian** byte
    ///   order.  The PAL flips to its primitive's native order (e.g. the
    ///   std/OpenSSL PAL reverses to big-endian).
    /// - `y` — output integer; must be exactly
    ///   `key_size.modulus_len()` bytes, written in wire **little-endian**
    ///   byte order.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `y` populated.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError)` — PKA driver failure.
    async fn mod_exp_pub(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        key: &DmaBuf,
        x: &DmaBuf,
        y: &mut DmaBuf,
    ) -> Result<(), HsmError>;

    /// Derive the raw wire-format public key (`n_le || e_le`) from a
    /// vault-stored RSA private key.
    ///
    /// Used to recover the public key of a vault-stored private key
    /// (e.g. the partition unwrapping key) without persisting a
    /// separate copy.
    ///
    /// `priv_key` is in the PAL's own vault representation — raw key
    /// material on real PKA hardware, the crypto crate's HSM byte layout
    /// in the std/OpenSSL PAL — and this method converts it into the wire
    /// form: the little-endian modulus followed by a fixed 4-byte
    /// little-endian exponent (the raw layout the host's `DdiDerPublicKey`
    /// post-decode turns into DER).  The PAL owns the whole vault-format →
    /// wire-format conversion, including any big-endian↔little-endian flip
    /// (real PKA is little-endian native; an OpenSSL backend holds
    /// big-endian components and reverses them).
    ///
    /// Follows the query/alloc/use convention: pass `pub_out = None` to
    /// query the wire length the caller must allocate, then
    /// `pub_out = Some(buf)` to serialize.
    ///
    /// # Returns
    /// - `Ok(len)` — wire byte length (`modulus_len + 4`); in `Some`
    ///   mode those bytes are written into `pub_out`.
    /// - `Err(HsmError::InvalidArg)` — `priv_key` is not valid vault
    ///   format.
    /// - `Err(HsmError::RsaInvalidKeyLength)` — `pub_out` is too small
    ///   or the derived public-key components do not fit the wire
    ///   format.
    /// - `Err(HsmError::RsaGenerateError)` — deriving or reading the
    ///   public key failed for another reason.
    fn rsa_priv_pub_key(
        &self,
        io: &impl HsmIo,
        priv_key: &DmaBuf,
        pub_out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize>;

    /// Convert a DER-encoded RSA private key (recovered from a
    /// `CKM_RSA_AES_KEY_WRAP` unwrap) **in place** into the PAL's vault
    /// representation, also reporting the modulus length used to classify
    /// the vault key kind (256 / 384 / 512 for RSA-2048 / 3072 / 4096).
    ///
    /// The conversion overwrites `buf` and returns the vault length: the
    /// valid vault bytes are `buf[..vault_len]`.  Converting in place lets
    /// the large recovered RSA material (up to ~2.3 KB for RSA-4096) be
    /// reused as the vault buffer rather than duplicated — important under
    /// the PAL's fixed per-slot DMA budget.
    ///
    /// The vault representation is PAL-defined, is **layout-dependent on
    /// `crt`**, and is no larger than the source DER (so it always fits in
    /// `buf`).  Real PKA hardware keeps its own raw non-CRT / custom CRT
    /// layouts; the std/OpenSSL PAL uses the crypto crate's fixed-size HSM
    /// byte layout — non-CRT `n || e || p || q`, CRT
    /// `n || e || d || p || q || dp || dq || qinv` — which is smaller than
    /// the source DER (so `buf` is overwritten and `vault_len < buf.len()`).
    ///
    /// # Returns
    /// - `Ok((vault_len, modulus_len))`.
    /// - `Err(HsmError::InvalidArg)` — `buf` is not a valid RSA private key.
    fn rsa_priv_der_to_vault(
        &self,
        io: &impl HsmIo,
        buf: &mut DmaBuf,
        crt: bool,
    ) -> HsmResult<(usize, usize)>;

    /// PKCS#1 v1.5 encrypt (EME-PKCS1-v1_5).
    ///
    /// Pads `message` with random non-zero bytes per RFC 8017 §7.2.1
    /// and encrypts under `pub_key`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `pub_key` — RSA public key.
    /// - `message` — plaintext; must satisfy
    ///   `message.len() <= key_size.max_pkcs1_message()`.
    /// - `output` — ciphertext destination; must be at least
    ///   `key_size.pkcs1_work_len()` bytes.
    /// - `alloc` — scoped allocator for RSA scratch.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `output[..modulus_len]` populated.
    /// - `Err(HsmError::InvalidArg)` — message too long or buffer
    ///   too small.
    /// - `Err(HsmError::NotEnoughSpace)` — allocator scope too
    ///   small.
    /// - `Err(HsmError)` — RNG / PKA failure.
    async fn rsa_pkcs1_encrypt<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        pub_key: &DmaBuf,
        message: &DmaBuf,
        output: &mut DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a;

    /// PKCS#1 v1.5 decrypt (EME-PKCS1-v1_5).
    ///
    /// Decrypts `ciphertext` under `priv_key` and strips PKCS#1 v1.5
    /// padding.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `priv_key` — RSA private key.
    /// - `ciphertext` — must be exactly
    ///   `key_size.modulus_len()` bytes.
    /// - `output` — plaintext destination; must be at least
    ///   `key_size.max_pkcs1_message()` bytes.
    /// - `alloc` — scoped allocator for RSA scratch.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — length of recovered plaintext;
    ///   `output[..len]` is valid.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError::RsaPkcs1DecryptFailed)` — padding check
    ///   failed (likely wrong key or tampered ciphertext).
    /// - `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
    /// - `Err(HsmError)` — PKA failure.
    async fn rsa_pkcs1_decrypt<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        priv_key: &DmaBuf,
        ciphertext: &DmaBuf,
        output: &mut DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<usize>
    where
        Self: 'a;

    /// PKCS#1 v1.5 sign (EMSA-PKCS1-v1_5, pre-hashed).
    ///
    /// Builds DigestInfo from `message_hash`, applies EMSA padding,
    /// and signs.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `algo` — hash algorithm whose OID is embedded in
    ///   DigestInfo.
    /// - `priv_key` — RSA private key.
    /// - `message_hash` — pre-computed digest;
    ///   `algo.digest_len()` bytes.
    /// - `signature` — destination; must be at least
    ///   `key_size.pkcs1_work_len()` bytes.
    /// - `alloc` — scoped allocator for RSA scratch.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `signature[..modulus_len]` populated.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
    /// - `Err(HsmError)` — PKA failure.
    #[allow(clippy::too_many_arguments)]
    async fn rsa_pkcs1_sign<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &DmaBuf,
        message_hash: &DmaBuf,
        signature: &mut DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a;

    /// PKCS#1 v1.5 verify (EMSA-PKCS1-v1_5, pre-hashed).
    ///
    /// Verifies `signature` against `message_hash` under `pub_key`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `algo` — hash algorithm whose OID is expected in
    ///   DigestInfo.
    /// - `pub_key` — RSA public key.
    /// - `message_hash` — pre-computed digest.
    /// - `signature` — signature to verify;
    ///   `key_size.modulus_len()` bytes.
    /// - `alloc` — scoped allocator for RSA scratch.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — signature valid.
    /// - `Ok(false)` — signature does not verify.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
    /// - `Err(HsmError)` — PKA failure.
    #[allow(clippy::too_many_arguments)]
    async fn rsa_pkcs1_verify<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        pub_key: &DmaBuf,
        message_hash: &DmaBuf,
        signature: &DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<bool>
    where
        Self: 'a;

    /// OAEP encrypt (EME-OAEP, RFC 8017 §7.1.1).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `algo` — OAEP hash (label hash + MGF1).
    /// - `pub_key` — RSA public key.
    /// - `message` — plaintext; must satisfy `message.len() <=
    ///   key_size.max_oaep_message(algo)`.
    /// - `label` — OAEP label; `&[]` for the default empty label.
    /// - `output` — ciphertext destination; must be at least
    ///   `key_size.oaep_work_len(algo)` bytes.
    /// - `alloc` — scoped allocator for RSA scratch.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `output[..modulus_len]` populated.
    /// - `Err(HsmError::InvalidArg)` — message too long or buffer
    ///   too small.
    /// - `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
    /// - `Err(HsmError)` — RNG / SHA / PKA failure.
    #[allow(clippy::too_many_arguments)]
    async fn rsa_oaep_encrypt<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        pub_key: &DmaBuf,
        message: &DmaBuf,
        label: &DmaBuf,
        output: &mut DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a;

    /// OAEP decrypt (EME-OAEP, RFC 8017 §7.1.2).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `algo` — OAEP hash.
    /// - `priv_key` — RSA private key.
    /// - `ciphertext` — must be exactly
    ///   `key_size.modulus_len()` bytes.
    /// - `label` — OAEP label; must equal the encryption-time
    ///   label.
    /// - `output` — plaintext destination; must be large enough to hold
    ///   the recovered plaintext (at most `key_size.modulus_len()`
    ///   bytes — the recovered length is returned).  A recovered
    ///   plaintext longer than `output` fails with
    ///   [`HsmError::RsaInvalidKeyLength`], so a caller that accepts only
    ///   a bounded plaintext (e.g. a small KEK) may size `output` to that
    ///   bound.
    /// - `alloc` — scoped allocator for RSA scratch.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — length of recovered plaintext;
    ///   `output[..len]` is valid.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError::RsaOaepDecryptFailed)` — OAEP unmasking
    ///   detected tampering or label mismatch.
    /// - `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
    /// - `Err(HsmError)` — SHA / PKA failure.
    #[allow(clippy::too_many_arguments)]
    async fn rsa_oaep_decrypt<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &DmaBuf,
        ciphertext: &DmaBuf,
        label: &DmaBuf,
        output: &mut DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<usize>
    where
        Self: 'a;

    /// PSS sign (EMSA-PSS, RFC 8017 §9.1.1, pre-hashed).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `algo` — PSS hash (H and MGF1).
    /// - `priv_key` — RSA private key.
    /// - `message_hash` — pre-computed digest;
    ///   `algo.digest_len()` bytes.
    /// - `salt_len` — PSS salt length in bytes.
    /// - `signature` — destination; must be at least
    ///   `key_size.pss_work_len(algo)` bytes.
    /// - `alloc` — scoped allocator for RSA scratch.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `signature[..modulus_len]` populated.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch or
    ///   `salt_len` exceeds the EMSA-PSS limit.
    /// - `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
    /// - `Err(HsmError)` — RNG / SHA / PKA failure.
    #[allow(clippy::too_many_arguments)]
    async fn rsa_pss_sign<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &DmaBuf,
        message_hash: &DmaBuf,
        salt_len: usize,
        signature: &mut DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a;

    /// PSS verify (EMSA-PSS, RFC 8017 §9.1.2, pre-hashed).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `algo` — PSS hash.
    /// - `pub_key` — RSA public key.
    /// - `message_hash` — pre-computed digest;
    ///   `algo.digest_len()` bytes.
    /// - `salt_len` — expected PSS salt length in bytes.
    /// - `signature` — signature to verify;
    ///   `key_size.modulus_len()` bytes.
    /// - `alloc` — scoped allocator for RSA scratch.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — signature valid.
    /// - `Ok(false)` — signature does not verify.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
    /// - `Err(HsmError)` — SHA / PKA failure.
    #[allow(clippy::too_many_arguments)]
    async fn rsa_pss_verify<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        pub_key: &DmaBuf,
        message_hash: &DmaBuf,
        salt_len: usize,
        signature: &DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<bool>
    where
        Self: 'a;
}
