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

    /// Fixed-width public exponent length used in the wire-format
    /// public key — 4 bytes, sized to comfortably hold the canonical
    /// 65537 exponent (`01 00 01 00` LE) with room for any other
    /// 32-bit-fitting choice.
    pub const fn pub_exp_len() -> usize {
        4
    }

    /// Length in bytes of the raw wire-format public key
    /// (`n_le || e_le`, with `n` padded to `modulus_len` and `e`
    /// padded to [`pub_exp_len`](Self::pub_exp_len)).
    pub const fn pub_wire_len(&self) -> usize {
        self.modulus_len() + Self::pub_exp_len()
    }

    /// Generous upper bound on the PKCS#8 DER encoding of a private
    /// key on this size.  Retained for callers that still serialize
    /// to DER; the std PAL now vaults raw HSM bytes (see
    /// [`priv_key_hsm_len`](Self::priv_key_hsm_len)).
    pub const fn priv_key_der_max(&self) -> usize {
        // PKCS#8 DER for a 2-prime RSA private key contains n, e, d,
        // p, q, dP, dQ, qInv (≈ 5×modulus_len) plus ASN.1 framing.
        // 6×modulus_len + 256 leaves comfortable headroom across
        // 2048 / 3072 / 4096.
        6 * self.modulus_len() + 256
    }

    /// Length in bytes of the raw **non-CRT** HSM private-key
    /// encoding (`n || e(4) || p || q`, each integer zero-padded to
    /// its fixed width), i.e. `2 × modulus_len + 4`.
    ///
    /// This is the vault-native private-key format the std PAL
    /// stores: [`rsa_gen_keypair`](HsmRsa::rsa_gen_keypair) writes it
    /// and [`rsa_priv_to_hsm`](HsmRsa::rsa_priv_to_hsm) converts an
    /// imported DER key into it.  Matches the firmware's canonical
    /// `Rsa*Private` raw blob size (516 / 772 / 1028 for 2048 / 3072
    /// / 4096).  CRT private keys use a larger layout and are not yet
    /// supported by the unwrap import path.
    pub const fn priv_key_hsm_len(&self) -> usize {
        2 * self.modulus_len() + Self::pub_exp_len()
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
    /// Generate an RSA key pair, query-alloc-use style.
    ///
    /// Uses the canonical query-alloc-use workflow:
    ///
    /// 1. **Query** — call with `out = None`.  No key generation
    ///    happens; the method returns `(priv_max, pub_max)` upper
    ///    bounds the caller must allocate.  `pub_max` is always
    ///    [`HsmRsaKey::pub_wire_len`] (raw `n || e` on the wire);
    ///    `priv_max` depends on the PAL's encoding — std PAL vaults
    ///    the raw non-CRT HSM bytes (`n || e || p || q`) and returns
    ///    [`HsmRsaKey::priv_key_hsm_len`], while real-HW PALs return
    ///    the size of their raw component layout.
    /// 2. **Alloc** — caller allocates two DMA buffers of those
    ///    sizes.
    /// 3. **Use** — call with `out = Some((priv_out, pub_out))`.
    ///    The method generates a fresh keypair (using `alloc` for
    ///    any internal contiguous PKA scratch), writes the
    ///    PAL-format private key into `priv_out[..priv_actual]` and
    ///    the wire-format LE public key (`n_le || e_le`) into
    ///    `pub_out[..pub_actual]`, and returns the actual lengths.
    ///    Both are guaranteed to be `≤` the upper bounds reported
    ///    by the matching query call.  In practice all current PALs
    ///    use fixed-width encodings, so the use-mode lengths equal
    ///    the query-mode values (`priv_actual == priv_max`,
    ///    `pub_actual == pub_max`).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `alloc` — scoped allocator used by the implementation for
    ///   any internal scratch (e.g. a contiguous `priv || pub`
    ///   buffer real PKA hardware emits).  Unused in query mode.
    /// - `key_size` — modulus size selector (2048 / 3072 / 4096).
    /// - `out` — `None` to query buffer sizes; `Some((priv_out,
    ///   pub_out))` to actually generate.  Each output buffer must
    ///   be at least as large as the corresponding length returned
    ///   by an earlier query call.
    /// - `pct` — Pairwise Consistency Test selector.  When not
    ///   [`HsmRsaPct::None`], a sign / verify or encrypt / decrypt
    ///   round-trip is performed (FIPS 140-3 requirement).
    ///
    /// # Returns
    ///
    /// - `Ok((priv_len, pub_len))` — in query mode, the upper-bound
    ///   sizes the caller must allocate; in use mode, the actual
    ///   bytes written into `priv_out` / `pub_out` (always `≤` the
    ///   query bounds).
    /// - `Err(HsmError::InvalidArg)` — `out` is `Some` and one of
    ///   the buffers is shorter than the required length.
    /// - `Err(HsmError)` — PKA / RNG failure or PCT failed (the key
    ///   pair is rejected).
    async fn rsa_gen_keypair(
        &self,
        io: &impl HsmIo,
        alloc: &impl HsmScopedAlloc,
        key_size: HsmRsaKey,
        out: Option<(&mut DmaBuf, &mut DmaBuf)>,
        pct: HsmRsaPct,
    ) -> HsmResult<(usize, usize)>;

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
    ///   `key_size.modulus_len()` bytes.
    /// - `x` — output integer; must be exactly
    ///   `key_size.modulus_len()` bytes.
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

    /// Determine the modulus size of a serialized RSA private key.
    ///
    /// Used by [`RsaUnwrap`](../../../../../../fw/core/lib/src/ddi/mbor/rsa_unwrap.rs)
    /// to pick the right [`HsmVaultKeyKind`] for an imported key
    /// whose size is announced only by its encoding.  Std PAL parses
    /// PKCS#8 DER; real-HW PALs parse their own raw-component layout.
    ///
    /// Always returns the non-CRT variant
    /// ([`HsmRsaKey::Rsa2048Priv`] etc.) since PKCS#8 DER (and most
    /// raw layouts) contain the same component set regardless of
    /// whether the caller intends to use CRT acceleration —
    /// callers that need the CRT variant should re-tag via
    /// [`HsmRsaKey::pub_variant`] inversely or pick the kind based
    /// on context.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `key` — serialized private key bytes.
    ///
    /// # Returns
    ///
    /// - `Ok(HsmRsaKey)` — matching non-CRT size variant.
    /// - `Err(HsmError::InvalidArg)` — bytes don't parse as an RSA
    ///   private key, or the modulus isn't one of the supported
    ///   sizes (2048 / 3072 / 4096).
    fn rsa_priv_key_size(&self, io: &impl HsmIo, key: &DmaBuf) -> HsmResult<HsmRsaKey>;

    /// Extract the wire-format public key (`n_le || e_le`, padded
    /// to `key_size.pub_wire_len()` bytes) from a serialized RSA
    /// private key, using the query-alloc-use pattern:
    ///
    /// 1. **Query** — call with `pub_out = None` to learn the
    ///    wire-format length the caller must allocate
    ///    ([`HsmRsaKey::pub_wire_len`]).
    /// 2. **Alloc** — caller allocates a DMA buffer of that size.
    /// 3. **Use** — call with `pub_out = Some(buf)` to write the
    ///    wire-format pub key into `buf` and receive the actual
    ///    length (always equal to the query result).
    ///
    /// Used by [`RsaUnwrap`](../../../../../../fw/core/lib/src/ddi/mbor/rsa_unwrap.rs)
    /// to populate the optional `pub_key` field of its response
    /// so callers can verify the imported private key bytewise
    /// without an extra DDI round-trip.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `key` — serialized private key bytes.
    /// - `pub_out` — `None` to query the buffer size; `Some(buf)`
    ///   to write the wire-format pub key.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — pub-key length (query) or bytes written (use).
    /// - `Err(HsmError::InvalidArg)` — bytes don't parse as a
    ///   supported RSA private key, or `pub_out` is too small.
    fn rsa_priv_pub_key(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        pub_out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize>;

    /// Re-encode a freshly imported RSA private key from its on-wire
    /// **PKCS#8 DER** import form into the PAL's native vault
    /// encoding (raw non-CRT HSM bytes, `n || e || p || q` =
    /// [`HsmRsaKey::priv_key_hsm_len`] bytes), using the
    /// query-alloc-use pattern:
    ///
    /// 1. **Query** — call with `out = None` to learn the
    ///    vault-encoding length the caller must allocate.
    /// 2. **Alloc** — caller allocates a DMA buffer of that size.
    /// 3. **Use** — call with `out = Some(buf)` to write the
    ///    vault-format private key into `buf` and receive the actual
    ///    length (always equal to the query result).
    ///
    /// `RsaUnwrap`'s RSA import path stores the returned bytes in the
    /// vault so a later [`mod_exp_priv`](Self::mod_exp_priv) /
    /// [`rsa_oaep_decrypt`](Self::rsa_oaep_decrypt) reads back the
    /// same vault-native encoding it expects.  This mirrors the
    /// reference firmware's `to_pka_bytes` step and the ECC twin
    /// `HsmEcc::ecc_priv_to_hsm`.
    ///
    /// Only non-CRT private keys are supported; CRT keys use a
    /// larger vault layout and are handled by a future change.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `key` — imported private key in PKCS#8 DER.
    /// - `out` — `None` to query the buffer size; `Some(buf)` to
    ///   write the vault-format private key.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — vault-encoding length (query) or bytes written
    ///   (use).
    /// - `Err(HsmError::InvalidArg)` — bytes don't parse as a
    ///   supported RSA private key, or `out` is too small.
    fn rsa_priv_to_hsm(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize>;

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
    ///   `key_size.modulus_len()` bytes.
    /// - `y` — output integer; must be exactly
    ///   `key_size.modulus_len()` bytes.
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
    /// - `label` — OAEP label; `None` for the default empty label.
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
        label: Option<&DmaBuf>,
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
    /// - `label` — OAEP label (`None` for the default empty label);
    ///   must equal the encryption-time label.
    /// - `output` — plaintext destination; must be at least
    ///   `key_size.max_oaep_message(algo)` bytes.
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
        label: Option<&DmaBuf>,
        output: &mut DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<usize>
    where
        Self: 'a;

    /// OAEP decrypt in-place (EME-OAEP, RFC 8017 §7.1.2).
    ///
    /// Identical to [`rsa_oaep_decrypt`](Self::rsa_oaep_decrypt) but
    /// the recovered plaintext is written back into the ciphertext
    /// buffer, avoiding a second allocation.  The recovered plaintext
    /// is always shorter than the `modulus_len` ciphertext, so it
    /// fits.  This is the natural shape for hardware engines that
    /// decrypt directly into DMA buffers.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `algo` — OAEP hash.
    /// - `priv_key` — RSA private key.
    /// - `data` — exactly `key_size.modulus_len()` bytes of ciphertext
    ///   on entry; on return `data[..len]` holds the recovered
    ///   plaintext.
    /// - `label` — OAEP label (`None` for the default empty label);
    ///   must equal the encryption-time label.
    /// - `alloc` — scoped allocator for RSA scratch.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — length of recovered plaintext; `data[..len]` is
    ///   valid.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError::RsaOaepDecryptFailed)` — OAEP unmasking
    ///   detected tampering or label mismatch.
    /// - `Err(HsmError::NotEnoughSpace)` — allocator scope too small.
    /// - `Err(HsmError)` — SHA / PKA failure.
    #[allow(clippy::too_many_arguments)]
    async fn rsa_oaep_decrypt_in_place<'a>(
        &self,
        io: &impl HsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &DmaBuf,
        data: &mut DmaBuf,
        label: Option<&DmaBuf>,
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
