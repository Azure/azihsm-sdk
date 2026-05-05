// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES cryptographic operations trait for the HSM PAL.
//!
//! Defines the [`HsmAes`] trait that PAL implementations use to expose
//! AES key generation and ECB/CBC block cipher operations.
//!
//! On Cortex-M7 hardware this would delegate to a dedicated AES engine.
//! On the standard (host-native) PAL it would use OpenSSL.
//!
//! ## Key representation
//!
//! All key parameters are plain `&[u8]` byte slices containing the raw
//! AES key material. Each PAL implementation is responsible for parsing
//! them into whatever internal representation it needs.
//!
//! ## Encrypt / decrypt unification
//!
//! CBC and ECB methods take a `encrypt: bool` flag instead of having
//! separate `_encrypt` / `_decrypt` methods. `true` = encrypt,
//! `false` = decrypt. This reduces trait surface and matches the
//! hardware register model where a single direction bit selects the
//! operation.
//!
//! ## In-place variants
//!
//! Methods suffixed `_in_place` operate on a single `&mut [u8]` buffer,
//! reading input and writing output to the same memory. This avoids an
//! extra buffer allocation and is the natural model for hardware engines
//! that operate directly on DMA buffers.

use super::*;

// ── AES-XTS data unit length ──────────────────────────────────────

/// XTS data unit length.
///
/// Controls how the hardware segments the input into data units and
/// increments the tweak between them. The input length must be a
/// multiple of the selected data unit length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XtsDataUnitLen {
    /// Entire input is a single data unit.
    Full,

    /// 512-byte blocks.
    Block512,

    /// 4096-byte blocks.
    Block4K,

    /// 8192-byte blocks.
    Block8K,
}

/// Asynchronous AES operations trait.
///
/// PAL implementations provide this to the core for AES key generation
/// and block cipher operations. The async signatures allow hardware-backed
/// implementations to yield while the AES engine processes data.
pub trait HsmAes {
    /// Generate a random AES key.
    ///
    /// # Parameters
    /// - `key` — Output buffer filled with random key material. The
    ///   buffer length determines the key size:
    ///   - 16 bytes → AES-128
    ///   - 24 bytes → AES-192
    ///   - 32 bytes → AES-256
    ///
    /// # Errors
    /// Returns [`HsmError`] if the RNG fails.
    async fn aes_gen_key(&self, key: &mut [u8]) -> HsmResult<()>;

    /// AES-CBC encrypt or decrypt with separate input/output buffers.
    ///
    /// # Parameters
    /// - `key` — The AES key.
    /// - `encrypt` — `true` for encryption, `false` for decryption.
    /// - `iv` — 16-byte initialization vector. Updated in-place to the
    ///   last ciphertext block after the operation, enabling chaining
    ///   across multiple calls.
    /// - `input` — Source data. Must be a multiple of 16 bytes.
    /// - `output` — Destination buffer. Must be at least `input.len()`
    ///   bytes.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the cipher operation fails.
    async fn aes_cbc_enc_dec(
        &self,
        key: &[u8],
        encrypt: bool,
        iv: &mut [u8],
        input: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()>;

    /// AES-CBC encrypt or decrypt in-place.
    ///
    /// Reads from and writes to the same `data` buffer. The IV is
    /// updated in-place for chaining.
    ///
    /// # Parameters
    /// - `key` — The AES key.
    /// - `encrypt` — `true` for encryption, `false` for decryption.
    /// - `iv` — 16-byte initialization vector (updated in-place).
    /// - `data` — Buffer holding the input; overwritten with the output.
    ///   Must be a multiple of 16 bytes.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the cipher operation fails.
    async fn aes_cbc_enc_dec_in_place(
        &self,
        key: &[u8],
        encrypt: bool,
        iv: &mut [u8],
        data: &mut [u8],
    ) -> HsmResult<()>;

    /// AES-ECB encrypt or decrypt with separate input/output buffers.
    ///
    /// # Parameters
    /// - `key` — The AES key.
    /// - `encrypt` — `true` for encryption, `false` for decryption.
    /// - `input` — Source block(s). Must be a multiple of 16 bytes.
    /// - `output` — Destination buffer. Must be at least `input.len()`
    ///   bytes.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the cipher operation fails.
    async fn aes_ecb_enc_dec(
        &self,
        key: &[u8],
        encrypt: bool,
        input: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()>;

    /// AES-ECB encrypt or decrypt in-place.
    ///
    /// Reads from and writes to the same `data` buffer.
    ///
    /// # Parameters
    /// - `key` — The AES key.
    /// - `encrypt` — `true` for encryption, `false` for decryption.
    /// - `data` — Buffer holding the input; overwritten with the output.
    ///   Must be a multiple of 16 bytes.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the cipher operation fails.
    async fn aes_ecb_enc_dec_in_place(
        &self,
        key: &[u8],
        encrypt: bool,
        data: &mut [u8],
    ) -> HsmResult<()>;

    /// AES-GCM encrypt with separate input/output buffers.
    ///
    /// Encrypts the text portion of `plaintext` using AES-GCM and writes
    /// the result to `ciphertext` and the authentication tag to `tag`.
    /// Data does not need to be 16-byte-aligned — the PAL handles
    /// alignment and tag correction internally.
    ///
    /// # Buffer layout
    ///
    /// Both `plaintext` and `ciphertext` use the layout
    /// `[padded_AAD | text]`, where `padded_AAD` is the AAD region
    /// prepared according to the BCP hardware `pad_aad` convention:
    ///
    /// | `aad_len % 32` | Layout |
    /// |----------------|--------|
    /// | `== 0` | `[AAD]` — no padding |
    /// | `1..=16` | `[zeros(16) \| AAD \| zeros(32 - 16 - rem)]` — prepend 16 zero bytes, AAD left-justified after, trail-pad to next 32 |
    /// | `17..=31` | `[AAD \| zeros(32 - rem)]` — AAD left-justified, trail-pad to next 32 |
    ///
    /// The total padded AAD region is always `round_up_32(aad_len)` bytes.
    /// When `aad_len` is `0`, no AAD region is present and `data` contains
    /// only the text.
    ///
    /// The prepend-zeros rule ensures the leading GHASH block is all zeros
    /// (transparent to the GHASH accumulator), so the AAD content occupies
    /// the same GHASH-block positions as standard GCM. This allows the
    /// PAL to correct the hardware tag with a simple length-field fixup.
    ///
    /// # Parameters
    ///
    /// - `key` — AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce. Must be unique per encryption
    ///   with the same key.
    /// - `aad_len` — **Unpadded** AAD length in bytes. The padded AAD
    ///   region in the buffer is `round_up_32(aad_len)` bytes.
    /// - `plaintext` — `[padded_AAD | plaintext_bytes]`.
    /// - `ciphertext` — Destination. Must be at least `plaintext.len()`.
    /// - `tag` — Output buffer for the 16-byte authentication tag.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if the encryption operation fails.
    async fn gcm_encrypt(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad_len: usize,
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> HsmResult<()>;

    /// AES-GCM encrypt in-place.
    ///
    /// Reads plaintext from and writes ciphertext to the same `data`
    /// buffer. The authentication tag is written to `tag`. This avoids
    /// an extra buffer allocation and is the natural model for hardware
    /// engines that operate directly on DMA buffers.
    ///
    /// # Buffer layout
    ///
    /// `data` uses the layout `[padded_AAD | text]`. See
    /// [`gcm_encrypt`](Self::gcm_encrypt) for the full `pad_aad`
    /// convention. The padded AAD region occupies the first
    /// `round_up_32(aad_len)` bytes; the remaining bytes are plaintext
    /// (overwritten with ciphertext on return).
    ///
    /// # Parameters
    ///
    /// - `key` — AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce. Must be unique per encryption
    ///   with the same key.
    /// - `aad_len` — **Unpadded** AAD length in bytes.
    /// - `data` — `[padded_AAD | plaintext]`; the text portion is
    ///   overwritten with ciphertext.
    /// - `tag` — Output buffer for the 16-byte authentication tag.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if the encryption operation fails.
    async fn gcm_encrypt_in_place(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad_len: usize,
        data: &mut [u8],
        tag: &mut [u8; 16],
    ) -> HsmResult<()>;

    /// AES-GCM decrypt with separate input/output buffers.
    ///
    /// Decrypts the text portion of `ciphertext` using AES-GCM and writes
    /// the result to `plaintext`. Verifies the authentication tag before
    /// returning.
    ///
    /// # Buffer layout
    ///
    /// Both `ciphertext` and `plaintext` use the layout
    /// `[padded_AAD | text]`. See [`gcm_encrypt`](Self::gcm_encrypt) for
    /// the full `pad_aad` convention.
    ///
    /// # Parameters
    ///
    /// - `key` — AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce used during encryption.
    /// - `aad_len` — **Unpadded** AAD length in bytes. Must match the
    ///   value supplied during encryption.
    /// - `tag` — The 16-byte authentication tag from encryption.
    /// - `ciphertext` — `[padded_AAD | ciphertext_bytes]`.
    /// - `plaintext` — Destination. Must be at least `ciphertext.len()`.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if the tag verification or decryption fails.
    async fn gcm_decrypt(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad_len: usize,
        tag: &[u8; 16],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> HsmResult<()>;

    /// AES-GCM decrypt in-place.
    ///
    /// Reads ciphertext from and writes plaintext to the same `data`
    /// buffer. Verifies the authentication tag before returning. This
    /// avoids an extra buffer allocation and is the natural model for
    /// hardware engines that operate directly on DMA buffers.
    ///
    /// # Buffer layout
    ///
    /// `data` uses the layout `[padded_AAD | text]`. See
    /// [`gcm_encrypt`](Self::gcm_encrypt) for the full `pad_aad`
    /// convention. The padded AAD region occupies the first
    /// `round_up_32(aad_len)` bytes; the remaining bytes are ciphertext
    /// (overwritten with plaintext on return).
    ///
    /// # Parameters
    ///
    /// - `key` — AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce used during encryption.
    /// - `aad_len` — **Unpadded** AAD length in bytes. Must match the
    ///   value supplied during encryption.
    /// - `tag` — The 16-byte authentication tag from encryption.
    /// - `data` — `[padded_AAD | ciphertext]`; the text portion is
    ///   overwritten with plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if the tag verification or decryption fails.
    async fn gcm_decrypt_in_place(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad_len: usize,
        tag: &[u8; 16],
        data: &mut [u8],
    ) -> HsmResult<()>;

    // ── AES Key Wrap (RFC 3394) ────────────────────────────────────

    /// AES Key Wrap (RFC 3394) — wrap key data.
    ///
    /// Wraps `input` using the KEK `key`. The output includes an 8-byte
    /// integrity check value (IV) prepended to the wrapped semiblocks.
    ///
    /// # Parameters
    ///
    /// - `key` — Key Encryption Key (16, 24, or 32 bytes).
    /// - `input` — Key data to wrap. Must be ≥ 16 bytes, a multiple of 8,
    ///   and at most 3072 bytes.
    /// - `output` — Destination buffer. Must be at least `input.len() + 8`.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidArg`] if input constraints are violated.
    async fn aes_kw_wrap(&self, key: &[u8], input: &[u8], output: &mut [u8]) -> HsmResult<()>;

    /// AES Key Wrap (RFC 3394) — unwrap key data.
    ///
    /// Unwraps `input` using the KEK `key` and verifies the integrity
    /// check value. Returns an error if the IV does not match the
    /// default 0xA6A6A6A6A6A6A6A6 (wrong key or tampered data).
    ///
    /// # Parameters
    ///
    /// - `key` — Key Encryption Key (16, 24, or 32 bytes).
    /// - `input` — Wrapped key data. Must be ≥ 24 bytes, a multiple of 8,
    ///   and at most 3080 bytes.
    /// - `output` — Destination buffer. Must be at least `input.len() - 8`.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidArg`] on bad input sizes.
    /// Returns [`HsmError::AesUnwrapFailed`] on IV mismatch.
    async fn aes_kw_unwrap(&self, key: &[u8], input: &[u8], output: &mut [u8]) -> HsmResult<()>;

    // ── AES Key Wrap with Padding (RFC 5649) ───────────────────────

    /// AES Key Wrap with Padding (RFC 5649) — wrap key data.
    ///
    /// Wraps `input` of any length (≥ 1 byte, ≤ 3072 bytes) using the
    /// KEK `key`. Pads to an 8-byte boundary and uses an Alternative
    /// Initial Value (AIV) that encodes the plaintext length.
    ///
    /// For padded input ≤ 8 bytes (1 semiblock), a single AES-ECB
    /// encryption is used. Otherwise, delegates to AES-KW with the AIV.
    ///
    /// # Parameters
    ///
    /// - `key` — Key Encryption Key (16, 24, or 32 bytes).
    /// - `input` — Key data to wrap (1..=3072 bytes, any alignment).
    /// - `output` — Destination buffer. Must be at least
    ///   `round_up_8(input.len()) + 8` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidArg`] if input constraints are violated.
    async fn aes_kwp_wrap(&self, key: &[u8], input: &[u8], output: &mut [u8]) -> HsmResult<()>;

    /// AES Key Wrap with Padding (RFC 5649) — unwrap key data.
    ///
    /// Unwraps `input` and verifies the AIV (constant prefix + MLI).
    /// Validates that padding bytes are all zero.
    ///
    /// # Parameters
    ///
    /// - `key` — Key Encryption Key (16, 24, or 32 bytes).
    /// - `input` — Wrapped key data. Must be ≥ 16 bytes, a multiple of 8,
    ///   and at most 3080 bytes.
    /// - `output` — Destination buffer. Must be at least `input.len() - 8`.
    ///
    /// # Returns
    ///
    /// The actual plaintext length (MLI), which may be shorter than
    /// `output.len()`.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidArg`] on bad input sizes.
    /// Returns [`HsmError::AesUnwrapFailed`] on AIV mismatch or bad padding.
    async fn aes_kwp_unwrap(&self, key: &[u8], input: &[u8], output: &mut [u8])
    -> HsmResult<usize>;

    // ── AES-XTS (IEEE 1619 / NIST SP 800-38E) ─────────────────────

    /// Generate a random AES-256-XTS key pair (K1 || K2).
    ///
    /// Fills `key` with 64 random bytes and verifies K1 ≠ K2.
    ///
    /// # Parameters
    /// - `key` — Output buffer. Must be exactly 64 bytes.
    ///
    /// # Errors
    /// Returns [`HsmError::InvalidArg`] if `key.len() != 64`.
    async fn aes_xts_gen_key(&self, key: &mut [u8]) -> HsmResult<()>;

    /// AES-XTS encrypt with separate input/output buffers.
    ///
    /// # Parameters
    /// - `key` — XTS key (64 bytes: K1\[32\] || K2\[32\]).
    /// - `tweak` — 8-byte tweak (sector number, little-endian).
    /// - `dul` — Data unit length mode.
    /// - `input` — Plaintext. Must be ≥ 16 bytes, a multiple of 16,
    ///   and a multiple of `dul` (when not [`XtsDataUnitLen::Full`]).
    /// - `output` — Ciphertext buffer. Must be at least `input.len()`.
    ///
    /// # Errors
    /// Returns [`HsmError::InvalidArg`] on invalid key/tweak/input sizes.
    async fn aes_xts_encrypt(
        &self,
        key: &[u8],
        tweak: &[u8],
        dul: XtsDataUnitLen,
        input: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()>;

    /// AES-XTS decrypt with separate input/output buffers.
    ///
    /// Same parameters and constraints as
    /// [`aes_xts_encrypt`](Self::aes_xts_encrypt).
    async fn aes_xts_decrypt(
        &self,
        key: &[u8],
        tweak: &[u8],
        dul: XtsDataUnitLen,
        input: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()>;

    /// AES-XTS encrypt in-place.
    ///
    /// # Parameters
    /// - `key` — XTS key (64 bytes: K1\[32\] || K2\[32\]).
    /// - `tweak` — 8-byte tweak (sector number, little-endian).
    /// - `dul` — Data unit length mode.
    /// - `data` — Buffer holding plaintext; overwritten with ciphertext.
    ///   Must be ≥ 16 bytes, a multiple of 16, and a multiple of `dul`.
    async fn aes_xts_encrypt_in_place(
        &self,
        key: &[u8],
        tweak: &[u8],
        dul: XtsDataUnitLen,
        data: &mut [u8],
    ) -> HsmResult<()>;

    /// AES-XTS decrypt in-place.
    ///
    /// Same parameters and constraints as
    /// [`aes_xts_encrypt_in_place`](Self::aes_xts_encrypt_in_place).
    async fn aes_xts_decrypt_in_place(
        &self,
        key: &[u8],
        tweak: &[u8],
        dul: XtsDataUnitLen,
        data: &mut [u8],
    ) -> HsmResult<()>;
}
