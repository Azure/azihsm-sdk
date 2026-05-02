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
    /// Encrypts `plaintext` using AES-GCM and writes the resulting
    /// ciphertext to `ciphertext` and the authentication tag to `tag`.
    /// Data does not need to be 16-byte-aligned — the PAL handles
    /// alignment and tag correction internally.
    ///
    /// # Parameters
    /// - `key` — The AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce. Must be unique per encryption
    ///   with the same key.
    /// - `aad_len` — Length in bytes of the additional authenticated data
    ///   (AAD) that precedes the plaintext in the input buffer.
    ///   The AAD is authenticated but not encrypted; pass `0` when
    ///   there is no AAD.
    /// - `plaintext` — Source data to encrypt (any length).
    /// - `ciphertext` — Destination buffer. Must be at least
    ///   `plaintext.len()` bytes.
    /// - `tag` — Output buffer for the 16-byte authentication tag.
    ///
    /// # Errors
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
    /// # Parameters
    /// - `key` — The AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce. Must be unique per encryption
    ///   with the same key.
    /// - `aad_len` — Length in bytes of the additional authenticated data
    ///   (AAD) that precedes the plaintext in `data`.
    ///   The AAD is authenticated but not encrypted; pass `0` when
    ///   there is no AAD.
    /// - `data` — Buffer holding the plaintext; overwritten with
    ///   ciphertext (any length).
    /// - `tag` — Output buffer for the 16-byte authentication tag.
    ///
    /// # Errors
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
    /// Decrypts `ciphertext` using AES-GCM and writes the resulting
    /// plaintext to `plaintext`. Verifies the authentication tag before
    /// returning.
    ///
    /// # Parameters
    /// - `key` — The AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce used during encryption.
    /// - `aad_len` — Length in bytes of the additional authenticated data
    ///   (AAD) that precedes the ciphertext in the input buffer.
    ///   Must match the AAD length supplied during encryption;
    ///   pass `0` when there is no AAD.
    /// - `tag` — The 16-byte authentication tag produced during
    ///   encryption.
    /// - `ciphertext` — Source data to decrypt (any length).
    /// - `plaintext` — Destination buffer. Must be at least
    ///   `ciphertext.len()` bytes.
    ///
    /// # Errors
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
    /// # Parameters
    /// - `key` — The AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce used during encryption.
    /// - `aad_len` — Length in bytes of the additional authenticated data
    ///   (AAD) that precedes the ciphertext in `data`.
    ///   Must match the AAD length supplied during encryption;
    ///   pass `0` when there is no AAD.
    /// - `tag` — The 16-byte authentication tag produced during
    ///   encryption.
    /// - `data` — Buffer holding the ciphertext; overwritten with
    ///   plaintext (any length).
    ///
    /// # Errors
    /// Returns [`HsmError`] if the tag verification or decryption fails.
    async fn gcm_decrypt_in_place(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad_len: usize,
        tag: &[u8; 16],
        data: &mut [u8],
    ) -> HsmResult<()>;
}
