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
}
