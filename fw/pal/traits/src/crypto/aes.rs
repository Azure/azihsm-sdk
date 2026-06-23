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
//! DMA-facing AES operations take [`DmaBuf`] inputs/outputs for any bytes
//! touched directly by the hardware engine (keys, IVs, payloads, tags,
//! tweaks). Random key-generation outputs remain plain `&mut [u8]` so
//! callers can write into either slices or DMA buffers via deref.
//!
//! ## Encrypt / decrypt unification
//!
//! CBC and ECB methods take an [`AesOp`] selector instead of having
//! separate `_encrypt` / `_decrypt` methods. This reduces trait
//! surface while keeping the operation direction explicit at the call
//! site.
//!
//! ## In-place variants
//!
//! Methods suffixed `_in_place` operate on a single `&mut DmaBuf` buffer,
//! reading input and writing output to the same memory. This avoids an
//! extra buffer allocation and is the natural model for hardware engines
//! that operate directly on DMA buffers.

use super::*;

// ── AES-XTS data unit length ──────────────────────────────────────
// AES-XTS support is currently disabled. The data unit length selector
// is retained here, commented out, for future re-enablement.
//
// /// XTS data unit length.
// ///
// /// Controls how the hardware segments the input into data units and
// /// increments the tweak between them. The input length must be a
// /// multiple of the selected data unit length.
// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// pub enum XtsDataUnitLen {
//     /// Entire input is a single data unit.
//     Full,
//
//     /// 512-byte blocks.
//     Block512,
//
//     /// 4096-byte blocks.
//     Block4K,
//
//     /// 8192-byte blocks.
//     Block8K,
// }

/// AES encrypt/decrypt operation selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesOp {
    /// Encrypt the input.
    Encrypt,

    /// Decrypt the input.
    Decrypt,
}

/// Asynchronous AES operations trait.
///
/// PAL implementations provide this to the core for AES key generation
/// and block cipher operations. The async signatures allow hardware-backed
/// implementations to yield while the AES engine processes data.
///
/// All methods take `io` as their second parameter so callers can forward
/// the operation-scoped [`HsmIo`] context through the PAL crypto stack.
pub trait HsmAes {
    /// Generate a random AES key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — output buffer; entirely filled with random bytes.
    ///   Buffer length determines key size: 16 / 24 / 32 bytes for
    ///   AES-128 / 192 / 256 respectively.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `key` populated.
    /// - `Err(HsmError::InvalidArg)` — `key.len()` is not 16, 24, or 32.
    /// - `Err(HsmError)` — propagated from the CSPRNG.
    async fn aes_gen_key(&self, io: &impl HsmIo, key: &mut [u8]) -> HsmResult<()>;

    /// AES-CBC encrypt or decrypt with separate input / output buffers.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `op` — [`AesOp::Encrypt`] or [`AesOp::Decrypt`].
    /// - `key` — AES key (16 / 24 / 32 bytes).
    /// - `input` — source bytes; length must be a multiple of 16.
    /// - `iv_in` — 16-byte IV used for this request.
    /// - `output` — destination; must be at least `input.len()` bytes.
    /// - `iv_out` — optional destination for the updated chaining IV.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `output[..input.len()]` populated and `iv_out`
    ///   updated when provided.
    /// - `Err(HsmError::InvalidArg)` — buffer-size or alignment
    ///   violation.
    /// - `Err(HsmError)` — AES driver failure.
    #[allow(clippy::too_many_arguments)]
    async fn aes_cbc_enc_dec(
        &self,
        io: &impl HsmIo,
        op: AesOp,
        key: &DmaBuf,
        input: &DmaBuf,
        iv_in: &DmaBuf,
        output: &mut DmaBuf,
        iv_out: Option<&mut DmaBuf>,
    ) -> HsmResult<()>;

    /// AES-CBC encrypt or decrypt in-place.
    ///
    /// Identical to [`aes_cbc_enc_dec`](Self::aes_cbc_enc_dec) but the
    /// transform is applied to a single buffer.  This avoids a second
    /// allocation and is the natural shape for hardware engines that
    /// operate directly on DMA buffers.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `op` — [`AesOp::Encrypt`] or [`AesOp::Decrypt`].
    /// - `key` — AES key (16 / 24 / 32 bytes).
    /// - `data` — input on entry, output on return; length must
    ///   be a multiple of 16.
    /// - `iv_in` — 16-byte IV used for this request.
    /// - `iv_out` — optional destination for the updated chaining IV.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `data` overwritten with the result and `iv_out`
    ///   updated when provided.
    /// - `Err(HsmError::InvalidArg)` — buffer-size or alignment
    ///   violation.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_cbc_enc_dec_in_place(
        &self,
        io: &impl HsmIo,
        op: AesOp,
        key: &DmaBuf,
        data: &mut DmaBuf,
        iv_in: &DmaBuf,
        iv_out: Option<&mut DmaBuf>,
    ) -> HsmResult<()>;

    /// AES-ECB encrypt or decrypt with separate input / output
    /// buffers.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `op` — [`AesOp::Encrypt`] or [`AesOp::Decrypt`].
    /// - `key` — AES key (16 / 24 / 32 bytes).
    /// - `input` — source block(s); length must be a multiple of
    ///   16.
    /// - `output` — destination; must be at least `input.len()`
    ///   bytes.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `output[..input.len()]` populated.
    /// - `Err(HsmError::InvalidArg)` — buffer-size or alignment
    ///   violation.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_ecb_enc_dec(
        &self,
        io: &impl HsmIo,
        op: AesOp,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()>;

    /// AES-ECB encrypt or decrypt in-place.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `op` — [`AesOp::Encrypt`] or [`AesOp::Decrypt`].
    /// - `key` — AES key (16 / 24 / 32 bytes).
    /// - `data` — input on entry, output on return; length must
    ///   be a multiple of 16.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `data` overwritten with the result.
    /// - `Err(HsmError::InvalidArg)` — buffer-size or alignment
    ///   violation.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_ecb_enc_dec_in_place(
        &self,
        io: &impl HsmIo,
        op: AesOp,
        key: &DmaBuf,
        data: &mut DmaBuf,
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
    /// prepared according to the `pad_aad` GHASH-alignment convention:
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
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce. Must be unique per encryption
    ///   with the same key.
    /// - `aad_len` — **Unpadded** AAD length in bytes. The padded AAD
    ///   region in the buffer is `round_up_32(aad_len)` bytes.
    /// - `plaintext` — `[padded_AAD | plaintext_bytes]`.
    /// - `ciphertext` — Destination. Must be at least `plaintext.len()`.
    /// - `tag` — Output buffer for the 16-byte authentication tag.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `ciphertext[..plaintext.len()]` populated, `tag`
    ///   set.
    /// - `Err(HsmError::InvalidArg)` — buffer-size violation, IV not
    ///   12 bytes, or AAD layout malformed.
    /// - `Err(HsmError)` — AES driver failure.
    #[allow(clippy::too_many_arguments)]
    async fn gcm_encrypt(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        plaintext: &DmaBuf,
        ciphertext: &mut DmaBuf,
        tag: &mut DmaBuf,
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
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce. Must be unique per encryption
    ///   with the same key.
    /// - `aad_len` — **Unpadded** AAD length in bytes.
    /// - `data` — `[padded_AAD | plaintext]`; the text portion is
    ///   overwritten with ciphertext.
    /// - `tag` — Output buffer for the 16-byte authentication tag.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `data` text portion overwritten, `tag` set.
    /// - `Err(HsmError::InvalidArg)` — buffer-size violation, IV not
    ///   12 bytes, or AAD layout malformed.
    /// - `Err(HsmError)` — AES driver failure.
    async fn gcm_encrypt_in_place(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        data: &mut DmaBuf,
        tag: &mut DmaBuf,
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
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce used during encryption.
    /// - `aad_len` — **Unpadded** AAD length in bytes. Must match the
    ///   value supplied during encryption.
    /// - `tag` — The 16-byte authentication tag from encryption.
    /// - `ciphertext` — `[padded_AAD | ciphertext_bytes]`.
    /// - `plaintext` — Destination. Must be at least `ciphertext.len()`.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — tag verified and `plaintext[..ciphertext.len()]`
    ///   populated.
    /// - `Err(HsmError::InvalidArg)` — buffer-size violation or AAD
    ///   layout malformed.
    /// - `Err(HsmError::AesGcmTagMismatch)` — authentication tag
    ///   does not match.
    /// - `Err(HsmError)` — AES driver failure.
    #[allow(clippy::too_many_arguments)]
    async fn gcm_decrypt(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        tag: &DmaBuf,
        ciphertext: &DmaBuf,
        plaintext: &mut DmaBuf,
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
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — AES key (16, 24, or 32 bytes for AES-128/192/256).
    /// - `iv` — 12-byte (96-bit) nonce used during encryption.
    /// - `aad_len` — **Unpadded** AAD length in bytes. Must match the
    ///   value supplied during encryption.
    /// - `tag` — The 16-byte authentication tag from encryption.
    /// - `data` — `[padded_AAD | ciphertext]`; the text portion is
    ///   overwritten with plaintext.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — tag verified, `data` text portion overwritten
    ///   with plaintext.
    /// - `Err(HsmError::InvalidArg)` — buffer-size violation or AAD
    ///   layout malformed.
    /// - `Err(HsmError::AesGcmTagMismatch)` — authentication tag
    ///   does not match (`data` is left in an unspecified state).
    /// - `Err(HsmError)` — AES driver failure.
    async fn gcm_decrypt_in_place(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        iv: &DmaBuf,
        aad_len: usize,
        tag: &DmaBuf,
        data: &mut DmaBuf,
    ) -> HsmResult<()>;

    // ── AES Key Wrap (RFC 3394) ────────────────────────────────────

    /// AES Key Wrap (RFC 3394) — wrap key data.
    ///
    /// Wraps `input` under the KEK `key`.  The output prepends the
    /// 8-byte default integrity check value
    /// `0xA6A6A6A6A6A6A6A6` to the wrapped semiblocks.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — Key Encryption Key (16 / 24 / 32 bytes).
    /// - `input` — plaintext key material.  Must be ≥ 16 bytes,
    ///   a multiple of 8, and at most 3072 bytes.
    /// - `output` — destination; must be at least
    ///   `input.len() + 8` bytes.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `output[..input.len() + 8]` populated.
    /// - `Err(HsmError::InvalidArg)` — size or alignment
    ///   constraints violated.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_kw_wrap(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()>;

    /// AES Key Wrap (RFC 3394) — unwrap key data.
    ///
    /// Unwraps `input` under the KEK `key` and verifies the
    /// integrity check value matches the default `0xA6A6…`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — Key Encryption Key (16 / 24 / 32 bytes).
    /// - `input` — wrapped key data.  Must be ≥ 24 bytes,
    ///   a multiple of 8, and at most 3080 bytes.
    /// - `output` — destination; must be at least
    ///   `input.len() - 8` bytes.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `output[..input.len() - 8]` populated.
    /// - `Err(HsmError::InvalidArg)` — size or alignment
    ///   constraints violated.
    /// - `Err(HsmError::AesUnwrapFailed)` — IV mismatch (wrong
    ///   key or tampered ciphertext).
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_kw_unwrap(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()>;

    // ── AES Key Wrap with Padding (RFC 5649) ───────────────────────

    /// AES Key Wrap with Padding (RFC 5649) — wrap key data of any
    /// length.
    ///
    /// Pads `input` to an 8-byte boundary and uses an Alternative
    /// Initial Value (AIV) that encodes the plaintext length.
    /// Padded payloads of one semiblock use a single AES-ECB pass;
    /// longer payloads delegate to AES-KW with the AIV.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — Key Encryption Key (16 / 24 / 32 bytes).
    /// - `input` — plaintext (1..=3072 bytes, any alignment).
    /// - `output` — destination; must be at least
    ///   `round_up_8(input.len()) + 8` bytes.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — wrapped output populated.
    /// - `Err(HsmError::InvalidArg)` — size constraints violated.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_kwp_wrap(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()>;

    /// AES Key Wrap with Padding (RFC 5649) — unwrap key data.
    ///
    /// Verifies the AIV (constant prefix + Message Length
    /// Indicator) and that all trailing pad bytes are zero.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key` — Key Encryption Key (16 / 24 / 32 bytes).
    /// - `input` — wrapped key data.  Must be ≥ 16 bytes, a
    ///   multiple of 8, and at most 3080 bytes.
    /// - `output` — destination; must be at least
    ///   `input.len() - 8` bytes.
    ///
    /// # Returns
    ///
    /// - `Ok(mli)` — the recovered plaintext length (the MLI from
    ///   the AIV); `output[..mli]` is valid plaintext.
    /// - `Err(HsmError::InvalidArg)` — size constraints violated.
    /// - `Err(HsmError::AesUnwrapFailed)` — AIV mismatch or
    ///   non-zero pad bytes.
    /// - `Err(HsmError)` — AES driver failure.
    async fn aes_kwp_unwrap(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<usize>;

    // ── AES-XTS (IEEE 1619 / NIST SP 800-38E) ─────────────────────
    //
    // AES-XTS support is currently disabled. The trait entry points are
    // retained here, commented out, for future re-enablement.
    //
    // /// Generate a random AES-256-XTS key (`K1 || K2`).
    // ///
    // /// Fills `key` with 64 random bytes and ensures `K1 ≠ K2` (XTS
    // /// requires distinct halves; the standard prohibits a tweak
    // /// degenerate case).
    // ///
    // /// # Parameters
    // ///
    // /// - `io` — caller's I/O context (per-IO scope).
    // /// - `key` — output buffer; must be exactly 64 bytes.
    // ///
    // /// # Returns
    // ///
    // /// - `Ok(())` — `key` populated, `K1 ≠ K2`.
    // /// - `Err(HsmError::InvalidArg)` — `key.len() != 64`.
    // /// - `Err(HsmError)` — propagated from the CSPRNG.
    // async fn aes_xts_gen_key(&self, io: &impl HsmIo, key: &mut [u8]) -> HsmResult<()>;
    //
    // /// AES-XTS encrypt with separate input / output buffers
    // /// (IEEE 1619 / NIST SP 800-38E).
    // ///
    // /// # Parameters
    // ///
    // /// - `io` — caller's I/O context (per-IO scope).
    // /// - `key` — XTS key, exactly 64 bytes (`K1[32] || K2[32]`).
    // /// - `tweak` — 8-byte tweak (typically a little-endian sector
    // ///   number).
    // /// - `dul` — data-unit length selector; controls how the
    // ///   tweak is incremented.
    // /// - `input` — plaintext.  Must be ≥ 16 bytes, a multiple of
    // ///   16, and a multiple of `dul.bytes()` when `dul` is not
    // ///   [`XtsDataUnitLen::Full`].
    // /// - `output` — destination; must be at least
    // ///   `input.len()` bytes.
    // ///
    // /// # Returns
    // ///
    // /// - `Ok(())` — `output[..input.len()]` populated.
    // /// - `Err(HsmError::InvalidArg)` — size or alignment
    // ///   violation, or `K1 == K2`.
    // /// - `Err(HsmError)` — AES driver failure.
    // async fn aes_xts_encrypt(
    //     &self,
    //     io: &impl HsmIo,
    //     key: &DmaBuf,
    //     tweak: &DmaBuf,
    //     dul: XtsDataUnitLen,
    //     input: &DmaBuf,
    //     output: &mut DmaBuf,
    // ) -> HsmResult<()>;
    //
    // /// AES-XTS decrypt with separate input / output buffers.
    // ///
    // /// Parameter and return semantics match
    // /// [`aes_xts_encrypt`](Self::aes_xts_encrypt) with the
    // /// direction reversed; `input` is ciphertext and `output`
    // /// receives plaintext.
    // async fn aes_xts_decrypt(
    //     &self,
    //     io: &impl HsmIo,
    //     key: &DmaBuf,
    //     tweak: &DmaBuf,
    //     dul: XtsDataUnitLen,
    //     input: &DmaBuf,
    //     output: &mut DmaBuf,
    // ) -> HsmResult<()>;
    //
    // /// AES-XTS encrypt in-place.
    // ///
    // /// # Parameters
    // ///
    // /// - `io` — caller's I/O context (per-IO scope).
    // /// - `key` — XTS key, exactly 64 bytes (`K1[32] || K2[32]`).
    // /// - `tweak` — 8-byte tweak.
    // /// - `dul` — data-unit length selector.
    // /// - `data` — plaintext on entry, ciphertext on return; must
    // ///   be ≥ 16 bytes, a multiple of 16, and a multiple of
    // ///   `dul.bytes()` when `dul` is not [`XtsDataUnitLen::Full`].
    // ///
    // /// # Returns
    // ///
    // /// - `Ok(())` — `data` overwritten with ciphertext.
    // /// - `Err(HsmError::InvalidArg)` — size or alignment
    // ///   violation, or `K1 == K2`.
    // /// - `Err(HsmError)` — AES driver failure.
    // async fn aes_xts_encrypt_in_place(
    //     &self,
    //     io: &impl HsmIo,
    //     key: &DmaBuf,
    //     tweak: &DmaBuf,
    //     dul: XtsDataUnitLen,
    //     data: &mut DmaBuf,
    // ) -> HsmResult<()>;
    //
    // /// AES-XTS decrypt in-place.
    // ///
    // /// Parameter and return semantics match
    // /// [`aes_xts_encrypt_in_place`](Self::aes_xts_encrypt_in_place)
    // /// with the direction reversed; `data` holds ciphertext on
    // /// entry and plaintext on return.
    // async fn aes_xts_decrypt_in_place(
    //     &self,
    //     io: &impl HsmIo,
    //     key: &DmaBuf,
    //     tweak: &DmaBuf,
    //     dul: XtsDataUnitLen,
    //     data: &mut DmaBuf,
    // ) -> HsmResult<()>;
}
