// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

//! Masked-key envelope: authenticated-encryption blob compatible with
//! the cross-domain `MaskedKey` wire format.
//!
//! ## Scheme
//!
//! Only `AES-CBC-256 + HMAC-SHA-384` (encrypt-then-MAC) is currently
//! supported.  An 80-byte masking key is split into a 32-byte AES key
//! (low half) and a 48-byte HMAC key (high half).  The HMAC tag covers
//! everything in the blob except the trailing tag itself.
//!
//! ## Output layout (AES-CBC-256 + HMAC-SHA-384)
//!
//! ```text
//! ┌──────────────────────┬────────┐
//! │ MaskedKeyHeader      │ 4 B    │ version + algorithm (LE u16s)
//! │ MaskedKeyAesHeader   │ 48 B   │ 7×u16 field lengths + 34-B reserved
//! │ IV                   │ 16 B   │ random per-blob
//! │ post-IV pad          │ 0..3 B │ aligns metadata to 4-byte boundary
//! │ metadata             │ N B    │ MBOR-encoded, caller-supplied
//! │ post-metadata pad    │ 0..3 B │ aligns ciphertext to 4-byte boundary
//! │ encrypted_key        │ M B    │ AES-CBC ciphertext (zero-pad to
//! │                      │        │ next 16-B block; no pad when
//! │                      │        │ plaintext is already block-aligned)
//! │ post-cipher pad      │ 0..3 B │ aligns tag to 4-byte boundary
//! │ HMAC-SHA-384 tag     │ 48 B   │ over every byte above
//! └──────────────────────┴────────┘
//! ```
//!
//! ## Public surface
//!
//! * [`mask_cbc`] — encode (encrypt-then-MAC) a masked-key blob.
//! * [`unmask_cbc_in_place`] — verify-and-decrypt a masked-key blob
//!   in place.
//! * [`UnmaskCbcLayout`] — offsets / lengths of the decrypted regions
//!   returned by [`unmask_cbc_in_place`].
//!
//! `mask_cbc` writes its result into a caller-provided `&mut DmaBuf`;
//! `unmask_cbc_in_place` decrypts the ciphertext directly into the
//! input `&mut DmaBuf`.  Neither requires any intermediate buffer.

mod decode;
mod encode;
mod format;

pub use decode::unmask_cbc_in_place;
pub use decode::UnmaskCbcLayout;
pub use encode::mask_cbc;
pub use format::MASKING_KEY_AES_CBC_256_HMAC_384_LEN;
