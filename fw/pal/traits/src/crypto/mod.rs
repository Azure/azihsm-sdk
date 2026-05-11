// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic primitives for the HSM PAL.
//!
//! Bundles every crypto sub-trait under a single [`HsmCrypto`]
//! supertrait.  PAL implementations satisfy the
//! [`HsmPal`](super::HsmPal) bound by implementing each sub-trait
//! and then writing an empty `impl HsmCrypto for MyPal {}`.
//!
//! ## Sub-traits
//!
//! | Trait | Purpose |
//! |---|---|
//! | [`HsmRng`] | Cryptographically secure random bytes |
//! | [`HsmHash`] | SHA-1 / SHA-256 / SHA-384 / SHA-512 digest |
//! | [`HsmHmac`] | HMAC sign / verify with the same SHA family |
//! | [`HsmAes`] | AES key gen + ECB / CBC / GCM / KW / KWP / XTS |
//! | [`HsmEcc`] | ECC key gen, raw EC sign / verify, ECDH (NIST P-256/384/521) |
//! | [`HsmRsa`] | RSA key gen + raw mod-exp + PKCS#1 v1.5 / OAEP / PSS |
//! | [`HsmKdf`] | HKDF, KBKDF (SP 800-108), MGF1, X9.63, SP 800-56A |
//!
//! ## Conventions
//!
//! Every method takes an `&impl HsmIo` handle to scope per-IO state
//! (allocator scope, partition).  Hardware-backed methods are
//! `async`; the only synchronous trait is [`HsmRng`] (RNG fills are
//! sub-tick and never benefit from yielding).
//!
//! Output buffers are caller-supplied `&mut [u8]` with size contracts
//! documented per method (typically derived from the algorithm or
//! key-size selector enum).  Methods whose scratch escapes the call
//! (for example, multi-step contexts) take an `&'a impl HsmScopedAlloc`;
//! one-shot helpers may allocate scoped scratch internally and free it
//! before they return.

mod aes;
mod ecc;
mod hash;
mod hmac;
mod kdf;
mod rng;
mod rsa;

pub use aes::*;
pub use ecc::*;
pub use hash::*;
pub use hmac::*;
pub use kdf::*;
pub use rng::*;
pub use rsa::*;

use super::*;

/// Aggregate crypto trait — supertrait of every other crypto trait
/// in this module.
///
/// Implementations are typically empty (`impl HsmCrypto for MyPal
/// {}`) since this trait only bundles the sub-trait bounds.  Adding
/// a new crypto family means adding a sub-trait here and a method
/// table to the standard PAL.
pub trait HsmCrypto: HsmRng + HsmHash + HsmHmac + HsmAes + HsmEcc + HsmRsa + HsmKdf {}
