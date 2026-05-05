// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic primitives for the HSM PAL.
//!
//! This module bundles all crypto-related traits under the [`HsmCrypto`]
//! supertrait. A PAL implementation must implement all constituent traits
//! to satisfy the [`HsmPal`](super::HsmPal) bound.
//!
//! | Trait | Purpose |
//! |---|---|
//! | [`HsmRng`] | Cryptographically secure random bytes |
//! | [`HsmHash`] | SHA-1/256/384/512 digest computation |
//! | [`HsmEcc`] | Elliptic curve key generation, signing, verification, and ECDH |
//! | [`HsmHmac`] | HMAC computation using SHA-1/256/384/512 |
//! | [`HsmKdf`] | KDF / MGF: HKDF, KBKDF, MGF1, X9.63, SP 800-56A |

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

/// Composite crypto trait — requires all crypto sub-traits.
///
/// Implementations are typically empty (`impl HsmCrypto for MyPal {}`)
/// since this trait only bundles the sub-trait bounds.
pub trait HsmCrypto: HsmRng + HsmHash + HsmHmac + HsmAes + HsmEcc + HsmRsa + HsmKdf {}
