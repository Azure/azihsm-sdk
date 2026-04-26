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

mod hash;
mod rng;

pub use hash::*;
pub use rng::*;

use super::*;

/// Composite crypto trait — requires all crypto sub-traits.
///
/// Implementations are typically empty (`impl HsmCrypto for MyPal {}`)
/// since this trait only bundles the sub-trait bounds.
pub trait HsmCrypto: HsmRng + HsmHash {}
