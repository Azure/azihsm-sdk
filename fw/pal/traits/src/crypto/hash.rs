// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic hash (digest) trait for the HSM PAL.
//!
//! Defines [`HsmHashAlgo`], [`HsmHashState`], and the [`HsmHash`] trait that PAL
//! implementations use to expose hardware-accelerated or software-backed hash
//! computation.
//!
//! On Cortex-M7 hardware this would typically delegate to a SHA engine
//! peripheral. On the standard (host-native) PAL it would use OpenSSL.
//!
//! **Status**: This trait is part of [`HsmCrypto`] and is implemented by PALs
//! that provide SHA digest support. Higher-level DDI commands can build on it
//! for operations such as signing and key derivation.

use super::*;

/// Supported hash algorithms.
///
/// Discriminant values are `u32` for direct mapping to hardware register
/// selectors on Cortex-M7.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmHashAlgo {
    /// SHA-1 (160-bit digest). **Not FIPS-approved for signing.**
    Sha1,

    /// SHA-256 (256-bit / 32-byte digest).
    Sha256,

    /// SHA-384 (384-bit / 48-byte digest).
    Sha384,

    /// SHA-512 (512-bit / 64-byte digest).
    Sha512,
}

impl HsmHashAlgo {
    /// Returns the output digest length in bytes for the given algorithm.
    pub const fn digest_len(&self) -> usize {
        match self {
            HsmHashAlgo::Sha1 => 20,
            HsmHashAlgo::Sha256 => 32,
            HsmHashAlgo::Sha384 => 48,
            HsmHashAlgo::Sha512 => 64,
        }
    }

    /// Block size in bytes for the algorithm.
    pub const fn block_len(&self) -> usize {
        match self {
            HsmHashAlgo::Sha1 | HsmHashAlgo::Sha256 => 64,
            HsmHashAlgo::Sha384 | HsmHashAlgo::Sha512 => 128,
        }
    }

    /// Working-variable state size in bytes (intermediate hash state).
    pub const fn state_len(&self) -> usize {
        match self {
            HsmHashAlgo::Sha1 => 20,
            HsmHashAlgo::Sha256 => 32,
            HsmHashAlgo::Sha384 | HsmHashAlgo::Sha512 => 64,
        }
    }

    /// Minimum buffer size for [`HsmHashState`]: state + block.
    pub const fn hash_state_len(&self) -> usize {
        self.state_len() + self.block_len()
    }

    /// Buffer size for `HsmHashState` in HMAC multi-step:
    /// state + block (pending) + block (opad key).
    pub const fn hmac_state_len(&self) -> usize {
        self.state_len() + self.block_len() * 2
    }

    /// Minimum state buffer size for [`HsmKdf::mgf1`]:
    /// `digest_len + seed_len + 4` (hash output + `seed || counter`).
    pub const fn mgf1_state_len(&self, seed_len: usize) -> usize {
        self.digest_len() + seed_len + 4
    }

    /// Minimum state buffer size for [`HsmKdf::x963_kdf`] and
    /// [`HsmKdf::sp800_56a_kdf`]:
    /// `digest_len + z_len + 4 + info_len`
    /// (hash output + `Z || counter || info` in the largest ordering).
    pub const fn concat_kdf_state_len(&self, z_len: usize, info_len: usize) -> usize {
        self.digest_len() + z_len + 4 + info_len
    }
}

/// Caller-owned hash state buffer tagged with its algorithm.
///
/// The buffer layout is `[state | block]`, where the first
/// [`HsmHashAlgo::state_len`] bytes hold the SHA working variables and the next
/// [`HsmHashAlgo::block_len`] bytes hold a partial block buffer.
#[derive(Debug)]
pub struct HsmHashState<'a> {
    buf: &'a mut [u8],
    algo: HsmHashAlgo,
}

impl<'a> HsmHashState<'a> {
    /// Creates a new hash state wrapper.
    pub fn new(algo: HsmHashAlgo, buf: &'a mut [u8]) -> Self {
        debug_assert!(buf.len() >= algo.hash_state_len());
        Self { buf, algo }
    }

    /// Returns the final digest bytes.
    pub fn digest(&self) -> &[u8] {
        &self.buf[..self.algo.digest_len()]
    }

    /// Returns the working-variable state portion of the buffer.
    pub fn state(&self) -> &[u8] {
        &self.buf[..self.algo.state_len()]
    }

    /// Returns the wrapped algorithm.
    pub fn algo(&self) -> HsmHashAlgo {
        self.algo
    }

    /// Returns the underlying buffer length.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns whether the underlying buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Consumes the wrapper and returns the underlying mutable buffer.
    pub fn into_buf(self) -> &'a mut [u8] {
        self.buf
    }
}

/// Asynchronous hash computation trait.
pub trait HsmHash {
    /// Platform-specific multi-step hash context.
    type HashCtx<'a>
    where
        Self: 'a;

    /// Compute a one-shot hash.
    ///
    /// # Parameters
    /// - `algo` — Hash algorithm.
    /// - `data` — Input message.
    /// - `digest` — Output buffer (≥ `algo.digest_len()` bytes).
    /// - `big_endian` — If true, big-endian (NIST standard). If false, little-endian.
    async fn hash(
        &self,
        algo: HsmHashAlgo,
        data: &[u8],
        digest: &mut [u8],
        big_endian: bool,
    ) -> HsmResult<()>;

    /// Begin a multi-step hash.
    ///
    /// # Parameters
    /// - `algo` — Hash algorithm.
    /// - `state` — Working state buffer (≥ `algo.hash_state_len()` bytes).
    async fn hash_begin<'a>(
        &self,
        algo: HsmHashAlgo,
        state: HsmHashState<'a>,
    ) -> HsmResult<Self::HashCtx<'a>>
    where
        Self: 'a;

    /// Feed arbitrary-length data into a multi-step hash.
    ///
    /// Data is buffered internally. Full blocks are submitted to
    /// hardware as they accumulate.
    async fn hash_continue(&self, ctx: &mut Self::HashCtx<'_>, data: &[u8]) -> HsmResult<()>;

    /// Finalize the hash and return the state buffer containing the digest.
    async fn hash_finish<'a>(
        &self,
        ctx: Self::HashCtx<'a>,
        big_endian: bool,
    ) -> HsmResult<HsmHashState<'a>>;
}
