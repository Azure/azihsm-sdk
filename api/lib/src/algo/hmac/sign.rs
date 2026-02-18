// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HMAC signing and verification algorithms.
//!
//! This module provides HSM-backed HMAC signing and verification.
//!
//! Unlike algorithms that require the caller to pre-hash, HMAC operates directly
//! over message bytes. Key material never leaves the HSM boundary; operations are
//! delegated to the device via DDI.
//!
//! # Supported Operations
//!
//! - [`HsmSignOp`]: Single-shot tag generation
//! - [`HsmVerifyOp`]: Single-shot tag verification
//! - [`HsmSignStreamingOp`]: Streaming tag generation by buffering message bytes
//! - [`HsmVerifyStreamingOp`]: Streaming tag verification by buffering message bytes
//!
//! # Implementation Notes
//!
//! The streaming implementations in this module are *buffered* (not incremental):
//! `update()` appends bytes to an in-memory buffer, and `finish()` delegates to the
//! single-shot operation over the concatenated message.
//!
//! # Message size
//!
//! The underlying DDI HMAC request uses a fixed-size MBOR byte array for the
//! message (currently 1024 bytes). The streaming contexts do not enforce this
//! limit during `update()`; if the final message exceeds the device limit,
//! `finish()` will fail.
//!
//! # Message size
//!
//! The underlying DDI HMAC request has a fixed maximum message length (currently
//! 1024 bytes). The streaming contexts buffer the full message in memory and do
//! not enforce the limit during [`update`](HsmHmacSignContext::update); callers
//! must ensure the final message fits within the device limit.

use super::*;

/// HMAC algorithm implementation.
///
/// This type provides single-shot and buffered streaming tag generation and
/// verification.
pub struct HsmHmacAlgo {}

impl HsmHmacAlgo {
    const MAX_MESSAGE_SIZE: usize = 1024;
    pub fn new() -> Self {
        HsmHmacAlgo {}
    }
}

impl HsmSignOp for HsmHmacAlgo {
    type Key = HsmHmacKey;
    type Error = HsmError;

    /// Computes an HMAC tag for the provided message.
    ///
    /// This method delegates to the HSM to compute the HMAC tag for `data`.
    ///
    /// # Arguments
    ///
    /// * `key` - HMAC key handle stored in the HSM.
    /// * `data` - Message bytes.
    /// * `signature` - Optional output buffer. If `None`, returns the required tag size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to `signature`, or the required size if
    /// `signature` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small.
    /// - The message exceeds the device/serialization limit.
    /// - The underlying DDI operation fails.
    ///
    /// # Arguments
    ///
    /// * `key` - HMAC key handle stored in the HSM.
    /// * `data` - Message bytes.
    /// * `signature` - Optional output buffer. If `None`, returns the required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to `signature`, or the required size if
    /// `signature` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small.
    /// - The message exceeds the device/serialization limit.
    /// - The underlying DDI operation fails.
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        // check if key can sign
        if !key.can_sign() {
            Err(HsmError::InvalidKey)?;
        }

        // return size of signature if signature buffer is None
        let Some(signature) = signature else {
            return Ok(key.size());
        };

        // check if signature buffer is large enough
        if signature.len() < key.size() {
            return Err(HsmError::BufferTooSmall);
        }
        //check if data length exceeds limit
        if data.len() > Self::MAX_MESSAGE_SIZE {
            return Err(HsmError::IndexOutOfRange);
        }

        // call ddi hmac sign
        ddi::hmac_sign(key, data, signature)
    }
}

impl HsmVerifyOp for HsmHmacAlgo {
    type Key = HsmHmacKey;
    type Error = HsmError;

    /// Verifies an HMAC tag for the provided message.
    ///
    /// This method recomputes the tag for `data` using the HSM and compares it to
    /// the provided `signature`.
    ///
    /// # Arguments
    ///
    /// * `key` - HMAC key handle stored in the HSM.
    /// * `data` - Message bytes.
    /// * `signature` - Expected tag bytes.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the signature matches.
    /// - `Ok(false)` if it does not match.
    /// - `Err(_)` if the verification operation could not be performed.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The message exceeds the device/serialization limit.
    /// - The underlying DDI operation fails.
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        //check key can verify
        if !key.can_verify() {
            Err(HsmError::InvalidKey)?;
        }

        //check if data length exceeds limit
        if data.len() > Self::MAX_MESSAGE_SIZE {
            return Err(HsmError::IndexOutOfRange);
        }

        // allocate buffer for computed signature
        let mut computed_sig = vec![0u8; key.size()];

        // call ddi hmac sign to compute signature
        let sig_size = ddi::hmac_sign(key, data, &mut computed_sig)?;

        // compare computed signature with provided signature
        if sig_size != signature.len() {
            return Ok(false);
        }
        Ok(&computed_sig[..sig_size] == signature)
    }
}

/// Context for buffered streaming HMAC operations.
///
/// This context buffers message bytes provided via `update()` and performs the
/// final HMAC operation when `finish()` is called.
///
/// # Internal State
///
/// The context encapsulates:
/// - A cloned HMAC algorithm instance
/// - A key handle used for the final operation
/// - An in-memory message buffer that grows with each `update()` call
///
/// # Lifecycle
///
/// 1. Created via [`HsmSignStreamingOp::sign_init`] or [`HsmVerifyStreamingOp::verify_init`]
/// 2. Message bytes appended via `update()`
/// 3. Tag generated/verified via `finish()`
///
/// Note: `finish()` does not clear the accumulated buffer; subsequent `update()` calls
/// continue appending to the existing message.
pub struct HsmHmacSignContext {
    algo: HsmHmacAlgo,
    key: HsmHmacKey,

    /// Buffered message data.
    ///
    /// The initial capacity is set to 1024 bytes to match the current DDI limit.
    /// This is only a capacity hint; callers must still ensure the total message
    /// size is within the device limit.
    data: Vec<u8>,
}

impl HsmSignStreamingOp for HsmHmacAlgo {
    type Key = HsmHmacKey;
    type Context = HsmHmacSignContext;
    type Error = HsmError;

    /// Initializes a streaming signing context.
    ///
    /// Creates a context that accumulates message bytes before generating the final
    /// HMAC tag.
    ///
    /// # Arguments
    ///
    /// * `key` - The HMAC key to use for signing. Ownership is taken to ensure the
    ///   key remains valid for the context's lifetime.
    ///
    /// # Returns
    ///
    /// Returns a context implementing [`HsmSignStreamingOpContext`].
    ///
    /// # Errors
    ///
    /// This initializer currently cannot fail.
    fn sign_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        // check if key can sign
        if !key.can_sign() {
            Err(HsmError::InvalidKey)?;
        }

        Ok(HsmHmacSignContext {
            algo: self,
            key,
            data: Vec::with_capacity(Self::MAX_MESSAGE_SIZE),
        })
    }
}

impl HsmSignStreamingOpContext for HsmHmacSignContext {
    type Algo = HsmHmacAlgo;

    /// Appends bytes to the buffered message.
    ///
    /// No HMAC computation occurs during update; this only buffers message bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Message bytes to append.
    ///
    /// # Errors
    ///
    /// This method currently cannot fail.
    ///
    /// Note: this does not enforce the device's maximum message size; exceeding the
    /// limit will cause `finish()` to fail.
    fn update(&mut self, data: &[u8]) -> Result<(), <Self::Algo as HsmSignStreamingOp>::Error> {
        //check if data length exceeds limit
        if self.data.len() + data.len() > Self::Algo::MAX_MESSAGE_SIZE {
            return Err(HsmError::IndexOutOfRange);
        }
        self.data.extend_from_slice(data);
        Ok(())
    }

    /// Finalizes the signature operation over the accumulated message.
    ///
    /// # Arguments
    ///
    /// * `signature` - Optional output buffer. If `None`, returns the required tag length.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to `signature`, or the required size if
    /// `signature` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small.
    /// - The accumulated message exceeds the device/serialization limit.
    /// - The underlying DDI operation fails.
    fn finish(
        &mut self,
        signature: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmSignStreamingOp>::Error> {
        // delegate to the underlying sign implementation
        self.algo.sign(&self.key, &self.data, signature)
    }
}

/// Context for buffered streaming HMAC operations.
///
/// This context buffers message bytes provided via `update()` and performs the
/// final HMAC operation when `finish()` is called.
///
/// # Internal State
///
/// The context encapsulates:
/// - A cloned HMAC algorithm instance
/// - A key handle used for the final operation
/// - An in-memory message buffer that grows with each `update()` call
///
/// # Lifecycle
///
/// 1. Created via  [`HsmVerifyStreamingOp::verify_init`]
/// 2. Message bytes appended via `update()`
/// 3. Tag generated/verified via `finish()`
///
/// Note: `finish()` does not clear the accumulated buffer; subsequent `update()` calls
/// continue appending to the existing message.
impl HsmVerifyStreamingOp for HsmHmacAlgo {
    type Key = HsmHmacKey;
    type Context = HsmHmacVerifyContext;
    type Error = HsmError;

    /// Initializes a streaming verification context.
    ///
    /// Creates a context that accumulates message bytes before verifying the final
    /// HMAC tag.
    ///
    /// # Arguments
    ///
    /// * `key` - The HMAC key to use for verification. Ownership is taken to ensure
    ///   the key remains valid for the context's lifetime.
    ///
    /// # Returns
    ///
    /// Returns a context implementing [`HsmVerifyStreamingOpContext`].
    ///
    /// # Errors
    ///
    /// This initializer currently cannot fail.
    fn verify_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        // check if key can verify
        if !key.can_verify() {
            Err(HsmError::InvalidKey)?;
        }

        Ok(HsmHmacVerifyContext {
            algo: self,
            key,
            data: Vec::with_capacity(Self::MAX_MESSAGE_SIZE),
        })
    }
}

/// Context for buffered streaming HMAC verify operations.
///
/// This context buffers message bytes provided via `update()` and performs the
/// final HMAC operation when `finish()` is called.
///
/// # Internal State
///
/// The context encapsulates:
/// - A cloned HMAC algorithm instance
/// - A key handle used for the final operation
/// - An in-memory message buffer that grows with each `update()` call
///
/// # Lifecycle
///
/// 1. Created via [`HsmVerifyStreamingOp::verify_init`]
/// 2. Message bytes appended via `update()`
/// 3. Tag generated/verified via `finish()`
///
/// Note: `finish()` does not clear the accumulated buffer; subsequent `update()` calls
/// continue appending to the existing message.
pub struct HsmHmacVerifyContext {
    algo: HsmHmacAlgo,
    key: HsmHmacKey,

    /// Buffered message data.
    ///
    /// The initial capacity is set to 1024 bytes to match the current DDI limit.
    /// This is only a capacity hint; callers must still ensure the total message
    /// size is within the device limit.
    data: Vec<u8>,
}
impl HsmVerifyStreamingOpContext for HsmHmacVerifyContext {
    type Algo = HsmHmacAlgo;

    /// Appends bytes to the buffered message.
    ///
    /// No HMAC computation occurs during update; this only buffers message bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Message bytes to append.
    ///
    /// # Errors
    ///
    /// This method currently cannot fail.
    ///
    /// Note: this does not enforce the device's maximum message size; exceeding the
    /// limit will cause `finish()` to fail.
    fn update(&mut self, data: &[u8]) -> Result<(), <Self::Algo as HsmVerifyStreamingOp>::Error> {
        //check if data length exceeds limit
        if self.data.len() + data.len() > Self::Algo::MAX_MESSAGE_SIZE {
            return Err(HsmError::IndexOutOfRange);
        }
        self.data.extend_from_slice(data);
        Ok(())
    }

    /// Finalizes verification over the accumulated message.
    ///
    /// This recomputes the tag for the accumulated message using the HSM and compares
    /// it to the provided `signature`.
    ///
    /// # Arguments
    ///
    /// * `signature` - Expected tag bytes.
    ///
    /// # Returns
    ///
    /// Returns a three-state result:
    /// - `Ok(true)` - The signature matches.
    /// - `Ok(false)` - The signature does not match.
    /// - `Err(_)` - The verification operation could not be performed.
    ///
    /// Note that `Ok(false)` is not an error; it indicates a mismatch.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The accumulated message exceeds the device/serialization limit.
    /// - The underlying DDI operation fails.
    fn finish(
        &mut self,
        signature: &[u8],
    ) -> Result<bool, <Self::Algo as HsmVerifyStreamingOp>::Error> {
        // delegate to the underlying verify implementation
        self.algo.verify(&self.key, &self.data, signature)
    }
}
