// Copyright (C) Microsoft Corporation. All rights reserved.

//! AES-CBC block buffering and management utilities.
//!
//! This module provides internal utilities for managing AES block-level operations
//! in CBC mode. The primary component is `AesCbcBlock`, which handles buffering
//! of partial blocks during streaming operations.
//!
//! # Block Management
//!
//! AES operates on fixed-size 16-byte blocks. When processing streaming data,
//! input may not always align to block boundaries. This module provides
//! buffering mechanisms to handle such cases efficiently.
//!
//! # Internal Use Only
//!
//! This module is intended for internal use by AES-CBC implementations and
//! should not be used directly by external code.

use super::*;

/// Internal block buffer for managing AES-CBC streaming operations.
///
/// This structure provides buffering for partial AES blocks during streaming
/// encryption or decryption operations. AES requires input data to be aligned
/// to 16-byte boundaries, and this buffer manages incomplete blocks until
/// they can be processed.
///
/// # Buffer Management
///
/// - Maintains a 16-byte buffer for incomplete blocks
/// - Automatically processes complete blocks as they become available
/// - Handles boundary conditions between input chunks
///
/// # Memory Efficiency
///
/// The buffer is pre-allocated with the exact capacity needed (16 bytes)
/// to minimize memory allocations during streaming operations.
pub(crate) struct AesCbcBlock {
    /// Internal buffer for storing partial block data.
    ///
    /// This vector has a fixed capacity of 16 bytes (one AES block)
    /// and stores incomplete block data between update operations.
    block: Vec<u8>,
}

/// Default implementation for `AesCbcBlock`.
///
/// Creates a new block buffer with pre-allocated capacity for one AES block (16 bytes).
/// The buffer starts empty but with sufficient capacity to avoid reallocations.
impl Default for AesCbcBlock {
    fn default() -> Self {
        Self {
            block: Vec::with_capacity(Self::BLOCK_SIZE),
        }
    }
}

impl AesCbcBlock {
    /// AES block size in bytes.
    ///
    /// AES always operates on 128-bit (16-byte) blocks regardless of key size.
    const BLOCK_SIZE: usize = 16;

    /// Processes input data with block-level buffering.
    ///
    /// This method handles streaming input data by:
    /// 1. Filling the internal buffer with input data
    /// 2. Processing complete blocks through the provided operation
    /// 3. Keeping partial blocks buffered for the next update
    ///
    /// # Algorithm
    ///
    /// - Fills the internal buffer first if it has space
    /// - Processes the buffered block if it becomes full and more input is available
    /// - Processes as many complete blocks as possible from remaining input
    /// - Keeps the last incomplete block (or one complete block if input ends on boundary)
    /// - Buffers any remaining partial data
    ///
    /// # Arguments
    ///
    /// * `input` - Input data to process
    /// * `op` - Closure that processes complete blocks and returns bytes written
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes processed by the operation
    /// * `Err(CryptoError)` - If the block processing operation fails
    ///
    /// # Block Boundary Handling
    ///
    /// This method implements careful boundary handling:
    /// - If input ends exactly on a block boundary, one block is kept buffered
    /// - This ensures proper padding handling during finalization
    /// - Only processes blocks when more input is definitely available
    pub fn update<F>(&mut self, input: &[u8], mut op: F) -> Result<usize, CryptoError>
    where
        F: FnMut(&[u8]) -> Result<usize, CryptoError>,
    {
        let mut count = 0;
        let avail = self.block.capacity() - self.block.len();
        let fill = &input[..input.len().min(avail)];

        self.block.extend_from_slice(fill);

        let input = &input[fill.len()..];

        // process full block if buffer is full and there is input data
        if self.block.len() == self.block.capacity() && !input.is_empty() {
            count += op(&self.block)?;
            self.block.clear();
        }

        let mut blocks = input.len() / Self::BLOCK_SIZE;
        let tailing = input.len() % Self::BLOCK_SIZE;

        // keep last block in buffer if there is no tailing data
        if tailing == 0 && blocks > 0 {
            blocks -= 1;
        }

        let bytes = blocks * Self::BLOCK_SIZE;
        if bytes > 0 {
            count += op(&input[..bytes])?;
        }

        self.block.extend_from_slice(&input[bytes..]);

        Ok(count)
    }

    /// Calculates the output size for the given input without performing the operation.
    ///
    /// This method mirrors the logic of `update` but only calculates how many
    /// bytes would be processed, without actually performing any cryptographic
    /// operations. This is useful for determining buffer sizes.
    ///
    /// # Arguments
    ///
    /// * `input` - Input data to calculate processing size for
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes that would be processed
    /// * `Err(CryptoError)` - Currently unused, maintained for consistency
    pub fn update_len(&self, input: &[u8]) -> Result<usize, CryptoError> {
        let mut count = 0;
        let avail = self.block.capacity() - self.block.len();
        let fill = &input[..input.len().min(avail)];
        let input = &input[fill.len()..];

        if self.block.len() + fill.len() == self.block.capacity() && !input.is_empty() {
            count += Self::BLOCK_SIZE;
        }

        let mut blocks = input.len() / Self::BLOCK_SIZE;
        let tailing = input.len() % Self::BLOCK_SIZE;

        // keep last block in buffer if there is no tailing data
        if tailing == 0 && blocks > 0 {
            blocks -= 1;
        }
        count += blocks * Self::BLOCK_SIZE;
        Ok(count)
    }

    /// Returns the output size for finalization.
    ///
    /// This method always returns one block size (16 bytes) as finalization
    /// will process whatever data remains in the buffer, potentially with
    /// padding applied.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Always returns `BLOCK_SIZE` (16 bytes)
    /// * `Err(CryptoError)` - Currently unused, maintained for consistency
    pub fn final_len(&mut self) -> Result<usize, CryptoError> {
        Ok(Self::BLOCK_SIZE)
    }

    /// Processes the final buffered data.
    ///
    /// This method processes whatever data remains in the internal buffer
    /// through the provided operation. It's called during finalization to
    /// handle the last block, which may include padding.
    ///
    /// # Arguments
    ///
    /// * `op` - Closure that processes the final block data
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes processed by the operation
    /// * `Err(CryptoError)` - If the final processing operation fails
    ///
    /// # Buffer State
    ///
    /// After calling this method, the buffer remains unchanged. The caller
    /// is responsible for any cleanup if needed.
    ///
    /// # Note
    ///
    /// The method name uses `r#final` syntax because `final` is a reserved
    /// keyword in Rust, but we want to maintain API consistency.
    pub fn r#final<F>(&mut self, mut op: F) -> Result<usize, CryptoError>
    where
        F: FnMut(&[u8]) -> Result<usize, CryptoError>,
    {
        op(&self.block)
    }
}
