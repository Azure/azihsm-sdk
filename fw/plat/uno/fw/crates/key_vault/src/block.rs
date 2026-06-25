// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Blob block allocator.
//!
//! Each table's blob region is carved into [`BLOCK_ALIGNMENT`]-byte blocks
//! tracked by a per-table bitmap (a `bit == 1` means the block is in use).
//! A key occupies a *contiguous* run of blocks (`[attributes][key]`), so
//! allocation is a first-fit search for a free run.
//!
//! The two failure modes are distinguished exactly as the reference
//! firmware does:
//! * [`HsmError::NotEnoughSpace`] — fewer than `count` free blocks remain.
//! * [`HsmError::DefragmentationNeeded`] — enough free blocks exist, but
//!   none of the free runs is long enough.

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;

use crate::storage::BLOB_BLOCKS;

/// Allocates a contiguous run of `count` blocks in `words` (the table's
/// bitmap, mutated in place), returning the start block index.
///
/// Uses a first-fit algorithm: scans linearly through the bitmap, tracking
/// the current free run length. Returns the index of the first run found that
/// is at least `count` blocks long. Distinguishes between fragmentation
/// (enough free blocks exist but no contiguous run) and true exhaustion
/// (insufficient free blocks total).
///
/// # Parameters
///
/// - `words`: The mutable bitmap array to allocate from. Blocks marked in-use
///   are updated in place. The array must have length [`BITMAP_WORDS`].
/// - `count`: The number of contiguous blocks to allocate.
///
/// # Returns
///
/// On success, returns the 0-indexed block number of the start of the allocated run.
/// The caller should multiply by [`BLOCK_ALIGNMENT`] to get the byte offset within
/// the blob region.
///
/// # Errors
///
/// - [`HsmError::DefragmentationNeeded`] if `count` total free blocks
///   exist but no single run is long enough.
/// - [`HsmError::NotEnoughSpace`] if fewer than `count` free blocks
///   remain (also for `count == 0` or `count > BLOB_BLOCKS`).
pub fn alloc(words: &mut [u32], count: usize) -> HsmResult<u16> {
    if count == 0 || count > BLOB_BLOCKS {
        return Err(HsmError::NotEnoughSpace);
    }

    // First-fit scan: find the first run of `count` contiguous free blocks.
    // Track three quantities across the scan:
    // - `run_start`: index of the first block in the current free run
    // - `run`: length of the current free run
    // - `total_free`: total count of all free blocks (for fragmentation detection)
    let mut run_start = 0usize;
    let mut run = 0usize;
    let mut total_free = 0usize;
    for block in 0..BLOB_BLOCKS {
        if used(words, block) {
            // Hit a used block; reset the current run and update start position
            // for the next potential run immediately after this block.
            run = 0;
            run_start = block + 1;
            continue;
        }
        total_free += 1;
        run += 1;
        if run == count {
            // Found a contiguous run of `count` free blocks; mark them all in use.
            for b in run_start..run_start + count {
                mark(words, b, true);
            }
            return Ok(run_start as u16);
        }
    }

    // No run of `count` blocks was found. Classify the failure by whether
    // we simply lack enough free blocks (exhaustion) or have enough blocks
    // but they're fragmented into runs shorter than `count`.
    if total_free >= count {
        Err(HsmError::DefragmentationNeeded)
    } else {
        Err(HsmError::NotEnoughSpace)
    }
}

/// Frees `count` blocks starting at `start` in `words` (mutated in place).
///
/// Marks the specified block range as free (unallocated) in the bitmap.
/// This operation complements [`alloc`] to allow reuse of previously allocated blocks.
/// Blocks beyond [`BLOB_BLOCKS`] are silently ignored (they are always treated as used).
///
/// # Parameters
///
/// - `words`: The mutable bitmap array to update. The array must have length [`BITMAP_WORDS`].
/// - `start`: The 0-indexed block number where the free range begins.
/// - `count`: The number of contiguous blocks to free.
///
/// # Returns
///
/// Returns `()` on success. No errors are returned; the operation always succeeds.
///
/// # Panics
///
/// Does not panic; silently truncates the range at [`BLOB_BLOCKS`] if `start + count`
/// extends beyond the valid block count.
pub fn free(words: &mut [u32], start: u16, count: usize) {
    let start = usize::from(start);
    for block in start..start + count {
        if block < BLOB_BLOCKS {
            mark(words, block, false);
        }
    }
}

/// Computes the number of [`BLOCK_ALIGNMENT`](crate::storage::BLOCK_ALIGNMENT)-byte
/// blocks required for a given storage size.
///
/// This is used to determine the allocation requirement from the total byte size
/// of a key (including attributes and alignment padding).
///
/// # Parameters
///
/// - `storage_bytes`: The total storage size in bytes. Must already be block-aligned
///   (i.e., a multiple of [`BLOCK_ALIGNMENT`]); unaligned sizes will be silently
///   truncated down to the nearest block boundary.
///
/// # Returns
///
/// The number of complete [`BLOCK_ALIGNMENT`]-byte blocks that fit into `storage_bytes`.
/// For an aligned input, this equals `storage_bytes / BLOCK_ALIGNMENT`.
///
/// # Example
///
/// With [`BLOCK_ALIGNMENT`] = 8 bytes:
/// - Input 32 bytes → returns 4 blocks
/// - Input 40 bytes → returns 5 blocks
#[inline]
pub const fn blocks_for(storage_bytes: usize) -> usize {
    storage_bytes / crate::storage::BLOCK_ALIGNMENT
}

// ── Private helper functions ────────────────────────────────────────

/// Returns whether `block` is in use.
///
/// Blocks at or beyond [`BLOB_BLOCKS`] do not exist and are treated as
/// permanently used, ensuring the allocator never hands them out. Each bit
/// in the bitmap `words` represents one block; 1 means in-use, 0 means free.
///
/// # Parameters
///
/// - `words`: The bitmap array where each bit represents a block's in-use status.
/// - `block`: The block index to check (0-indexed).
///
/// # Returns
///
/// `true` if the block is in use or does not exist; `false` if the block is free.
#[inline]
fn used(words: &[u32], block: usize) -> bool {
    if block >= BLOB_BLOCKS {
        return true;
    }
    words[block / 32] & (1 << (block % 32)) != 0
}

/// Sets or clears `block`'s in-use bit.
///
/// When `used` is true, sets the bit (marks as in-use); when false, clears it
/// (marks as free). The block index is divided by 32 to find the word, and
/// the remainder determines the bit position within that word.
///
/// # Parameters
///
/// - `words`: The mutable bitmap array to update.
/// - `block`: The block index to modify (0-indexed).
/// - `used`: `true` to mark the block as in-use; `false` to mark as free.
///
/// # Returns
///
/// Returns `()` on success. No errors are returned.
///
/// # Panics
///
/// Panics if `block / 32 >= words.len()`; the caller must ensure `block`
/// is within the valid range for the bitmap.
#[inline]
fn mark(words: &mut [u32], block: usize, used: bool) {
    let mask = 1 << (block % 32);
    if used {
        words[block / 32] |= mask;
    } else {
        words[block / 32] &= !mask;
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::storage::BITMAP_WORDS;

    fn empty() -> [u32; BITMAP_WORDS] {
        [0u32; BITMAP_WORDS]
    }

    #[test]
    fn alloc_is_contiguous_and_marks_used() {
        let mut b = empty();
        assert_eq!(alloc(&mut b, 4), Ok(0));
        assert_eq!(alloc(&mut b, 4), Ok(4));
        // Blocks 0..8 now used.
        for i in 0..8 {
            assert!(used(&b, i));
        }
        assert!(!used(&b, 8));
    }

    #[test]
    fn free_reopens_space() {
        let mut b = empty();
        let a = alloc(&mut b, 10).unwrap();
        free(&mut b, a, 10);
        for i in 0..10 {
            assert!(!used(&b, i));
        }
        assert_eq!(alloc(&mut b, 10), Ok(0));
    }

    #[test]
    fn not_enough_space_when_total_insufficient() {
        let mut b = empty();
        // Consume all but 3 blocks.
        alloc(&mut b, BLOB_BLOCKS - 3).unwrap();
        assert_eq!(alloc(&mut b, 4), Err(HsmError::NotEnoughSpace));
        assert_eq!(alloc(&mut b, 3), Ok((BLOB_BLOCKS - 3) as u16));
    }

    #[test]
    fn defrag_needed_when_fragmented() {
        let mut b = empty();
        // Allocate three 4-block runs, free the middle one → a 4-block
        // hole plus the tail, but request 8 contiguous with the tail
        // consumed so only fragmented free space remains.
        let r0 = alloc(&mut b, 4).unwrap();
        let _r1 = alloc(&mut b, 4).unwrap();
        let r2 = alloc(&mut b, 4).unwrap();
        // Fill the remainder of the region so only r0 (freed) + r2 (freed)
        // are free: two separate 4-block holes = 8 free, no run of 8.
        let mid = alloc(&mut b, BLOB_BLOCKS - 12).unwrap();
        let _ = mid;
        free(&mut b, r0, 4);
        free(&mut b, r2, 4);
        assert_eq!(alloc(&mut b, 8), Err(HsmError::DefragmentationNeeded));
        // But two 4-block requests still succeed.
        assert!(alloc(&mut b, 4).is_ok());
        assert!(alloc(&mut b, 4).is_ok());
    }

    #[test]
    fn zero_and_oversized_rejected() {
        let mut b = empty();
        assert_eq!(alloc(&mut b, 0), Err(HsmError::NotEnoughSpace));
        assert_eq!(
            alloc(&mut b, BLOB_BLOCKS + 1),
            Err(HsmError::NotEnoughSpace)
        );
    }
}
