// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GDMA controller trait.
//!
//! Defines the [`HsmGdmaController`] trait used by the HSM core to
//! move bulk data between three memory domains:
//!
//! - **Host** memory — addressed by 64-bit physical addresses
//!   ([`HsmDmaAddr`]) supplied by the host in SQE PRP fields.
//! - **HSM-local DMA-capable memory** — the SRAM region from which
//!   the per-IO DMA bump allocator (see [`HsmAlloc`]) hands out
//!   buffers.
//! - **HSM-local non-DMA memory** — DTCM scratch space used for
//!   crypto state.  The GDMA does *not* operate on DTCM; only the
//!   on-device variant of [`copy_mem`](HsmGdmaController::copy_mem)
//!   may target a non-DMA buffer (and only when both endpoints fit
//!   that requirement; PAL implementations may fall back to a
//!   memcpy in that case).
//!
//! ## When DMA buffers are required
//!
//! Both [`copy_mem_from_host`](HsmGdmaController::copy_mem_from_host)
//! and [`copy_mem_to_host`](HsmGdmaController::copy_mem_to_host)
//! require their HSM-local endpoints to live in DMA-capable memory.
//! In practice this means the slice must come from
//! [`HsmAlloc::alloc_buf`] with [`HsmHeap::Dma`] (or one of the
//! `dma_*` convenience helpers).  Passing a DTCM-backed buffer is
//! undefined behavior at the hardware level; PAL implementations
//! are free to reject it with [`HsmError::InvalidArg`].
//!
//! ## PRP vs. flat addressing
//!
//! Host-side transfers take a `prp: bool` flag:
//!
//! - `prp = true` — `src`/`dst` is a *PRP1* host pointer; the GDMA
//!   walks the PRP list to assemble a scatter/gather descriptor.
//!   Used for the request/response DMAs that bracket every
//!   MBOR / TBOR IO command.
//! - `prp = false` — `src`/`dst` is a flat host physical address; a
//!   single contiguous transfer is performed.  Used for inline
//!   sub-blob copies (e.g. cert chain fragments) where PRP overhead
//!   is unwanted.

use super::*;

/// 64-bit DMA address split into high and low 32-bit halves.
///
/// Mirrors the host's PRP / flat-address representation: SQE fields
/// store the address as two adjacent dwords, and PAL drivers consume
/// the two halves directly without needing to reconstruct a `u64`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HsmDmaAddr {
    /// Lower 32 bits of the address.
    pub lo: u32,

    /// Upper 32 bits of the address.
    pub hi: u32,
}

/// Bytes one host response page can hold.
///
/// The Uno GDMA moves at most one 4 KiB page per transfer via PRP0, must not
/// cross a page boundary, and implements no PRP list, so this is a hardware
/// limit rather than a convention.
pub const HOST_RESP_PAGE_LEN: usize = 4096;

/// Divides a response across the two host response pages.
///
/// The host driver always supplies two, so a response up to 8 KiB can be
/// delivered as two transfers. Returns `(head, tail)` where `tail == 0` means
/// one page sufficed, or `None` when the response is too large for both --
/// which callers must treat as an error, since a truncated response decodes
/// as a malformed frame a long way from the cause.
///
/// Shared by the uno and std PALs so the boundary cannot drift between the
/// hardware path and the one the emulator exercises.
#[inline]
pub const fn host_resp_split(len: usize) -> Option<(usize, usize)> {
    if len <= HOST_RESP_PAGE_LEN {
        Some((len, 0))
    } else if len <= 2 * HOST_RESP_PAGE_LEN {
        Some((HOST_RESP_PAGE_LEN, len - HOST_RESP_PAGE_LEN))
    } else {
        None
    }
}

#[cfg(test)]
mod resp_split_tests {
    use super::HOST_RESP_PAGE_LEN;
    use super::host_resp_split;

    #[test]
    fn single_page_responses_are_not_split() {
        assert_eq!(host_resp_split(0), Some((0, 0)));
        assert_eq!(host_resp_split(1), Some((1, 0)));
        // Exactly one page must still be one transfer, not a page plus an
        // empty second -- an empty GDMA transfer is not a no-op.
        assert_eq!(
            host_resp_split(HOST_RESP_PAGE_LEN),
            Some((HOST_RESP_PAGE_LEN, 0))
        );
    }

    #[test]
    fn two_page_responses_split_at_the_page_boundary() {
        assert_eq!(
            host_resp_split(HOST_RESP_PAGE_LEN + 1),
            Some((HOST_RESP_PAGE_LEN, 1))
        );
        // An ML-DSA-87 signature, the response this exists for.
        assert_eq!(host_resp_split(4627), Some((4096, 531)));
        assert_eq!(
            host_resp_split(2 * HOST_RESP_PAGE_LEN),
            Some((HOST_RESP_PAGE_LEN, HOST_RESP_PAGE_LEN))
        );
    }

    #[test]
    fn oversized_responses_are_refused_rather_than_truncated() {
        assert_eq!(host_resp_split(2 * HOST_RESP_PAGE_LEN + 1), None);
    }

    #[test]
    fn the_two_halves_always_reconstitute_the_whole() {
        for len in [0, 1, 4095, 4096, 4097, 4627, 8191, 8192] {
            let (head, tail) = host_resp_split(len).expect("within two pages");
            assert_eq!(head + tail, len, "len {len}");
            assert!(head <= HOST_RESP_PAGE_LEN);
            assert!(tail <= HOST_RESP_PAGE_LEN);
        }
    }
}

impl HsmDmaAddr {
    /// Returns `true` if both halves are zero (null address).
    ///
    /// Used by the core to detect optional / absent host buffers in
    /// the SQE before attempting a DMA.
    ///
    /// # Returns
    ///
    /// - `true` — `lo == 0 && hi == 0`.
    /// - `false` — at least one half is non-zero.
    #[inline]
    pub fn is_null(&self) -> bool {
        self.lo == 0 && self.hi == 0
    }
}

/// GDMA memory-copy interface.
///
/// All three methods are `async`: they queue a DMA descriptor with
/// the GDMA hardware and yield until the engine signals completion.
/// They are partition-scoped via the [`HsmIo`] handle (the GDMA
/// driver uses `io.pid()` to apply per-partition policy and
/// throttling) and consume no per-IO allocator scope.
///
/// PAL implementations may serialize concurrent calls through an
/// internal async mutex; callers should treat the await as
/// potentially long-running.
pub trait HsmGdmaController {
    /// Copies bytes between two HSM-local buffers.
    ///
    /// Both endpoints live in HSM-local memory.  At least one — and
    /// often both — must be DMA-capable; PAL implementations may
    /// fall back to a memcpy when both happen to be non-DMA, but
    /// callers should not rely on this.
    ///
    /// `dst.len()` must equal `src.len()`; partial copies are not
    /// supported.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope; per-IO state
    ///   is not consumed).
    /// - `src` — source buffer.
    /// - `dst` — destination buffer; must satisfy
    ///   `dst.len() == src.len()`.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — the copy completed successfully.
    /// - `Err(HsmError::InvalidArg)` — length mismatch, or one of
    ///   the buffers is not in a memory region the GDMA can
    ///   address.
    /// - `Err(HsmError::FailedToStartDmaTransaction)` — descriptor
    ///   could not be queued (e.g. engine in error state).
    /// - `Err(HsmError)` — propagated from the GDMA driver on
    ///   completion errors.
    async fn copy_mem(&self, io: &impl HsmIo, src: &DmaBuf, dst: &mut DmaBuf) -> HsmResult<()>;

    /// Zeroes an HSM-local buffer in place.
    ///
    /// Semantically equivalent to filling `dst` with `0x00`. Intended
    /// for scrubbing key material on deletion. `dst` should be
    /// DMA-capable; implementations may offload the clear to the DMA
    /// engine, but the std and uno PALs currently zero in software
    /// (CPU) — to be replaced by a hardware memset on uno later.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope; per-IO state is
    ///   not consumed).
    /// - `dst` — buffer to zero; the whole `dst.len()` is cleared.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `dst` is fully zeroed.
    /// - `Err(HsmError::InvalidArg)` — `dst` is not in a memory region
    ///   the GDMA can address.
    /// - `Err(HsmError)` — propagated from the GDMA driver on
    ///   completion errors.
    async fn zeroize_mem(&self, io: &impl HsmIo, dst: &mut DmaBuf) -> HsmResult<()>;

    /// Copies bytes from host memory into an HSM-local DMA buffer.
    ///
    /// `dst` **must** live in DMA-capable memory (see module-level
    /// docs).  The transfer length is `dst.len()`; the host buffer
    /// at `src` must be at least that long.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `src` — host-side address.  When `prp == true`, this is the
    ///   PRP1 entry from the SQE; the GDMA walks the PRP list
    ///   pointed to by it to handle scatter/gather.  When
    ///   `prp == false`, this is a flat 64-bit physical host
    ///   address.
    /// - `dst` — HSM-local DMA-capable destination buffer.  Length
    ///   determines the transfer size.
    /// - `prp` — `true` to interpret `src` as a PRP entry, `false`
    ///   for a flat address.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — bytes copied successfully; `dst` is fully
    ///   populated.
    /// - `Err(HsmError::InvalidArg)` — `dst` is not in DMA memory,
    ///   or `src` is null when a non-empty transfer was requested.
    /// - `Err(HsmError::FailedToStartDmaTransaction)` — descriptor
    ///   could not be queued.
    /// - `Err(HsmError)` — propagated from the GDMA driver on
    ///   completion errors (e.g. host bus fault).
    async fn copy_mem_from_host(
        &self,
        io: &impl HsmIo,
        src: HsmDmaAddr,
        dst: &mut DmaBuf,
        prp: bool,
    ) -> HsmResult<()>;

    /// Copies bytes from host memory into an HSM-local DMA buffer, using
    /// a **raw 16-byte NVMe SGL Data Block descriptor** as the host
    /// source.
    ///
    /// Unlike [`copy_mem_from_host`](Self::copy_mem_from_host) — which
    /// takes a single address and synthesizes the second descriptor
    /// dword as zero — this passes both descriptor dwords straight to
    /// the GDMA hardware SGL source (`sgl0`/`sgl1`).  `desc[0..8]` is the
    /// address; `desc[8..16]` is the block's embedded `length(4) ‖
    /// rsvd(3) ‖ type(1)` (each little-endian, per NVMe).  This lets the
    /// firmware forward an SGL Data Block descriptor read out of an OOB
    /// descriptor page verbatim.
    ///
    /// The **transfer length is the descriptor's `length` field**
    /// (`desc[8..12]`), which **must equal `dst.len()`**.
    ///
    /// Only SGL is supported: `prp == true` returns
    /// [`HsmError::UnsupportedCmd`].
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `desc` — the raw 16-byte SGL Data Block descriptor.
    /// - `dst` — HSM-local DMA-capable destination buffer;
    ///   `dst.len()` must equal the descriptor's `length`.
    /// - `prp` — must be `false` (SGL); `true` is unsupported.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — bytes copied successfully.
    /// - `Err(HsmError::UnsupportedCmd)` — `prp == true`.
    /// - `Err(HsmError::InvalidArg)` — the descriptor `length` does not
    ///   equal `dst.len()`, `dst` is not in DMA memory, or the address is
    ///   null for a non-empty transfer.
    /// - `Err(HsmError::FailedToStartDmaTransaction)` — descriptor could
    ///   not be queued.
    /// - `Err(HsmError)` — propagated from the GDMA driver.
    async fn copy_mem_from_host_raw(
        &self,
        io: &impl HsmIo,
        desc: &[u8; 16],
        dst: &mut DmaBuf,
        prp: bool,
    ) -> HsmResult<()>;

    /// Copies bytes from an HSM-local DMA buffer to host memory.
    ///
    /// `src` **must** live in DMA-capable memory (see module-level
    /// docs).  The transfer length is `src.len()`; the host buffer
    /// at `dst` must be at least that long.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `src` — HSM-local DMA-capable source buffer.  Length
    ///   determines the transfer size.
    /// - `dst` — host-side address.  Same `prp == true`/`false`
    ///   semantics as
    ///   [`copy_mem_from_host`](Self::copy_mem_from_host).
    /// - `dst2` — second host page, used only when `src.len()` exceeds
    ///   4 KiB.  The Uno GDMA moves at most one 4 KiB page per transfer
    ///   and does not implement PRP lists, so a larger response is split
    ///   across two transfers rather than described by one descriptor:
    ///   the first 4 KiB go to `dst`, the remainder to `dst2`.  Pass a
    ///   null address when there is no second page; a response larger
    ///   than 4 KiB is then rejected rather than silently truncated.
    /// - `prp` — `true` to interpret `dst` as a PRP entry, `false`
    ///   for a flat address.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — bytes copied successfully.
    /// - `Err(HsmError::InvalidArg)` — `src` is not in DMA memory,
    ///   or `dst` is null when a non-empty transfer was requested.
    /// - `Err(HsmError::FailedToStartDmaTransaction)` — descriptor
    ///   could not be queued.
    /// - `Err(HsmError)` — propagated from the GDMA driver on
    ///   completion errors.
    async fn copy_mem_to_host(
        &self,
        io: &impl HsmIo,
        src: &DmaBuf,
        dst: HsmDmaAddr,
        dst2: HsmDmaAddr,
        prp: bool,
    ) -> HsmResult<()>;
}
