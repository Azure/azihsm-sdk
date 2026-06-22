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
#[derive(Debug, Clone, Copy, Default)]
pub struct HsmDmaAddr {
    /// Lower 32 bits of the address.
    pub lo: u32,

    /// Upper 32 bits of the address.
    pub hi: u32,
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
        prp: bool,
    ) -> HsmResult<()>;
}
