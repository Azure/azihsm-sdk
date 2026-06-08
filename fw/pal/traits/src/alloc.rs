// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-IO memory allocator trait.
//!
//! Defines the [`HsmAlloc`] PAL trait and the
//! [`HsmScopedAlloc`] handle that callers receive inside an
//! allocation scope.  The trait is the entry point for every
//! firmware-side scratch allocation: DMA staging buffers, crypto
//! state, hash contexts, KDF working memory, DDI response framing.
//!
//! ## Memory pools
//!
//! Each IO has access to two distinct pools, chosen implicitly by
//! method name:
//!
//! - **NonDma** — fast, tightly-coupled DTCM (~2 KB).  Reached via
//!   [`alloc`](HsmAlloc::alloc), [`alloc_zeroed`](HsmAlloc::alloc_zeroed),
//!   [`alloc_val`](HsmAlloc::alloc_val), and the matching methods on
//!   [`HsmScopedAlloc`].  Use for small, CPU-only state where DTCM
//!   latency matters: SHA/HMAC contexts, KDF scratch, structs that
//!   never touch a DMA engine.
//!
//! - **Dma** — larger, slower SRAM (~8 KB).  Reached via
//!   [`dma_alloc`](HsmAlloc::dma_alloc),
//!   [`dma_alloc_zeroed`](HsmAlloc::dma_alloc_zeroed),
//!   [`dma_alloc_var`](HsmAlloc::dma_alloc_var),
//!   [`dma_alloc_var_with`](HsmAlloc::dma_alloc_var_with), and the
//!   matching methods on [`HsmScopedAlloc`].  Use for any buffer
//!   that is the source or destination of a GDMA/SHA/AES transfer,
//!   plus large staging buffers (DDI request/response framing,
//!   certificate streaming).
//!
//! All allocations are 4-byte aligned.  All sizes are honored
//! exactly — there is no rounding past the alignment requirement.
//!
//! ## Lifetime model
//!
//! Allocations come in two lifetime flavors:
//!
//! - **Scoped** — made through an
//!   [`HsmScopedAlloc`] handle inside
//!   [`alloc_scoped`](HsmAlloc::alloc_scoped) /
//!   [`alloc_scoped_async`](HsmAlloc::alloc_scoped_async).  Every
//!   buffer is freed when the closure returns; the borrow lives only
//!   inside the closure body.  This is the common path for short-
//!   lived crypto scratch.
//!
//! - **IO-scoped** — made directly on the PAL via
//!   [`dma_alloc`](HsmAlloc::dma_alloc) / friends.  The borrow lives
//!   for the rest of the IO and survives across `await` points,
//!   which is required for buffers that bracket a DMA descriptor
//!   yield (e.g. the inbound/outbound DMA staging buffer in
//!   `handle_mbor_op` / `handle_tbor_op`).
//!
//! ## Errors
//!
//! Every fallible method returns [`HsmError::NotEnoughSpace`] when
//! the underlying bump allocator's watermark cannot satisfy the
//! request.  This is the *only* error any allocator method
//! produces; other errors are propagated only through user closures
//! ([`dma_alloc_var`](HsmAlloc::dma_alloc_var) etc.).
//!
//! ## Example
//!
//! ```ignore
//! // Scoped: all allocations freed on closure return.
//! pal.alloc_scoped(io, |a| {
//!     let scratch = a.alloc(384)?;     // NonDma DTCM
//!     let dma_buf = a.dma_alloc(256)?; // Dma SRAM
//!     // ... use buffers ...
//!     Ok::<_, HsmError>(())
//! })?;
//!
//! // IO-scoped: lives across await points.
//! let staging = pal.dma_alloc(io, 512)?;
//! pal.copy_mem_from_host(io, src_addr, staging, true).await?;
//! ```

use core::ops::AsyncFnOnce;

use super::*;

// ── DmaBuf ────────────────────────────────────────────────────────

/// A byte slice guaranteed to reside in DMA-accessible memory.
///
/// `DmaBuf` is a `#[repr(transparent)]` newtype over `[u8]`. The
/// only way to construct one is via the unsafe `from_raw` /
/// `from_raw_mut` helpers, which the PAL allocator uses to brand
/// SRAM-backed buffers handed out by `dma_alloc`. Everywhere a
/// `&DmaBuf` or `&mut DmaBuf` is required, the type system proves
/// the bytes live in a region the GDMA / SHA / AES engines can
/// reach.
///
/// `DmaBuf` `Deref`s to `[u8]`, so all read-only slice operations
/// (length, iteration, `as_ptr`) work transparently. Mutable
/// access goes through `DerefMut`.
#[repr(transparent)]
pub struct DmaBuf {
    inner: [u8],
}

impl DmaBuf {
    /// Brands a borrowed `[u8]` as DMA-accessible.
    ///
    /// # Safety
    ///
    /// `buf` must point into a memory region that the platform's
    /// DMA engines (GDMA, SHA, AES, etc.) can address. The PAL
    /// allocator is the only place this should be called with
    /// freshly allocated SRAM. Outside the PAL, prefer constructing
    /// sub-views of an existing `DmaBuf` via indexing.
    #[doc(hidden)]
    #[inline(always)]
    pub unsafe fn from_raw(buf: &[u8]) -> &Self {
        unsafe { &*(buf as *const [u8] as *const DmaBuf) }
    }

    /// Mutable equivalent of [`DmaBuf::from_raw`].
    ///
    /// # Safety
    ///
    /// Same requirements as [`DmaBuf::from_raw`].
    #[doc(hidden)]
    #[inline(always)]
    pub unsafe fn from_raw_mut(buf: &mut [u8]) -> &mut Self {
        unsafe { &mut *(buf as *mut [u8] as *mut DmaBuf) }
    }

    /// Splits this `DmaBuf` into two `DmaBuf` views at `mid`.
    ///
    /// Both halves remain DMA-accessible because they are
    /// sub-views of an existing `DmaBuf`.
    #[inline(always)]
    pub fn split_at(&self, mid: usize) -> (&DmaBuf, &DmaBuf) {
        let (a, b) = self.inner.split_at(mid);
        unsafe { (DmaBuf::from_raw(a), DmaBuf::from_raw(b)) }
    }

    /// Mutable equivalent of [`DmaBuf::split_at`].
    #[inline(always)]
    pub fn split_at_mut(&mut self, mid: usize) -> (&mut DmaBuf, &mut DmaBuf) {
        let (a, b) = self.inner.split_at_mut(mid);
        unsafe { (DmaBuf::from_raw_mut(a), DmaBuf::from_raw_mut(b)) }
    }
}

impl core::ops::Deref for DmaBuf {
    type Target = [u8];
    #[inline(always)]
    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

impl core::ops::DerefMut for DmaBuf {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

// `DmaBuf` is a transparent newtype over `[u8]`, so byte-wise equality
// matches caller expectations. This impl is required by the FW TBOR
// codec's `TocEntry` enum (variants hold `&DmaBuf` and derive
// `PartialEq`/`Eq` for test assertions and the wire round-trip).
//
// Note: comparing two byte buffers in constant time is the caller's
// responsibility (use `subtle::ConstantTimeEq` for secrets); this
// `PartialEq` is `[u8]::eq` and short-circuits.
impl PartialEq for DmaBuf {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for DmaBuf {}

// Cross-type byte equality used by tests and codec assertions that
// compare a `&DmaBuf` to a `&[u8; N]` literal (e.g. `b"hello"`).
impl PartialEq<[u8]> for DmaBuf {
    #[inline(always)]
    fn eq(&self, other: &[u8]) -> bool {
        &self.inner == other
    }
}

impl<const N: usize> PartialEq<[u8; N]> for DmaBuf {
    #[inline(always)]
    fn eq(&self, other: &[u8; N]) -> bool {
        &self.inner == other.as_slice()
    }
}

impl core::fmt::Debug for DmaBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DmaBuf({} bytes)", self.inner.len())
    }
}

impl core::ops::Index<usize> for DmaBuf {
    type Output = u8;
    #[inline(always)]
    fn index(&self, i: usize) -> &u8 {
        &self.inner[i]
    }
}

impl core::ops::IndexMut<usize> for DmaBuf {
    #[inline(always)]
    fn index_mut(&mut self, i: usize) -> &mut u8 {
        &mut self.inner[i]
    }
}

impl core::ops::Index<core::ops::Range<usize>> for DmaBuf {
    type Output = DmaBuf;
    #[inline(always)]
    fn index(&self, r: core::ops::Range<usize>) -> &DmaBuf {
        unsafe { DmaBuf::from_raw(&self.inner[r]) }
    }
}

impl core::ops::IndexMut<core::ops::Range<usize>> for DmaBuf {
    #[inline(always)]
    fn index_mut(&mut self, r: core::ops::Range<usize>) -> &mut DmaBuf {
        unsafe { DmaBuf::from_raw_mut(&mut self.inner[r]) }
    }
}

impl core::ops::Index<core::ops::RangeTo<usize>> for DmaBuf {
    type Output = DmaBuf;
    #[inline(always)]
    fn index(&self, r: core::ops::RangeTo<usize>) -> &DmaBuf {
        unsafe { DmaBuf::from_raw(&self.inner[r]) }
    }
}

impl core::ops::IndexMut<core::ops::RangeTo<usize>> for DmaBuf {
    #[inline(always)]
    fn index_mut(&mut self, r: core::ops::RangeTo<usize>) -> &mut DmaBuf {
        unsafe { DmaBuf::from_raw_mut(&mut self.inner[r]) }
    }
}

impl core::ops::Index<core::ops::RangeFrom<usize>> for DmaBuf {
    type Output = DmaBuf;
    #[inline(always)]
    fn index(&self, r: core::ops::RangeFrom<usize>) -> &DmaBuf {
        unsafe { DmaBuf::from_raw(&self.inner[r]) }
    }
}

impl core::ops::IndexMut<core::ops::RangeFrom<usize>> for DmaBuf {
    #[inline(always)]
    fn index_mut(&mut self, r: core::ops::RangeFrom<usize>) -> &mut DmaBuf {
        unsafe { DmaBuf::from_raw_mut(&mut self.inner[r]) }
    }
}

impl core::ops::Index<core::ops::RangeFull> for DmaBuf {
    type Output = DmaBuf;
    #[inline(always)]
    fn index(&self, _: core::ops::RangeFull) -> &DmaBuf {
        self
    }
}

impl core::ops::IndexMut<core::ops::RangeFull> for DmaBuf {
    #[inline(always)]
    fn index_mut(&mut self, _: core::ops::RangeFull) -> &mut DmaBuf {
        self
    }
}

// ── Scoped allocation handle ──────────────────────────────────────

/// Handle to allocations whose lifetime is bounded by an
/// [`alloc_scoped`](HsmAlloc::alloc_scoped) /
/// [`alloc_scoped_async`](HsmAlloc::alloc_scoped_async) closure.
///
/// Every method on this trait mirrors the corresponding direct
/// method on [`HsmAlloc`], minus the `io` parameter — the IO is
/// captured implicitly by the scope.  All buffers handed out by a
/// scoped handle are freed atomically when the enclosing closure
/// returns.
#[allow(clippy::mut_from_ref)]
pub trait HsmScopedAlloc {
    /// Allocates `size` bytes of uninitialised memory from the
    /// NonDma (DTCM) pool.
    ///
    /// Contents of the returned slice are unspecified.
    ///
    /// # Parameters
    ///
    /// - `size` — number of bytes to allocate.
    ///
    /// # Returns
    ///
    /// - `Ok(&mut [u8])` — slice of length exactly `size`, 4-byte
    ///   aligned.
    /// - `Err(HsmError::NotEnoughSpace)` — the NonDma pool cannot
    ///   satisfy the request.
    fn alloc(&self, size: usize) -> HsmResult<&mut [u8]>;

    /// Allocates `size` bytes from the NonDma (DTCM) pool and
    /// zero-fills them.
    ///
    /// # Parameters
    ///
    /// - `size` — number of bytes to allocate.
    ///
    /// # Returns
    ///
    /// - `Ok(&mut [u8])` — zero-initialised slice of length `size`.
    /// - `Err(HsmError::NotEnoughSpace)` — pool exhausted.
    fn alloc_zeroed(&self, size: usize) -> HsmResult<&mut [u8]>;

    /// Allocates space for a `T` from the NonDma (DTCM) pool and
    /// moves `value` into it.
    ///
    /// # Type Parameters
    ///
    /// - `T` — `Sized`. The allocation is `core::mem::size_of::<T>()`
    ///   bytes; alignment is the standard 4-byte allocator alignment
    ///   (matches `T`'s alignment for all `T` with `align_of::<T>()
    ///   <= 4`).
    ///
    /// # Parameters
    ///
    /// - `value` — `T` to be moved into the allocation.
    ///
    /// # Returns
    ///
    /// - `Ok(&mut T)` — exclusive reference to the freshly placed
    ///   value.
    /// - `Err(HsmError::NotEnoughSpace)` — pool exhausted.
    fn alloc_val<T: Sized>(&self, value: T) -> HsmResult<&mut T>;

    /// Allocates `size` bytes of uninitialised memory from the Dma
    /// (SRAM) pool.
    ///
    /// # Parameters
    ///
    /// - `size` — number of bytes to allocate.
    ///
    /// # Returns
    ///
    /// - `Ok(&mut [u8])` — DMA-capable slice of length exactly
    ///   `size`, 4-byte aligned.  Suitable as a GDMA/SHA/AES
    ///   endpoint.
    /// - `Err(HsmError::NotEnoughSpace)` — the Dma pool cannot
    ///   satisfy the request.
    fn dma_alloc(&self, size: usize) -> HsmResult<&mut DmaBuf>;

    /// Allocates `size` bytes from the Dma (SRAM) pool and
    /// zero-fills them.
    ///
    /// # Parameters
    ///
    /// - `size` — number of bytes to allocate.
    ///
    /// # Returns
    ///
    /// - `Ok(&mut [u8])` — zero-initialised DMA-capable slice.
    /// - `Err(HsmError::NotEnoughSpace)` — pool exhausted.
    fn dma_alloc_zeroed(&self, size: usize) -> HsmResult<&mut DmaBuf>;
}

// ── Public allocator trait ────────────────────────────────────────

/// Per-IO scratch memory allocator.
///
/// Concrete PALs implement this trait by carving each IO's slot out
/// of two static heaps (NonDma / Dma) and handing out bump-allocated
/// slices via [`HsmScopedAlloc`] (scope-bounded) or directly
/// (IO-bounded).
///
/// **Allocation methods** (the same set is mirrored on
/// [`HsmScopedAlloc`] without the `io` argument):
///
/// | NonDma (DTCM) | Dma (SRAM) |
/// |---------------|------------|
/// | [`alloc`](Self::alloc) | [`dma_alloc`](Self::dma_alloc) |
/// | [`alloc_zeroed`](Self::alloc_zeroed) | [`dma_alloc_zeroed`](Self::dma_alloc_zeroed) |
/// | [`alloc_val`](Self::alloc_val) | — |
///
/// **Dma-only** (long-lived, variable-size, populated via closure):
///
/// | Method | Description |
/// |--------|-------------|
/// | [`dma_alloc_var`](Self::dma_alloc_var) | Hand out the rest of Dma to a closure, shrink to the closure's reported length |
/// | [`dma_alloc_var_with`](Self::dma_alloc_var_with) | Same, plus return an owned `T` alongside the buffer |
///
/// **Scoping**:
///
/// | Method | Description |
/// |--------|-------------|
/// | [`alloc_scoped`](Self::alloc_scoped) | Synchronous scope; all scope allocations freed on return |
/// | [`alloc_scoped_async`](Self::alloc_scoped_async) | Async scope; same lifetime semantics across awaits |
#[allow(clippy::mut_from_ref)]
pub trait HsmAlloc {
    /// PAL-specific scoped allocator handle.
    ///
    /// The associated lifetime ties the handle to the enclosing
    /// scope so allocations cannot escape it.
    type Scoped<'a>: HsmScopedAlloc
    where
        Self: 'a;

    // ── NonDma (DTCM) ─────────────────────────────────────────

    /// Allocates `size` bytes of uninitialised memory from `io`'s
    /// NonDma pool.
    ///
    /// The borrow lives for the rest of the IO and survives across
    /// `await` points.  Use this when the buffer must outlive a
    /// scope (rare for NonDma; most NonDma allocations are scoped).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (selects the per-IO heap slot).
    /// - `size` — number of bytes to allocate.
    ///
    /// # Returns
    ///
    /// - `Ok(&mut [u8])` — slice of length exactly `size`, 4-byte
    ///   aligned.
    /// - `Err(HsmError::NotEnoughSpace)` — pool exhausted.
    fn alloc(&self, io: &impl HsmIo, size: usize) -> HsmResult<&mut [u8]>;

    /// Allocates `size` bytes from `io`'s NonDma pool and
    /// zero-fills them.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `size` — number of bytes to allocate.
    ///
    /// # Returns
    ///
    /// - `Ok(&mut [u8])` — zero-initialised slice.
    /// - `Err(HsmError::NotEnoughSpace)` — pool exhausted.
    fn alloc_zeroed(&self, io: &impl HsmIo, size: usize) -> HsmResult<&mut [u8]>;

    /// Allocates space for a `T` on `io`'s NonDma pool and moves
    /// `value` into it.
    ///
    /// # Type Parameters
    ///
    /// - `T` — `Sized`. Allocation size is
    ///   `core::mem::size_of::<T>()`; alignment is the standard
    ///   4-byte allocator alignment.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `value` — `T` to be moved into the allocation.
    ///
    /// # Returns
    ///
    /// - `Ok(&mut T)` — exclusive reference to the placed value.
    /// - `Err(HsmError::NotEnoughSpace)` — pool exhausted.
    fn alloc_val<T: Sized>(&self, io: &impl HsmIo, value: T) -> HsmResult<&mut T>;

    // ── Dma (SRAM) ────────────────────────────────────────────

    /// Allocates `size` bytes of uninitialised memory from `io`'s
    /// Dma pool.
    ///
    /// The borrow lives for the rest of the IO and survives across
    /// `await` points — the canonical use is staging a host↔device
    /// DMA transfer that yields between request submission and
    /// completion.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `size` — number of bytes to allocate.
    ///
    /// # Returns
    ///
    /// - `Ok(&mut [u8])` — DMA-capable slice of length exactly
    ///   `size`, 4-byte aligned.
    /// - `Err(HsmError::NotEnoughSpace)` — pool exhausted.
    fn dma_alloc(&self, io: &impl HsmIo, size: usize) -> HsmResult<&mut DmaBuf>;

    /// Allocates `size` bytes from `io`'s Dma pool and zero-fills
    /// them.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `size` — number of bytes to allocate.
    ///
    /// # Returns
    ///
    /// - `Ok(&mut [u8])` — zero-initialised DMA-capable slice.
    /// - `Err(HsmError::NotEnoughSpace)` — pool exhausted.
    fn dma_alloc_zeroed(&self, io: &impl HsmIo, size: usize) -> HsmResult<&mut DmaBuf>;

    /// Variable-size DMA allocation populated by a closure.
    ///
    /// Hands `f` the *entire* remaining Dma watermark as a mutable
    /// slice.  `f` writes a prefix of unknown length and returns the
    /// number of bytes it actually populated.  The allocation is
    /// then shrunk to that length and the unused tail is returned to
    /// the pool.
    ///
    /// Used wherever a buffer's exact size is only known after the
    /// fact — for example, MBOR encoding of a DDI response.
    ///
    /// # Type Parameters
    ///
    /// - `F` — `FnOnce(&mut [u8]) -> HsmResult<usize>`.  The closure
    ///   may return any [`HsmError`]; the allocator only contributes
    ///   [`HsmError::NotEnoughSpace`] of its own.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `f` — populates a prefix and returns its length in bytes.
    ///   The returned length must be ≤ the slice the closure
    ///   received.
    ///
    /// # Returns
    ///
    /// - `Ok(&mut [u8])` — slice trimmed to the length returned by
    ///   `f`.
    /// - `Err(HsmError::NotEnoughSpace)` — Dma pool was empty before
    ///   `f` ran.
    /// - `Err(e)` — propagated unchanged from `f`.
    fn dma_alloc_var<F>(&self, io: &impl HsmIo, f: F) -> HsmResult<&mut DmaBuf>
    where
        F: FnOnce(&mut [u8]) -> HsmResult<usize>;

    /// Like [`dma_alloc_var`](Self::dma_alloc_var) but `f` returns
    /// an owned `T` alongside the populated length.
    ///
    /// Useful when the closure needs to communicate something else
    /// to the caller in addition to the buffer length — for example,
    /// a parsed length field, a derived `usize` count, or a small
    /// struct describing the encoded layout.
    ///
    /// # Type Parameters
    ///
    /// - `F` — `FnOnce(&mut [u8]) -> HsmResult<(usize, T)>`.
    /// - `T` — owned value produced by the closure.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `f` — populates a prefix and returns `(prefix_len, value)`.
    ///   `prefix_len` must be ≤ the slice the closure received.
    ///
    /// # Returns
    ///
    /// - `Ok((&mut [u8], T))` — trimmed slice plus the closure's
    ///   value.
    /// - `Err(HsmError::NotEnoughSpace)` — Dma pool empty before
    ///   `f` ran.
    /// - `Err(e)` — propagated unchanged from `f`.
    fn dma_alloc_var_with<F, T>(&self, io: &impl HsmIo, f: F) -> HsmResult<(&mut DmaBuf, T)>
    where
        F: FnOnce(&mut [u8]) -> HsmResult<(usize, T)>;

    // ── Scoping ───────────────────────────────────────────────

    /// Runs `f` with an [`HsmScopedAlloc`] handle and frees every
    /// allocation made through that handle when `f` returns.
    ///
    /// Scopes may nest; nested scopes see the parent's watermark
    /// and roll back to it on return.  Allocations made through the
    /// outer PAL trait (e.g. [`dma_alloc`](Self::dma_alloc)) are
    /// **not** freed by scope exit.
    ///
    /// # Type Parameters
    ///
    /// - `R` — value returned by `f` and forwarded to the caller.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `f` — closure that performs scoped allocations through the
    ///   provided handle.
    ///
    /// # Returns
    ///
    /// Whatever `f` returned (`R`); `f` is expected to encode any
    /// fallibility into `R` itself (typically `R = HsmResult<…>`).
    fn alloc_scoped<R>(&self, io: &impl HsmIo, f: impl FnOnce(&Self::Scoped<'_>) -> R) -> R;

    /// Async variant of [`alloc_scoped`](Self::alloc_scoped).
    ///
    /// Scope semantics are identical: the watermark rolls back when
    /// `f`'s future completes, regardless of how many `await` points
    /// it contained.
    ///
    /// # Type Parameters
    ///
    /// - `R` — value returned by `f`'s future.
    /// - `F` — `for<'a> AsyncFnOnce(&'a Self::Scoped<'a>) -> R`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context.
    /// - `f` — async closure that performs scoped allocations.
    ///
    /// # Returns
    ///
    /// Whatever `f` returned (`R`).
    async fn alloc_scoped_async<R, F>(&self, io: &impl HsmIo, f: F) -> R
    where
        F: for<'a> AsyncFnOnce(&'a Self::Scoped<'a>) -> R;
}
