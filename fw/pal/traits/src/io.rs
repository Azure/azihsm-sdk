// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! I/O controller and per-IO traits for the HSM platform abstraction
//! layer.
//!
//! Defines the two traits the core uses to receive and complete host
//! commands:
//!
//! - [`HsmIoController`] — the platform's I/O fabric.  Drives the
//!   submission/completion queue lifecycle and produces individual
//!   [`HsmIo`] handles.
//! - [`HsmIo`] — a single in-flight command: borrows of its SQE/CQE,
//!   plus the partition / queue / slot identifiers used to scope
//!   per-IO state (partition, allocator scope, vault, session).
//!
//! ## SQE / CQE layout
//!
//! Submission and completion queue entries are fixed-size dword
//! arrays with platform-defined contents.  This crate exposes only
//! the raw shape ([`HsmSqe`], [`HsmCqe`], [`SQE_DWORDS`],
//! [`CQE_DWORDS`]); the semantic decode (opcode, PRP fields, session
//! flags, status word, …) lives in the core (`azihsm_fw_hsm_core`).
//!
//! ## Pipeline
//!
//! ```text
//! poll_io().await        — receive next request
//!   ↓
//! io.sqe() / io.cqe()    — decode SQE, populate CQE
//! io.pid()               — resolve partition for downstream PAL calls
//!   ↓
//! complete_io(io).await  — emit CQE; or
//! drop_io(io).await      — silently discard (e.g. disabled partition)
//! ```

use super::*;

/// Number of dwords in a submission queue entry.
///
/// The total SQE size in bytes is `SQE_DWORDS * 4`.
pub const SQE_DWORDS: usize = 16;

/// Number of dwords in a completion queue entry.
///
/// The total CQE size in bytes is `CQE_DWORDS * 4`.
pub const CQE_DWORDS: usize = 4;

/// A submission queue entry as a raw dword array.
///
/// Layout is platform-defined and decoded by the core's `Sqe` wrapper.
pub type HsmSqe = [u32; SQE_DWORDS];

/// A completion queue entry as a raw dword array.
///
/// Layout is platform-defined and decoded by the core's `Cqe` wrapper.
pub type HsmCqe = [u32; CQE_DWORDS];

/// Handle to a single in-flight I/O.
///
/// Represents a submission/completion pair: the caller reads the
/// submission queue entry via [`sqe`](Self::sqe) to determine the
/// requested operation and writes the result into the completion
/// queue entry via [`cqe`](Self::cqe).  The handle also exposes the
/// partition, queue, and slot identifiers used to scope per-IO state
/// (allocator scope, vault, sessions, certificate store) across the
/// rest of the PAL traits.
///
/// `HsmIo` is `Send` (via [`HsmIoController::Io`]) so an IO can be
/// moved between Embassy executor tasks during processing.  It is
/// **not** `Sync`: each IO is owned by exactly one task at a time.
///
/// The handle is consumed by exactly one of
/// [`HsmIoController::complete_io`] or
/// [`HsmIoController::drop_io`]; failing to do so leaks the
/// underlying queue slot.
pub trait HsmIo {
    /// Returns the IO slot index used to address per-IO resources
    /// (e.g. the per-IO bump-allocator scope).
    ///
    /// # Returns
    ///
    /// A `u16` in the range `0..N`, where `N` is the platform's IO
    /// concurrency (e.g. number of preallocated SQE/CQE buffer
    /// slots).  Stable across the lifetime of this `HsmIo`.
    fn index(&self) -> u16;

    /// Returns the partition that owns this IO.
    ///
    /// All partition-scoped PAL calls (vault, session, partition
    /// metadata, certificate store) resolve their target partition
    /// by calling this method on the IO handle they're given.
    ///
    /// # Returns
    ///
    /// The [`HsmPartId`] of the partition whose submission queue
    /// produced this IO.  Stable across the lifetime of this
    /// `HsmIo`.
    fn pid(&self) -> HsmPartId;

    /// Returns the controller queue this IO belongs to.
    ///
    /// A partition may be backed by multiple SQ/CQ pairs; this
    /// identifies which one delivered the request and to which the
    /// completion will be posted.
    ///
    /// # Returns
    ///
    /// The queue identifier as a `u16`.  Stable across the lifetime
    /// of this `HsmIo`.
    fn queue_id(&self) -> u16;

    /// Returns the slot index of this IO within its controller queue.
    ///
    /// # Returns
    ///
    /// The intra-queue index as a `u16`.  Stable across the lifetime
    /// of this `HsmIo`.
    fn queue_idx(&self) -> u16;

    /// Borrows the submission queue entry.
    ///
    /// The SQE is read-only from the firmware's perspective: the
    /// host populated it before raising the doorbell that triggered
    /// [`HsmIoController::poll_io`].
    ///
    /// # Returns
    ///
    /// An immutable reference to the [`HsmSqe`] dword array.  Borrow
    /// lives for the duration of the `&self` borrow.
    fn sqe(&self) -> &HsmSqe;

    /// Borrows the completion queue entry for in-place population.
    ///
    /// The firmware writes the status word, response length, and any
    /// session-control fields here before calling
    /// [`HsmIoController::complete_io`].  Contents prior to that
    /// call are unspecified; callers must overwrite, not read.
    ///
    /// # Returns
    ///
    /// A mutable reference to the [`HsmCqe`] dword array.  Borrow
    /// lives for the duration of the `&mut self` borrow.
    fn cqe(&mut self) -> &mut HsmCqe;
}

/// Asynchronous I/O controller that produces and completes IOs.
///
/// Implementations own the platform's submission/completion queue
/// pair (or pairs): IPC mailboxes on Uno, in-process channels for
/// the std PAL emulator.  The controller is consumed by the core's
/// main loop, which calls [`poll_io`](Self::poll_io) in an
/// `async` fashion and dispatches each returned [`HsmIo`] to the
/// command pipeline.
///
/// Lifecycle invariant: every IO returned by
/// [`poll_io`](Self::poll_io) must eventually be passed to either
/// [`complete_io`](Self::complete_io) or
/// [`drop_io`](Self::drop_io) — dropping the IO without either call
/// leaks the underlying queue slot.
pub trait HsmIoController {
    /// Platform-specific IO type.
    ///
    /// Bound to be `Send` so that the core can move IOs across
    /// Embassy executor tasks during async processing.
    type Io: HsmIo + Send;

    /// Awaits the next IO from any submission queue.
    ///
    /// Yields until at least one queue has a pending entry, then
    /// returns the corresponding [`Self::Io`] handle.
    ///
    /// # Returns
    ///
    /// - `Ok(io)` — a fresh in-flight IO ready for processing.
    /// - `Err(HsmError)` — fatal queue error (controller is no
    ///   longer usable; the main loop should treat this as
    ///   unrecoverable).
    async fn poll_io(&self) -> HsmResult<Self::Io>;

    /// Posts the completion entry for `io` and frees its queue slot.
    ///
    /// Consumes the [`Self::Io`] handle.  Callers must have written
    /// the desired CQE contents via [`HsmIo::cqe`] before invoking
    /// this method; the contents are flushed to the host as part of
    /// completion.
    ///
    /// # Parameters
    ///
    /// - `io` — handle previously returned by
    ///   [`poll_io`](Self::poll_io).
    ///
    /// # Returns
    ///
    /// - `Ok(())` — completion was successfully posted.
    /// - `Err(HsmError)` — failed to enqueue the CQE; the slot is
    ///   still freed, but the host will not see this completion.
    async fn complete_io(&self, io: Self::Io) -> HsmResult<()>;

    /// Frees the queue slot **without** posting a CQE.
    ///
    /// Used when the IO must be silently discarded — for example
    /// when it arrived for a non-[`PartState::Enabled`](crate::PartState::Enabled)
    /// partition and core wants to drop it without surfacing
    /// anything to the host.
    ///
    /// # Parameters
    ///
    /// - `io` — handle previously returned by
    ///   [`poll_io`](Self::poll_io).
    ///
    /// # Returns
    ///
    /// - `Ok(())` — slot was freed.
    /// - `Err(HsmError)` — slot release failed (logged by core; the
    ///   IO is no longer accessible regardless).
    async fn drop_io(&self, io: Self::Io) -> HsmResult<()>;
}
