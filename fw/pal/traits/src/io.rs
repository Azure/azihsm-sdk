// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! I/O controller and IO traits for the HSM platform abstraction layer.

use super::*;

/// Number of dwords in a submission queue entry.
pub const SQE_DWORDS: usize = 16;

// Number of dwords in a completion queue entry.
pub const CQE_DWORDS: usize = 4;

/// A submission queue entry as a raw dword array.
pub type HsmSqe = [u32; SQE_DWORDS];

/// A completion queue entry as a raw dword array.
pub type HsmCqe = [u32; CQE_DWORDS];

/// A single I/O received from a controller queue.
///
/// Represents a submission/completion pair: the caller reads the submission
/// queue entry ([`sqe`](Self::sqe)) to determine the requested operation and
/// writes the result into the completion queue entry ([`cqe`](Self::cqe)).
pub trait HsmIo {
    /// Returns the controller that owns this IO.
    fn part_id(&self) -> u8;

    /// Returns the queue within the controller that this IO belongs to.
    fn queue_id(&self) -> u16;

    /// Returns the index of this IO within its queue.
    fn queue_idx(&self) -> u16;

    /// Convenience method to get SQE
    fn sqe(&self) -> &HsmSqe;

    /// Convenience method to get CQE
    fn cqe(&mut self) -> &mut HsmCqe;

    /// Returns a mutable slice of the large IO buffer (8KB).
    fn mem(&mut self) -> (&mut [u8], &mut [u8]);
}

/// An asynchronous I/O controller that produces and consumes IOs.
///
/// Implementors provide platform-specific queue access. The controller
/// receives IOs from a submission queue and sends completed IOs back
/// through a completion queue.
pub trait HsmIoController {
    /// The platform-specific IO type.
    type Io: HsmIo + Send;

    /// Waits for the next IO from the submission queue.
    async fn poll_io(&self) -> HsmResult<Self::Io>;

    /// Sends a completed IO back through the completion queue.
    /// Consumes the IO, freeing the underlying slot.
    async fn complete_io(&self, io: Self::Io) -> HsmResult<()>;
}
