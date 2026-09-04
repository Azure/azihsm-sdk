// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Platform hook for commands the core does not implement.
//!
//! Both DDI dispatchers reject an opcode they do not recognise with
//! [`HsmError::UnsupportedCmd`]. That is the right answer for a
//! production build, but it leaves no way for a platform to add commands
//! that exist purely to drive testing — crash injection, fault
//! injection, and similar.
//!
//! [`HsmCustomDispatch`] gives the platform one place to intercept an
//! otherwise-unsupported opcode. The core calls it only *after* its own
//! opcode match has failed, so a platform hook can never shadow a real
//! command: if the core knows the opcode, the core handles it.
//!
//! # Everything about such a command stays below the PAL
//!
//! MBOR and TBOR are host **API contracts**, and the layering runs
//! DDI handlers -> PAL trait -> platform adapters -> drivers. A
//! test-only command must not perforate that: nothing above the PAL may
//! know a `TestAction` exists, and no build above the PAL may be
//! feature-gated on it.
//!
//! So the hook is deliberately **opaque**. The core hands over the
//! untouched request buffer and gets back an encoded response; it never
//! learns the opcode, the request shape, or whether the platform even
//! claimed it. The opcode is not in any core table, the wire types are
//! not in any core crate, and the feature flag that turns the command on
//! lives in the uno PAL alone.
//!
//! The cost is that an implementer decodes the envelope and header for
//! itself, duplicating work the core already did for MBOR. That is the
//! price of the core staying oblivious, and it is what keeps the two
//! protocols' hooks identical in shape.
//!
//! # Contract
//!
//! The hook returns the encoded response as a slice borrowed from the
//! PAL's per-IO allocator, exactly as the core's own handlers do.
//!
//! Returning the slice — rather than filling a buffer the core
//! pre-allocates — is what keeps this cheap. The implementer allocates
//! *after* any `await`, so it can use
//! [`HsmAlloc::dma_alloc_var`](crate::HsmAlloc::dma_alloc_var), which
//! hands over the remaining watermark and returns the unused tail to the
//! pool. Pre-allocating a worst-case buffer for the hook to fill would
//! instead pin the per-IO high-water mark at that maximum, and that mark
//! drives the teardown scrub.
//!
//! Note an `async fn` may call `dma_alloc_var` freely; only `await`-ing
//! *inside* the closure is disallowed. Doing the asynchronous work first
//! and encoding afterwards is therefore the natural shape.
//!
//! # Default behaviour
//!
//! Both methods default to [`HsmError::UnsupportedCmd`], so a platform
//! that adds no test commands — and every production build — behaves
//! exactly as it did before this hook existed.

use crate::DmaBuf;
use crate::HsmError;
use crate::HsmIo;
use crate::HsmResult;

/// Platform hook for opcodes the core does not implement.
///
/// MBOR and TBOR get separate entry points rather than one dispatcher
/// with a protocol discriminator: the two opcode spaces are disjoint,
/// the two core dispatchers apply different pre-gating before they reach
/// the fall-through, and a platform may want to extend one protocol
/// without touching the other.
pub trait HsmCustomDispatch {
    /// Handle an MBOR opcode the core does not implement.
    ///
    /// `req` is the whole request, exactly as it arrived. The core has
    /// decoded the envelope and header to learn the opcode, but hands
    /// over the original buffer rather than its decoder — passing a
    /// decoder would put DDI codec types in this crate, which sits below
    /// them, and would tell the core something about a command it must
    /// stay oblivious to.
    ///
    /// Taken by `&mut` because the MBOR decoder peels mutable
    /// sub-slices off the front, so byte fields can be borrowed in place
    /// rather than copied.
    ///
    /// # Parameters
    ///
    /// - `io` — the in-flight IO, for per-IO allocation.
    /// - `req` — the untouched request buffer.
    ///
    /// # Returns
    ///
    /// - `Ok(resp)` — the encoded response, borrowed from the PAL's
    ///   per-IO allocator and valid until the IO completes.
    /// - `Err(HsmError::UnsupportedCmd)` — opcode not handled here
    ///   either; the core surfaces this to the host unchanged.
    async fn mbor_dispatch(&self, io: &impl HsmIo, req: &mut DmaBuf) -> HsmResult<&DmaBuf> {
        // The parameters are the trait's contract, not this body's — an
        // overriding platform uses both. Consumed rather than renamed
        // to `_io` / `_req` so the documented names survive, and rather
        // than silenced with `#[allow(unused_variables)]` so static
        // analysis sees a genuine use.
        let _ = (io, req);
        Err(HsmError::UnsupportedCmd)
    }

    /// Handle a TBOR opcode the core does not implement.
    ///
    /// As with [`mbor_dispatch`](Self::mbor_dispatch), `req` is the
    /// whole request. TBOR rejects an unknown opcode before parsing
    /// anything, so nothing has been consumed in any case.
    ///
    /// The opcode is passed separately here only because TBOR's is a
    /// bare leading byte the core already has in hand; MBOR's sits
    /// inside the encoded header, and pulling it out for the hook would
    /// mean handing over a decoded DDI type.
    ///
    /// # Parameters
    ///
    /// - `io` — the in-flight IO, for per-IO allocation.
    /// - `opcode` — the opcode that was not recognised.
    /// - `req` — the untouched request buffer.
    ///
    /// # Returns
    ///
    /// - `Ok(resp)` — the encoded response, borrowed from the PAL's
    ///   per-IO allocator and valid until the IO completes.
    /// - `Err(HsmError::UnsupportedCmd)` — opcode not handled here
    ///   either; the core surfaces this to the host unchanged.
    async fn tbor_dispatch(&self, io: &impl HsmIo, opcode: u8, req: &DmaBuf) -> HsmResult<&DmaBuf> {
        // See `mbor_dispatch` — consumed, not renamed or silenced.
        let _ = (io, opcode, req);
        Err(HsmError::UnsupportedCmd)
    }
}
